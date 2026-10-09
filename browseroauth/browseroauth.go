// Package browseroauth provides storage-neutral OAuth authorization-code
// primitives for applications that own their browser and callback lifecycle.
package browseroauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kayiik/llm-provider-auth/internal/sanitize"
	"github.com/kayiik/llm-provider-auth/tokenstore"
)

const (
	defaultTimeout           = 20 * time.Second
	maxResponseBytes   int64 = 1 << 20
	maxDiagnosticChars       = 512
	randomByteCount          = 32
)

// ClientAuthMode identifies how the OAuth client authenticates to the token
// endpoint. The zero value is invalid so callers cannot silently omit a secret.
type ClientAuthMode string

const (
	ClientAuthModePublicPKCE       ClientAuthMode = "public_pkce"
	ClientAuthModeClientSecretPost ClientAuthMode = "client_secret_post"
)

// Config contains all provider- and application-specific OAuth configuration.
// ClientAuthMode is required. ExtraAuthParams are added only to authorization
// URLs; ExtraTokenParams are added to both authorization-code and refresh token
// requests, except that client authentication fields are mode-controlled.
type Config struct {
	AuthorizeURL     string
	TokenURL         string
	ClientID         string
	ClientSecret     string
	ClientAuthMode   ClientAuthMode
	Scopes           []string
	ExtraAuthParams  url.Values
	ExtraTokenParams url.Values
	HTTPClient       *http.Client
}

// Authorization contains the values a caller needs to start and later finish
// one browser authorization attempt. State and CodeVerifier are secrets and
// must be retained by the caller until the callback is validated.
type Authorization struct {
	URL          string
	State        string
	CodeVerifier string
}

// TokenEnvelope is the typed token endpoint result returned to the caller for
// its own lifecycle and persistence policy.
type TokenEnvelope struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type,omitempty"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	Scope        string         `json:"scope,omitempty"`
	ExpiresIn    int64          `json:"expires_in,omitempty"`
	ExpiresAt    time.Time      `json:"expires_at,omitempty"`
	IDToken      string         `json:"id_token,omitempty"`
	Extra        map[string]any `json:"extra,omitempty"`
}

// EndpointError exposes safe, machine-inspectable token endpoint failure facts.
type EndpointError struct {
	StatusCode  int
	Code        string
	Description string
}

// ValidateState compares callback state to the state generated for the
// authorization attempt without leaking a useful timing signal.
func ValidateState(expected, actual string) error {
	if expected == "" || actual == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) != 1 {
		return fmt.Errorf("OAuth state mismatch")
	}
	return nil
}

// Terminal reports whether the token endpoint rejected a refresh grant
// permanently, so a tokenstore.Coordinator revokes the credential instead of
// retrying it. Transport and response-format failures are not terminal.
func (e *EndpointError) Terminal() bool {
	return e != nil && tokenstore.TerminalOAuthCode(e.Code)
}

func (e *EndpointError) Error() string {
	message := "OAuth token request failed"
	if e.StatusCode != 0 {
		message += fmt.Sprintf(" (HTTP %d)", e.StatusCode)
	}
	if e.Code != "" {
		message += ": " + e.Code
	}
	if e.Description != "" && e.Description != e.Code {
		message += ": " + e.Description
	}
	return sanitize.SanitizeTextLimit(message, maxDiagnosticChars)
}

// AuthorizationURL generates cryptographic state and a PKCE S256 verifier and
// returns the provider authorization URL. The redirect URI is caller-owned.
func (c Config) AuthorizationURL(redirectURI string) (Authorization, error) {
	if err := c.validateClientAuth(); err != nil {
		return Authorization{}, err
	}
	endpoint, err := validateURL("authorize URL", c.AuthorizeURL)
	if err != nil {
		return Authorization{}, err
	}
	if err := validateClientAndRedirect(c.ClientID, redirectURI); err != nil {
		return Authorization{}, err
	}
	state, err := randomValue()
	if err != nil {
		return Authorization{}, fmt.Errorf("generate OAuth state: %w", err)
	}
	values := cloneValues(c.ExtraAuthParams)
	values.Set("response_type", "code")
	values.Set("client_id", strings.TrimSpace(c.ClientID))
	values.Set("redirect_uri", strings.TrimSpace(redirectURI))
	values.Set("state", state)
	verifier, err := randomValue()
	if err != nil {
		return Authorization{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	digest := sha256.Sum256([]byte(verifier))
	values.Set("code_challenge", base64.RawURLEncoding.EncodeToString(digest[:]))
	values.Set("code_challenge_method", "S256")
	if len(c.Scopes) > 0 {
		values.Set("scope", strings.Join(c.Scopes, " "))
	}
	query := endpoint.Query()
	for key, entries := range values {
		query.Del(key)
		for _, value := range entries {
			query.Add(key, value)
		}
	}
	endpoint.RawQuery = query.Encode()
	return Authorization{URL: endpoint.String(), State: state, CodeVerifier: verifier}, nil
}

// Exchange trades an authorization code for tokens using the supplied PKCE
// verifier and caller-owned redirect URI.
func (c Config) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (TokenEnvelope, error) {
	if err := c.validateClientAuth(); err != nil {
		return TokenEnvelope{}, err
	}
	if err := validateClientAndRedirect(c.ClientID, redirectURI); err != nil {
		return TokenEnvelope{}, err
	}
	if strings.TrimSpace(code) == "" {
		return TokenEnvelope{}, fmt.Errorf("authorization code is required")
	}
	if c.ClientAuthMode == ClientAuthModePublicPKCE && strings.TrimSpace(codeVerifier) == "" {
		return TokenEnvelope{}, fmt.Errorf("PKCE verifier is required")
	}
	form := cloneValues(c.ExtraTokenParams)
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.TrimSpace(code))
	form.Del("code_verifier")
	if strings.TrimSpace(codeVerifier) != "" {
		form.Set("code_verifier", strings.TrimSpace(codeVerifier))
	}
	form.Set("redirect_uri", strings.TrimSpace(redirectURI))
	return c.tokenRequest(ctx, form)
}

// Refresh exchanges a refresh token. Providers may rotate refresh tokens; when
// a successful response omits one, the input refresh token is preserved.
func (c Config) Refresh(ctx context.Context, refreshToken string) (TokenEnvelope, error) {
	if err := c.validateClientAuth(); err != nil {
		return TokenEnvelope{}, err
	}
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return TokenEnvelope{}, fmt.Errorf("refresh token is required")
	}
	form := cloneValues(c.ExtraTokenParams)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	tokens, err := c.tokenRequest(ctx, form)
	if err != nil {
		return TokenEnvelope{}, err
	}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = refreshToken
	}
	return tokens, nil
}

func (c Config) tokenRequest(ctx context.Context, form url.Values) (TokenEnvelope, error) {
	endpoint, err := validateURL("token URL", c.TokenURL)
	if err != nil {
		return TokenEnvelope{}, err
	}
	clientID := strings.TrimSpace(c.ClientID)
	if clientID == "" {
		return TokenEnvelope{}, fmt.Errorf("OAuth client ID is required")
	}
	form.Set("client_id", clientID)
	form.Del("client_secret")
	if c.ClientAuthMode == ClientAuthModeClientSecretPost {
		form.Set("client_secret", c.ClientSecret)
	}
	requestContext, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return TokenEnvelope{}, endpointError(0, "request", err.Error())
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.client().Do(request)
	if err != nil {
		return TokenEnvelope{}, endpointError(0, "transport", err.Error())
	}
	defer response.Body.Close()
	raw, err := readBounded(response.Body)
	if err != nil {
		return TokenEnvelope{}, endpointError(response.StatusCode, "invalid_response", err.Error())
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return TokenEnvelope{}, endpointError(response.StatusCode, "invalid_response", "token endpoint response was not JSON")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		code := stringValue(payload["error"])
		if code == "" {
			code = fmt.Sprintf("http_%d", response.StatusCode)
		}
		return TokenEnvelope{}, endpointError(response.StatusCode, code, stringValue(payload["error_description"]))
	}
	accessToken := stringValue(payload["access_token"])
	if accessToken == "" {
		return TokenEnvelope{}, endpointError(response.StatusCode, "invalid_response", "response returned no access_token")
	}
	expiresIn := intValue(payload["expires_in"])
	tokens := TokenEnvelope{
		AccessToken:  accessToken,
		TokenType:    stringValue(payload["token_type"]),
		RefreshToken: stringValue(payload["refresh_token"]),
		Scope:        stringValue(payload["scope"]),
		ExpiresIn:    expiresIn,
		IDToken:      stringValue(payload["id_token"]),
		Extra:        payload,
	}
	if expiresIn > 0 {
		tokens.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	for _, key := range []string{"access_token", "token_type", "refresh_token", "scope", "expires_in", "id_token"} {
		delete(tokens.Extra, key)
	}
	if len(tokens.Extra) == 0 {
		tokens.Extra = nil
	}
	return tokens, nil
}

func (c Config) validateClientAuth() error {
	switch c.ClientAuthMode {
	case ClientAuthModePublicPKCE:
		return nil
	case ClientAuthModeClientSecretPost:
		if strings.TrimSpace(c.ClientSecret) == "" {
			return fmt.Errorf("OAuth client secret is required for client_secret_post")
		}
		return nil
	default:
		return fmt.Errorf("unsupported OAuth client auth mode %q", c.ClientAuthMode)
	}
}

func (c Config) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: defaultTimeout}
}

func validateClientAndRedirect(clientID, redirectURI string) error {
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("OAuth client ID is required")
	}
	parsed, err := url.Parse(strings.TrimSpace(redirectURI))
	if err != nil || !parsed.IsAbs() {
		return fmt.Errorf("redirect URI must be absolute")
	}
	return nil
}

func validateURL(name, raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return nil, fmt.Errorf("%s must be an absolute URL", name)
	}
	return parsed, nil
}

func randomValue() (string, error) {
	value := make([]byte, randomByteCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func cloneValues(source url.Values) url.Values {
	result := make(url.Values, len(source))
	for key, values := range source {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func readBounded(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("token endpoint response exceeded %d bytes", maxResponseBytes)
	}
	return raw, nil
}

func endpointError(status int, code, description string) *EndpointError {
	return &EndpointError{
		StatusCode:  status,
		Code:        sanitize.SanitizeTextLimit(strings.TrimSpace(code), maxDiagnosticChars),
		Description: sanitize.SanitizeTextLimit(strings.TrimSpace(description), maxDiagnosticChars),
	}
}

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func intValue(value any) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	case string:
		parsed, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed
	}
	return 0
}
