package gcp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kayiik/llm-provider-auth/internal/sanitize"
)

const maxAuthDiagnosticChars = 512

// TokenError retains safe machine-inspectable token endpoint facts.
type TokenError struct {
	StatusCode  int
	Code        string
	Description string
}

func (e *TokenError) Error() string {
	message := "service account token exchange failed"
	if e.StatusCode != 0 {
		message += fmt.Sprintf(" (HTTP %d)", e.StatusCode)
	}
	if e.Code != "" {
		message += ": " + e.Code
	}
	if e.Description != "" && e.Description != e.Code {
		message += ": " + e.Description
	}
	return sanitize.SanitizeTextLimit(message, maxAuthDiagnosticChars)
}

func tokenError(status int, code, description string) *TokenError {
	return &TokenError{
		StatusCode:  status,
		Code:        sanitize.SanitizeTextLimit(strings.TrimSpace(code), maxAuthDiagnosticChars),
		Description: sanitize.SanitizeTextLimit(strings.TrimSpace(description), maxAuthDiagnosticChars),
	}
}

// defaultExchangeTimeout bounds a token exchange when TokenCache.HTTPClient is
// nil.
const defaultExchangeTimeout = 30 * time.Second

// TokenCache mints access tokens for service-account credentials and caches
// them per credential and scope until shortly before they expire. A credential
// is identified by its account, key id, private key and token endpoint, so two
// credentials that differ in any of them never share a token.
//
// Each TokenCache owns its tokens, HTTP client and clock, so separate caches
// share nothing. Tokens are short lived and re-mintable, so they are held in
// memory only: a restart costs one extra exchange, while persisting them would
// put bearer tokens on disk.
//
// The zero value is ready to use and a TokenCache is safe for concurrent use.
// Set its fields before first use, and do not copy it afterwards.
type TokenCache struct {
	// HTTPClient performs the token exchange. Nil uses a client that times out
	// after 30 seconds and does not follow redirects, so a redirect fails the
	// exchange with a TokenError. A supplied client should not follow redirects
	// either, for example by returning http.ErrUseLastResponse from
	// CheckRedirect: the exchange request carries a signed assertion, and
	// following a redirect sends it to another URL.
	HTTPClient *http.Client
	// Now returns the current time. Nil uses time.Now.
	Now func() time.Time

	mu      sync.Mutex
	entries map[[sha256.Size]byte]cachedToken
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

func (t *TokenCache) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *TokenCache) client() *http.Client {
	if t.HTTPClient != nil {
		return t.HTTPClient
	}
	return &http.Client{Timeout: defaultExchangeTimeout, CheckRedirect: refuseRedirect}
}

// refuseRedirect stops the default client at the first redirect, so the signed
// assertion only ever reaches the credential's own token endpoint. The client
// returns the redirect response, which exchange reports as an error.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// cacheKey covers everything that decides which token an exchange returns: the
// account and key that sign the assertion, the key id it names, the endpoint
// that issues the token, and the scope. Each field is length-prefixed, so
// different field values never produce the same hash input. No field is
// secret, and hashing keeps the key opaque if it is ever printed.
func cacheKey(c *Credential, scope string) [sha256.Size]byte {
	var input []byte
	for _, field := range [][]byte{
		[]byte(c.clientEmail),
		[]byte(c.privateKeyID),
		c.keyFingerprint[:],
		[]byte(c.tokenURI),
		[]byte(scope),
	} {
		input = binary.AppendUvarint(input, uint64(len(field)))
		input = append(input, field...)
	}
	return sha256.Sum256(input)
}

// AccessToken returns a cached token for the credential and scope, minting a
// new one when none is cached or the cached one is close to expiry. An empty
// scope means CloudPlatformScope.
func (t *TokenCache) AccessToken(c *Credential, scope string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("service account credential is not configured")
	}
	if strings.TrimSpace(scope) == "" {
		scope = CloudPlatformScope
	}
	key := cacheKey(c, scope)

	t.mu.Lock()
	entry, ok := t.entries[key]
	t.mu.Unlock()
	if ok && t.now().Add(refreshBeforeExpiry).Before(entry.expiresAt) {
		return entry.token, nil
	}

	token, expiresAt, err := t.exchange(c, scope)
	if err != nil {
		return "", err
	}
	t.mu.Lock()
	if t.entries == nil {
		t.entries = map[[sha256.Size]byte]cachedToken{}
	}
	t.entries[key] = cachedToken{token: token, expiresAt: expiresAt}
	t.mu.Unlock()
	return token, nil
}

// Reset drops every cached token, for example after a credential is revoked or
// replaced.
func (t *TokenCache) Reset() {
	t.mu.Lock()
	t.entries = nil
	t.mu.Unlock()
}

// signAssertion builds the RS256 JWT that Google exchanges for a token.
func signAssertion(c *Credential, scope string, issued time.Time) (string, error) {
	issued = issued.UTC()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if c.privateKeyID != "" {
		header["kid"] = c.privateKeyID
	}
	claims := map[string]any{
		"iss":   c.clientEmail,
		"scope": scope,
		"aud":   c.tokenURI,
		"iat":   issued.Unix(),
		"exp":   issued.Add(assertionTTL).Unix(),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("service account key: signing failed")
	}
	return signingInput + "." + enc.EncodeToString(signature), nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// exchange trades the signed assertion for an access token.
func (t *TokenCache) exchange(c *Credential, scope string) (string, time.Time, error) {
	assertion, err := signAssertion(c, scope, t.now())
	if err != nil {
		return "", time.Time{}, err
	}
	form := url.Values{"grant_type": {jwtGrantType}, "assertion": {assertion}}
	request, err := http.NewRequest(
		http.MethodPost, c.tokenURI, strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", time.Time{}, tokenError(0, "request", err.Error())
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := t.client().Do(request)
	if err != nil {
		return "", time.Time{}, tokenError(0, "transport", err.Error())
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		// A client that declines a redirect returns it here. Its target and body
		// are not used: the token must come from the endpoint the key names.
		return "", time.Time{}, tokenError(response.StatusCode, "redirect", "redirects are not followed")
	}
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))

	var parsed tokenResponse
	_ = json.Unmarshal(raw, &parsed)
	if response.StatusCode != http.StatusOK {
		detail := parsed.ErrorDesc
		if strings.TrimSpace(detail) == "" {
			detail = "no error detail returned"
		}
		return "", time.Time{}, tokenError(response.StatusCode, parsed.Error, detail)
	}
	if strings.TrimSpace(parsed.AccessToken) == "" {
		return "", time.Time{}, tokenError(response.StatusCode, "invalid_response", "response returned no access_token")
	}
	lifetime := parsed.ExpiresIn
	if lifetime <= 0 {
		lifetime = int64(assertionTTL / time.Second)
	}
	return parsed.AccessToken, t.now().Add(time.Duration(lifetime) * time.Second), nil
}
