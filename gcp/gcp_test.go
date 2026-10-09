package gcp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestKey generates a throwaway RSA key. No real credential is used in these
// tests; every fixture below is synthesised in-process.
func newTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// keyJSON renders a key document for pemText and tokenURI with every other
// field fixed, so a test can vary just the private key or the token endpoint.
func keyJSON(t *testing.T, pemText, tokenURI string) string {
	t.Helper()
	doc := map[string]string{
		"type":           "service_account",
		"project_id":     "test-project",
		"private_key_id": "key-1",
		"private_key":    pemText,
		"client_email":   "svc@test-project.iam.gserviceaccount.com",
		"token_uri":      tokenURI,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return string(raw)
}

func testKeyJSON(t *testing.T, tokenURI string) (string, *rsa.PrivateKey) {
	t.Helper()
	key, pemText := newTestKey(t)
	return keyJSON(t, pemText, tokenURI), key
}

func mustParse(t *testing.T, raw string) *Credential {
	t.Helper()
	cred, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cred
}

func testCredential(t *testing.T, tokenURI string) *Credential {
	t.Helper()
	raw, _ := testKeyJSON(t, tokenURI)
	return mustParse(t, raw)
}

// countingTokenServer answers every exchange with a distinct token and counts
// how many exchanges it served.
func countingTokenServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"access_token":"ya29.test-token-%d","expires_in":3600}`, calls.Add(1))
	}))
	t.Cleanup(server.Close)
	return server, calls
}

// verifyRS256 checks the assertion signature the way Google's endpoint would.
func verifyRS256(signingInput, signature string, pub *rsa.PublicKey) error {
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], raw)
}

func TestParseAcceptsServiceAccountKey(t *testing.T) {
	t.Parallel()
	raw, _ := testKeyJSON(t, "")
	cred, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cred.ProjectID() != "test-project" {
		t.Fatalf("project = %q, want test-project", cred.ProjectID())
	}
	meta := cred.Metadata()
	if meta.ClientEmail != "svc@test-project.iam.gserviceaccount.com" {
		t.Fatalf("client email = %q", meta.ClientEmail)
	}
	if meta.PrivateKeyID != "key-1" {
		t.Fatalf("key id = %q", meta.PrivateKeyID)
	}
	// An absent token_uri must fall back to Google's endpoint.
	if cred.tokenURI != defaultTokenURI {
		t.Fatalf("tokenURI = %q, want the default", cred.tokenURI)
	}
}

func TestParseRejectsNonServiceAccountShapes(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"authorized user": `{"type":"authorized_user","client_id":"x"}`,
		"missing type":    `{"project_id":"p"}`,
		"not json":        `nonsense`,
		"bad pem":         `{"type":"service_account","project_id":"p","client_email":"a@b","private_key":"not-a-pem"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatalf("expected an error for %s", name)
			}
		})
	}
}

func TestParseReportsEveryMissingField(t *testing.T) {
	t.Parallel()
	_, pemText := newTestKey(t)
	raw := fmt.Sprintf(`{"type":"service_account","private_key":%q}`, pemText)
	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "client_email") {
		t.Fatalf("error should name client_email, got: %v", err)
	}
	if !strings.Contains(err.Error(), "project_id") {
		t.Fatalf("error should name project_id, got: %v", err)
	}
}

// TestParseErrorsNeverLeakKeyMaterial guards the invariant that key bytes must
// never reach a log line or an API error.
func TestParseErrorsNeverLeakKeyMaterial(t *testing.T) {
	t.Parallel()
	_, pemText := newTestKey(t)
	raw := fmt.Sprintf(`{"type":"authorized_user","private_key":%q}`, pemText)
	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatal("error message leaked the PEM header")
	}
	if strings.Contains(err.Error(), pemText[40:80]) {
		t.Fatal("error message leaked private key bytes")
	}
}

// TestParseRequiresHTTPSTokenURI pins which token endpoints a key may name:
// https on any host, and plain http only on a loopback host, where a local test
// server listens.
func TestParseRequiresHTTPSTokenURI(t *testing.T) {
	t.Parallel()
	_, pemText := newTestKey(t)
	for _, tokenURI := range []string{
		"https://tokens.example.test/token",
		"http://127.0.0.1:8080/token",
		"http://[::1]:8080/token",
		"http://localhost:8080/token",
	} {
		if _, err := Parse([]byte(keyJSON(t, pemText, tokenURI))); err != nil {
			t.Errorf("token_uri %q: unexpected error: %v", tokenURI, err)
		}
	}
	for _, tokenURI := range []string{
		"http://tokens.example.test/token",
		"http://192.0.2.10/token",
		"http://[2001:db8::1]/token",
		"http://localhost.example.test/token",
		"http://127.0.0.1.example.test/token",
		"ftp://tokens.example.test/token",
		"//tokens.example.test/token",
		"tokens.example.test/token",
		"https:///token",
	} {
		_, err := Parse([]byte(keyJSON(t, pemText, tokenURI)))
		if err == nil || !strings.Contains(err.Error(), "token_uri") {
			t.Errorf("token_uri %q: error = %v, want a token_uri error", tokenURI, err)
		}
	}
}

// tokenServer stands in for oauth2.googleapis.com and captures the assertion.
func tokenServer(t *testing.T, status int) (*httptest.Server, *atomic.Value) {
	t.Helper()
	captured := new(atomic.Value)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		captured.Store(r.Form.Get("assertion"))
		if got := r.Form.Get("grant_type"); got != jwtGrantType {
			t.Errorf("grant_type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"ya29.test-token","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(server.Close)
	return server, captured
}

func TestAccessTokenMintsAVerifiableAssertion(t *testing.T) {
	t.Parallel()
	server, captured := tokenServer(t, http.StatusOK)
	raw, key := testKeyJSON(t, server.URL)
	cred, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	token, err := (&TokenCache{}).AccessToken(cred, CloudPlatformScope)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if token != "ya29.test-token" {
		t.Fatalf("token = %q", token)
	}

	assertion, _ := captured.Load().(string)
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d segments, want 3", len(parts))
	}
	if err := verifyRS256(strings.Join(parts[:2], "."), parts[2], &key.PublicKey); err != nil {
		t.Fatalf("assertion signature did not verify: %v", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims["iss"] != "svc@test-project.iam.gserviceaccount.com" {
		t.Fatalf("iss = %v", claims["iss"])
	}
	if claims["scope"] != CloudPlatformScope {
		t.Fatalf("scope = %v", claims["scope"])
	}
	if claims["aud"] != server.URL {
		t.Fatalf("aud = %v", claims["aud"])
	}
	if claims["exp"].(float64) <= claims["iat"].(float64) {
		t.Fatal("exp must be after iat")
	}
}

func TestAccessTokenCachesUntilCloseToExpiry(t *testing.T) {
	t.Parallel()
	server, calls := countingTokenServer(t)
	cred := testCredential(t, server.URL)

	base := time.Now()
	current := base
	cache := &TokenCache{Now: func() time.Time { return current }}

	for i := 0; i < 3; i++ {
		if _, err := cache.AccessToken(cred, CloudPlatformScope); err != nil {
			t.Fatalf("AccessToken: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("minted %d times, want 1 (later calls should hit the cache)", got)
	}

	// Inside the refresh window the token must be re-minted, not served.
	current = base.Add(3600*time.Second - 30*time.Second)
	if _, err := cache.AccessToken(cred, CloudPlatformScope); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("minted %d times, want 2 (early refresh)", got)
	}
}

func TestAccessTokenSurfacesExchangeFailure(t *testing.T) {
	t.Parallel()
	server, _ := tokenServer(t, http.StatusBadRequest)
	cred := testCredential(t, server.URL)
	if _, err := (&TokenCache{}).AccessToken(cred, CloudPlatformScope); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(err.Error(), "Invalid JWT Signature") {
		t.Fatalf("error should carry Google's reason, got: %v", err)
	}
}

// TestAccessTokenDoesNotFollowRedirects pins that the default client keeps the
// exchange on the credential's token endpoint: a redirect is an exchange error,
// and the redirect target never receives the request or its assertion.
func TestAccessTokenDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			t.Parallel()
			target, targetCalls := countingTokenServer(t)
			redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, status)
			}))
			t.Cleanup(redirector.Close)

			_, err := (&TokenCache{}).AccessToken(testCredential(t, redirector.URL), CloudPlatformScope)
			tokenErr := &TokenError{}
			if !errors.As(err, &tokenErr) || tokenErr.StatusCode != status || tokenErr.Code != "redirect" {
				t.Fatalf("error = %v, want a redirect token error with HTTP %d", err, status)
			}
			if got := targetCalls.Load(); got != 0 {
				t.Fatalf("redirect target received %d requests, want none", got)
			}
		})
	}
}

func TestAccessTokenSanitizesSyntheticEndpointDiagnostics(t *testing.T) {
	t.Parallel()
	secret := "llmgw_" + strings.Repeat("a", 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"Bearer malicious-bearer owner@example.test api_key=%s %s"}`, secret, strings.Repeat("z", 700))
	}))
	defer server.Close()
	cred := testCredential(t, server.URL)
	_, err := (&TokenCache{}).AccessToken(cred, CloudPlatformScope)
	tokenErr := &TokenError{}
	if !errors.As(err, &tokenErr) || tokenErr.StatusCode != http.StatusUnauthorized || tokenErr.Code != "invalid_grant" {
		t.Fatalf("error=%v tokenError=%+v", err, tokenErr)
	}
	if len([]rune(tokenErr.Description)) > maxAuthDiagnosticChars || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "malicious-bearer") || strings.Contains(err.Error(), "owner@example.test") {
		t.Fatalf("unsafe or unbounded error: %q", err)
	}
}

type syntheticRoundTripper func(*http.Request) (*http.Response, error)

func (f syntheticRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAccessTokenSanitizesSyntheticTransportURL(t *testing.T) {
	t.Parallel()
	cache := &TokenCache{HTTPClient: &http.Client{Transport: syntheticRoundTripper(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial %s?access_token=query-secret for owner@example.test", r.URL)
	})}}
	cred := testCredential(t, "https://tokens.example.test/exchange")
	_, err := cache.AccessToken(cred, CloudPlatformScope)
	tokenErr := &TokenError{}
	if !errors.As(err, &tokenErr) || tokenErr.Code != "transport" || strings.Contains(err.Error(), "query-secret") || strings.Contains(err.Error(), "owner@example.test") {
		t.Fatalf("unsafe transport error: %v", err)
	}
}

func TestTokenErrorFinalMessageIsSanitizedAndBounded(t *testing.T) {
	t.Parallel()
	secret := "llmgw_" + strings.Repeat("e", 32)
	err := &TokenError{
		StatusCode:  http.StatusBadGateway,
		Code:        strings.Repeat("c", maxAuthDiagnosticChars-len(secret)) + secret,
		Description: strings.Repeat("d", maxAuthDiagnosticChars-len("owner@example.test")) + "owner@example.test",
	}
	message := err.Error()
	if len([]rune(message)) > maxAuthDiagnosticChars || strings.Contains(message, secret) || strings.Contains(message, "owner@example.test") {
		t.Fatalf("unsafe or unbounded final error: %q", message)
	}
}

func TestScopesAreCachedSeparately(t *testing.T) {
	t.Parallel()
	server, calls := countingTokenServer(t)
	cred := testCredential(t, server.URL)
	cache := &TokenCache{}

	if _, err := cache.AccessToken(cred, CloudPlatformScope); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if _, err := cache.AccessToken(cred, "https://www.googleapis.com/auth/devstorage.read_only"); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("minted %d times, want 2 (one per scope)", got)
	}
}

// TestCredentialsWithDifferentKeysDoNotShareTokens pins the cache identity: two
// keys that name the same account and key id but hold different private keys
// each get the token from their own exchange, while the same key parsed again
// is the same credential and is served from the cache.
func TestCredentialsWithDifferentKeysDoNotShareTokens(t *testing.T) {
	t.Parallel()
	server, calls := countingTokenServer(t)
	_, firstPEM := newTestKey(t)
	_, secondPEM := newTestKey(t)
	first := mustParse(t, keyJSON(t, firstPEM, server.URL))
	second := mustParse(t, keyJSON(t, secondPEM, server.URL))
	cache := &TokenCache{}

	firstToken, err := cache.AccessToken(first, CloudPlatformScope)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	secondToken, err := cache.AccessToken(second, CloudPlatformScope)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if secondToken == firstToken {
		t.Fatal("a credential with a different private key was served the other key's token")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("minted %d times, want 2 (one per private key)", got)
	}

	reparsed := mustParse(t, keyJSON(t, firstPEM, server.URL))
	for _, check := range []struct {
		cred *Credential
		want string
	}{{reparsed, firstToken}, {second, secondToken}} {
		got, err := cache.AccessToken(check.cred, CloudPlatformScope)
		if err != nil {
			t.Fatalf("AccessToken: %v", err)
		}
		if got != check.want {
			t.Fatalf("token = %q, want %q", got, check.want)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("minted %d times, want 2 (cached tokens should be reused)", got)
	}
}

// TestCredentialsWithDifferentTokenEndpointsDoNotShareTokens pins that the
// token endpoint is part of the cache identity: the same key pointed at another
// endpoint exchanges there instead of reusing the first endpoint's token.
func TestCredentialsWithDifferentTokenEndpointsDoNotShareTokens(t *testing.T) {
	t.Parallel()
	firstServer, firstCalls := countingTokenServer(t)
	secondServer, secondCalls := countingTokenServer(t)
	_, pemText := newTestKey(t)
	cache := &TokenCache{}

	for _, tokenURI := range []string{firstServer.URL, secondServer.URL, firstServer.URL, secondServer.URL} {
		if _, err := cache.AccessToken(mustParse(t, keyJSON(t, pemText, tokenURI)), CloudPlatformScope); err != nil {
			t.Fatalf("AccessToken: %v", err)
		}
	}
	if first, second := firstCalls.Load(), secondCalls.Load(); first != 1 || second != 1 {
		t.Fatalf("exchanges = %d and %d, want 1 per endpoint", first, second)
	}
}

// TestTokenCachesShareNothing pins the per-instance ownership: one cache never
// serves another cache's token, and resetting one leaves the other intact.
func TestTokenCachesShareNothing(t *testing.T) {
	t.Parallel()
	server, calls := countingTokenServer(t)
	cred := testCredential(t, server.URL)
	first, second := &TokenCache{}, &TokenCache{}

	for _, cache := range []*TokenCache{first, second, first, second} {
		if _, err := cache.AccessToken(cred, CloudPlatformScope); err != nil {
			t.Fatalf("AccessToken: %v", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("minted %d times, want 2 (one per cache)", got)
	}

	first.Reset()
	if _, err := second.AccessToken(cred, CloudPlatformScope); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("minted %d times, want 2 (reset must not reach another cache)", got)
	}
	if _, err := first.AccessToken(cred, CloudPlatformScope); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("minted %d times, want 3 (reset cache re-mints)", got)
	}
}

func TestAccessTokenRejectsMissingCredential(t *testing.T) {
	t.Parallel()
	if _, err := (&TokenCache{}).AccessToken(nil, CloudPlatformScope); err == nil {
		t.Fatal("expected an error for a nil credential")
	}
}
