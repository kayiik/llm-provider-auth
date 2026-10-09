package browseroauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizationURLBuildsPKCES256AndState(t *testing.T) {
	config := Config{
		AuthorizeURL:    "https://auth.example.test/authorize?provider=fixture",
		ClientID:        "fixture-client",
		ClientAuthMode:  ClientAuthModePublicPKCE,
		Scopes:          []string{"profile", "offline_access"},
		ExtraAuthParams: url.Values{"audience": {"fixture-api"}, "response_type": {"overridden"}},
	}
	authorization, err := config.AuthorizationURL("http://127.0.0.1:8484/callback")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	digest := sha256.Sum256([]byte(authorization.CodeVerifier))
	if authorization.State == "" || len(authorization.CodeVerifier) < 43 {
		t.Fatalf("weak authorization material: %+v", authorization)
	}
	if query.Get("response_type") != "code" || query.Get("client_id") != "fixture-client" || query.Get("redirect_uri") != "http://127.0.0.1:8484/callback" || query.Get("scope") != "profile offline_access" || query.Get("audience") != "fixture-api" || query.Get("provider") != "fixture" || query.Get("state") != authorization.State || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("authorization query=%v", query)
	}
	if err := ValidateState(authorization.State, authorization.State); err != nil {
		t.Fatal(err)
	}
	if err := ValidateState(authorization.State, authorization.State+"x"); err == nil {
		t.Fatal("mismatched state was accepted")
	}
}

func TestAuthorizationURLAcceptsCallerOwnedCustomRedirectScheme(t *testing.T) {
	config := Config{AuthorizeURL: "https://auth.example.test/authorize", ClientID: "fixture-client", ClientAuthMode: ClientAuthModePublicPKCE}
	authorization, err := config.AuthorizationURL("fixture-app:/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorization.URL)
	if parsed.Query().Get("redirect_uri") != "fixture-app:/oauth/callback" {
		t.Fatalf("authorization URL=%q", authorization.URL)
	}
}

func TestExchangeUsesCallerConfigurationAndReturnsTypedEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Accept") != "application/json" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatalf("request=%s accept=%q content-type=%q", r.Method, r.Header.Get("Accept"), r.Header.Get("Content-Type"))
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("client_id") != "fixture-client" || r.Form.Get("client_secret") != "fixture-secret" || r.Form.Get("code") != "fixture-code" || r.Form.Has("code_verifier") || r.Form.Get("redirect_uri") != "http://127.0.0.1/callback" || r.Form.Get("resource") != "fixture-resource" {
			t.Fatalf("exchange form=%v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fixture-access","refresh_token":"fixture-refresh","token_type":"Bearer","scope":"profile","expires_in":120,"id_token":"fixture-id","account_id":"account-1"}`))
	}))
	defer server.Close()

	config := Config{
		TokenURL:         server.URL,
		ClientID:         "fixture-client",
		ClientSecret:     "fixture-secret",
		ClientAuthMode:   ClientAuthModeClientSecretPost,
		ExtraTokenParams: url.Values{"resource": {"fixture-resource"}, "client_id": {"must-be-overridden"}},
		HTTPClient:       server.Client(),
	}
	tokens, err := config.Exchange(context.Background(), "fixture-code", "", "http://127.0.0.1/callback")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "fixture-access" || tokens.RefreshToken != "fixture-refresh" || tokens.TokenType != "Bearer" || tokens.Scope != "profile" || tokens.ExpiresIn != 120 || tokens.ExpiresAt.IsZero() || tokens.IDToken != "fixture-id" || tokens.Extra["account_id"] != "account-1" {
		t.Fatalf("tokens=%+v", tokens)
	}
}

func TestRefreshPreservesOmittedRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "existing-refresh" || r.Form.Has("client_secret") {
			t.Fatalf("refresh form=%v", r.Form)
		}
		_, _ = w.Write([]byte(`{"access_token":"new-access","expires_in":"60"}`))
	}))
	defer server.Close()
	config := Config{TokenURL: server.URL, ClientID: "fixture-client", ClientAuthMode: ClientAuthModePublicPKCE, HTTPClient: server.Client()}
	tokens, err := config.Refresh(context.Background(), "existing-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "new-access" || tokens.RefreshToken != "existing-refresh" || tokens.ExpiresIn != 60 {
		t.Fatalf("tokens=%+v", tokens)
	}
}

func TestPublicExchangeRequiresVerifierAndNeverSendsSecret(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("code_verifier") != "fixture-verifier" || r.Form.Has("client_secret") {
			t.Fatalf("public exchange form=%v", r.Form)
		}
		_, _ = w.Write([]byte(`{"access_token":"fixture-access"}`))
	}))
	defer server.Close()
	config := Config{
		TokenURL:         server.URL,
		ClientID:         "fixture-client",
		ClientSecret:     "must-not-be-sent",
		ClientAuthMode:   ClientAuthModePublicPKCE,
		ExtraTokenParams: url.Values{"client_secret": {"also-must-not-be-sent"}},
		HTTPClient:       server.Client(),
	}
	if _, err := config.Exchange(context.Background(), "fixture-code", "", "http://127.0.0.1/callback"); err == nil || !strings.Contains(err.Error(), "PKCE verifier") {
		t.Fatalf("missing verifier error=%v", err)
	}
	if requests != 0 {
		t.Fatalf("token endpoint called without verifier: requests=%d", requests)
	}
	if _, err := config.Exchange(context.Background(), "fixture-code", "fixture-verifier", "http://127.0.0.1/callback"); err != nil {
		t.Fatal(err)
	}
}

func TestConfidentialRefreshRequiresAndSendsSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("client_secret") != "fixture-secret" {
			t.Fatalf("confidential refresh form=%v", r.Form)
		}
		_, _ = w.Write([]byte(`{"access_token":"fixture-access"}`))
	}))
	defer server.Close()
	config := Config{TokenURL: server.URL, ClientID: "fixture-client", ClientAuthMode: ClientAuthModeClientSecretPost, HTTPClient: server.Client()}
	if _, err := config.Refresh(context.Background(), "fixture-refresh"); err == nil || !strings.Contains(err.Error(), "client secret") {
		t.Fatalf("missing secret error=%v", err)
	}
	config.ClientSecret = "fixture-secret"
	if _, err := config.Refresh(context.Background(), "fixture-refresh"); err != nil {
		t.Fatal(err)
	}
}

func TestClientAuthModeFailsClosed(t *testing.T) {
	for _, mode := range []ClientAuthMode{"", "unsupported"} {
		t.Run(string(mode), func(t *testing.T) {
			config := Config{AuthorizeURL: "https://auth.example.test/authorize", ClientID: "fixture-client", ClientAuthMode: mode}
			if _, err := config.AuthorizationURL("http://127.0.0.1/callback"); err == nil || !strings.Contains(err.Error(), "client auth mode") {
				t.Fatalf("mode=%q error=%v", mode, err)
			}
		})
	}
}

func TestTokenErrorsAreTypedSanitizedAndBounded(t *testing.T) {
	secret := "sk-" + strings.Repeat("s", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"Bearer malicious owner@example.test api_key=%s %s"}`, secret, strings.Repeat("x", 700))
	}))
	defer server.Close()
	config := Config{TokenURL: server.URL, ClientID: "fixture-client", ClientAuthMode: ClientAuthModePublicPKCE, HTTPClient: server.Client()}
	_, err := config.Refresh(context.Background(), "fixture-refresh")
	endpointErr := &EndpointError{}
	if !errors.As(err, &endpointErr) || endpointErr.StatusCode != http.StatusUnauthorized || endpointErr.Code != "invalid_grant" || len([]rune(err.Error())) > maxDiagnosticChars || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "owner@example.test") || strings.Contains(err.Error(), "malicious") {
		t.Fatalf("unsafe endpoint error: %v (%+v)", err, endpointErr)
	}
}

func TestTokenResponseBodyIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", int(maxResponseBytes)+1)))
	}))
	defer server.Close()
	config := Config{TokenURL: server.URL, ClientID: "fixture-client", ClientAuthMode: ClientAuthModePublicPKCE, HTTPClient: server.Client()}
	_, err := config.Refresh(context.Background(), "fixture-refresh")
	endpointErr := &EndpointError{}
	if !errors.As(err, &endpointErr) || endpointErr.Code != "invalid_response" || !strings.Contains(endpointErr.Description, "exceeded") {
		t.Fatalf("error=%v typed=%+v", err, endpointErr)
	}
}
