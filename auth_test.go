package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/kayiik/llm-provider-auth"
)

func TestTokenValid(t *testing.T) {
	var nilToken *auth.Token
	if nilToken.Valid() {
		t.Fatal("nil token must not be valid")
	}

	emptyToken := &auth.Token{AccessToken: ""}
	if emptyToken.Valid() {
		t.Fatal("empty access token must not be valid")
	}

	expiredToken := &auth.Token{
		AccessToken: "expired-secret",
		Expiry:      time.Now().Add(-10 * time.Minute),
	}
	if expiredToken.Valid() {
		t.Fatal("past expiry token must not be valid")
	}

	validToken := &auth.Token{
		AccessToken: "valid-secret",
		Expiry:      time.Now().Add(10 * time.Minute),
	}
	if !validToken.Valid() {
		t.Fatal("future expiry token must be valid")
	}

	zeroExpiryToken := &auth.Token{
		AccessToken: "static-secret",
	}
	if !zeroExpiryToken.Valid() {
		t.Fatal("zero expiry static token must be valid")
	}

	src := auth.NewStaticTokenSource(validToken)
	got, err := src.Token(context.Background())
	if err != nil || got.AccessToken != "valid-secret" {
		t.Fatalf("unexpected static token source: got=%v, err=%v", got, err)
	}
}
