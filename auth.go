package auth

import (
	"context"
	"net/http"
	"time"
)

// Token represents an authorization token with an optional expiry.
type Token struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type,omitempty"`
	Expiry      time.Time `json:"expiry,omitempty"`
}

// Valid reports whether the token is non-empty and has not expired.
func (t *Token) Valid() bool {
	if t == nil || t.AccessToken == "" {
		return false
	}
	if t.Expiry.IsZero() {
		return true
	}
	return t.Expiry.After(time.Now())
}

// TokenSource returns a valid token or an error.
type TokenSource interface {
	Token(ctx context.Context) (*Token, error)
}

// StaticTokenSource always returns the same static token.
type StaticTokenSource struct {
	token *Token
}

// NewStaticTokenSource wraps a static token into a TokenSource.
func NewStaticTokenSource(t *Token) TokenSource {
	return StaticTokenSource{token: t}
}

// Token returns the static token.
func (s StaticTokenSource) Token(ctx context.Context) (*Token, error) {
	return s.token, nil
}

// HeaderSource applies authorization headers to an outgoing HTTP request.
type HeaderSource interface {
	Apply(ctx context.Context, req *http.Request) error
}
