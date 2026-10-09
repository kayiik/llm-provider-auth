package tokenstore

import (
	"errors"
	"strings"
)

// IsTerminal reports whether err means the refresh grant can never be used
// again, for example an OAuth invalid_grant. Errors opt in by implementing
// Terminal() bool; the drivers' refresh errors do.
func IsTerminal(err error) bool {
	var terminal interface{ Terminal() bool }
	return errors.As(err, &terminal) && terminal.Terminal()
}

// TerminalOAuthCode reports whether an OAuth token-endpoint error code means
// the refresh grant is permanently unusable.
func TerminalOAuthCode(code string) bool {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "invalid_grant", "invalid_token", "token_reused", "refresh_token_reused",
		"refresh_token_invalidated", "expired_token", "refresh_token_expired":
		return true
	default:
		return false
	}
}
