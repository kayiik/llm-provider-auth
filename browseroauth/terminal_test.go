package browseroauth

import (
	"fmt"
	"testing"

	"github.com/kayiik/llm-provider-auth/tokenstore"
)

func TestEndpointErrorTerminalClassification(t *testing.T) {
	for code, want := range map[string]bool{
		"invalid_grant": true, "invalid_token": true,
		"transport": false, "invalid_response": false, "http_503": false, "": false,
	} {
		err := fmt.Errorf("refresh: %w", &EndpointError{StatusCode: 400, Code: code})
		if got := tokenstore.IsTerminal(err); got != want {
			t.Errorf("code %q: terminal=%v, want %v", code, got, want)
		}
	}
}
