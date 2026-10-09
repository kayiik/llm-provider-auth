package tokenstore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kayiik/llm-provider-auth/tokenstore"
	"github.com/kayiik/llm-provider-auth/tokenstore/storetest"
)

func TestMemoryConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) storetest.Opener {
		memory := tokenstore.NewMemory()
		return func(*testing.T) tokenstore.Store { return memory }
	})
}

func TestRecordNeverPrintsTokens(t *testing.T) {
	record := tokenstore.Record{
		Revision: "7", AccessToken: "fixture-access-secret", RefreshToken: "fixture-refresh-secret",
		IDToken: "fixture-id-secret", AccountID: "fixture-account", Expiry: time.Unix(1700000000, 0),
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("credential", "record", record)
	for _, rendered := range []string{
		fmt.Sprint(record), fmt.Sprintf("%v", record), fmt.Sprintf("%+v", record),
		fmt.Sprintf("%#v", record), fmt.Sprintf("%s", record), logged.String(),
	} {
		if strings.Contains(rendered, "secret") {
			t.Fatalf("record rendering leaked token material: %s", rendered)
		}
		if !strings.Contains(rendered, "fixture-account") {
			t.Fatalf("record rendering lost its non-secret identity: %s", rendered)
		}
	}
}

func TestNewCoordinatorValidates(t *testing.T) {
	refresh := func(context.Context, tokenstore.Record) (tokenstore.Record, error) { return tokenstore.Record{}, nil }
	for name, build := range map[string]func() (*tokenstore.Coordinator, error){
		"nil store":   func() (*tokenstore.Coordinator, error) { return tokenstore.NewCoordinator(nil, refresh) },
		"nil refresh": func() (*tokenstore.Coordinator, error) { return tokenstore.NewCoordinator(tokenstore.NewMemory(), nil) },
		"zero wait": func() (*tokenstore.Coordinator, error) {
			return tokenstore.NewCoordinator(tokenstore.NewMemory(), refresh, tokenstore.WithLeaseWait(0))
		},
		"negative skew": func() (*tokenstore.Coordinator, error) {
			return tokenstore.NewCoordinator(tokenstore.NewMemory(), refresh, tokenstore.WithSkew(-time.Second))
		},
		"missing clock": func() (*tokenstore.Coordinator, error) {
			return tokenstore.NewCoordinator(tokenstore.NewMemory(), refresh, tokenstore.WithClock(nil))
		},
	} {
		if _, err := build(); err == nil {
			t.Errorf("%s: NewCoordinator accepted invalid input", name)
		}
	}
}

func TestCoordinatorMergesOmittedFields(t *testing.T) {
	ctx := context.Background()
	store := tokenstore.NewMemory()
	if _, err := store.Save(ctx, "fixture", tokenstore.Record{
		AccessToken: "fixture-access-old", RefreshToken: "fixture-refresh-old", IDToken: "fixture-id",
		TokenType: "Bearer", AccountID: "fixture-account", Expiry: time.Now().Add(-time.Minute),
		Metadata: map[string]string{"project": "fixture-project", "profile": "old"},
	}); err != nil {
		t.Fatal(err)
	}
	coordinator, err := tokenstore.NewCoordinator(store, func(context.Context, tokenstore.Record) (tokenstore.Record, error) {
		return tokenstore.Record{AccessToken: "fixture-access-new", Metadata: map[string]string{"profile": "new"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := coordinator.Token(ctx, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "fixture-access-new" || got.RefreshToken != "fixture-refresh-old" || got.IDToken != "fixture-id" ||
		got.TokenType != "Bearer" || got.AccountID != "fixture-account" || !got.Expiry.IsZero() ||
		got.Metadata["project"] != "fixture-project" || got.Metadata["profile"] != "new" {
		t.Fatalf("merge lost or kept the wrong fields: %s metadata=%v", got, got.Metadata)
	}
}

func TestCoordinatorRefreshBoundaries(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1700000000, 0)
	calls := 0
	refresh := func(context.Context, tokenstore.Record) (tokenstore.Record, error) {
		calls++
		return tokenstore.Record{AccessToken: "fixture-access-new"}, nil
	}
	for _, tc := range []struct {
		name      string
		record    tokenstore.Record
		wantCalls int
		wantErr   error
	}{
		{"zero expiry is usable", tokenstore.Record{AccessToken: "fixture-access"}, 0, nil},
		{"outside skew is usable", tokenstore.Record{AccessToken: "fixture-access", Expiry: now.Add(2 * time.Minute)}, 0, nil},
		{"inside skew refreshes", tokenstore.Record{AccessToken: "fixture-access", RefreshToken: "fixture-refresh", Expiry: now.Add(30 * time.Second)}, 1, nil},
		{"missing refresh token", tokenstore.Record{AccessToken: "fixture-access", Expiry: now.Add(-time.Second)}, 0, tokenstore.ErrNoRefreshToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls = 0
			store := tokenstore.NewMemory()
			if _, err := store.Save(ctx, "fixture", tc.record); err != nil {
				t.Fatal(err)
			}
			coordinator, err := tokenstore.NewCoordinator(store, refresh, tokenstore.WithClock(func() time.Time { return now }))
			if err != nil {
				t.Fatal(err)
			}
			_, err = coordinator.Token(ctx, "fixture")
			if !errors.Is(err, tc.wantErr) || calls != tc.wantCalls {
				t.Fatalf("err=%v calls=%d, want err=%v calls=%d", err, calls, tc.wantErr, tc.wantCalls)
			}
		})
	}
}

func TestCoordinatorRejectsEmptyRefresh(t *testing.T) {
	ctx := context.Background()
	store := tokenstore.NewMemory()
	stored, err := store.Save(ctx, "fixture", tokenstore.Record{AccessToken: "fixture-access", RefreshToken: "fixture-refresh", Expiry: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := tokenstore.NewCoordinator(store, func(context.Context, tokenstore.Record) (tokenstore.Record, error) {
		return tokenstore.Record{}, nil
	})
	if _, err := coordinator.Token(ctx, "fixture"); !errors.Is(err, tokenstore.ErrInvalidRefresh) {
		t.Fatalf("empty refresh result: err=%v", err)
	}
	if current, _ := store.Load(ctx, "fixture"); current.Revision != stored.Revision {
		t.Fatal("an empty refresh result was stored")
	}
}

type terminalFixture struct{ terminal bool }

func (e terminalFixture) Error() string  { return "fixture refresh error" }
func (e terminalFixture) Terminal() bool { return e.terminal }

func TestTerminalClassification(t *testing.T) {
	for _, code := range []string{"invalid_grant", "INVALID_GRANT", "refresh_token_reused", "token_reused", "invalid_token", "refresh_token_invalidated", "expired_token", "refresh_token_expired"} {
		if !tokenstore.TerminalOAuthCode(code) {
			t.Errorf("%s should be terminal", code)
		}
	}
	for _, code := range []string{"", "transport", "invalid_response", "temporarily_unavailable", "http_503", "slow_down"} {
		if tokenstore.TerminalOAuthCode(code) {
			t.Errorf("%s should not be terminal", code)
		}
	}
	if !tokenstore.IsTerminal(fmt.Errorf("wrapped: %w", terminalFixture{terminal: true})) {
		t.Error("wrapped terminal error was not recognised")
	}
	if tokenstore.IsTerminal(terminalFixture{terminal: false}) || tokenstore.IsTerminal(errors.New("plain")) || tokenstore.IsTerminal(nil) {
		t.Error("non-terminal error classified as terminal")
	}
}
