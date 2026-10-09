// Package storetest is the conformance suite every tokenstore.Store
// implementation must pass. Run it from the implementation's tests:
//
//	func TestConformance(t *testing.T) {
//		storetest.Run(t, func(t *testing.T) storetest.Opener {
//			path := filepath.Join(t.TempDir(), "auth.json")
//			return func(t *testing.T) tokenstore.Store { return mystore.Open(path) }
//		})
//	}
//
// Openers backed by files or databases should return a separately opened
// instance on every call, the way separate processes would. Several checks
// rely on that to prove leases and revisions hold across processes rather
// than only inside one instance.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kayiik/llm-provider-auth/tokenstore"
)

// Opener opens a store instance over one shared backing store.
type Opener func(t *testing.T) tokenstore.Store

// NewBackend creates an empty, isolated backing store and returns an opener
// for it.
type NewBackend func(t *testing.T) Opener

const key = "fixture-provider"

// Run executes the conformance suite.
func Run(t *testing.T, newBackend NewBackend) {
	t.Helper()
	t.Run("LoadMissing", func(t *testing.T) { testLoadMissing(t, newBackend(t)) })
	t.Run("SaveAssignsRevisions", func(t *testing.T) { testSaveAssignsRevisions(t, newBackend(t)) })
	t.Run("RoundTripsFields", func(t *testing.T) { testRoundTripsFields(t, newBackend(t)) })
	t.Run("ReplaceIfCurrent", func(t *testing.T) { testReplaceIfCurrent(t, newBackend(t)) })
	t.Run("RevokeIfCurrent", func(t *testing.T) { testRevokeIfCurrent(t, newBackend(t)) })
	t.Run("LeaseIsExclusiveAcrossInstances", func(t *testing.T) { testLeaseExclusive(t, newBackend(t)) })
	t.Run("LeaseIsPerKey", func(t *testing.T) { testLeasePerKey(t, newBackend(t)) })
	t.Run("ConcurrentRefreshSpendsTokenOnce", func(t *testing.T) { testConcurrentRefresh(t, newBackend(t)) })
	t.Run("ConcurrentRejectionsRefreshOnce", func(t *testing.T) { testConcurrentRejections(t, newBackend(t)) })
	t.Run("WaiterUsesRefreshedCredential", func(t *testing.T) { testWaiterSkipsRefresh(t, newBackend(t)) })
	t.Run("LoginDuringRefreshWins", func(t *testing.T) { testLoginDuringRefreshWins(t, newBackend(t)) })
	t.Run("IdentityNeverChanges", func(t *testing.T) { testIdentityNeverChanges(t, newBackend(t)) })
	t.Run("TerminalRefreshRevokes", func(t *testing.T) { testTerminalRefreshRevokes(t, newBackend(t)) })
	t.Run("RetryableRefreshKeepsCredential", func(t *testing.T) { testRetryableRefreshKeeps(t, newBackend(t)) })
}

func expired() tokenstore.Record {
	return tokenstore.Record{
		AccessToken: "fixture-access-0", RefreshToken: "fixture-refresh-0", TokenType: "Bearer",
		Expiry: time.Now().Add(-time.Minute), AccountID: "fixture-account",
		Metadata: map[string]string{"project": "fixture-project"},
	}
}

func seed(t *testing.T, open Opener, record tokenstore.Record) tokenstore.Record {
	t.Helper()
	stored, err := open(t).Save(context.Background(), key, record)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if stored.Revision == "" {
		t.Fatal("Save returned an empty revision")
	}
	return stored
}

// issuer is a token endpoint with rotating refresh tokens and reuse
// detection: presenting any refresh token except the latest is terminal.
type issuer struct {
	mu      sync.Mutex
	latest  string
	calls   atomic.Int32
	delay   time.Duration
	account string
}

type reusedGrant struct{}

func (reusedGrant) Error() string  { return "fixture issuer: refresh_token_reused" }
func (reusedGrant) Terminal() bool { return true }

func newIssuer(latest string) *issuer {
	return &issuer{latest: latest, delay: 25 * time.Millisecond, account: "fixture-account"}
}

func (i *issuer) refresh(_ context.Context, current tokenstore.Record) (tokenstore.Record, error) {
	call := i.calls.Add(1)
	i.mu.Lock()
	defer i.mu.Unlock()
	if current.RefreshToken != i.latest {
		return tokenstore.Record{}, reusedGrant{}
	}
	time.Sleep(i.delay) // widen the race window for concurrent callers
	i.latest = fmt.Sprintf("fixture-refresh-%d", call)
	return tokenstore.Record{
		AccessToken: fmt.Sprintf("fixture-access-%d", call), RefreshToken: i.latest,
		Expiry: time.Now().Add(time.Hour), AccountID: i.account,
	}, nil
}

func coordinator(t *testing.T, store tokenstore.Store, refresh tokenstore.RefreshFunc) *tokenstore.Coordinator {
	t.Helper()
	c, err := tokenstore.NewCoordinator(store, refresh, tokenstore.WithLeaseWait(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func assertSecretFree(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if message := err.Error(); strings.Contains(message, "fixture-access") || strings.Contains(message, "fixture-refresh") {
		t.Fatalf("error contains token material: %v", err)
	}
}

func testLoadMissing(t *testing.T, open Opener) {
	_, err := open(t).Load(context.Background(), key)
	if !errors.Is(err, tokenstore.ErrNotFound) {
		t.Fatalf("Load missing: err=%v, want ErrNotFound", err)
	}
}

func testSaveAssignsRevisions(t *testing.T, open Opener) {
	first := seed(t, open, expired())
	second := seed(t, open, expired())
	if first.Revision == second.Revision {
		t.Fatalf("Save kept revision %q", first.Revision)
	}
	loaded, err := open(t).Load(context.Background(), key)
	if err != nil || loaded.Revision != second.Revision {
		t.Fatalf("Load after Save: revision=%q err=%v, want %q", loaded.Revision, err, second.Revision)
	}
}

func testRoundTripsFields(t *testing.T, open Opener) {
	want := tokenstore.Record{
		AccessToken: "fixture-access-a", RefreshToken: "fixture-refresh-a", IDToken: "fixture-id-token",
		TokenType: "Bearer", Expiry: time.Now().Add(time.Hour).UTC().Truncate(time.Second), AccountID: "fixture-account",
		Metadata: map[string]string{"project": "fixture-project", "profile": "fixture-profile"},
	}
	stored := seed(t, open, want)
	got, err := open(t).Load(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken || got.IDToken != want.IDToken ||
		got.TokenType != want.TokenType || !got.Expiry.Equal(want.Expiry) || got.AccountID != want.AccountID ||
		got.Revision != stored.Revision || len(got.Metadata) != 2 || got.Metadata["project"] != "fixture-project" ||
		got.Metadata["profile"] != "fixture-profile" {
		t.Fatalf("round trip changed the record: %s", got)
	}
	got.Metadata["project"] = "mutated"
	again, _ := open(t).Load(context.Background(), key)
	if again.Metadata["project"] != "fixture-project" {
		t.Fatal("Load returned metadata shared with the store")
	}
}

func testReplaceIfCurrent(t *testing.T, open Opener) {
	ctx := context.Background()
	stored := seed(t, open, expired())
	replacement := expired()
	replacement.AccessToken = "fixture-access-replaced"
	replaced, err := open(t).ReplaceIfCurrent(ctx, key, stored.Revision, replacement)
	if err != nil || replaced.Revision == "" || replaced.Revision == stored.Revision {
		t.Fatalf("ReplaceIfCurrent current: revision=%q err=%v", replaced.Revision, err)
	}
	_, err = open(t).ReplaceIfCurrent(ctx, key, stored.Revision, expired())
	if !errors.Is(err, tokenstore.ErrConflict) {
		t.Fatalf("ReplaceIfCurrent stale: err=%v, want ErrConflict", err)
	}
	assertSecretFree(t, err)
	loaded, _ := open(t).Load(ctx, key)
	if loaded.AccessToken != "fixture-access-replaced" || loaded.Revision != replaced.Revision {
		t.Fatalf("stale replace changed the record: %s", loaded)
	}
	if _, err := open(t).ReplaceIfCurrent(ctx, "fixture-missing", "1", expired()); !errors.Is(err, tokenstore.ErrConflict) {
		t.Fatalf("ReplaceIfCurrent missing: err=%v, want ErrConflict", err)
	}
}

func testRevokeIfCurrent(t *testing.T, open Opener) {
	ctx := context.Background()
	stored := seed(t, open, expired())
	if err := open(t).RevokeIfCurrent(ctx, key, "stale-revision"); !errors.Is(err, tokenstore.ErrConflict) {
		t.Fatalf("RevokeIfCurrent stale: err=%v, want ErrConflict", err)
	}
	if _, err := open(t).Load(ctx, key); err != nil {
		t.Fatalf("stale revoke removed the credential: %v", err)
	}
	if err := open(t).RevokeIfCurrent(ctx, key, stored.Revision); err != nil {
		t.Fatalf("RevokeIfCurrent current: %v", err)
	}
	if _, err := open(t).Load(ctx, key); !errors.Is(err, tokenstore.ErrNotFound) {
		t.Fatalf("Load after revoke: err=%v, want ErrNotFound", err)
	}
	if err := open(t).RevokeIfCurrent(ctx, key, stored.Revision); !errors.Is(err, tokenstore.ErrNotFound) {
		t.Fatalf("RevokeIfCurrent missing: err=%v, want ErrNotFound", err)
	}
	if _, err := open(t).ReplaceIfCurrent(ctx, key, stored.Revision, expired()); !errors.Is(err, tokenstore.ErrConflict) {
		t.Fatalf("ReplaceIfCurrent after revoke: err=%v, want ErrConflict", err)
	}
}

func testLeaseExclusive(t *testing.T, open Opener) {
	holder, waiter := open(t), open(t)
	release, err := holder.Lease(context.Background(), key)
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	short, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if extra, err := waiter.Lease(short, key); err == nil {
		extra()
		t.Fatal("a second instance acquired a held lease")
	}
	release()
	release() // release must be idempotent
	acquired, err := waiter.Lease(context.Background(), key)
	if err != nil {
		t.Fatalf("Lease after release: %v", err)
	}
	acquired()
}

func testLeasePerKey(t *testing.T, open Opener) {
	release, err := open(t).Lease(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	short, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	other, err := open(t).Lease(short, "fixture-other-provider")
	if err != nil {
		t.Fatalf("a lease on one key blocked another key: %v", err)
	}
	other()
}

func testConcurrentRefresh(t *testing.T, open Opener) {
	seed(t, open, expired())
	token := newIssuer("fixture-refresh-0")
	const workers = 8
	coordinators := make([]*tokenstore.Coordinator, workers)
	for index := range workers {
		coordinators[index] = coordinator(t, open(t), token.refresh)
	}
	var group sync.WaitGroup
	results := make([]tokenstore.Record, workers)
	errs := make([]error, workers)
	for index := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			results[index], errs[index] = coordinators[index].Token(context.Background(), key)
		}()
	}
	group.Wait()
	for index := range workers {
		if errs[index] != nil {
			assertSecretFree(t, errs[index])
			t.Fatalf("worker %d: %v", index, errs[index])
		}
		if results[index].AccessToken != "fixture-access-1" {
			t.Fatalf("worker %d received %s", index, results[index])
		}
	}
	if calls := token.calls.Load(); calls != 1 {
		t.Fatalf("token endpoint received %d refresh requests, want exactly 1", calls)
	}
	stored, _ := open(t).Load(context.Background(), key)
	if stored.RefreshToken != "fixture-refresh-1" || stored.Metadata["project"] != "fixture-project" || stored.AccountID != "fixture-account" {
		t.Fatalf("refreshed record lost state: %s metadata=%v", stored, stored.Metadata)
	}
}

func testConcurrentRejections(t *testing.T, open Opener) {
	usable := expired()
	usable.Expiry = time.Now().Add(time.Hour)
	rejected := seed(t, open, usable)
	token := newIssuer("fixture-refresh-0")
	const workers = 6
	coordinators := make([]*tokenstore.Coordinator, workers)
	for index := range workers {
		coordinators[index] = coordinator(t, open(t), token.refresh)
	}
	var group sync.WaitGroup
	errs := make([]error, workers)
	results := make([]tokenstore.Record, workers)
	for index := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			results[index], errs[index] = coordinators[index].Rejected(context.Background(), key, rejected)
		}()
	}
	group.Wait()
	for index := range workers {
		if errs[index] != nil || results[index].AccessToken != "fixture-access-1" {
			t.Fatalf("worker %d: record=%s err=%v", index, results[index], errs[index])
		}
	}
	if calls := token.calls.Load(); calls != 1 {
		t.Fatalf("concurrent rejections caused %d refreshes, want exactly 1", calls)
	}
}

func testWaiterSkipsRefresh(t *testing.T, open Opener) {
	ctx := context.Background()
	stored := seed(t, open, expired())
	release, err := open(t).Lease(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	token := newIssuer("fixture-refresh-0")
	waiter := coordinator(t, open(t), token.refresh)
	done := make(chan struct {
		record tokenstore.Record
		err    error
	}, 1)
	go func() {
		record, err := waiter.Token(ctx, key)
		done <- struct {
			record tokenstore.Record
			err    error
		}{record, err}
	}()
	time.Sleep(100 * time.Millisecond)
	fresh := expired()
	fresh.AccessToken, fresh.RefreshToken, fresh.Expiry = "fixture-access-other", "fixture-refresh-other", time.Now().Add(time.Hour)
	if _, err := open(t).ReplaceIfCurrent(ctx, key, stored.Revision, fresh); err != nil {
		t.Fatal(err)
	}
	release()
	result := <-done
	if result.err != nil || result.record.AccessToken != "fixture-access-other" {
		t.Fatalf("waiter: record=%s err=%v", result.record, result.err)
	}
	if calls := token.calls.Load(); calls != 0 {
		t.Fatalf("waiter refreshed %d times after another holder already refreshed", calls)
	}
}

func testLoginDuringRefreshWins(t *testing.T, open Opener) {
	ctx := context.Background()
	seed(t, open, expired())
	login := expired()
	login.AccessToken, login.RefreshToken, login.Expiry = "fixture-access-login", "fixture-refresh-login", time.Now().Add(time.Hour)
	refresh := func(ctx context.Context, current tokenstore.Record) (tokenstore.Record, error) {
		// A new login lands while the refresh request is in flight.
		if _, err := open(t).Save(ctx, key, login); err != nil {
			return tokenstore.Record{}, err
		}
		return tokenstore.Record{AccessToken: "fixture-access-refreshed", RefreshToken: "fixture-refresh-refreshed", Expiry: time.Now().Add(time.Hour)}, nil
	}
	record, err := coordinator(t, open(t), refresh).Token(ctx, key)
	if err != nil || record.AccessToken != "fixture-access-login" {
		t.Fatalf("login during refresh: record=%s err=%v", record, err)
	}
	stored, _ := open(t).Load(ctx, key)
	if stored.AccessToken != "fixture-access-login" {
		t.Fatalf("refresh overwrote a concurrent login: %s", stored)
	}
}

func testIdentityNeverChanges(t *testing.T, open Opener) {
	ctx := context.Background()
	stored := seed(t, open, expired())
	token := newIssuer("fixture-refresh-0")
	token.account = "fixture-other-account"
	_, err := coordinator(t, open(t), token.refresh).Token(ctx, key)
	if !errors.Is(err, tokenstore.ErrIdentityChanged) {
		t.Fatalf("identity change: err=%v, want ErrIdentityChanged", err)
	}
	assertSecretFree(t, err)
	current, _ := open(t).Load(ctx, key)
	if current.Revision != stored.Revision || current.AccountID != "fixture-account" {
		t.Fatalf("identity change was stored: %s", current)
	}
}

func testTerminalRefreshRevokes(t *testing.T, open Opener) {
	ctx := context.Background()
	seed(t, open, expired())
	token := newIssuer("fixture-refresh-rotated-elsewhere")
	_, err := coordinator(t, open(t), token.refresh).Token(ctx, key)
	if !errors.Is(err, tokenstore.ErrRevoked) || !tokenstore.IsTerminal(err) {
		t.Fatalf("terminal refresh: err=%v, want ErrRevoked wrapping a terminal cause", err)
	}
	assertSecretFree(t, err)
	if _, err := open(t).Load(ctx, key); !errors.Is(err, tokenstore.ErrNotFound) {
		t.Fatalf("terminal refresh left the credential usable: err=%v", err)
	}
}

func testRetryableRefreshKeeps(t *testing.T, open Opener) {
	ctx := context.Background()
	stored := seed(t, open, expired())
	transient := errors.New("fixture transport failure")
	_, err := coordinator(t, open(t), func(context.Context, tokenstore.Record) (tokenstore.Record, error) {
		return tokenstore.Record{}, transient
	}).Token(ctx, key)
	if !errors.Is(err, transient) || errors.Is(err, tokenstore.ErrRevoked) {
		t.Fatalf("retryable refresh: err=%v", err)
	}
	current, _ := open(t).Load(ctx, key)
	if current.Revision != stored.Revision {
		t.Fatalf("retryable refresh changed the credential: %s", current)
	}
}
