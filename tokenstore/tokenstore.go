// Package tokenstore defines how refreshable OAuth credentials are stored and
// refreshed when several goroutines or processes share one store.
//
// Correctness rests on two store guarantees. A lease serializes refreshes of
// one credential across every process that uses the store, so a rotating
// refresh token is spent once. Compare-and-swap writes keyed by an opaque
// revision fence out a writer whose view is stale, such as a lease holder
// that stalled or a refresh that raced a new login. The Coordinator combines
// both; stores prove them by passing the storetest conformance suite.
package tokenstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"time"
)

var (
	// ErrNotFound reports that no usable credential exists for a key.
	ErrNotFound = errors.New("tokenstore: credential not found")
	// ErrConflict reports that the stored revision differs from the one the
	// caller observed, so the write was not applied.
	ErrConflict = errors.New("tokenstore: credential changed concurrently")
	// ErrNoRefreshToken reports an expired credential that cannot refresh.
	ErrNoRefreshToken = errors.New("tokenstore: credential has no refresh token")
	// ErrIdentityChanged reports a refresh that returned a different account.
	// The refreshed tokens are discarded.
	ErrIdentityChanged = errors.New("tokenstore: refresh returned a different account")
	// ErrRevoked reports a refresh the provider rejected permanently. The
	// credential has been revoked in the store.
	ErrRevoked = errors.New("tokenstore: provider rejected the refresh grant")
	// ErrInvalidRefresh reports a refresh result without an access token.
	ErrInvalidRefresh = errors.New("tokenstore: refresh returned no access token")
)

// Record is one stored credential.
//
// Stores assign Revision on every write and ignore any value supplied on
// input. AccountID binds the credential to one upstream account; a refresh
// may never change it. Metadata carries provider-specific values that the
// store round-trips without interpreting.
type Record struct {
	Revision     string
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	Expiry       time.Time
	AccountID    string
	Metadata     map[string]string
}

// Clone returns a deep copy, so callers and stores never share Metadata.
func (r Record) Clone() Record {
	r.Metadata = maps.Clone(r.Metadata)
	return r
}

// String describes the record without token material.
func (r Record) String() string {
	return fmt.Sprintf("tokenstore.Record{Revision:%q AccountID:%q Expiry:%s AccessToken:%s RefreshToken:%s}",
		r.Revision, r.AccountID, r.Expiry.UTC().Format(time.RFC3339), presence(r.AccessToken), presence(r.RefreshToken))
}

// GoString keeps %#v from printing token material.
func (r Record) GoString() string { return r.String() }

// LogValue keeps structured logging from printing token material.
func (r Record) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("revision", r.Revision),
		slog.String("account_id", r.AccountID),
		slog.Time("expiry", r.Expiry),
		slog.Bool("has_refresh_token", r.RefreshToken != ""),
	)
}

func presence(value string) string {
	if value == "" {
		return "absent"
	}
	return "redacted"
}

// Store persists credentials. Implementations must be safe for concurrent
// use, and separately opened instances over the same backing store (other
// processes) must observe each other's writes and leases.
type Store interface {
	// Load returns the current record, or ErrNotFound.
	Load(ctx context.Context, key string) (Record, error)
	// Save stores record unconditionally, as a new login does, and returns
	// it with its new revision.
	Save(ctx context.Context, key string, record Record) (Record, error)
	// ReplaceIfCurrent stores record only if the current revision equals
	// revision. It returns ErrConflict otherwise, including when the
	// credential was revoked or never existed.
	ReplaceIfCurrent(ctx context.Context, key, revision string, record Record) (Record, error)
	// RevokeIfCurrent removes the credential only if the current revision
	// equals revision; afterwards Load returns ErrNotFound. It returns
	// ErrConflict on a revision mismatch and ErrNotFound when absent.
	RevokeIfCurrent(ctx context.Context, key, revision string) error
	// Lease blocks until it holds the exclusive refresh lease for key or ctx
	// ends. The lease spans every instance over the backing store and holds
	// until release is called or the holding process exits. Release is safe
	// to call more than once. Stores that expire leases must not expire them
	// sooner than a complete refresh can take.
	Lease(ctx context.Context, key string) (release func(), err error)
}
