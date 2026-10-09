package tokenstore

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"
)

// RefreshFunc exchanges current's refresh token for new tokens. It must not
// return token material in errors. Implementations signal a permanently
// rejected grant with an error for which IsTerminal reports true.
type RefreshFunc func(ctx context.Context, current Record) (Record, error)

const (
	defaultSkew      = 60 * time.Second
	defaultLeaseWait = 90 * time.Second
)

// Coordinator hands out usable credentials, refreshing each one at most once
// across every goroutine and process that shares the store.
type Coordinator struct {
	store     Store
	refresh   RefreshFunc
	skew      time.Duration
	leaseWait time.Duration
	now       func() time.Time
}

// Option configures a Coordinator.
type Option func(*Coordinator)

// WithSkew refreshes credentials this long before they expire. Default 60s.
func WithSkew(skew time.Duration) Option { return func(c *Coordinator) { c.skew = skew } }

// WithLeaseWait bounds how long a caller waits for another holder's refresh.
// It must exceed the longest refresh the RefreshFunc can take, including its
// HTTP timeout. Default 90s.
func WithLeaseWait(wait time.Duration) Option { return func(c *Coordinator) { c.leaseWait = wait } }

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option { return func(c *Coordinator) { c.now = now } }

// NewCoordinator returns a Coordinator over store using refresh.
func NewCoordinator(store Store, refresh RefreshFunc, options ...Option) (*Coordinator, error) {
	if store == nil || refresh == nil {
		return nil, errors.New("tokenstore: coordinator requires a store and a refresh function")
	}
	coordinator := &Coordinator{store: store, refresh: refresh, skew: defaultSkew, leaseWait: defaultLeaseWait, now: time.Now}
	for _, option := range options {
		option(coordinator)
	}
	if coordinator.leaseWait <= 0 || coordinator.skew < 0 || coordinator.now == nil {
		return nil, errors.New("tokenstore: invalid coordinator options")
	}
	return coordinator, nil
}

// Token returns a usable credential for key, refreshing it if it expires
// within the skew window.
func (c *Coordinator) Token(ctx context.Context, key string) (Record, error) {
	current, err := c.store.Load(ctx, key)
	if err != nil {
		return Record{}, err
	}
	if c.usable(current) {
		return current, nil
	}
	release, err := c.lease(ctx, key)
	if err != nil {
		return Record{}, err
	}
	defer release()
	// Another holder may have refreshed while this caller waited.
	current, err = c.store.Load(ctx, key)
	if err != nil {
		return Record{}, err
	}
	if c.usable(current) {
		return current, nil
	}
	return c.refreshHeld(ctx, key, current)
}

// Rejected handles an upstream rejection of rejected (for example HTTP 401)
// by refreshing once. Concurrent callers that report the same revision share
// that single refresh.
func (c *Coordinator) Rejected(ctx context.Context, key string, rejected Record) (Record, error) {
	release, err := c.lease(ctx, key)
	if err != nil {
		return Record{}, err
	}
	defer release()
	current, err := c.store.Load(ctx, key)
	if err != nil {
		return Record{}, err
	}
	if current.Revision != rejected.Revision && c.usable(current) {
		return current, nil
	}
	return c.refreshHeld(ctx, key, current)
}

func (c *Coordinator) lease(ctx context.Context, key string) (func(), error) {
	leaseCtx, cancel := context.WithTimeout(ctx, c.leaseWait)
	defer cancel()
	release, err := c.store.Lease(leaseCtx, key)
	if err != nil {
		return nil, fmt.Errorf("tokenstore: acquire refresh lease: %w", err)
	}
	return release, nil
}

// refreshHeld runs with the lease held.
func (c *Coordinator) refreshHeld(ctx context.Context, key string, current Record) (Record, error) {
	if strings.TrimSpace(current.RefreshToken) == "" {
		return Record{}, ErrNoRefreshToken
	}
	refreshed, err := c.refresh(ctx, current.Clone())
	if err != nil {
		if !IsTerminal(err) {
			return Record{}, err
		}
		revokeErr := c.store.RevokeIfCurrent(ctx, key, current.Revision)
		if revokeErr != nil && !errors.Is(revokeErr, ErrConflict) && !errors.Is(revokeErr, ErrNotFound) {
			return Record{}, revokeErr
		}
		return Record{}, fmt.Errorf("%w: %w", ErrRevoked, err)
	}
	if strings.TrimSpace(refreshed.AccessToken) == "" {
		return Record{}, ErrInvalidRefresh
	}
	if current.AccountID != "" && refreshed.AccountID != "" && refreshed.AccountID != current.AccountID {
		return Record{}, ErrIdentityChanged
	}
	stored, err := c.store.ReplaceIfCurrent(ctx, key, current.Revision, merge(current, refreshed))
	if errors.Is(err, ErrConflict) {
		// A login, logout or stale holder changed the credential while the
		// refresh ran. Their state wins; never overwrite it.
		latest, loadErr := c.store.Load(ctx, key)
		if loadErr != nil {
			return Record{}, loadErr
		}
		if c.usable(latest) {
			return latest, nil
		}
		return Record{}, err
	}
	return stored, err
}

// merge carries forward values that token endpoints commonly omit on refresh.
func merge(current, refreshed Record) Record {
	merged := refreshed.Clone()
	merged.Revision = ""
	if merged.RefreshToken == "" {
		merged.RefreshToken = current.RefreshToken
	}
	if merged.IDToken == "" {
		merged.IDToken = current.IDToken
	}
	if merged.TokenType == "" {
		merged.TokenType = current.TokenType
	}
	if merged.AccountID == "" {
		merged.AccountID = current.AccountID
	}
	metadata := maps.Clone(current.Metadata)
	if metadata == nil && len(refreshed.Metadata) > 0 {
		metadata = map[string]string{}
	}
	maps.Copy(metadata, refreshed.Metadata)
	merged.Metadata = metadata
	return merged
}

// usable reports a present access token outside the refresh window. A zero
// expiry means the provider did not report one.
func (c *Coordinator) usable(record Record) bool {
	if strings.TrimSpace(record.AccessToken) == "" {
		return false
	}
	return record.Expiry.IsZero() || c.now().Add(c.skew).Before(record.Expiry)
}
