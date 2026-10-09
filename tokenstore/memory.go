package tokenstore

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
)

// Memory is an in-process reference Store. Its leases and revisions are
// shared by every caller holding the same *Memory, which makes it suitable
// for tests and for single-process products.
type Memory struct {
	mu       sync.Mutex
	records  map[string]Record
	leases   map[string]chan struct{}
	revision uint64
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{records: map[string]Record{}, leases: map[string]chan struct{}{}}
}

var _ Store = (*Memory)(nil)

func (m *Memory) Load(ctx context.Context, key string) (Record, error) {
	if err := checkRequest(ctx, key); err != nil {
		return Record{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.records[key]
	if !ok {
		return Record{}, ErrNotFound
	}
	return record.Clone(), nil
}

func (m *Memory) Save(ctx context.Context, key string, record Record) (Record, error) {
	if err := checkRequest(ctx, key); err != nil {
		return Record{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.storeLocked(key, record), nil
}

func (m *Memory) ReplaceIfCurrent(ctx context.Context, key, revision string, record Record) (Record, error) {
	if err := checkRequest(ctx, key); err != nil {
		return Record{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.records[key]
	if !ok || current.Revision != revision {
		return Record{}, ErrConflict
	}
	return m.storeLocked(key, record), nil
}

func (m *Memory) RevokeIfCurrent(ctx context.Context, key, revision string) error {
	if err := checkRequest(ctx, key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.records[key]
	if !ok {
		return ErrNotFound
	}
	if current.Revision != revision {
		return ErrConflict
	}
	delete(m.records, key)
	return nil
}

func (m *Memory) Lease(ctx context.Context, key string) (func(), error) {
	if err := checkRequest(ctx, key); err != nil {
		return nil, err
	}
	for {
		m.mu.Lock()
		held, busy := m.leases[key]
		if !busy {
			released := make(chan struct{})
			m.leases[key] = released
			m.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					m.mu.Lock()
					delete(m.leases, key)
					m.mu.Unlock()
					close(released)
				})
			}, nil
		}
		m.mu.Unlock()
		select {
		case <-held:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (m *Memory) storeLocked(key string, record Record) Record {
	m.revision++
	stored := record.Clone()
	stored.Revision = strconv.FormatUint(m.revision, 10)
	m.records[key] = stored
	return stored.Clone()
}

func checkRequest(ctx context.Context, key string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("tokenstore: key is required")
	}
	return ctx.Err()
}
