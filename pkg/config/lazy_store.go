package config

import (
	"context"
	"fmt"
	"sync"

	"github.com/wentf9/xops-cli/pkg/credential"
)

// lazyStore defers backend availability checks until actual access. Failed
// initialization is retryable, and no lock covers backend construction or I/O.
type lazyStore struct {
	storeID string
	config  StoreConfig
	mu      sync.Mutex
	store   credential.Store
}

func (s *lazyStore) backend(ctx context.Context) (credential.Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	st := s.store
	s.mu.Unlock()
	if st != nil {
		return st, nil
	}
	built, err := BuildStore(s.storeID, s.config)
	if err != nil {
		return nil, fmt.Errorf("initialize store %q: %w", s.storeID, err)
	}
	s.mu.Lock()
	if s.store == nil {
		s.store = built
	}
	st = s.store
	s.mu.Unlock()
	return st, nil
}

func (s *lazyStore) Get(ctx context.Context, ref credential.Ref) (credential.Secret, error) {
	st, err := s.backend(ctx)
	if err != nil {
		return credential.Secret{}, err
	}
	return st.Get(ctx, ref)
}

func (s *lazyStore) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	st, err := s.backend(ctx)
	if err != nil {
		return err
	}
	return st.Put(ctx, ref, secret)
}

func (s *lazyStore) Delete(ctx context.Context, ref credential.Ref) error {
	st, err := s.backend(ctx)
	if err != nil {
		return err
	}
	return st.Delete(ctx, ref)
}
