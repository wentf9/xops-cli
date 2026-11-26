package keychain_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/vault/keychain"
	"go.uber.org/goleak"
)

// 编译期接口契约断言。
var _ ports.SecretVault = (*keychain.Store)(nil)

type memKeychainBackend struct {
	mu     sync.Mutex
	locked bool
	items  map[string][]byte
}

func newMemKeychainBackend(locked bool) *memKeychainBackend {
	return &memKeychainBackend{locked: locked, items: make(map[string][]byte)}
}

func (m *memKeychainBackend) Read(service, account string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return nil, ports.ErrVaultLocked
	}
	v, ok := m.items[service+"\x00"+account]
	if !ok {
		return nil, ports.ErrSecretNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (m *memKeychainBackend) Write(service, account string, box *secret.SecretBox) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ports.ErrVaultLocked
	}
	for _, tok := range []string{tck.TestSecretTokenA, tck.TestSecretTokenB} {
		var matched bool
		_ = secret.WithBytes([]byte(tok), func(cand *secret.SecretBox) error {
			matched = box.Equal(cand)
			return nil
		})
		if matched {
			m.items[service+"\x00"+account] = []byte(tok)
			return nil
		}
	}
	return ports.ErrInvalidArgument
}

func (m *memKeychainBackend) Delete(service, account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ports.ErrVaultLocked
	}
	k := service + "\x00" + account
	if _, ok := m.items[k]; !ok {
		return ports.ErrSecretNotFound
	}
	delete(m.items, k)
	return nil
}

func TestTCKSecretVault_Keychain(t *testing.T) {
	defer goleak.VerifyNone(t)
	tck.RunSecretVaultSuite(t, tck.SecretVaultFixture{
		NewVault: func(t *testing.T) ports.SecretVault {
			st, err := keychain.NewStoreWithBackend(newMemKeychainBackend(false))
			if err != nil {
				t.Fatalf("NewStoreWithBackend 失败: %v", err)
			}
			return st
		},
		NewLockedVault: func(t *testing.T) ports.SecretVault {
			st, err := keychain.NewStoreWithBackend(newMemKeychainBackend(true))
			if err != nil {
				t.Fatalf("NewStoreWithBackend(locked) 失败: %v", err)
			}
			return st
		},
	})
}

func TestKeychain_ZeroValueAndServiceAccount(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zero keychain.Store
	ref := tck.MustRef(t, "mac", "token1")
	svc, acct := keychain.ServiceAccount(ref)
	if svc != "xops:mac" || acct != "token1" {
		t.Fatalf("ServiceAccount = (%q, %q), 期望 (xops:mac, token1)", svc, acct)
	}
	if err := zero.WithSecret(context.Background(), ref, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 WithSecret = %v, 期望 ErrInvalidArgument", err)
	}
}
