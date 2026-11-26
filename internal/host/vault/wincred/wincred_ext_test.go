package wincred_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/vault/wincred"
	"go.uber.org/goleak"
)

// 编译期接口契约断言。
var _ ports.SecretVault = (*wincred.Store)(nil)

type memWinCredBackend struct {
	mu     sync.Mutex
	locked bool
	items  map[string][]byte
}

func newMemWinCredBackend(locked bool) *memWinCredBackend {
	return &memWinCredBackend{locked: locked, items: make(map[string][]byte)}
}

func (m *memWinCredBackend) Read(target string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return nil, ports.ErrVaultLocked
	}
	v, ok := m.items[target]
	if !ok {
		return nil, ports.ErrSecretNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (m *memWinCredBackend) Write(target, _ string, box *secret.SecretBox) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ports.ErrVaultLocked
	}
	// 外置测试包禁止 box.Use；借助公开的 SecretBox.Equal 匹配测试令牌即可完整驱动 TCK。
	for _, tok := range []string{tck.TestSecretTokenA, tck.TestSecretTokenB} {
		var matched bool
		_ = secret.WithBytes([]byte(tok), func(cand *secret.SecretBox) error {
			matched = box.Equal(cand)
			return nil
		})
		if matched {
			m.items[target] = []byte(tok)
			return nil
		}
	}
	return ports.ErrInvalidArgument
}

func (m *memWinCredBackend) Delete(target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ports.ErrVaultLocked
	}
	if _, ok := m.items[target]; !ok {
		return ports.ErrSecretNotFound
	}
	delete(m.items, target)
	return nil
}

func TestTCKSecretVault_WinCred(t *testing.T) {
	defer goleak.VerifyNone(t)
	tck.RunSecretVaultSuite(t, tck.SecretVaultFixture{
		NewVault: func(t *testing.T) ports.SecretVault {
			st, err := wincred.NewStoreWithBackend(newMemWinCredBackend(false))
			if err != nil {
				t.Fatalf("NewStoreWithBackend 失败: %v", err)
			}
			return st
		},
		NewLockedVault: func(t *testing.T) ports.SecretVault {
			st, err := wincred.NewStoreWithBackend(newMemWinCredBackend(true))
			if err != nil {
				t.Fatalf("NewStoreWithBackend(locked) 失败: %v", err)
			}
			return st
		},
	})
}

func TestWinCred_ZeroValueAndTargetName(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zero wincred.Store
	ref := tck.MustRef(t, "win", "key1")
	if got := wincred.TargetName(ref); got != "xops:win:key1" {
		t.Fatalf("TargetName = %q, 期望 xops:win:key1", got)
	}
	if err := zero.WithSecret(context.Background(), ref, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 WithSecret = %v, 期望 ErrInvalidArgument", err)
	}
}
