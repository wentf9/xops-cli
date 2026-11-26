package vault_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"github.com/wentf9/xops-cli/internal/host/vault"
	"github.com/wentf9/xops-cli/internal/host/vault/helper"
	"github.com/wentf9/xops-cli/internal/host/vault/offline"
	"go.uber.org/goleak"
)

// 编译期接口契约断言。
var _ ports.SecretVault = (*vault.RouterVault)(nil)

func newUnlockedOffline(t *testing.T, storeName string) *offline.Vault {
	t.Helper()
	dir, err := pathalg.ParseLocalDir(t.TempDir())
	if err != nil {
		t.Fatalf("ParseLocalDir 失败: %v", err)
	}
	params, err := helper.NewArgon2idParams(1, 1024, 1)
	if err != nil {
		t.Fatalf("NewArgon2idParams 失败: %v", err)
	}
	v, err := offline.NewVault(offline.Spec{
		ScopedFS:   osfs.NewScopedRootFS(),
		RootDir:    dir,
		Entropy:    sys.NewCryptoEntropy(),
		KDFParams:  params,
		StoreNames: []string{storeName},
	})
	if err != nil {
		t.Fatalf("NewVault 失败: %v", err)
	}
	if err := secret.WithBytes([]byte("router-master-pass"), func(pass *secret.SecretBox) error {
		return v.Init(context.Background(), pass)
	}); err != nil {
		t.Fatalf("Init 失败: %v", err)
	}
	return v
}

func TestTCKSecretVault_RouterVault(t *testing.T) {
	defer goleak.VerifyNone(t)
	tck.RunSecretVaultSuite(t, tck.SecretVaultFixture{
		NewVault: func(t *testing.T) ports.SecretVault {
			primary := newUnlockedOffline(t, "tck-store")
			r, err := vault.NewRouterVault(vault.RouterSpec{
				Stores: map[string]ports.SecretVault{"tck-store": primary},
			})
			if err != nil {
				t.Fatalf("NewRouterVault 失败: %v", err)
			}
			return r
		},
		NewLockedVault: func(t *testing.T) ports.SecretVault {
			locked := newUnlockedOffline(t, "tck-store")
			if err := locked.Lock(context.Background()); err != nil {
				t.Fatalf("Lock 失败: %v", err)
			}
			r, err := vault.NewRouterVault(vault.RouterSpec{
				Stores: map[string]ports.SecretVault{"tck-store": locked},
			})
			if err != nil {
				t.Fatalf("NewRouterVault(locked) 失败: %v", err)
			}
			return r
		},
	})
}

func TestRouterVault_DispatchIsolationAndPlatformKeychain(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	storeA := newUnlockedOffline(t, "store-a")
	storeB := newUnlockedOffline(t, "store-b")
	r, err := vault.NewRouterVault(vault.RouterSpec{
		Stores: map[string]ports.SecretVault{"store-b": storeB, "store-a": storeA},
	})
	if err != nil {
		t.Fatalf("NewRouterVault 失败: %v", err)
	}
	if !slices.Equal(r.KnownStores(), []string{"store-a", "store-b"}) {
		t.Fatalf("KnownStores = %v, 期望 [store-a store-b]", r.KnownStores())
	}
	refA := tck.MustRef(t, "store-a", "k1")
	refB := tck.MustRef(t, "store-b", "k1")
	refUnknown := tck.MustRef(t, "unregistered", "k1")
	if err := secret.WithBytes([]byte("val-A"), func(box *secret.SecretBox) error {
		return r.PutAndVerify(ctx, refA, box)
	}); err != nil {
		t.Fatalf("PutAndVerify(A) 失败: %v", err)
	}
	if err := r.WithSecret(ctx, refB, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrSecretNotFound) {
		t.Fatalf("不同存储间必须严格隔离: got=%v", err)
	}
	if err := r.WithSecret(ctx, refUnknown, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrSecretNotFound) {
		t.Fatalf("未注册存储须失败关闭: got=%v", err)
	}
	var zero vault.RouterVault
	if err := zero.WithSecret(ctx, refA, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 RouterVault = %v, 期望 ErrInvalidArgument", err)
	}
	if kc, err := vault.NewPlatformOSKeychain(sys.NewSystemEnv(), sys.NewCryptoEntropy()); err != nil || kc == nil {
		t.Fatalf("NewPlatformOSKeychain = (%v, %v)", kc, err)
	}
}
