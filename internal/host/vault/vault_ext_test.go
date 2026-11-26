package vault_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync/atomic"
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
	// 使用 t.TempDir() 下新建子目录，使 Windows EnsureRoot 以 Owner-Only DACL 创建目录。
	dir, err := pathalg.ParseLocalDir(filepath.Join(t.TempDir(), "vault"))
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

type spyLockCloseVault struct {
	lockCalls  atomic.Int32
	closeCalls atomic.Int32
	closeErr   error
}

func (*spyLockCloseVault) WithSecret(context.Context, secret.Ref, func(*secret.SecretBox) error) error {
	return ports.ErrSecretNotFound
}
func (*spyLockCloseVault) PutAndVerify(context.Context, secret.Ref, *secret.SecretBox) error {
	return nil
}
func (*spyLockCloseVault) Delete(context.Context, secret.Ref) error { return nil }
func (s *spyLockCloseVault) Lock(context.Context) error {
	s.lockCalls.Add(1)
	return nil
}
func (s *spyLockCloseVault) Close() error {
	s.closeCalls.Add(1)
	return s.closeErr
}

// TestRouterVault_CloseDeduplicatesLocksClosesAndFailsClosed 验证 #160 Minor-1：
// RouterVault.Close() 幂等、去重（stores + defaultStore 同一后端仅 Lock/Close 一次）、锁定已解锁 offline.Vault、
// 容忍未初始化 offline.Vault，并在关闭后拒绝所有新凭据请求。
func TestRouterVault_CloseDeduplicatesLocksClosesAndFailsClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. nil 与零值 Close 安全返回 nil。
	var nilRouter *vault.RouterVault
	var zeroRouter vault.RouterVault
	if err := nilRouter.Close(); err != nil {
		t.Fatalf("nil RouterVault.Close: %v", err)
	}
	if err := zeroRouter.Close(); err != nil {
		t.Fatalf("zero RouterVault.Close: %v", err)
	}

	// 2. 共享后端同时挂在多个 store 键与 defaultStore：去重且各仅调用一次 Lock + Close；offline.Vault 锁定且未初始化容忍。
	sharedSpy := &spyLockCloseVault{}
	offUnlocked := newUnlockedOffline(t, "off-a")
	uninitDir, err := pathalg.ParseLocalDir(filepath.Join(t.TempDir(), "uninit-vault"))
	if err != nil {
		t.Fatalf("ParseLocalDir: %v", err)
	}
	params, _ := helper.NewArgon2idParams(1, 1024, 1)
	offUninit, err := offline.NewVault(offline.Spec{
		ScopedFS: osfs.NewScopedRootFS(), RootDir: uninitDir, Entropy: sys.NewCryptoEntropy(), KDFParams: params, StoreNames: []string{"off-uninit"},
	})
	if err != nil {
		t.Fatalf("NewVault(uninit): %v", err)
	}

	r, err := vault.NewRouterVault(vault.RouterSpec{
		Stores:       map[string]ports.SecretVault{"alias1": sharedSpy, "alias2": sharedSpy, "off-a": offUnlocked, "off-uninit": offUninit},
		DefaultStore: sharedSpy,
	})
	if err != nil {
		t.Fatalf("NewRouterVault: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("RouterVault.Close 首次调用失败: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("RouterVault.Close 二次幂等调用失败: %v", err)
	}
	if sharedSpy.lockCalls.Load() != 1 || sharedSpy.closeCalls.Load() != 1 {
		t.Fatalf("共享后端去重失配: lockCalls=%d closeCalls=%d", sharedSpy.lockCalls.Load(), sharedSpy.closeCalls.Load())
	}
	if st, err := offUnlocked.Status(ctx); err != nil || st.State() != ports.VaultStateLocked {
		t.Fatalf("Close 后 offline.Vault 必须锁定: st=%+v err=%v", st, err)
	}
	ref := tck.MustRef(t, "off-a", "k1")
	if err := r.WithSecret(ctx, ref, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("Close 后 WithSecret 期望 ErrClosed，实际=%v", err)
	}

	assertRouterVaultClosePropagatesError(t)
}

func assertRouterVaultClosePropagatesError(t *testing.T) {
	t.Helper()
	wantErr := errors.New("backend close failed")
	failSpy := &spyLockCloseVault{closeErr: wantErr}
	rFail, err := vault.NewRouterVault(vault.RouterSpec{DefaultStore: failSpy})
	if err != nil {
		t.Fatalf("NewRouterVault(fail): %v", err)
	}
	if err := rFail.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("期望传播底层 Close 错误，实际=%v", err)
	}
	if err := rFail.Close(); !errors.Is(err, wantErr) || failSpy.closeCalls.Load() != 1 {
		t.Fatalf("重复 Close 须幂等保留错误且仅调用一次: err=%v calls=%d", err, failSpy.closeCalls.Load())
	}
}
