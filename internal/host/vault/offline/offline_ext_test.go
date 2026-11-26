package offline_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"github.com/wentf9/xops-cli/internal/host/vault/helper"
	"github.com/wentf9/xops-cli/internal/host/vault/offline"
	"go.uber.org/goleak"
)

// 编译期接口契约断言。
var (
	_ ports.SecretVault      = (*offline.Vault)(nil)
	_ ports.VaultControlPort = (*offline.Vault)(nil)
)

const offlineKDFWorkerEnv = "XOPS_OFFLINE_VAULT_KDF_WORKER"

func TestOfflineVaultKDFWorker(t *testing.T) {
	if os.Getenv(offlineKDFWorkerEnv) != "1" {
		return
	}
	if err := helper.ServeArgon2idWorker(os.Stdin, os.Stdout); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func newTestOfflineVault(t *testing.T, dir string, withKDFProc bool) *offline.Vault {
	t.Helper()
	rootDir, err := pathalg.ParseLocalDir(dir)
	if err != nil {
		t.Fatalf("ParseLocalDir 失败: %v", err)
	}
	params, err := helper.NewArgon2idParams(1, 1024, 1)
	if err != nil {
		t.Fatalf("NewArgon2idParams 失败: %v", err)
	}
	spec := offline.Spec{
		ScopedFS:  osfs.NewScopedRootFS(),
		RootDir:   rootDir,
		Entropy:   sys.NewCryptoEntropy(),
		KDFParams: params,
	}
	if withKDFProc {
		exe, eErr := os.Executable()
		if eErr != nil {
			t.Fatalf("os.Executable 失败: %v", eErr)
		}
		ps, pErr := ports.NewProcessSpec(ports.ProcessSpecInput{
			Command:        exe,
			Args:           []string{"-test.run=^TestOfflineVaultKDFWorker$"},
			Env:            map[string]string{offlineKDFWorkerEnv: "1"},
			MaxOutputBytes: algebraic.Some(uint64(256)),
		})
		if pErr != nil {
			t.Fatalf("NewProcessSpec 失败: %v", pErr)
		}
		spec.KDFProcess = sys.NewSystemProcess()
		spec.KDFSpec = ps
	}
	v, err := offline.NewVault(spec)
	if err != nil {
		t.Fatalf("NewVault 失败: %v", err)
	}
	return v
}

func mustInitVault(t *testing.T, v *offline.Vault, master string) {
	t.Helper()
	err := secret.WithBytes([]byte(master), func(pass *secret.SecretBox) error {
		return v.Init(context.Background(), pass)
	})
	if err != nil {
		t.Fatalf("Vault.Init 失败: %v", err)
	}
}

func newFreshVaultDir(t *testing.T) string {
	t.Helper()
	// 使用 t.TempDir() 下尚未创建的子目录，以便 Windows EnsureRoot 以 Owner-Only DACL 创建根目录而非继承父临时目录宽松 DACL。
	return filepath.Join(t.TempDir(), "vault")
}

func TestTCKOfflineVaultAndControl(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Run("SecretVaultTCK", func(t *testing.T) {
		tck.RunSecretVaultSuite(t, tck.SecretVaultFixture{
			NewVault: func(t *testing.T) ports.SecretVault {
				v := newTestOfflineVault(t, newFreshVaultDir(t), false)
				mustInitVault(t, v, "offline-master-pass")
				return v
			},
			NewLockedVault: func(t *testing.T) ports.SecretVault {
				v := newTestOfflineVault(t, newFreshVaultDir(t), false)
				mustInitVault(t, v, "offline-master-pass")
				if err := v.Lock(context.Background()); err != nil {
					t.Fatalf("Vault.Lock 失败: %v", err)
				}
				return v
			},
		})
	})

	t.Run("VaultControlTCK", func(t *testing.T) {
		tck.RunVaultControlSuite(t, tck.VaultControlFixture{
			NewUninitialized: func(t *testing.T) ports.VaultControlPort {
				return newTestOfflineVault(t, newFreshVaultDir(t), false)
			},
		})
	})
}

func TestOfflineVault_PersistenceTamperAndSubprocessKDF(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	dir := newFreshVaultDir(t)
	ref := tck.MustRef(t, "offline", "db-pass")

	v1 := newTestOfflineVault(t, dir, true)
	mustInitVault(t, v1, "subprocess-master")
	err := secret.WithBytes([]byte("super-secret-value"), func(box *secret.SecretBox) error {
		return v1.PutAndVerify(ctx, ref, box)
	})
	if err != nil {
		t.Fatalf("PutAndVerify 失败: %v", err)
	}
	if err := v1.Lock(ctx); err != nil {
		t.Fatalf("Lock 失败: %v", err)
	}

	// 重新打开同一目录并使用隔离 KDF 子进程解锁回读。
	v2 := newTestOfflineVault(t, dir, true)
	err = secret.WithBytes([]byte("subprocess-master"), func(pass *secret.SecretBox) error {
		return v2.Unlock(ctx, pass)
	})
	if err != nil {
		t.Fatalf("重开 Unlock 失败: %v", err)
	}
	err = secret.WithBytes([]byte("super-secret-value"), func(want *secret.SecretBox) error {
		return v2.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
			if !got.Equal(want) {
				t.Fatal("重开回读明文不匹配")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("重开 WithSecret 失败: %v", err)
	}

	// 篡改密文文件必须触发 AEAD 认证失败返回 ErrCorruptData。
	itemPath := findSingleEncFile(t, filepath.Join(dir, "items"))
	raw, err := os.ReadFile(itemPath)
	if err != nil {
		t.Fatalf("读取密文文件失败: %v", err)
	}
	raw[len(raw)-5] ^= 0x01
	if err := os.WriteFile(itemPath, raw, 0o600); err != nil {
		t.Fatalf("写入篡改密文失败: %v", err)
	}
	if err := v2.WithSecret(ctx, ref, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrCorruptData) {
		t.Fatalf("篡改密文 WithSecret = %v, 期望 ErrCorruptData", err)
	}
}

func findSingleEncFile(t *testing.T, itemsDir string) string {
	t.Helper()
	entries, err := os.ReadDir(itemsDir)
	if err != nil {
		t.Fatalf("ReadDir(%q) 失败: %v", itemsDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".enc") {
			return filepath.Join(itemsDir, e.Name())
		}
	}
	t.Fatalf("目录 %q 下未找到 .enc 密文文件", itemsDir)
	return ""
}

// TestOfflineVault_CaseCollisionStoreSyncAndCorruptMetaLock 回归验证：
// 1. 大小写不同引用（MixedCaseKey vs mixedcasekey）在大小写不敏感 FS 上严格隔离零碰撞；
// 2. Unlock 从 meta.stores 同步 KnownStores；
// 3. 元数据损坏时 Lock 仍必须立即清空内存 AEAD 句柄。
func TestOfflineVault_CaseCollisionStoreSyncAndCorruptMetaLock(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	dir := newFreshVaultDir(t)
	rootDir, err := pathalg.ParseLocalDir(dir)
	if err != nil {
		t.Fatalf("ParseLocalDir 失败: %v", err)
	}
	params, err := helper.NewArgon2idParams(1, 1024, 1)
	if err != nil {
		t.Fatalf("NewArgon2idParams 失败: %v", err)
	}
	v1, err := offline.NewVault(offline.Spec{
		ScopedFS:   osfs.NewScopedRootFS(),
		RootDir:    rootDir,
		Entropy:    sys.NewCryptoEntropy(),
		KDFParams:  params,
		StoreNames: []string{"custom-b", "custom-a"},
	})
	if err != nil {
		t.Fatalf("NewVault(v1) 失败: %v", err)
	}
	mustInitVault(t, v1, "case-master")

	refUpper := tck.MustRef(t, "offline", "MixedCaseKey")
	refLower := tck.MustRef(t, "offline", "mixedcasekey")
	putSecret(t, v1, refUpper, "val-UPPER")
	putSecret(t, v1, refLower, "val-lower")
	assertSecretEquals(t, v1, refUpper, "val-UPPER")
	assertSecretEquals(t, v1, refLower, "val-lower")
	if err := v1.Delete(ctx, refUpper); err != nil {
		t.Fatalf("Delete(MixedCaseKey) 失败: %v", err)
	}
	assertSecretEquals(t, v1, refLower, "val-lower")

	// 以默认 StoreNames 重新打开并解锁，Status().KnownStores() 须与持久化 meta.stores 保持一致。
	v2 := newTestOfflineVault(t, dir, false)
	if err := secret.WithBytes([]byte("case-master"), func(pass *secret.SecretBox) error {
		return v2.Unlock(ctx, pass)
	}); err != nil {
		t.Fatalf("v2.Unlock 失败: %v", err)
	}
	st, err := v2.Status(ctx)
	if err != nil || !slices.Equal(st.KnownStores(), []string{"custom-a", "custom-b"}) {
		t.Fatalf("Unlock 后 KnownStores = %v (err=%v), 期望 [custom-a custom-b]", st.KnownStores(), err)
	}

	// 即使磁盘 vault.meta.json 已损坏，对已解锁 Vault 调用 Lock 仍须立即擦除内存 AEAD 句柄。
	if err := os.WriteFile(filepath.Join(dir, "vault.meta.json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatalf("破坏 vault.meta.json 失败: %v", err)
	}
	if err := v2.Lock(ctx); err != nil {
		t.Fatalf("已解锁态元数据损坏时 Lock 必须清空内存句柄并返回 nil，实际得到: %v", err)
	}
	if err := v2.WithSecret(ctx, refLower, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrVaultLocked) {
		t.Fatalf("Lock 后 WithSecret = %v, 期望 ErrVaultLocked", err)
	}
}

func putSecret(t *testing.T, v ports.SecretVault, ref secret.Ref, val string) {
	t.Helper()
	if err := secret.WithBytes([]byte(val), func(box *secret.SecretBox) error {
		return v.PutAndVerify(context.Background(), ref, box)
	}); err != nil {
		t.Fatalf("PutAndVerify(%s) 失败: %v", ref, err)
	}
}

func assertSecretEquals(t *testing.T, v ports.SecretVault, ref secret.Ref, want string) {
	t.Helper()
	err := secret.WithBytes([]byte(want), func(wantBox *secret.SecretBox) error {
		return v.WithSecret(context.Background(), ref, func(got *secret.SecretBox) error {
			if !got.Equal(wantBox) {
				t.Fatalf("条目 %s 回读明文与预期不匹配", ref)
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("WithSecret(%s) 失败: %v", ref, err)
	}
}
