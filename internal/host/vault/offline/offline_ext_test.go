package offline_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

func TestTCKOfflineVaultAndControl(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Run("SecretVaultTCK", func(t *testing.T) {
		tck.RunSecretVaultSuite(t, tck.SecretVaultFixture{
			NewVault: func(t *testing.T) ports.SecretVault {
				v := newTestOfflineVault(t, t.TempDir(), false)
				mustInitVault(t, v, "offline-master-pass")
				return v
			},
			NewLockedVault: func(t *testing.T) ports.SecretVault {
				v := newTestOfflineVault(t, t.TempDir(), false)
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
				return newTestOfflineVault(t, t.TempDir(), false)
			},
		})
	})
}

func TestOfflineVault_PersistenceTamperAndSubprocessKDF(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	dir := t.TempDir()
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
	itemPath := filepath.Join(dir, "items", "offline", "db-pass.enc")
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
