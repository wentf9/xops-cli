//go:build windows

package wincred_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/vault/wincred"
	"go.uber.org/goleak"
)

// TestWinCred_NativeSmoke 在真实 Windows Runner 上验证 Advapi32 CredWriteW/CredReadW/CredDeleteW 往返。
func TestWinCred_NativeSmoke(t *testing.T) {
	defer goleak.VerifyNone(t)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("rand.Read 失败: %v", err)
	}
	ref, err := secret.NewRef("xops-ci-smoke", "item-"+hex.EncodeToString(rnd[:]))
	if err != nil {
		t.Fatalf("NewRef 失败: %v", err)
	}
	st := wincred.NewStore()
	ctx := context.Background()
	t.Cleanup(func() { _ = st.Delete(context.Background(), ref) })

	err = secret.WithBytes([]byte("wincred-native-token"), func(box *secret.SecretBox) error {
		if pErr := st.PutAndVerify(ctx, ref, box); pErr != nil {
			if errors.Is(pErr, ports.ErrVaultLocked) || errors.Is(pErr, ports.ErrPermissionDenied) {
				t.Skipf("当前 Windows 会话无交互凭据管理器访问权限: %v", pErr)
			}
			return pErr
		}
		return st.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
			if !got.Equal(box) {
				t.Fatal("Windows Credential Manager 回读失配")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("Windows Credential Manager 往返失败: %v", err)
	}
	if err := st.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
}
