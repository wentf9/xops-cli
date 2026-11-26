package helper_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"github.com/wentf9/xops-cli/internal/host/vault/helper"
	"go.uber.org/goleak"
	"golang.org/x/crypto/argon2"
)

// 编译期接口契约断言。
var _ ports.SecretVault = (*helper.HelperVault)(nil)

const (
	helperModeEnv = "XOPS_VAULT_HELPER_TEST_MODE"
	helperDirEnv  = "XOPS_VAULT_HELPER_TEST_DIR"
)

type mockHelperReq struct {
	ProtocolVersion int    `json:"protocol_version"`
	NonInteractive  bool   `json:"non_interactive"`
	Action          string `json:"action"`
	Store           string `json:"store"`
	Item            string `json:"item"`
	SecretB64       string `json:"secret_b64,omitzero"`
}

type mockHelperResp struct {
	SecretB64 *string `json:"secret_b64,omitzero"`
	Code      string  `json:"code,omitzero"`
}

// TestVaultHelperSubprocess 为跨平台外部凭据助手与隔离 KDF 子进程提供自托管测试入口。
func TestVaultHelperSubprocess(t *testing.T) {
	mode := os.Getenv(helperModeEnv)
	if mode == "" {
		return
	}
	switch mode {
	case "kdf":
		if err := helper.ServeArgon2idWorker(os.Stdin, os.Stdout); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "locked":
		writeJSONExit(mockHelperResp{Code: "locked"}, 1)
	case "drop-write":
		runMockHelperDropWrite()
	case "store":
		runMockHelperStore(os.Getenv(helperDirEnv))
	default:
		os.Exit(3)
	}
}

func runMockHelperDropWrite() {
	raw, _ := io.ReadAll(os.Stdin)
	var req mockHelperReq
	_ = jsonv2.Unmarshal(raw, &req)
	if req.Action == "store" {
		writeJSONExit(mockHelperResp{Code: "ok"}, 0)
	}
	writeJSONExit(mockHelperResp{Code: "not-found"}, 1)
}

func runMockHelperStore(dir string) {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(4)
	}
	var req mockHelperReq
	if err := jsonv2.Unmarshal(raw, &req, jsonv2.RejectUnknownMembers(true)); err != nil || req.ProtocolVersion != helper.ProtocolVersion {
		writeJSONExit(mockHelperResp{Code: "invalid"}, 1)
	}
	p := filepath.Join(dir, req.Store+"__"+req.Item+".txt")
	switch req.Action {
	case "get":
		data, rErr := os.ReadFile(p)
		if errors.Is(rErr, os.ErrNotExist) {
			writeJSONExit(mockHelperResp{Code: "not-found"}, 1)
		}
		if rErr != nil {
			writeJSONExit(mockHelperResp{Code: "unavailable"}, 1)
		}
		val := string(data)
		writeJSONExit(mockHelperResp{SecretB64: &val}, 0)
	case "store":
		if wErr := os.WriteFile(p, []byte(req.SecretB64), 0o600); wErr != nil {
			writeJSONExit(mockHelperResp{Code: "unavailable"}, 1)
		}
		writeJSONExit(mockHelperResp{Code: "ok"}, 0)
	case "erase":
		if rmErr := os.Remove(p); errors.Is(rmErr, os.ErrNotExist) {
			writeJSONExit(mockHelperResp{Code: "not-found"}, 1)
		} else if rmErr != nil {
			writeJSONExit(mockHelperResp{Code: "unavailable"}, 1)
		}
		writeJSONExit(mockHelperResp{Code: "ok"}, 0)
	default:
		writeJSONExit(mockHelperResp{Code: "invalid"}, 1)
	}
}

func writeJSONExit(resp mockHelperResp, code int) {
	b, _ := jsonv2.Marshal(resp)
	_, _ = os.Stdout.Write(b)
	os.Exit(code)
}

func newTestHelperVault(t *testing.T, mode, dir string, readOnly bool) *helper.HelperVault {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable 失败: %v", err)
	}
	v, err := helper.NewHelperVault(helper.HelperSpec{
		Process:  sys.NewSystemProcess(),
		Command:  exe,
		Args:     []string{"-test.run=^TestVaultHelperSubprocess$"},
		Env:      map[string]string{helperModeEnv: mode, helperDirEnv: dir},
		ReadOnly: readOnly,
	})
	if err != nil {
		t.Fatalf("NewHelperVault 失败: %v", err)
	}
	return v
}

func TestTCKSecretVault_ExternalHelper(t *testing.T) {
	defer goleak.VerifyNone(t)
	tck.RunSecretVaultSuite(t, tck.SecretVaultFixture{
		NewVault: func(t *testing.T) ports.SecretVault {
			return newTestHelperVault(t, "store", t.TempDir(), false)
		},
		NewLockedVault: func(t *testing.T) ports.SecretVault {
			return newTestHelperVault(t, "locked", t.TempDir(), false)
		},
	})
}

func TestHelperVault_ReadOnlyAndZeroValue(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zero helper.HelperVault
	ref := tck.MustRef(t, "ext", "item1")
	if err := zero.WithSecret(context.Background(), ref, func(*secret.SecretBox) error { return nil }); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 WithSecret = %v, 期望 ErrInvalidArgument", err)
	}
	ro := newTestHelperVault(t, "store", t.TempDir(), true)
	if err := ro.Delete(context.Background(), ref); !errors.Is(err, ports.ErrPermissionDenied) {
		t.Fatalf("只读 Delete = %v, 期望 ErrPermissionDenied", err)
	}
	err := secret.WithBytes([]byte("secret-ro"), func(box *secret.SecretBox) error {
		if pErr := ro.PutAndVerify(context.Background(), ref, box); !errors.Is(pErr, ports.ErrPermissionDenied) {
			t.Fatalf("只读 PutAndVerify = %v, 期望 ErrPermissionDenied", pErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytes 失败: %v", err)
	}
}

func TestDeriveArgon2idSubprocess_MatchesInProcess(t *testing.T) {
	defer goleak.VerifyNone(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable 失败: %v", err)
	}
	spec, err := ports.NewProcessSpec(ports.ProcessSpecInput{
		Command:        exe,
		Args:           []string{"-test.run=^TestVaultHelperSubprocess$"},
		Env:            map[string]string{helperModeEnv: "kdf"},
		MaxOutputBytes: algebraic.Some(uint64(256)),
	})
	if err != nil {
		t.Fatalf("NewProcessSpec 失败: %v", err)
	}
	params, err := helper.NewArgon2idParams(1, 1024, 1)
	if err != nil {
		t.Fatalf("NewArgon2idParams 失败: %v", err)
	}
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	want := argon2.IDKey([]byte("master-pass-v2"), salt[:], params.TimeCost(), params.MemoryKiB(), params.Threads(), 32)
	var got [32]byte
	err = secret.WithBytes([]byte("master-pass-v2"), func(pass *secret.SecretBox) error {
		var dErr error
		got, dErr = helper.DeriveArgon2idSubprocess(context.Background(), sys.NewSystemProcess(), spec, params, salt, pass)
		return dErr
	})
	if err != nil {
		t.Fatalf("DeriveArgon2idSubprocess 失败: %v", err)
	}
	if string(got[:]) != string(want) {
		t.Fatal("子进程 Argon2id 派生密钥与本地标准计算结果不一致")
	}
}

// TestHelperVault_EmptySecretVerifyFailAndKDFReservedHeader 回归验证空凭据存取、回读丢写归一化及 KDF 保留字节校验。
func TestHelperVault_EmptySecretVerifyFailAndKDFReservedHeader(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	ref := tck.MustRef(t, "ext", "empty-item")

	// 1. 空凭据 []byte{} 写入与回读不能与 ErrSecretNotFound 混淆。
	st := newTestHelperVault(t, "store", t.TempDir(), false)
	if err := secret.WithBytes([]byte{}, func(emptyBox *secret.SecretBox) error {
		if err := st.PutAndVerify(ctx, ref, emptyBox); err != nil {
			return err
		}
		return st.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
			if !got.IsValid() || got.Len() != 0 || !got.Equal(emptyBox) {
				t.Fatalf("空凭据回读异常: valid=%v len=%d", got.IsValid(), got.Len())
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("空凭据 PutAndVerify/WithSecret 失败: %v", err)
	}

	// 2. 助手静默丢写导致回读 ErrSecretNotFound 时，PutAndVerify 须包装返回 ErrSecretVerifyFailed。
	dropper := newTestHelperVault(t, "drop-write", t.TempDir(), false)
	err := secret.WithBytes([]byte("lost-secret"), func(box *secret.SecretBox) error {
		return dropper.PutAndVerify(ctx, ref, box)
	})
	if !errors.Is(err, ports.ErrSecretVerifyFailed) {
		t.Fatalf("丢写助手 PutAndVerify = %v, 期望 ErrSecretVerifyFailed", err)
	}

	// 3. KDF Worker 须拒绝保留字节 b[42:44] 非零的畸形帧。
	badFrame := make([]byte, 48)
	copy(badFrame[0:8], "XOPSKDF2")
	badFrame[9] = 2
	badFrame[13] = 48
	badFrame[17] = 1
	badFrame[21] = 64
	badFrame[22] = 1
	badFrame[23] = 32
	badFrame[41] = 4
	badFrame[42] = 1 // 非法非零保留字节
	var respBuf bytes.Buffer
	if err := helper.ServeArgon2idWorker(bytes.NewReader(badFrame), &respBuf); err != nil {
		t.Fatalf("ServeArgon2idWorker 写入错误帧失败: %v", err)
	}
	if respBuf.Len() < 15 || respBuf.Bytes()[14] == 0 {
		t.Fatalf("非零保留字节帧须返回非零错误状态，实际输出长度=%d", respBuf.Len())
	}
}
