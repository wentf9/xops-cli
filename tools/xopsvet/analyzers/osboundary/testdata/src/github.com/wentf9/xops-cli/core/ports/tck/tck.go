package tck

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

// VerifyFS 演示测试契约夹具层（core/ports/tck）合法调用 OS/env/exec，同时仍禁止 RemotePath 使用 filepath。
func VerifyFS(t *testing.T, rp pathalg.RemotePath) {
	t.Helper()
	_, _ = os.Open(t.TempDir())
	_ = os.Getenv("XOPS_DST_SEEDS")
	_ = exec.Command("ssh", "-G", "example")
	_ = filepath.Join("/tmp", "local")
	_ = filepath.Join(rp.String(), "remote") // want "禁止对 RemotePath 调用 path/filepath"
}
