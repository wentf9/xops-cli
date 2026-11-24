package osfs_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

func TestTestFileExemptFromOSSymbolsButEnforcesRemotePath(t *testing.T) {
	// 测试文件允许直接构造临时目录、读取测试环境变量与执行对照命令。
	_, _ = os.Open("x")
	_ = os.Getenv("XOPS_DST_SEEDS")
	_ = exec.Command("ssh", "-G", "localhost")

	// 但对 RemotePath 禁调 path/filepath.* 在测试文件中仍 100% 强制。
	var rp pathalg.RemotePath
	_ = filepath.Join(rp.String(), "sub") // want "禁止对 RemotePath 调用 path/filepath"
}
