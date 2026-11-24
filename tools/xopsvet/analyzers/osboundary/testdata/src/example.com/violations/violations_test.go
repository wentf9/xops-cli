package violations

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

func TestInternalTestFileExemptFromOSButNotRemotePath(t *testing.T) {
	_, _ = os.Open("fixture")
	_ = os.Getenv("XOPS_DST_SEEDS")
	_ = exec.Command("ssh", "-G", "localhost")

	var rp pathalg.RemotePath
	_ = filepath.Clean(rp.String()) // want "禁止对 RemotePath 调用 path/filepath"
}
