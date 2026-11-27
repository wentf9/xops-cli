package cmdssh

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

func TestCleanupAndPostAnnounceErrorHelpers(t *testing.T) {
	defer goleak.VerifyNone(t)

	var stdout, stderr bytes.Buffer
	rt := &clikit.Runtime{Stdout: &stdout, Stderr: &stderr}

	// 1) reportCleanupError 在退出码为 0 时提升为 ExitGeneral，且不覆盖既有非零业务码。
	code := clikit.ExitOK
	reportCleanupError(rt, errors.New("stop-failed"), &code)
	if code != clikit.ExitGeneral || !strings.Contains(stderr.String(), "stop-failed") {
		t.Fatalf("清理失败必须提升退出码并写 stderr: code=%d stderr=%q", code, stderr.String())
	}
	code2 := clikit.ExitSSHError
	reportCleanupError(rt, errors.New("stop-failed-2"), &code2)
	if code2 != clikit.ExitSSHError {
		t.Fatalf("既有非零业务退出码不得被覆盖: code=%d", code2)
	}

	// 2) failAfterAnnounce 在 JSON 模式下绝不向 stdout 追加第二个 JSON 文档，仅写 stderr 并返回 ExitSSHError。
	stdout.Reset()
	stderr.Reset()
	if c := failAfterAnnounce(rt, true, errors.New("forward dropped")); c != clikit.ExitSSHError {
		t.Fatalf("failAfterAnnounce 应返回 ExitSSHError，实际=%d", c)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "forward dropped") {
		t.Fatalf("JSON 模式下 post-announce 错误不得污染 stdout: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
