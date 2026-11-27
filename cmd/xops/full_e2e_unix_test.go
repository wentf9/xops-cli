//go:build !windows

package main_test

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

func terminateChildOnEarlyFailure(cmd *exec.Cmd, cancel context.CancelFunc) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
		return
	}
	cancel()
}

// stopChildAndVerifyShutdown 在 Unix 平台发送 SIGINT 触发优雅逆序停机，
// 严格断言子进程退出码为 0 且 ~/.xops/run 下零残留锁文件。
func stopChildAndVerifyShutdown(
	t *testing.T,
	_ string,
	_ []string,
	xopsHome pathalg.LocalDir,
	cmd *exec.Cmd,
	cancel context.CancelFunc,
	label string,
	readStderr func() string,
) {
	t.Helper()
	if cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	} else {
		cancel()
	}
	if err := cmd.Wait(); err != nil {
		stderrText := ""
		if readStderr != nil {
			stderrText = readStderr()
		}
		t.Fatalf("%s 收到 SIGINT 期望退出码 0，实际=%v stderr=%q", label, err, stderrText)
	}
	assertNoRemainingLocks(t, xopsHome)
}
