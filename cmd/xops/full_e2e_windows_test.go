//go:build windows

package main_test

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

func terminateChildOnEarlyFailure(_ *exec.Cmd, cancel context.CancelFunc) {
	cancel()
}

// stopChildAndVerifyShutdown 在 Windows 平台对子进程执行 TerminateProcess（模拟真实崩溃硬终止）后，
// 严格验证 ADR-008 跨进程崩溃对账契约：
//  1. 确认硬终止确实留下了死亡进程 .lock 文件；
//  2. 启动后续真实编译二进制执行 `xops audit reconcile --json`，验证启动期 O(1) 对账与 Windows 安全删锁成功；
//  3. 最终断言 ~/.xops/run 下零残留锁文件。
//
// 注：Windows 下优雅 ctx 取消（等价 Console CTRL_C_EVENT）逆序停机与零残留锁由
// graceful_shutdown_test.go 中的 TestGracefulCancel_MCPHTTPAndTunnelZeroRemainingLocks 同步严格验证。
func stopChildAndVerifyShutdown(
	t *testing.T,
	binPath string,
	env []string,
	xopsHome pathalg.LocalDir,
	cmd *exec.Cmd,
	cancel context.CancelFunc,
	label string,
	_ func() string,
) {
	t.Helper()
	cancel()
	_ = cmd.Wait()

	if countRemainingLocks(t, xopsHome) == 0 {
		t.Fatalf("%s Windows TerminateProcess 硬终止后应遗留死亡锁文件供对账验证", label)
	}
	stdout, stderr, code, err := runCompiledXops(binPath, env, nil, "audit", "reconcile", "--json")
	if err != nil || code != 0 {
		t.Fatalf("%s 硬终止后执行 audit reconcile 失败: code=%d err=%v stdout=%q stderr=%q", label, code, err, stdout, stderr)
	}
	assertNoRemainingLocks(t, xopsHome)
}

func countRemainingLocks(t *testing.T, xopsHome pathalg.LocalDir) int {
	t.Helper()
	rootFS := osfs.NewScopedRootFS()
	runDirDest, _ := pathalg.ParseLocalRootedDest("run")
	count := 0
	err := rootFS.WithRoot(xopsHome, func(root ports.RootHandle) error {
		entries, rErr := root.ReadDir(algebraic.Some(runDirDest))
		if rErr != nil {
			return rErr
		}
		count = len(entries)
		return nil
	})
	if err != nil && !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("扫描 run 锁目录失败: %v", err)
	}
	return count
}
