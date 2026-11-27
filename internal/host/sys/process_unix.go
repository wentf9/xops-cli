//go:build unix

package sys

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"golang.org/x/sys/unix"
)

// configureCmdPlatform 为 Unix 子进程启用独立进程组；当 bindCancel 为 true 时注册 ctx 取消回调，
// 在 cmd.Wait 回收 PID 之前安全整组终止，杜绝孤儿后代进程残留与 PID 复用误杀风险。
func configureCmdPlatform(cmd *exec.Cmd, bindCancel bool) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if !bindCancel {
		return
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL); err == nil || errors.Is(err, unix.ESRCH) {
			return nil
		}
		return cmd.Process.Kill()
	}
}

// attachRunCleanup 在 Unix Run 路径返回空操作：取消终止已由 cmd.Cancel 在 Wait 之前执行，
// 禁止在 cmd.Wait 已回收子进程 PID 之后再次按 -pid 发信号。
func attachRunCleanup(*exec.Cmd) func() {
	return func() {}
}

// attachDialCleanup 为 DialStdio 子进程提供幂等进程组终止钩子，由 processStdioConn.Close 在 Wait 之前调用。
func attachDialCleanup(cmd *exec.Cmd) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			if cmd.Process != nil {
				_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
			}
		})
	}
}

func exitStatusFromState(ps *os.ProcessState) (execution.ExitStatus, error) {
	if ps == nil {
		return execution.NewExitUnknown("process exit status unavailable"), nil
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		sigName := strings.TrimPrefix(strings.ToUpper(unix.SignalName(ws.Signal())), "SIG")
		if sigName == "" {
			sigName = "UNKNOWN"
		}
		return execution.NewExitSignal(sigName, ws.CoreDump(), "")
	}
	return execution.NewExitCode(int32(ps.ExitCode())), nil
}
