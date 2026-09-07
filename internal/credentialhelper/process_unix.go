//go:build !windows

package credentialhelper

import (
	"os/exec"
	"syscall"
)

func configureProcessIsolation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// 向独立进程组发送 SIGKILL，确保包含所有子孙进程在内的整个进程树被安全终止
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
