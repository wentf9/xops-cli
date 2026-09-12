//go:build !windows

package credentialhelper

import (
	"context"
	"os/exec"
	"syscall"
)

type processSession struct {
	cmd  *exec.Cmd
	pgid int
}

func startProcessSession(_ context.Context, cmd *exec.Cmd) (*processSession, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true

	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// 向独立进程组发送 SIGKILL，确保包含所有子孙进程在内的整个进程树被安全终止
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return &processSession{
		cmd:  cmd,
		pgid: cmd.Process.Pid,
	}, nil
}

func (s *processSession) KillTree() error {
	if s == nil || s.pgid <= 0 {
		return nil
	}
	return syscall.Kill(-s.pgid, syscall.SIGKILL)
}

func (s *processSession) Close() error {
	if s == nil {
		return nil
	}
	return s.KillTree()
}
