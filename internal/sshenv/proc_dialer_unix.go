//go:build !windows

package sshenv

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const fallbackPosixShell = "/bin/sh"

type platformProc struct {
	pgid int
}

func startPlatformShellCommand(command string, stdin io.Reader, stdout, stderr io.Writer) (*platformProc, *exec.Cmd, error) {
	shell := resolveUserShell(os.Getenv("SHELL"))
	cmd := exec.Command(shell, "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	attachCommandIO(cmd, stdin, stdout, stderr)
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start local shell command via %s: %w", shell, err)
	}
	return &platformProc{pgid: cmd.Process.Pid}, cmd, nil
}

func resolveUserShell(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsRune(trimmed, 0) || !filepath.IsAbs(trimmed) {
		return fallbackPosixShell
	}
	info, err := os.Stat(trimmed)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return fallbackPosixShell
	}
	return trimmed
}

func (p *platformProc) terminateTree(termGrace time.Duration, done <-chan struct{}) {
	if p == nil || p.pgid <= 0 {
		return
	}
	_ = syscall.Kill(-p.pgid, syscall.SIGTERM)
	if done == nil {
		return
	}
	timer := time.NewTimer(termGrace)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		_ = syscall.Kill(-p.pgid, syscall.SIGKILL)
	}
}

func (p *platformProc) reapRemainingGroup(termGrace time.Duration, stderrDone <-chan struct{}) {
	if p == nil || p.pgid <= 0 {
		return
	}
	if syscall.Kill(-p.pgid, 0) != nil {
		return
	}
	_ = syscall.Kill(-p.pgid, syscall.SIGTERM)
	if stderrDone != nil {
		timer := time.NewTimer(termGrace)
		select {
		case <-stderrDone:
			timer.Stop()
			if syscall.Kill(-p.pgid, 0) == nil {
				_ = syscall.Kill(-p.pgid, syscall.SIGKILL)
			}
			return
		case <-timer.C:
		}
	}
	_ = syscall.Kill(-p.pgid, syscall.SIGKILL)
}

func (p *platformProc) cleanupAfterWait() {
	if p == nil || p.pgid <= 0 {
		return
	}
	if syscall.Kill(-p.pgid, 0) == nil {
		_ = syscall.Kill(-p.pgid, syscall.SIGTERM)
		time.Sleep(10 * time.Millisecond)
		if syscall.Kill(-p.pgid, 0) == nil {
			_ = syscall.Kill(-p.pgid, syscall.SIGKILL)
		}
	}
}
