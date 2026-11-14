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

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const fallbackPosixShell = "/bin/sh"

var (
	probeControllingTTY      = defaultHasControllingTTY
	onUnixReapRemainingGroup func(pgid int)
)

type platformProc struct {
	process       *os.Process
	pgid          int // > 0 only when isolated with Setpgid: true (headless mode)
	foregroundTTY bool
}

// defaultHasControllingTTY reports whether the current process is attached to a
// controlling terminal in its foreground process group. Matching OpenSSH
// ssh_proxy_connect, foreground TTY invocations keep ProxyCommand / LocalCommand
// in the caller's process group so /dev/tty prompts and tcsetattr succeed
// without SIGTTIN / SIGTTOU stops, whereas headless invocations isolate the
// child in its own process group.
func defaultHasControllingTTY() bool {
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err == nil {
		fgPGID, pgrpErr := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		_ = unix.Close(fd)
		return pgrpErr == nil && fgPGID > 0 && fgPGID == unix.Getpgrp()
	}
	return isForegroundTerminalFD(int(os.Stdin.Fd())) || isForegroundTerminalFD(int(os.Stderr.Fd()))
}

func isForegroundTerminalFD(fd int) bool {
	if !term.IsTerminal(fd) {
		return false
	}
	fgPGID, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	return err == nil && fgPGID > 0 && fgPGID == unix.Getpgrp()
}

func startPlatformShellCommand(command string, stdin io.Reader, stdout, stderr io.Writer) (*platformProc, *exec.Cmd, error) {
	shell := resolveUserShell(os.Getenv("SHELL"))
	cmd := exec.Command(shell, "-c", command)
	foregroundTTY := probeControllingTTY()
	if !foregroundTTY {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	attachCommandIO(cmd, stdin, stdout, stderr)
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start local shell command via %s: %w", shell, err)
	}
	pgid := 0
	if !foregroundTTY {
		pgid = cmd.Process.Pid
	}
	return &platformProc{
		process:       cmd.Process,
		pgid:          pgid,
		foregroundTTY: foregroundTTY,
	}, cmd, nil
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
	if p == nil {
		return
	}
	if p.foregroundTTY || p.pgid <= 0 {
		if p.process == nil {
			return
		}
		_ = p.process.Signal(syscall.SIGHUP)
		_ = p.process.Signal(syscall.SIGTERM)
		if done == nil {
			return
		}
		timer := time.NewTimer(termGrace)
		defer timer.Stop()
		select {
		case <-done:
			return
		case <-timer.C:
			_ = p.process.Kill()
		}
		return
	}

	_ = syscall.Kill(-p.pgid, syscall.SIGTERM)
	if p.process != nil {
		_ = p.process.Signal(syscall.SIGTERM)
	}
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
		if p.process != nil {
			_ = p.process.Kill()
		}
	}
}

func (p *platformProc) reapRemainingGroup(termGrace time.Duration, stderrDone <-chan struct{}, alreadyExited bool) {
	if p == nil || p.foregroundTTY || p.pgid <= 0 || alreadyExited {
		return
	}
	if hook := onUnixReapRemainingGroup; hook != nil {
		hook(p.pgid)
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

func (p *platformProc) cleanupAfterWait(canceled bool) {
	if p == nil || p.foregroundTTY || p.pgid <= 0 || !canceled {
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
