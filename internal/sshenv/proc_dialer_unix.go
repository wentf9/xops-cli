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
	process        *os.Process
	pgid           int // > 0 only when isolated with Setpgid: true (headless mode)
	foregroundTTY  bool
	groupSentinelR *os.File
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

func startPlatformShellCommand(command string, stdin io.Reader, stdout, stderr io.Writer, killTreeOnNormalExit bool) (*platformProc, *exec.Cmd, error) {
	shell := resolveUserShell(os.Getenv("SHELL"))
	cmd := exec.Command(shell, "-c", command)
	foregroundTTY := probeControllingTTY()
	var sentinelR, sentinelW *os.File
	if !foregroundTTY {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if killTreeOnNormalExit {
			r, w, err := os.Pipe()
			if err != nil {
				return nil, nil, fmt.Errorf("create ProxyCommand sentinel pipe: %w", err)
			}
			sentinelR = r
			sentinelW = w
			cmd.ExtraFiles = []*os.File{sentinelW}
		}
	}
	attachCommandIO(cmd, stdin, stdout, stderr)
	err := cmd.Start()
	if sentinelW != nil {
		_ = sentinelW.Close()
	}
	if err != nil {
		if sentinelR != nil {
			_ = sentinelR.Close()
		}
		return nil, nil, fmt.Errorf("start local shell command via %s: %w", shell, err)
	}
	pgid := 0
	if !foregroundTTY {
		pgid = cmd.Process.Pid
	}
	return &platformProc{
		process:        cmd.Process,
		pgid:           pgid,
		foregroundTTY:  foregroundTTY,
		groupSentinelR: sentinelR,
	}, cmd, nil
}

func (p *platformProc) detachSentinelPipe() *os.File {
	if p == nil {
		return nil
	}
	r := p.groupSentinelR
	p.groupSentinelR = nil
	return r
}

func pipeHasOpenWriter(f *os.File) bool {
	if f == nil {
		return false
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return false
	}
	hasWriter := false
	ctlErr := raw.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: 0}}
		for {
			_, pollErr := unix.Poll(fds, 0)
			if pollErr == unix.EINTR {
				continue
			}
			if pollErr != nil {
				return
			}
			hasWriter = fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) == 0
			return
		}
	})
	if ctlErr != nil {
		return false
	}
	return hasWriter
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
	if done != nil && isClosedChan(done) {
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
			if isClosedChan(done) {
				return
			}
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
		if isClosedChan(done) {
			return
		}
		_ = syscall.Kill(-p.pgid, syscall.SIGKILL)
		if p.process != nil {
			_ = p.process.Kill()
		}
	}
}

func activeProcessGroupWake(ch <-chan struct{}) <-chan struct{} {
	if ch != nil && isClosedChan(ch) {
		return nil
	}
	return ch
}

func waitProcessGroupExit(pgid int, termGrace time.Duration, stderrDone, sentinelDone <-chan struct{}) bool {
	watchStderr := activeProcessGroupWake(stderrDone)
	watchSentinel := activeProcessGroupWake(sentinelDone)
	timer := time.NewTimer(termGrace)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if syscall.Kill(-pgid, 0) != nil {
			return true
		}
		select {
		case <-watchStderr:
			watchStderr = nil
		case <-watchSentinel:
			watchSentinel = nil
		case <-ticker.C:
		case <-timer.C:
			return syscall.Kill(-pgid, 0) != nil
		}
	}
}

func (p *platformProc) reapRemainingGroup(termGrace time.Duration, stderrDone, sentinelDone <-chan struct{}, alreadyExited bool) {
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
	if termGrace > 0 && waitProcessGroupExit(p.pgid, termGrace, stderrDone, sentinelDone) {
		return
	}
	if syscall.Kill(-p.pgid, 0) == nil {
		_ = syscall.Kill(-p.pgid, syscall.SIGKILL)
	}
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
