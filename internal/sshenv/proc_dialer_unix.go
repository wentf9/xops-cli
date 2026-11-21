//go:build !windows

package sshenv

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const fallbackPosixShell = "/bin/sh"

func init() {
	probeControllingTTY = defaultHasControllingTTY
}

type platformProc struct {
	process        *os.Process
	pgid           int // > 0 only when isolated with Setpgid: true (headless mode)
	foregroundTTY  bool
	reapMu         sync.Mutex
	reaped         bool
	groupSentinelR *os.File
	sentinelProbe  *os.File
	sentinelDone   <-chan struct{}
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

func startPlatformShellCommand(command string, stdin io.Reader, stdout, stderr io.Writer, _ bool) (*platformProc, *exec.Cmd, error) {
	shell := resolveUserShell(os.Getenv("SHELL"))
	cmd := exec.Command(shell, "-c", command)
	foregroundTTY := probeControllingTTY()
	var sentinelR, sentinelW *os.File
	if !foregroundTTY {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		r, w, err := os.Pipe()
		if err != nil {
			return nil, nil, fmt.Errorf("create process group sentinel pipe: %w", err)
		}
		sentinelR = r
		sentinelW = w
		cmd.ExtraFiles = []*os.File{sentinelW}
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
		sentinelProbe:  sentinelR,
	}, cmd, nil
}

func (p *platformProc) detachSentinelPipe() *os.File {
	if p == nil {
		return nil
	}
	p.reapMu.Lock()
	r := p.groupSentinelR
	p.groupSentinelR = nil
	p.sentinelProbe = nil
	p.reapMu.Unlock()
	return r
}

func (p *platformProc) markReaped() {
	if p == nil {
		return
	}
	p.reapMu.Lock()
	p.reaped = true
	p.reapMu.Unlock()
}

func (p *platformProc) bindSentinelObserver(sentinelR *os.File, sentinelDone <-chan struct{}) {
	if p == nil {
		return
	}
	p.reapMu.Lock()
	p.sentinelProbe = sentinelR
	p.sentinelDone = sentinelDone
	p.reapMu.Unlock()
}

func (p *platformProc) clearSentinelObserver() {
	if p == nil {
		return
	}
	p.reapMu.Lock()
	p.sentinelProbe = nil
	p.reapMu.Unlock()
}

func (p *platformProc) sentinelClosedLocked() bool {
	if p.sentinelDone != nil && isClosedChan(p.sentinelDone) {
		return true
	}
	if p.sentinelProbe != nil && !pipeHasOpenWriter(p.sentinelProbe) {
		return true
	}
	return false
}

func (p *platformProc) isReapedOrDone(done <-chan struct{}) bool {
	p.reapMu.Lock()
	reaped := p.reaped
	p.reapMu.Unlock()
	return reaped || (done != nil && isClosedChan(done))
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
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for {
			fds[0].Revents = 0
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

func (p *platformProc) signalForeground(done <-chan struct{}, signals ...syscall.Signal) bool {
	p.reapMu.Lock()
	defer p.reapMu.Unlock()
	if p.reaped || (done != nil && isClosedChan(done)) {
		return true
	}
	if p.process == nil {
		return true
	}
	for _, sig := range signals {
		if sig == syscall.SIGKILL {
			_ = p.process.Kill()
		} else {
			_ = p.process.Signal(sig)
		}
	}
	return false
}

func (p *platformProc) signalGroup(sig syscall.Signal, done <-chan struct{}) bool {
	p.reapMu.Lock()
	defer p.reapMu.Unlock()
	if p.reaped || (done != nil && isClosedChan(done)) {
		return true
	}
	if !p.sentinelClosedLocked() {
		_ = syscall.Kill(-p.pgid, sig)
	}
	if p.process != nil {
		if sig == syscall.SIGKILL {
			_ = p.process.Kill()
		} else {
			_ = p.process.Signal(sig)
		}
	}
	return false
}

func (p *platformProc) terminateTree(termGrace time.Duration, done <-chan struct{}) {
	if p == nil || p.isReapedOrDone(done) {
		return
	}
	if p.foregroundTTY || p.pgid <= 0 {
		if p.signalForeground(done, syscall.SIGHUP, syscall.SIGTERM) {
			return
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
			p.signalForeground(done, syscall.SIGKILL)
		}
		return
	}

	if p.signalGroup(syscall.SIGTERM, done) {
		return
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
		p.signalGroup(syscall.SIGKILL, done)
	}
}

func activeProcessGroupWake(ch <-chan struct{}) <-chan struct{} {
	if ch != nil && isClosedChan(ch) {
		return nil
	}
	return ch
}

func groupPipesClosed(stderrDone, sentinelDone <-chan struct{}) bool {
	return isClosedChan(stderrDone) && (sentinelDone == nil || isClosedChan(sentinelDone))
}

func waitProcessGroupExit(pgid int, termGrace time.Duration, stderrDone, sentinelDone <-chan struct{}) bool {
	hasPipeWatch := stderrDone != nil || sentinelDone != nil
	watchStderr := activeProcessGroupWake(stderrDone)
	watchSentinel := activeProcessGroupWake(sentinelDone)
	if hasPipeWatch && watchStderr == nil && watchSentinel == nil {
		return true
	}
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
			if watchSentinel == nil {
				return true
			}
		case <-watchSentinel:
			watchSentinel = nil
			if watchStderr == nil {
				return true
			}
		case <-ticker.C:
		case <-timer.C:
			if hasPipeWatch && (stderrDone == nil || isClosedChan(stderrDone)) && (sentinelDone == nil || isClosedChan(sentinelDone)) {
				return true
			}
			return syscall.Kill(-pgid, 0) != nil
		}
	}
}

func (p *platformProc) reapRemainingGroup(termGrace time.Duration, stderrDone, sentinelDone <-chan struct{}, alreadyExited bool) {
	if p == nil || p.foregroundTTY || p.pgid <= 0 || alreadyExited {
		return
	}
	if groupPipesClosed(stderrDone, sentinelDone) {
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
	if groupPipesClosed(stderrDone, sentinelDone) {
		return
	}
	if syscall.Kill(-p.pgid, 0) == nil {
		_ = syscall.Kill(-p.pgid, syscall.SIGKILL)
	}
}

func (p *platformProc) cleanupAfterWait(canceled bool) {
	if p == nil {
		return
	}
	sentinelR := p.detachSentinelPipe()
	if sentinelR != nil {
		defer func() { _ = sentinelR.Close() }()
	}
	if p.foregroundTTY || p.pgid <= 0 || !canceled {
		return
	}
	if sentinelR != nil && !pipeHasOpenWriter(sentinelR) {
		return
	}
	if hook := onUnixReapRemainingGroup; hook != nil {
		hook(p.pgid)
	}
	if syscall.Kill(-p.pgid, 0) == nil {
		_ = syscall.Kill(-p.pgid, syscall.SIGTERM)
		deadline := time.Now().Add(10 * time.Millisecond)
		for time.Now().Before(deadline) {
			if (sentinelR != nil && !pipeHasOpenWriter(sentinelR)) || syscall.Kill(-p.pgid, 0) != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
		if (sentinelR == nil || pipeHasOpenWriter(sentinelR)) && syscall.Kill(-p.pgid, 0) == nil {
			_ = syscall.Kill(-p.pgid, syscall.SIGKILL)
		}
	}
}
