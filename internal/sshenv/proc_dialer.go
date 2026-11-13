package sshenv

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	proxyCloseGracePeriod = 200 * time.Millisecond
	proxyTermGracePeriod  = 100 * time.Millisecond
	stderrLineChunkSize   = 4096
)

type processAddr string

func (processAddr) Network() string  { return "stdio" }
func (a processAddr) String() string { return string(a) }

// ProcessStdioConn wraps a localProxyCommand child process's stdin and stdout pipes
// as a net.Conn while isolating stderr onto a bounded background forwarder and ensuring
// idempotent process-group / Job-Object cleanup on Close.
type ProcessStdioConn struct {
	stdinW  *os.File
	stdoutR *os.File
	stderrR *os.File

	proc       *platformProc
	waitDone   chan struct{}
	stderrDone chan struct{}

	mu            sync.Mutex
	closed        bool
	readTimer     *time.Timer
	writeTimer    *time.Timer
	readTimedOut  bool
	writeTimedOut bool

	closeOnce sync.Once
	closeErr  error
	remote    processAddr
}

var _ net.Conn = (*ProcessStdioConn)(nil)

// DefaultDialProxyCommand spawns command under the platform shell ($SHELL -c on Unix,
// cmd.exe /d /s /c on Windows) in an isolated process group / Job Object, wrapping only
// stdin/stdout as a net.Conn and forwarding stderr lines to os.Stderr.
func DefaultDialProxyCommand(ctx context.Context, command string) (net.Conn, error) {
	return DialProxyCommandWithStderr(ctx, command, os.Stderr)
}

// DialProxyCommandWithStderr behaves like DefaultDialProxyCommand with a caller-supplied
// writer for child stderr diagnostics (or io.Discard when stderr is nil).
func DialProxyCommandWithStderr(ctx context.Context, command string, stderr io.Writer) (net.Conn, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if err := validateExecCommandString(command); err != nil {
		return nil, err
	}
	if stderr == nil {
		stderr = io.Discard
	}

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create ProxyCommand stdin pipe: %w", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		return nil, fmt.Errorf("create ProxyCommand stdout pipe: %w", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		return nil, fmt.Errorf("create ProxyCommand stderr pipe: %w", err)
	}

	proc, cmd, err := startPlatformShellCommand(command, stdinR, stdoutW, stderrW)
	// Always close child-side pipe ends in the parent immediately after Start (or on error).
	_ = stdinR.Close()
	_ = stdoutW.Close()
	_ = stderrW.Close()
	if err != nil {
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stderrR.Close()
		return nil, err
	}

	conn := &ProcessStdioConn{
		stdinW:     stdinW,
		stdoutR:    stdoutR,
		stderrR:    stderrR,
		proc:       proc,
		waitDone:   make(chan struct{}),
		stderrDone: make(chan struct{}),
		remote:     processAddr("0.0.0.0:0"),
	}

	go func() {
		defer close(conn.waitDone)
		_ = cmd.Wait()
	}()
	go func() {
		defer close(conn.stderrDone)
		forwardStderrLines(stderrR, stderr)
	}()

	if ctx != nil {
		if err := ctx.Err(); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// DefaultRunLocalCommand executes command locally with stdin bound to os.DevNull and
// stdout/stderr connected to os.Stdout/os.Stderr inside an isolated process group / Job Object.
func DefaultRunLocalCommand(ctx context.Context, command string) error {
	return RunLocalCommandWithIO(ctx, command, os.Stdout, os.Stderr)
}

// RunLocalCommandWithIO executes command locally with stdin bound to os.DevNull and
// stdout/stderr connected to the supplied writers inside an isolated process group / Job Object.
func RunLocalCommandWithIO(ctx context.Context, command string, stdout, stderr io.Writer) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if err := validateExecCommandString(command); err != nil {
		return err
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("open %s for LocalCommand stdin: %w", os.DevNull, err)
	}
	proc, cmd, err := startPlatformShellCommand(command, devNull, stdout, stderr)
	_ = devNull.Close()
	if err != nil {
		return err
	}

	waitDone := make(chan struct{})
	var waitErr error
	go func() {
		defer close(waitDone)
		waitErr = cmd.Wait()
	}()

	var stopCancel func() bool
	var cancelDone chan struct{}
	if ctx != nil {
		cancelDone = make(chan struct{})
		stopCancel = context.AfterFunc(ctx, func() {
			defer close(cancelDone)
			proc.terminateTree(proxyTermGracePeriod, waitDone)
		})
	}
	<-waitDone
	if stopCancel != nil && !stopCancel() {
		<-cancelDone
	}
	proc.cleanupAfterWait()

	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return waitErr
}

func validateExecCommandString(command string) error {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" || strings.EqualFold(trimmed, "none") {
		return errors.New("local execution command cannot be empty")
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if c == 0 || (c < 0x20 && c != '\t') || c == 0x7f {
			return errors.New("local execution command contains disallowed control characters")
		}
	}
	return nil
}

func forwardStderrLines(r io.Reader, dst io.Writer) {
	reader := bufio.NewReaderSize(r, stderrLineChunkSize)
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(chunk) > 0 {
			_, _ = dst.Write(chunk)
		}
		if err == nil || errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return
	}
}

func (c *ProcessStdioConn) Read(b []byte) (int, error) {
	n, err := c.stdoutR.Read(b)
	if err != nil {
		return n, c.normalizeIOError(err, true)
	}
	return n, nil
}

func (c *ProcessStdioConn) Write(b []byte) (int, error) {
	n, err := c.stdinW.Write(b)
	if err != nil {
		return n, c.normalizeIOError(err, false)
	}
	return n, nil
}

func (c *ProcessStdioConn) normalizeIOError(err error, isRead bool) error {
	c.mu.Lock()
	timedOut := c.writeTimedOut
	if isRead {
		timedOut = c.readTimedOut
	}
	closed := c.closed
	c.mu.Unlock()

	if timedOut {
		return os.ErrDeadlineExceeded
	}
	if closed && errors.Is(err, os.ErrClosed) {
		return net.ErrClosed
	}
	return err
}

func (c *ProcessStdioConn) LocalAddr() net.Addr  { return processAddr("127.0.0.1:0") }
func (c *ProcessStdioConn) RemoteAddr() net.Addr { return c.remote }

func (c *ProcessStdioConn) SetDeadline(t time.Time) error {
	readErr := c.SetReadDeadline(t)
	writeErr := c.SetWriteDeadline(t)
	return errors.Join(readErr, writeErr)
}

func (c *ProcessStdioConn) SetReadDeadline(t time.Time) error {
	return c.setPipeDeadline(c.stdoutR, t, true)
}

func (c *ProcessStdioConn) SetWriteDeadline(t time.Time) error {
	return c.setPipeDeadline(c.stdinW, t, false)
}

func (c *ProcessStdioConn) setPipeDeadline(f *os.File, t time.Time, isRead bool) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.stopTimerLocked(isRead)
	c.mu.Unlock()

	var err error
	if isRead {
		err = f.SetReadDeadline(t)
	} else {
		err = f.SetWriteDeadline(t)
	}
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNoDeadline) {
		if errors.Is(err, os.ErrClosed) {
			return net.ErrClosed
		}
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		c.markTimedOutLocked(isRead)
		_ = f.Close()
		return nil
	}
	timer := time.AfterFunc(d, func() {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.markTimedOutLocked(isRead)
		c.mu.Unlock()
		_ = f.Close()
	})
	if isRead {
		c.readTimer = timer
	} else {
		c.writeTimer = timer
	}
	return nil
}

func (c *ProcessStdioConn) stopTimerLocked(isRead bool) {
	if isRead {
		if c.readTimer != nil {
			c.readTimer.Stop()
			c.readTimer = nil
		}
		c.readTimedOut = false
		return
	}
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	c.writeTimedOut = false
}

func (c *ProcessStdioConn) markTimedOutLocked(isRead bool) {
	if isRead {
		c.readTimedOut = true
		return
	}
	c.writeTimedOut = true
}

// Close idempotently closes the child's stdin/stdout pipes, waits up to 200ms for
// graceful EOF exit, terminates the entire process group / Job Object if still alive,
// and joins both the stderr forwarder and cmd.Wait() so no zombies or goroutines leak.
func (c *ProcessStdioConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.stopTimerLocked(true)
		c.stopTimerLocked(false)
		c.mu.Unlock()

		var errs []error
		if err := c.stdinW.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			errs = append(errs, err)
		}
		if err := c.stdoutR.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			errs = append(errs, err)
		}

		graceTimer := time.NewTimer(proxyCloseGracePeriod)
		select {
		case <-c.waitDone:
			graceTimer.Stop()
		case <-graceTimer.C:
			c.proc.terminateTree(proxyTermGracePeriod, c.waitDone)
		}

		<-c.waitDone
		c.proc.reapRemainingGroup(proxyTermGracePeriod, c.stderrDone)
		_ = c.stderrR.Close()
		<-c.stderrDone

		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

func attachCommandIO(cmd *exec.Cmd, stdin io.Reader, stdout, stderr io.Writer) {
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
}
