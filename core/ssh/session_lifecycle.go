package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// sessionRequest establishes cancellation before entering a blocking SSH
// request. Its worker exits on a reply or on channel/transport interruption.
func (c *Client) sessionRequest(ctx context.Context, session *cryptoSSH.Session, name string, request func() error) (retErr error) {
	if ctx == nil {
		return fmt.Errorf("SSH %s request context is nil", name)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("SSH %s request canceled: %w", name, err)
	}
	c.observeSession(corelog.SessionRequest, 2, name, "sending")
	defer func() {
		outcome := "accepted"
		if retErr != nil {
			outcome = "failed or interrupted"
		}
		c.observeSession(corelog.SessionRequest, 2, name, outcome)
		if retErr == nil && name != "pty" && name != "privilege pty" {
			c.observeSession(corelog.SessionStarted, 1, name, "accepted")
		}
	}()
	work, cancel := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- request() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("SSH %s request failed: %w", name, err)
		}
		return nil
	case <-work.Done():
		return fmt.Errorf("SSH %s request interrupted: %w", name, c.closeCanceledSession(work, session, done))
	}
}

func (c *Client) waitTerminalSession(ctx context.Context, session *cryptoSSH.Session, done, outputFailed <-chan error, abort context.CancelFunc) error {
	select {
	case err := <-done:
		return err
	case err := <-outputFailed:
		abort()
		return errors.Join(err, c.closeCanceledSession(ctx, session, done))
	case <-ctx.Done():
		abort()
		return c.closeCanceledSession(ctx, session, done)
	}
}

func (c *Client) closeSessionBounded(session *cryptoSSH.Session) (retErr error) {
	defer func() {
		outcome := "completed"
		if retErr != nil {
			outcome = "failed"
		}
		c.observeSession(corelog.SessionCleanup, 3, "close", outcome)
	}()
	work, cancel := withTimeoutOrDefault(context.Background(), sessionShutdownTimeout, sessionShutdownTimeout)
	defer cancel()
	done := make(chan error, 1)
	// Close exits once its write succeeds or Interrupt closes the transport.
	go func() { done <- closeResource(session, "SSH session") }()
	select {
	case err := <-done:
		return err
	case <-work.Done():
		interruptErr := c.Interrupt()
		return errors.Join(fmt.Errorf("close SSH session: %w", work.Err()), interruptErr, <-done)
	}
}

// runTerminalSession distinguishes protocol shell requests from exec requests,
// and full login-session exit policy from one-shot command exit policy.
func (c *Client) runTerminalSession(ctx context.Context, payload string, streams InteractiveIO, shellRequest, ignoreExit bool, cancelOutput ...context.CancelFunc) (retErr error) {
	if !shellRequest && payload == "" {
		return fmt.Errorf("PTY command must not be empty")
	}
	fdIn, fdOut, err := validateInteractiveIO(streams)
	if err != nil {
		return err
	}
	escapeByte, escapeEnabled, err := resolveInteractiveEscapeChar(c.ConnectionConfig().Options)
	if err != nil {
		return err
	}
	session, err := c.newSessionContext(ctx)
	if err != nil {
		return err
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	releaseAgent := c.enableSessionAgentForward(work, session)
	defer releaseAgent()
	defer func() { retErr = errors.Join(retErr, c.closeSessionBounded(session)) }()
	request, name := func() error { return session.Start(payload) }, "exec"
	if shellRequest {
		request, name = session.Shell, "shell"
	}
	untrackSession := c.trackActiveSession("client-session (" + name + ")")
	defer untrackSession()

	stdin, stdout, stderr, width, height, err := c.prepareTerminalSessionChannel(ctx, session, fdOut, name, request)
	if err != nil {
		return err
	}
	suspendTerminal, restoreRaw, err := c.enterTerminalRawMode(fdIn, fdOut, session)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, restoreRaw()) }()

	stopResize := startWindowResizeLoop(work, session, fdOut, width, height, c.getLogger(), c.Interrupt)
	defer func() { retErr = errors.Join(retErr, stopResize()) }()
	output := startSessionOutput(stdout, stderr, streams.Stdout, streams.Stderr)
	waitDone := make(chan error, 1)
	// Start before input initialization: even that failure must join Wait and
	// force transport interruption if the peer ignores channel closure.
	go func() { waitDone <- c.waitSession(session) }()
	abort := combineOutputCancels(cancel, cancelOutput)

	inputDst, escapeFilter := c.wrapTerminalEscapeInput(stdin, streams, escapeByte, escapeEnabled, abort, suspendTerminal)
	stopInput, inputDone, err := startInputCopy(work, c.environment.InputBridge, streams, inputDst)
	if err != nil {
		abort()
		return errors.Join(err, c.closeCanceledSession(work, session, waitDone), output.wait())
	}
	inputJoined := make(chan error, 1)
	// EOF closes only the sending direction. On cancellation, closing the SSH
	// session unblocks both an input write and this final CloseWrite.
	go func() { inputJoined <- errors.Join(<-inputDone, closeResource(stdin, "terminal stdin")) }()
	waitErr := c.waitTerminalSession(work, session, waitDone, output.failed, abort)
	cancel()
	closeErr := c.closeSessionBounded(session)
	inputErr := errors.Join(stopInput(), <-inputJoined)
	if ignoreExit {
		waitErr = ignoreShellExitError(waitErr)
	}
	outputErr := joinTerminalOutput(ctx, output.wait, cancelOutput)
	if escapeFilter.Disconnected() && ctx.Err() == nil {
		if closeErr == nil {
			return ErrEscapeDisconnect
		}
		return errors.Join(ErrEscapeDisconnect, closeErr)
	}
	return errors.Join(waitErr, closeErr, inputErr, outputErr)
}

func (c *Client) prepareTerminalSessionChannel(
	ctx context.Context,
	session *cryptoSSH.Session,
	fdOut int,
	name string,
	request func() error,
) (io.WriteCloser, io.Reader, io.Reader, int, int, error) {
	if err := c.applySessionEnv(ctx, session); err != nil {
		return nil, nil, nil, 0, 0, err
	}
	width, height, err := term.GetSize(fdOut)
	if err != nil || width <= 0 || height <= 0 {
		width, height = 80, 40
	}
	modes := cryptoSSH.TerminalModes{cryptoSSH.ECHO: 1, cryptoSSH.TTY_OP_ISPEED: 14400, cryptoSSH.TTY_OP_OSPEED: 14400}
	if err := c.sessionRequest(ctx, session, "pty", func() error { return session.RequestPty("xterm-256color", height, width, modes) }); err != nil {
		return nil, nil, nil, 0, 0, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, nil, nil, 0, 0, fmt.Errorf("open terminal stdin: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, nil, 0, 0, fmt.Errorf("open terminal stdout: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, nil, nil, 0, 0, fmt.Errorf("open terminal stderr: %w", err)
	}
	if err := c.sessionRequest(ctx, session, name, request); err != nil {
		return nil, nil, nil, 0, 0, err
	}
	return stdin, stdout, stderr, width, height, nil
}

func (c *Client) enterTerminalRawMode(
	fdIn, fdOut int,
	session *cryptoSSH.Session,
) (onSuspend func() error, restore func() error, err error) {
	state, err := term.MakeRaw(fdIn)
	if err != nil {
		return nil, nil, fmt.Errorf("set terminal raw mode: %w", err)
	}
	var termMu sync.Mutex
	rawActive := true
	restore = func() error {
		termMu.Lock()
		defer termMu.Unlock()
		if !rawActive {
			return nil
		}
		rawActive = false
		if err := term.Restore(fdIn, state); err != nil {
			return fmt.Errorf("restore terminal: %w", err)
		}
		return nil
	}
	onSuspend = func() error {
		suspendFn := c.environment.SuspendProcess
		if suspendFn == nil {
			return nil
		}
		termMu.Lock()
		defer termMu.Unlock()
		if rawActive {
			if err := term.Restore(fdIn, state); err != nil {
				return fmt.Errorf("restore terminal before suspend: %w", err)
			}
			rawActive = false
		}
		suspendErr := suspendFn()
		newState, rawErr := term.MakeRaw(fdIn)
		if rawErr != nil {
			return fatalSuspendTerminalError{
				err: errors.Join(suspendErr, fmt.Errorf("re-enter terminal raw mode after suspend: %w", rawErr)),
			}
		}
		state = newState
		rawActive = true
		if currW, currH, szErr := term.GetSize(fdOut); szErr == nil && currW > 0 && currH > 0 {
			_ = session.WindowChange(currH, currW)
		}
		return suspendErr
	}
	return onSuspend, restore, nil
}

func (c *Client) wrapTerminalEscapeInput(
	stdin io.Writer,
	streams InteractiveIO,
	escapeByte byte,
	escapeEnabled bool,
	abort func(),
	onSuspend func() error,
) (io.Writer, *escapeFilterWriter) {
	if !escapeEnabled {
		return stdin, nil
	}
	localOut := streams.Stderr
	if localOut == nil {
		localOut = streams.Stdout
	}
	filter := newEscapeFilterWriter(stdin, escapeFilterConfig{
		escapeByte:   escapeByte,
		host:         c.ConnectionConfig().Address,
		localOut:     localOut,
		onDisconnect: abort,
		onSuspend:    onSuspend,
		summaryFn:    c.formatOpenChannelsSummary,
	})
	return filter, filter
}

func joinTerminalOutput(ctx context.Context, wait func() error, cancelOutput []context.CancelFunc) error {
	if len(cancelOutput) > 0 {
		return waitTerminalOutput(ctx, wait, cancelOutput[0])
	}
	return wait()
}

// Bound output pumps use this join. Cancellation never abandons the waiter or
// its stdout/stderr workers. In-flight regular-file writes must finish first;
// legacy arbitrary writers migrate later.
func waitTerminalOutput(ctx context.Context, wait func() error, cancel context.CancelFunc) error {
	return waitSessionOutput(ctx, wait, cancel)
}

// RunInteractivePlan executes a validated command plan in a PTY with the
// environment's terminal streams. stdin belongs to the terminal, not the plan.
func (c *Client) RunInteractivePlan(ctx context.Context, plan CommandPlan) error {
	return c.RunInteractivePlanWithIO(ctx, plan, c.defaultInteractiveIO())
}

// RunInteractivePlanWithIO requires local terminal input and finite,
// context-aware, or regular-file output. Regular files are borrowed and check
// cancellation between writes; a kernel write in progress must finish before
// return, so file-output cleanup has no hard time bound. Native terminal/pipe
// support follows the platform adapters; macOS blocking pipes remain unsupported.
func (c *Client) RunInteractivePlanWithIO(ctx context.Context, plan CommandPlan, streams InteractiveIO) (retErr error) {
	if err := validateCommandExecution(ctx, c, plan); err != nil {
		return err
	}
	if plan.input != "" {
		return fmt.Errorf("PTY command input must come from terminal streams")
	}
	work, cancel := context.WithTimeout(ctx, plan.timeout)
	defer cancel()
	outCtx, cancelOut := context.WithCancel(work)
	defer cancelOut()
	stdout, closeOut, err := prepareContextOutput(outCtx, streams.Stdout)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeOut()) }()
	stderr, closeErr, err := prepareContextOutput(outCtx, streams.Stderr)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeErr()) }()
	streams.Stdout, streams.Stderr = stdout, stderr
	return c.runTerminalSession(work, plan.payload, streams, false, false, cancelOut)
}

// RunInteractiveWithOptions preserves the legacy login default while honoring
// an explicit WithLoginShell override. Terminal I/O is supplied by Environment.
func (c *Client) RunInteractiveWithOptions(ctx context.Context, command string, opts ...RunOption) error {
	config := DefaultRunConfig()
	for _, option := range opts {
		option(config)
	}
	if config.OutMode != OutputModeString {
		return fmt.Errorf("PTY output is controlled by terminal streams")
	}
	login := LoginDisabled
	if config.LoginShell {
		login = LoginEnabled
	}
	plan, err := PlanCommand(command, CommandOptions{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX, Login: login})
	if err != nil {
		return err
	}
	// Legacy PTY sessions retain caller-controlled duration, unlike new plans.
	return c.runTerminalSession(ctx, plan.payload, c.defaultInteractiveIO(), false, false)
}
