package ssh

import (
	"context"
	"errors"
	"fmt"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// sessionRequest establishes cancellation before entering a blocking SSH
// request. Its worker exits on a reply or on channel/transport interruption.
func (c *Client) sessionRequest(ctx context.Context, session *cryptoSSH.Session, name string, request func() error) error {
	if ctx == nil {
		return fmt.Errorf("SSH %s request context is nil", name)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("SSH %s request canceled: %w", name, err)
	}
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

func (c *Client) closeSessionBounded(session *cryptoSSH.Session) error {
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
	session, err := c.newSessionContext(ctx)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, c.closeSessionBounded(session)) }()
	width, height, err := term.GetSize(fdOut)
	if err != nil || width <= 0 || height <= 0 {
		width, height = 80, 40
	}
	modes := cryptoSSH.TerminalModes{cryptoSSH.ECHO: 1, cryptoSSH.TTY_OP_ISPEED: 14400, cryptoSSH.TTY_OP_OSPEED: 14400}
	if err := c.sessionRequest(ctx, session, "pty", func() error { return session.RequestPty("xterm-256color", height, width, modes) }); err != nil {
		return err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("open terminal stdin: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open terminal stdout: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("open terminal stderr: %w", err)
	}
	request := func() error { return session.Start(payload) }
	name := "exec"
	if shellRequest {
		request, name = session.Shell, "shell"
	}
	if err := c.sessionRequest(ctx, session, name, request); err != nil {
		return err
	}
	state, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("set terminal raw mode: %w", err)
	}
	defer func() {
		if err := term.Restore(fdIn, state); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("restore terminal: %w", err))
		}
	}()
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	stopResize := startWindowResizeLoop(work, session, fdOut, width, height, c.getLogger(), c.Interrupt)
	defer func() { retErr = errors.Join(retErr, stopResize()) }()
	output := startSessionOutput(stdout, stderr, streams.Stdout, streams.Stderr)
	waitDone := make(chan error, 1)
	// Start before input initialization: even that failure must join Wait and
	// force transport interruption if the peer ignores channel closure.
	go func() { waitDone <- session.Wait() }()
	abort := func() {
		cancel()
		if len(cancelOutput) > 0 {
			cancelOutput[0]()
		}
	}
	stopInput, inputDone, err := startInputCopy(work, c.environment.InputBridge, streams, stdin)
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
	var outputErr error
	if len(cancelOutput) > 0 {
		outputErr = waitTerminalOutput(ctx, output.wait, cancelOutput[0])
	} else {
		outputErr = output.wait()
	}
	return errors.Join(waitErr, closeErr, inputErr, outputErr)
}

// Only cancellable output pumps use this join. Cancellation never abandons the
// waiter or its stdout/stderr workers; legacy arbitrary writers migrate later.
func waitTerminalOutput(ctx context.Context, wait func() error, cancel context.CancelFunc) error {
	return waitSessionOutput(ctx, wait, cancel)
}

// RunInteractivePlan executes a validated command plan in a PTY with the
// environment's terminal streams. stdin belongs to the terminal, not the plan.
func (c *Client) RunInteractivePlan(ctx context.Context, plan CommandPlan) error {
	return c.RunInteractivePlanWithIO(ctx, plan, c.defaultInteractiveIO())
}

// RunInteractivePlanWithIO requires local terminal input and finite or
// context-aware output. Native Linux files must be terminals/pipes; other native
// file bridges and regular-file redirection require subsequent acceptance.
func (c *Client) RunInteractivePlanWithIO(ctx context.Context, plan CommandPlan, streams InteractiveIO) (retErr error) {
	if err := validateCommandExecution(ctx, c, plan); err != nil {
		return err
	}
	if plan.input != "" {
		return fmt.Errorf("PTY command input must come from terminal streams")
	}
	work, cancel := context.WithTimeout(ctx, plan.timeout)
	defer cancel()
	stdout, closeOut, err := prepareContextOutput(work, streams.Stdout)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeOut()) }()
	stderr, closeErr, err := prepareContextOutput(work, streams.Stderr)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeErr()) }()
	streams.Stdout, streams.Stderr = stdout, stderr
	return c.runTerminalSession(work, plan.payload, streams, false, false, cancel)
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
