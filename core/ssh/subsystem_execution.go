package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type channelStdinWriteCloser struct {
	ch cryptoSSH.Channel
}

func (w channelStdinWriteCloser) Write(p []byte) (int, error) {
	return w.ch.Write(p)
}

func (w channelStdinWriteCloser) Close() error {
	return w.ch.CloseWrite()
}

func marshalDefaultTerminalModes() []byte {
	// RFC 4254 §8 terminal mode encoding:
	// opcode ECHO (53) = 1, TTY_OP_ISPEED (128) = 14400 (0x3840), TTY_OP_OSPEED (129) = 14400 (0x3840), TTY_OP_END (0).
	return []byte{
		cryptoSSH.ECHO, 0x00, 0x00, 0x00, 0x01,
		cryptoSSH.TTY_OP_ISPEED, 0x00, 0x00, 0x38, 0x40,
		cryptoSSH.TTY_OP_OSPEED, 0x00, 0x00, 0x38, 0x40,
		0x00,
	}
}

func startChannelWindowResizeLoop(
	ctx context.Context,
	ch cryptoSSH.Channel,
	fdOut, width, height int,
	l logger.DebugLogger,
	interrupt func() error,
) func() error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		lastW, lastH := width, height
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				currW, currH, err := term.GetSize(fdOut)
				if err != nil || currW <= 0 || currH <= 0 {
					continue
				}
				if currW != lastW || currH != lastH {
					payload := cryptoSSH.Marshal(struct {
						Columns uint32
						Rows    uint32
						Width   uint32
						Height  uint32
					}{
						Columns: uint32(currW),
						Rows:    uint32(currH),
						Width:   uint32(currW * 8),
						Height:  uint32(currH * 8),
					})
					if _, err := ch.SendRequest("window-change", false, payload); err != nil {
						l.Debugf("resize remote subsystem terminal failed: %v", err)
						continue
					}
					lastW, lastH = currW, currH
				}
			}
		}
	}()
	return func() error {
		cancel()
		timer := time.NewTimer(sessionShutdownTimeout)
		defer timer.Stop()
		select {
		case <-done:
			return nil
		case <-timer.C:
			err := interrupt()
			<-done
			return errors.Join(fmt.Errorf("subsystem window resize worker shutdown timed out"), err)
		}
	}
}

// RunSubsystemWithIO opens a session channel and invokes an SSH subsystem (RFC 4254 §6.5
// "subsystem" request, such as "sftp" or "netconf") using caller-provided I/O streams.
//
// Borrowed caller streams (stdin, stdout, stderr) are never closed by this method.
// EscapeChar filtering is never enabled on subsystem streams so binary subsystem frames
// pass through unmodified even when allocatePTY is true. Non-zero remote exit statuses or
// signals are returned as *CommandExitError.
func (c *Client) RunSubsystemWithIO(ctx context.Context, subsystem string, stdin io.Reader, stdout, stderr io.Writer, allocatePTY bool) (retErr error) {
	if err := validateSubsystemArgs(ctx, c, subsystem, stdin); err != nil {
		return err
	}
	envVars, err := c.resolveClientSessionEnv()
	if err != nil {
		return err
	}
	isRealTTY, fdIn, fdOut, width, height := resolveSubsystemPTYDims(allocatePTY, stdin, stdout)

	work, cancel := context.WithCancel(ctx)
	defer cancel()
	// Outputs use their own context so a normal completion (which cancels work)
	// cannot abort draining stdout/stderr still buffered in the channel.
	outputCtx, cancelOutput := context.WithCancel(ctx)
	defer cancelOutput()
	cancelAllOutputs := combineOutputCancels(cancel, []context.CancelFunc{cancelOutput})
	boundOut, boundErr, closeOutput, err := c.bindSubsystemOutputs(outputCtx, stdout, stderr)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeOutput()) }()

	channel, requests, err := c.openCommandChannel(work)
	if err != nil {
		return err
	}
	untrackSession := c.trackActiveSession("client-session (subsystem:" + subsystem + ")")
	defer untrackSession()
	wantAgent, releaseAgent := c.prepareChannelAgentForward(work)
	defer releaseAgent()

	observation, reqDone := startSubsystemRequestObserver(channel, requests)
	if setupErr := c.setupSubsystemChannel(work, channel, subsystem, envVars, wantAgent, releaseAgent, allocatePTY, width, height); setupErr != nil {
		cancel()
		closeErr := c.closeCommandChannel(channel, reqDone)
		releaseAgent()
		return errors.Join(setupErr, closeErr)
	}

	if isRealTTY {
		cleanupTTY, ttyErr := c.activateSubsystemTTY(work, channel, fdIn, fdOut, width, height)
		if ttyErr != nil {
			cancel()
			closeErr := c.closeCommandChannel(channel, reqDone)
			releaseAgent()
			return errors.Join(ttyErr, closeErr)
		}
		defer func() { retErr = errors.Join(retErr, cleanupTTY()) }()
	}

	finishStdin, setupPipeErr := setupStdinPipeline(
		stdin,
		channelStdinWriteCloser{ch: channel},
		"",
		inputPipelineOptions{ctx: work, bridge: c.environment.InputBridge},
	)
	if setupPipeErr != nil {
		cancel()
		closeErr := c.closeCommandChannel(channel, reqDone)
		releaseAgent()
		return errors.Join(setupPipeErr, closeErr)
	}
	finishStdinOnce := sync.OnceValue(finishStdin)

	output := startSessionOutput(channel, channel.Stderr(), boundOut, boundErr)
	outputFailedErr := waitSubsystemCompletion(work, reqDone, output.failed, cancelAllOutputs)
	cancel()
	cleanupErr := c.closeCommandChannel(channel, reqDone)
	releaseAgent()
	inputErr := finishStdinOnce()
	outputErr := waitSessionOutput(ctx, output.wait, cancelAllOutputs)
	cancelOutput()

	return finalizeSubsystemResult(ctx, observation.snapshot(), outputFailedErr, cleanupErr, inputErr, outputErr)
}

func validateSubsystemArgs(ctx context.Context, c *Client, subsystem string, stdin io.Reader) error {
	if _, ok := c.configSnapshot(); !ok || c.sshClient == nil {
		return fmt.Errorf("ssh client is not connected")
	}
	if ctx == nil {
		return fmt.Errorf("subsystem execution context is nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("subsystem execution canceled: %w", err)
	}
	if strings.TrimSpace(subsystem) == "" {
		return fmt.Errorf("%w: subsystem name must not be empty", ErrExecutionValidation)
	}
	if hasASCIIControlChar(subsystem) {
		return fmt.Errorf("%w: subsystem name %q contains invalid control character", ErrExecutionValidation, subsystem)
	}
	return validateCommandStdin(stdin, c.environment.InputBridge)
}

func resolveSubsystemPTYDims(allocatePTY bool, stdin io.Reader, stdout io.Writer) (isRealTTY bool, fdIn, fdOut, width, height int) {
	width, height = 80, 24
	if !allocatePTY {
		return false, 0, 0, width, height
	}
	fileIn, ok := stdin.(*os.File)
	if !ok || fileIn == nil || !term.IsTerminal(int(fileIn.Fd())) {
		return false, 0, 0, width, height
	}
	fdIn = int(fileIn.Fd())
	fdOut = fdIn
	if outFile, outOK := stdout.(*os.File); outOK && outFile != nil {
		fdOut = int(outFile.Fd())
	}
	if w, h, err := term.GetSize(fdOut); err == nil && w > 0 && h > 0 {
		return true, fdIn, fdOut, w, h
	}
	return true, fdIn, fdOut, 80, 40
}

func (c *Client) bindSubsystemOutputs(ctx context.Context, stdout, stderr io.Writer) (io.Writer, io.Writer, func() error, error) {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	return c.bindCommandOutputs(ctx, stdout, stderr, false)
}

func startSubsystemRequestObserver(channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request) (*commandObservation, <-chan struct{}) {
	observation := &commandObservation{result: CommandResult{
		Phase:   "open",
		Outcome: ExecutionNotStarted,
	}}
	var reqWorkers sync.WaitGroup
	reqDone := make(chan struct{})
	reqWorkers.Go(func() { observeCommandRequests(channel, requests, observation) })
	go func() { reqWorkers.Wait(); close(reqDone) }()
	return observation, reqDone
}

func (c *Client) activateSubsystemTTY(work context.Context, channel cryptoSSH.Channel, fdIn, fdOut, width, height int) (func() error, error) {
	state, err := term.MakeRaw(fdIn)
	if err != nil {
		return nil, fmt.Errorf("set terminal raw mode: %w", err)
	}
	stopResize := startChannelWindowResizeLoop(work, channel, fdOut, width, height, c.getLogger(), c.Interrupt)
	return func() error {
		resizeErr := stopResize()
		if restoreErr := term.Restore(fdIn, state); restoreErr != nil {
			return errors.Join(resizeErr, fmt.Errorf("restore terminal: %w", restoreErr))
		}
		return resizeErr
	}, nil
}

func waitSubsystemCompletion(work context.Context, reqDone <-chan struct{}, outputFailed <-chan error, cancel context.CancelFunc) error {
	select {
	case <-reqDone:
		return nil
	case err := <-outputFailed:
		cancel()
		return err
	case <-work.Done():
		cancel()
		return nil
	}
}

func finalizeSubsystemResult(ctx context.Context, snap CommandResult, outputFailedErr, cleanupErr, inputErr, outputErr error) error {
	if outputFailedErr != nil {
		return errors.Join(outputFailedErr, snap.ExecutionErr, snap.IOErr, cleanupErr, inputErr, outputErr)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, snap.IOErr, cleanupErr, inputErr, outputErr)
	}
	if snap.ExecutionErr != nil {
		return errors.Join(snap.ExecutionErr, snap.IOErr, cleanupErr, inputErr, outputErr)
	}
	if snap.Outcome != ExecutionCompleted {
		return errors.Join(&cryptoSSH.ExitMissingError{}, snap.IOErr, cleanupErr, inputErr, outputErr)
	}
	return errors.Join(snap.IOErr, cleanupErr, inputErr, outputErr)
}

func (c *Client) setupSubsystemChannel(
	ctx context.Context,
	channel cryptoSSH.Channel,
	subsystem string,
	envVars []EnvVar,
	wantAgent bool,
	releaseAgent func(),
	allocatePTY bool,
	width, height int,
) error {
	if wantAgent {
		accepted, err := c.sendBoundedChannelRequest(ctx, channel, agentForwardRequestType, nil, false)
		if err != nil {
			releaseAgent()
			return err
		}
		if !accepted {
			releaseAgent()
			c.getLogger().Debugf("SSH server rejected %s; continuing without agent forwarding", agentForwardRequestType)
		}
	}
	for _, ev := range envVars {
		accepted, err := c.sendBoundedChannelRequest(ctx, channel, "env", cryptoSSH.Marshal(struct{ Name, Value string }{ev.Name, ev.Value}), false)
		if err != nil {
			return err
		}
		if !accepted {
			c.getLogger().Debugf("SSH server rejected env variable %q", ev.Name)
		}
	}
	if allocatePTY {
		ptyPayload := cryptoSSH.Marshal(struct {
			Term     string
			Columns  uint32
			Rows     uint32
			Width    uint32
			Height   uint32
			Modelist string
		}{
			Term:     "xterm-256color",
			Columns:  uint32(width),
			Rows:     uint32(height),
			Width:    uint32(width * 8),
			Height:   uint32(height * 8),
			Modelist: string(marshalDefaultTerminalModes()),
		})
		accepted, err := c.sendBoundedChannelRequest(ctx, channel, "pty-req", ptyPayload, false)
		if err != nil {
			return err
		}
		if !accepted {
			return errors.New("SSH pty-req request rejected")
		}
	}
	subPayload := cryptoSSH.Marshal(struct{ Value string }{subsystem})
	accepted, err := c.sendBoundedChannelRequest(ctx, channel, "subsystem", subPayload, true)
	if err != nil {
		return err
	}
	if !accepted {
		return fmt.Errorf("SSH subsystem %q request rejected", subsystem)
	}
	return nil
}

type channelRequestReply struct {
	accepted bool
	err      error
}

func (c *Client) sendBoundedChannelRequest(
	ctx context.Context,
	channel cryptoSSH.Channel,
	reqType string,
	payload []byte,
	emitSessionStarted bool,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("SSH %s request canceled: %w", reqType, err)
	}
	c.observeSession(logger.SessionRequest, 2, reqType, "sending")
	work, cancel := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancel()

	done := make(chan channelRequestReply, 1)
	go func() {
		ok, err := channel.SendRequest(reqType, true, payload)
		done <- channelRequestReply{accepted: ok, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			c.observeSession(logger.SessionRequest, 2, reqType, "failed or interrupted")
			return false, fmt.Errorf("SSH %s request failed: %w", reqType, r.err)
		}
		if r.accepted {
			c.observeSession(logger.SessionRequest, 2, reqType, "accepted")
			if emitSessionStarted {
				c.observeSession(logger.SessionStarted, 1, reqType, "accepted")
			}
			return true, nil
		}
		c.observeSession(logger.SessionRequest, 2, reqType, "rejected")
		return false, nil
	case <-work.Done():
		c.observeSession(logger.SessionRequest, 2, reqType, "failed or interrupted")
		return false, fmt.Errorf("SSH %s request interrupted: %w", reqType, c.closeInterruptedChannelRequest(work.Err(), channel, done))
	}
}

// closeInterruptedChannelRequest closes the channel and waits for an in-flight
// channel.SendRequest goroutine to exit. If a stalled peer leaves channel
// shutdown blocked past sessionShutdownTimeout, interrupting the owned client
// transport forces both goroutines to join before returning.
func (c *Client) closeInterruptedChannelRequest(cause error, channel cryptoSSH.Channel, reqDone <-chan channelRequestReply) error {
	shutdownDone := make(chan error, 1)
	go func() {
		closeErr := closeResource(channel, "canceled SSH subsystem channel")
		reply := <-reqDone
		var reqErr error
		if reply.err != nil {
			reqErr = fmt.Errorf("wait for canceled SSH channel request failed: %w", reply.err)
		}
		shutdownDone <- errors.Join(closeErr, reqErr)
	}()

	timer := time.NewTimer(sessionShutdownTimeout)
	defer timer.Stop()
	select {
	case shutdownErr := <-shutdownDone:
		return errors.Join(cause, shutdownErr)
	case <-timer.C:
		interruptErr := c.Interrupt()
		shutdownErr := <-shutdownDone
		return errors.Join(
			cause,
			fmt.Errorf("ssh channel request shutdown timed out after %s", sessionShutdownTimeout),
			interruptErr,
			shutdownErr,
		)
	}
}
