package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// ExecutionOutcome describes what is known about remote execution, not whether
// it succeeded. Unknown results must never be automatically replayed.
type ExecutionOutcome string

const (
	ExecutionNotStarted ExecutionOutcome = "not_started"
	ExecutionCompleted  ExecutionOutcome = "completed"
	ExecutionUnknown    ExecutionOutcome = "unknown"
)

// CommandResult retains remote termination independently of local I/O/cleanup
// failures. ExitCode is nil if no exit-status was received, including signals.
type CommandResult struct {
	PlanDigest   string
	Phase        string
	Outcome      ExecutionOutcome
	ExitCode     *uint32
	Signal       string
	Output       string
	Truncated    bool
	ExecutionErr error
	IOErr        error
	CleanupErr   error
}

func (r CommandResult) Err() error { return errors.Join(r.ExecutionErr, r.IOErr, r.CleanupErr) }

// CommandExitError reports a confirmed unsuccessful remote termination.
type CommandExitError struct {
	ExitCode *uint32
	Signal   string
}

func (e *CommandExitError) Error() string {
	if e.Signal != "" {
		return fmt.Sprintf("remote command terminated by signal %q", e.Signal)
	}
	if e.ExitCode != nil {
		return fmt.Sprintf("remote command exited with status %d", *e.ExitCode)
	}
	return "remote command terminated without an exit code"
}

type commandObservation struct {
	mu     sync.Mutex
	result CommandResult
}

func (o *commandObservation) update(fn func(*CommandResult)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fn(&o.result)
}

func (o *commandObservation) snapshot() CommandResult {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.result
}

// ExecuteCommand sends a frozen command exactly once with finite stdin and
// internally bounded output. It does not accept external writers or request a
// PTY, perform privilege escalation, probe the server, or retry execution.
// All workers are joined; closing a stuck channel may interrupt the shared
// transport, including other operations using the same ProxyJump connection.
func (c *Client) ExecuteCommand(ctx context.Context, plan CommandPlan) CommandResult {
	observation := &commandObservation{result: CommandResult{
		PlanDigest: plan.digest, Phase: "validate", Outcome: ExecutionNotStarted,
	}}
	if err := validateCommandExecution(ctx, c, plan); err != nil {
		observation.result.ExecutionErr = err
		return observation.snapshot()
	}
	work, cancel := context.WithTimeout(ctx, plan.timeout)
	defer cancel()
	observation.result.Phase = "open"
	channel, requests, err := c.openCommandChannel(work)
	if err != nil {
		observation.result.ExecutionErr = err
		return observation.snapshot()
	}
	output := newOutputWriter(&RunConfig{OutMode: OutputModeRingBuffer, RingMaxBytes: plan.outputLimit})
	workersDone, startDone := startCommandWorkers(work, channel, requests, plan, output, observation)
	waitErr := c.waitCommandWorkers(work, workersDone, startDone)
	cleanupErr := c.closeCommandChannel(channel, workersDone)
	result := observation.snapshot()
	result.Output, result.Truncated = output.String(), output.truncated
	result.CleanupErr = cleanupErr
	if waitErr != nil {
		result.ExecutionErr = errors.Join(result.ExecutionErr, fmt.Errorf("wait for SSH command: %w", waitErr))
	}
	if result.Outcome == ExecutionUnknown && result.ExecutionErr == nil {
		result.ExecutionErr = &cryptoSSH.ExitMissingError{}
	}
	return result
}

func validateCommandExecution(ctx context.Context, c *Client, plan CommandPlan) error {
	if ctx == nil {
		return fmt.Errorf("command execution context is nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("command execution canceled: %w", err)
	}
	if plan.digest == "" {
		return fmt.Errorf("command execution plan is invalid")
	}
	if c == nil || c.sshClient == nil {
		return fmt.Errorf("SSH client is not connected")
	}
	return nil
}

type commandChannelResult struct {
	channel  cryptoSSH.Channel
	requests <-chan *cryptoSSH.Request
	err      error
}

func (c *Client) openCommandChannel(ctx context.Context) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	// A raw session channel keeps negative exec replies and terminal status
	// separate from output/cleanup failures, which Session.Wait combines.
	openCtx, cancel := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancel()
	done := make(chan commandChannelResult, 1)
	// OpenChannel exits when it receives a reply or Interrupt closes transport.
	go func() {
		ch, requests, err := c.sshClient.OpenChannel("session", nil)
		done <- commandChannelResult{ch, requests, err}
	}()
	select {
	case opened := <-done:
		if opened.err != nil {
			return nil, nil, fmt.Errorf("open SSH command channel: %w", opened.err)
		}
		return opened.channel, opened.requests, nil
	case <-openCtx.Done():
		interruptErr := c.Interrupt()
		opened := <-done
		var closeErr error
		if opened.channel != nil {
			closeErr = closeResource(opened.channel, "late SSH command channel")
		}
		return nil, nil, errors.Join(fmt.Errorf("open SSH command channel: %w", openCtx.Err()), opened.err, interruptErr, closeErr)
	}
}

type commandStartResult struct {
	accepted bool
	err      error
}

func startCommandWorkers(ctx context.Context, channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request,
	plan CommandPlan, output *outputWriter, observation *commandObservation,
) (<-chan struct{}, <-chan commandStartResult) {
	var workers sync.WaitGroup
	// Readers and request handling exit when the server closes the channel, or
	// the supervisor closes it/interrupts transport on timeout or cancellation.
	workers.Go(func() { observeCommandRequests(channel, requests, observation) })
	for _, source := range []io.Reader{channel, channel.Stderr()} {
		workers.Go(func() {
			if _, err := io.Copy(output, source); err != nil {
				observation.update(func(r *CommandResult) {
					r.IOErr = errors.Join(r.IOErr, fmt.Errorf("collect SSH command output: %w", err))
				})
			}
		})
	}
	startDone := make(chan commandStartResult, 1)
	workers.Go(func() { sendCommandInput(ctx, channel, plan, observation, startDone) })
	done := make(chan struct{})
	// Every worker is unblocked by the supervisor's channel/transport closure.
	go func() { workers.Wait(); close(done) }()
	return done, startDone
}

func sendCommandInput(ctx context.Context, channel cryptoSSH.Channel, plan CommandPlan, observation *commandObservation, startDone chan<- commandStartResult) {
	if err := ctx.Err(); err != nil {
		startDone <- commandStartResult{err: err}
		return
	}
	observation.update(func(r *CommandResult) { r.Phase, r.Outcome = "request", ExecutionUnknown })
	accepted, err := channel.SendRequest("exec", true, cryptoSSH.Marshal(struct{ Command string }{plan.payload}))
	startDone <- commandStartResult{accepted, err}
	if err != nil {
		observation.update(func(r *CommandResult) { r.ExecutionErr = fmt.Errorf("send SSH exec request: %w", err) })
		return
	}
	if !accepted {
		observation.update(func(r *CommandResult) {
			r.Phase, r.Outcome = "request", ExecutionNotStarted
			r.ExecutionErr = fmt.Errorf("server rejected SSH exec request")
		})
		return
	}
	observation.update(func(r *CommandResult) {
		if r.Outcome != ExecutionCompleted {
			r.Phase = "running"
		}
	})
	_, inputErr := io.Copy(channel, strings.NewReader(plan.input))
	closeErr := channel.CloseWrite()
	// A command may terminate without reading stdin. Closing an already closed
	// send direction is harmless; a failed/partial data write is still retained.
	if errors.Is(closeErr, io.EOF) {
		closeErr = nil
	}
	if err := errors.Join(inputErr, closeErr); err != nil {
		observation.update(func(r *CommandResult) { r.IOErr = errors.Join(r.IOErr, fmt.Errorf("send SSH command stdin: %w", err)) })
	}
}

func (c *Client) waitCommandWorkers(ctx context.Context, done <-chan struct{}, start <-chan commandStartResult) error {
	startCtx, cancel := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancel()
	select {
	case started := <-start:
		if started.err != nil || !started.accepted {
			return started.err
		}
	case <-startCtx.Done():
		return startCtx.Err()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func observeCommandRequests(channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request, observation *commandObservation) {
	for request := range requests {
		recognized, err := observeCommandTermination(request, observation)
		if request.WantReply {
			err = errors.Join(err, request.Reply(recognized, nil))
		}
		if err != nil {
			observation.update(func(r *CommandResult) {
				// Retain the first protocol failure without accumulating unbounded errors from a malformed peer.
				if r.IOErr == nil {
					r.IOErr = fmt.Errorf("handle SSH command result: %w", err)
				}
			})
		}
	}
}

func observeCommandTermination(request *cryptoSSH.Request, observation *commandObservation) (bool, error) {
	switch request.Type {
	case "exit-status":
		var value struct{ Status uint32 }
		if err := cryptoSSH.Unmarshal(request.Payload, &value); err != nil {
			return false, err
		}
		observation.update(func(r *CommandResult) {
			if r.ExitCode != nil || r.Signal != "" {
				if r.IOErr == nil {
					r.IOErr = fmt.Errorf("duplicate SSH command termination result")
				}
				return
			}
			r.Phase, r.Outcome, r.ExitCode = "finished", ExecutionCompleted, &value.Status
			if value.Status != 0 {
				r.ExecutionErr = &CommandExitError{ExitCode: &value.Status}
			}
		})
		return true, nil
	case "exit-signal":
		var value struct {
			Signal                 string
			CoreDumped             bool
			ErrorMessage, Language string
		}
		if err := cryptoSSH.Unmarshal(request.Payload, &value); err != nil {
			return false, err
		}
		if value.Signal == "" {
			return false, fmt.Errorf("empty SSH exit signal")
		}
		observation.update(func(r *CommandResult) {
			if r.ExitCode != nil || r.Signal != "" {
				if r.IOErr == nil {
					r.IOErr = fmt.Errorf("duplicate SSH command termination result")
				}
				return
			}
			r.Phase, r.Outcome, r.Signal = "finished", ExecutionCompleted, value.Signal
			r.ExecutionErr = &CommandExitError{Signal: value.Signal}
		})
		return true, nil
	default:
		return false, nil
	}
}

func (c *Client) closeCommandChannel(channel cryptoSSH.Channel, workersDone <-chan struct{}) error {
	done := make(chan error, 1)
	// Channel.Close may block writing to a broken transport. Interrupt is the
	// bounded fallback; the supervisor always joins this worker and I/O workers.
	go func() {
		closeErr := closeResource(channel, "SSH command channel")
		<-workersDone
		done <- closeErr
	}()
	timer := time.NewTimer(sessionShutdownTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		interruptErr := c.Interrupt()
		closeErr := <-done
		return errors.Join(fmt.Errorf("SSH command shutdown exceeded %s", sessionShutdownTimeout), interruptErr, closeErr)
	}
}
