package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// RunCommandPlanWithIO executes a frozen command plan with streaming stdin,
// stdout and stderr, without a PTY, privilege escalation, or replay.
//
// stdin is borrowed and follows the RunCommandWithIO ownership contract (nil,
// an *os.File, or a finite in-memory reader); EOF closes only the sending
// direction. The plan must not carry finite input of its own: runtime stdin and
// plan input are never concatenated. stdout and stderr must be non-nil and
// cancelable as described by BindOutput; arbitrary writers are rejected before
// the command is sent. The plan's total timeout applies. A confirmed non-zero
// exit, signal or missing status is returned as an *ssh.ExitError or
// *ssh.ExitMissingError wrapped with context. Output is not retained.
func (c *Client) RunCommandPlanWithIO(ctx context.Context, plan CommandPlan, stdin io.Reader, stdout, stderr io.Writer) (retErr error) {
	if err := validateCommandExecution(ctx, c, plan); err != nil {
		return err
	}
	if plan.input != "" {
		return fmt.Errorf("streaming command plan must not include finite input")
	}
	if err := validateCommandStdin(stdin); err != nil {
		return err
	}
	work, cancel := context.WithTimeout(ctx, plan.timeout)
	defer cancel()
	boundOut, boundErr, closeOutput, err := bindStrictOutputs(work, stdout, stderr)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeOutput()) }()
	return c.runRawCommandWithPayload(work, plan.payload, "", stdin, boundOut, boundErr, cancel)
}

// RunShellWithoutPTY sends an SSH shell request without a PTY and forwards
// streaming stdin. It is for non-terminal input to a server shell: no
// interpreter is inserted, no empty exec request is sent, and unlike a full
// login terminal session the remote exit status is retained. Input, output and
// cancellation follow RunCommandPlanWithIO. Duration is controlled by ctx.
func (c *Client) RunShellWithoutPTY(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) (retErr error) {
	if ctx == nil {
		return fmt.Errorf("shell execution context is nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("shell execution canceled: %w", err)
	}
	if c == nil || c.sshClient == nil {
		return fmt.Errorf("SSH client is not connected")
	}
	if err := validateCommandStdin(stdin); err != nil {
		return err
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	boundOut, boundErr, closeOutput, err := bindStrictOutputs(work, stdout, stderr)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeOutput()) }()
	return c.runSessionWithInput(work, "shell", func(session *cryptoSSH.Session) error { return session.Shell() }, "", stdin, boundOut, boundErr, cancel)
}

// bindStrictOutputs is the new-API counterpart of bindCommandOutputs: output
// that cannot be canceled is rejected rather than silently used.
func bindStrictOutputs(ctx context.Context, stdout, stderr io.Writer) (io.Writer, io.Writer, func() error, error) {
	boundOut, closeOut, err := bindStrictOutput(ctx, stdout, "stdout")
	if err != nil {
		return nil, nil, nil, err
	}
	boundErr, closeErr, err := bindStrictOutput(ctx, stderr, "stderr")
	if err != nil {
		return nil, nil, nil, errors.Join(err, closeOut())
	}
	return boundOut, boundErr, func() error { return errors.Join(closeOut(), closeErr()) }, nil
}

func bindStrictOutput(ctx context.Context, target io.Writer, name string) (io.Writer, func() error, error) {
	if target == nil {
		return nil, nil, fmt.Errorf("command %s is nil", name)
	}
	bound, closeFn, cancelable, err := BindOutput(ctx, target)
	if err != nil {
		return nil, nil, fmt.Errorf("bind command %s: %w", name, err)
	}
	if !cancelable {
		return nil, nil, fmt.Errorf("unsupported command %s %T: provide a ContextWriter, terminal, pipe, or regular file", name, target)
	}
	return bound, closeFn, nil
}
