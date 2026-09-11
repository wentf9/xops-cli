package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Terminal state is activated only after authentication, and restored after the
// stdin reader and resize worker have stopped. Tests may inject this boundary.
type privilegeTerminal struct {
	width, height int
	activate      func(context.Context, *cryptoSSH.Session) (func() error, error)
	ignoreExit    bool
}

func (c *Client) runInteractivePrivilege(ctx context.Context, mode SudoMode, command string, streams InteractiveIO) error {
	fdIn, fdOut, err := validateInteractiveIO(streams)
	if err != nil {
		return err
	}
	width, height, err := term.GetSize(fdOut)
	if err != nil || width <= 0 || height <= 0 {
		width, height = 80, 40
	}
	terminal := &privilegeTerminal{width: width, height: height, ignoreExit: true}
	terminal.activate = func(work context.Context, session *cryptoSSH.Session) (func() error, error) {
		if err := work.Err(); err != nil {
			return nil, err
		}
		state, err := term.MakeRaw(fdIn)
		if err != nil {
			return nil, fmt.Errorf("set interactive privilege terminal raw mode: %w", err)
		}
		stopResize := startWindowResizeLoop(work, session, fdOut, width, height, c.getLogger(), c.Interrupt)
		return func() error {
			resizeErr := stopResize()
			if err := term.Restore(fdIn, state); err != nil {
				return errors.Join(resizeErr, fmt.Errorf("restore interactive privilege terminal: %w", err))
			}
			return resizeErr
		}, nil
	}
	return c.runPrivilegeOperation(ctx, mode, command, streams.Stdin, streams.Stdout, streams.Stderr, terminal)
}

func (e *privilegeExchange) forwardInput(ctx context.Context, stdin io.Reader, pipe io.WriteCloser) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.terminal != nil {
		restore, err := e.terminal.activate(ctx, e.session)
		if err != nil {
			return err
		}
		defer func() { retErr = errors.Join(retErr, restore()) }()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(pipe, e.ackToken); err != nil {
		return fmt.Errorf("confirm privilege readiness: %w", err)
	}
	if e.terminal != nil {
		handoff, cancel := withTimeoutOrDefault(ctx, e.client.handshakeTimeout, defaultSSHHandshakeTimeout)
		defer cancel()
		select {
		case <-e.terminalReady:
		case <-handoff.Done():
			return fmt.Errorf("wait for remote terminal handoff: %w", handoff.Err())
		}
	}
	finish, err := setupStdinPipeline(stdin, pipe, "")
	if err != nil {
		return err
	}
	<-ctx.Done()
	return finish()
}

func (e *privilegeExchange) outputReady() bool {
	if e.terminal == nil {
		return e.started()
	}
	select {
	case <-e.terminalReady:
		return true
	default:
		return false
	}
}
