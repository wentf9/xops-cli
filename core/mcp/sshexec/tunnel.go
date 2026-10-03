package sshexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/core/ssh"
)

var _ ports.TunnelBackend = (*Backend)(nil)

func (b *Backend) RunTunnel(ctx context.Context, permit ports.Permit, spec tunnel.Spec, ready func(string) bool, report func(error)) (retErr error) {
	work, cancel, err := b.work(ctx, permit, ports.Execute)
	if err != nil {
		return err
	}
	defer cancel()
	view := permit.Snapshot().Clone()
	if err := permit.Binding().Validate(view); err != nil {
		return err
	}
	_, target, err := view.Resolve(spec.NodeID)
	if err != nil {
		return err
	}
	connector := b.newConnector()
	defer func() { retErr = errors.Join(retErr, connector.CloseAll()) }()
	connection, err := connector.ConnectPlan(work, target.Plan)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, connection.Close()) }()
	return RunDedicatedForward(work, connection.Client, spec, ready, report)
}

// RunDedicatedForward requires an exclusively owned SSH/ProxyJump transport.
// Wait interrupts that physical transport on cancellation; this must never be
// called with an ordinary command/transfer pool's borrowed client.
func RunDedicatedForward(ctx context.Context, client *ssh.Client, spec tunnel.Spec, ready func(string) bool, report func(error)) (retErr error) {
	if ctx == nil || client == nil || ready == nil {
		return errors.New("dedicated forward requires context, client, and readiness callback")
	}
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	// Client.Wait exits on transport loss or cancellation and unblocks a stuck
	// global Listen request before the owned connector is joined by its caller.
	go func() { err := client.Wait(run); cancel(); done <- err }()
	defer func() {
		cancel()
		monitorErr := <-done
		if ctx.Err() != nil {
			retErr = forwardStopError(retErr)
			monitorErr = forwardStopError(monitorErr)
		}
		retErr = errors.Join(retErr, monitorErr)
	}()
	options := []ssh.ForwardOption{ssh.WithForwardErrorHandler(report), ssh.WithForwardConnectionLimit(tunnel.ConnectionLimit)}
	var forward *ssh.Forward
	var err error
	if spec.Mode == "local" {
		forward, err = client.LocalForward(run, spec.ListenAddress(), spec.TargetAddress(), options...)
	} else {
		forward, err = client.RemoteForward(run, spec.ListenAddress(), spec.TargetAddress(), options...)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("start SSH tunnel listener: %w", err)
	}
	if !ready(forward.Addr().String()) {
		cancel()
	}
	return forward.Wait()
}

// A cancelled dedicated transport can report EOF before its waiter observes
// cancellation. Normalize only expected stop leaves; preserve unrelated errors
// even when a joined error also contains a benign close result.
func forwardStopError(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var retained []error
		for _, cause := range joined.Unwrap() {
			if filtered := forwardStopError(cause); filtered != nil {
				retained = append(retained, filtered)
			}
		}
		return errors.Join(retained...)
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if cause := wrapped.Unwrap(); cause != nil && forwardStopError(cause) == nil {
			return nil
		}
		return err
	}
	for _, expected := range []error{io.EOF, net.ErrClosed, context.Canceled, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE} {
		if errors.Is(err, expected) {
			return nil
		}
	}
	return err
}
