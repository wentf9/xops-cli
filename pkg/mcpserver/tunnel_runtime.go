package mcpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/mcpserver/tunnel"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

func (r *Runtime) initializeTunnels(cfg *serverConfig) {
	if r.http != nil {
		return
	}
	r.tunnelProvider = cfg.provider
	if provider, ok := cfg.provider.(interface{ Frozen() config.ConfigProvider }); ok {
		r.tunnelProvider = provider.Frozen()
	}
	r.tunnels = tunnel.New(r.ctx, func(ctx context.Context, spec tunnel.Spec, ready func(string) bool, report func(error)) error {
		connector := newNonInteractiveMCPConnector(r.tunnelProvider, cfg.logger, cfg.credentialRegistry)
		return runMCPSSHTunnel(ctx, connector, spec, ready, report)
	}, r.auditTunnel)
}

// runMCPSSHTunnel owns the entire connector, including every ProxyJump hop.
// CloseAll interrupts established jump transports before joining unfinished
// Connect workers, including cancellation during a downstream SSH handshake.
// The monitor is started before remote Listen: cancellation can therefore
// interrupt a stuck SSH global request by closing the physical transport.
func runMCPSSHTunnel(ctx context.Context, connector *ssh.Connector, spec tunnel.Spec, ready func(string) bool, report func(error)) (retErr error) {
	defer func() {
		if err := connector.CloseAll(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close tunnel connector: %w", err))
		}
	}()
	client, err := connector.Connect(ctx, spec.NodeID)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("connect tunnel SSH node: %w", FormatMCPError(err))
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	monitorDone := make(chan error, 1)
	// Client.Wait exits on transport loss or cancellation and interrupts the
	// owned physical connection before joining its transport goroutine.
	go func() {
		err := client.Wait(runCtx)
		cancel()
		monitorDone <- err
	}()
	defer func() {
		cancel()
		retErr = errors.Join(retErr, <-monitorDone)
	}()
	opts := []ssh.ForwardOption{ssh.WithForwardErrorHandler(report), ssh.WithForwardConnectionLimit(tunnel.ConnectionLimit)}
	var forward *ssh.Forward
	if spec.Mode == "local" {
		forward, err = client.LocalForward(runCtx, spec.ListenAddress(), spec.TargetAddress(), opts...)
	} else {
		forward, err = client.RemoteForward(runCtx, spec.ListenAddress(), spec.TargetAddress(), opts...)
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

func (r *Runtime) auditTunnel(status tunnel.Status, event string, cause error) error {
	risk := tunnelRisk(status.Spec)
	risk.Details += "; tunnelID=" + status.TunnelID
	return r.guardrail.RecordAuthorized(status.OperationID, risk, event, cause)
}
