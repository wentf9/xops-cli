package runtime

import (
	"context"
	"errors"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"time"
)

func (r *Runtime) initializeTunnels() {
	if r.http != nil {
		return
	}
	run := r.tunnelRun
	if run == nil {
		run = r.runBoundTunnel
	}
	r.tunnels = tunnel.New(r.ctx, run, r.auditTunnel)
}
func (r *Runtime) runBoundTunnel(ctx context.Context, spec tunnel.Spec, ready func(string) bool, report func(error)) (retErr error) {
	backend, ok := r.backend.(ports.TunnelBackend)
	if !ok {
		return errors.New("MCP backend does not provide dedicated SSH tunnels")
	}
	work, cancel := context.WithTimeout(ctx, tunnel.MaxTTL+time.Minute)
	defer cancel()
	view, err := r.resolve(work, []string{spec.NodeID})
	if err != nil {
		return err
	}
	binding, err := ports.Bind(view, r.scope(), "xops_tunnel_create", spec)
	if err != nil {
		return err
	}
	permission, err := r.enter(work, view, binding, ports.Execute, "")
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, permission.Close()) }()
	return backend.RunTunnel(work, permission, spec, ready, report)
}
func (r *Runtime) auditTunnel(status tunnel.Status, event string, cause error) error {
	risk := tunnelRisk(status.Spec)
	risk.Details += "; tunnelID=" + status.TunnelID
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
	defer cancel()
	return r.guardrail.RecordAuthorizedContext(ctx, status.OperationID, risk, event, cause)
}
