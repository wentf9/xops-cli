package runtime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
)

type CreateTunnelInput struct {
	RequestID  string `json:"requestID" jsonschema:"Client-generated idempotency key. Reuse the same key and parameters to recover a lost response; use a new key for a new tunnel."`
	NodeID     string `json:"nodeID" jsonschema:"Managed SSH node ID or alias, including canonical openssh:host IDs returned by tunnel tools."`
	Mode       string `json:"mode" jsonschema:"local (-L): listen on the MCP process machine and connect from the SSH node. remote (-R): listen on the SSH node and connect from the MCP process machine. No dynamic forwarding."`
	ListenHost string `json:"listenHost,omitempty" jsonschema:"IP literal or localhost; defaults to 127.0.0.1. Remote exposure is controlled by sshd GatewayPorts."`
	ListenPort int    `json:"listenPort" jsonschema:"Listening TCP port, 0 to 65535. Zero requests an automatically allocated port."`
	TargetHost string `json:"targetHost" jsonschema:"Destination host name or unbracketed IP literal, interpreted on the destination side of the tunnel."`
	TargetPort int    `json:"targetPort" jsonschema:"Destination TCP port, 1 to 65535."`
	TTLSeconds int    `json:"ttlSeconds,omitempty" jsonschema:"Lifetime after startup, 1 to 86400 seconds; default 3600. Not renewed by queries or retries."`
}

type TunnelInput struct {
	TunnelID string `json:"tunnelID" jsonschema:"Tunnel ID returned by xops_tunnel_create or xops_tunnel_list."`
}

type ListTunnelsInput struct {
	NodeID string `json:"nodeID,omitempty" jsonschema:"Optional node ID or alias filter; accepts returned canonical openssh:host IDs."`
	State  string `json:"state,omitempty" jsonschema:"Optional state: starting, running, stopping, stopped, expired, or failed."`
}

type TunnelOutput struct {
	Tunnel tunnel.Status `json:"tunnel"`
}
type ListTunnelsOutput struct {
	Tunnels []tunnel.Status `json:"tunnels"`
}

func tunnelRisk(s tunnel.Spec) guardrail.RiskInput {
	return guardrail.RiskInput{ToolName: "xops_tunnel_create", NodeID: s.NodeID, TunnelMode: s.Mode, ListenHost: s.ListenHost,
		Details: fmt.Sprintf("mode=%s; listen=%s; target=%s; ttlSeconds=%d; requestID=%s", s.Mode, s.ListenAddress(), s.TargetAddress(), s.TTLSeconds, s.RequestID)}
}

func (r *Runtime) resolveTunnelNode(ctx context.Context, selector string) (string, error) {
	if r.tunnels == nil {
		return "", errors.New("SSH tunnel tools are available only over stdio")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// A retained task proves its canonical ID even if execution is now disabled
	// or the inventory entry is gone. Aliases still use current inventory rules.
	if len(r.tunnels.List(selector, "")) != 0 {
		return selector, nil
	}
	view, err := r.resolve(ctx, []string{selector})
	if err != nil {
		return "", err
	}
	id, _, err := view.Resolve(selector)
	return id, err
}

func (r *Runtime) createTunnel(ctx context.Context, req *mcp.CallToolRequest, input CreateTunnelInput) (*mcp.CallToolResult, TunnelOutput, error) {
	ctx, cancel := r.toolContext(ctx)
	defer cancel()
	spec, err := tunnel.Normalize(tunnel.Spec{RequestID: input.RequestID, NodeID: input.NodeID, Mode: input.Mode,
		ListenHost: input.ListenHost, ListenPort: input.ListenPort, TargetHost: input.TargetHost, TargetPort: input.TargetPort, TTLSeconds: input.TTLSeconds})
	if err != nil {
		return nil, TunnelOutput{}, err
	}
	view, err := r.resolve(ctx, []string{spec.NodeID})
	if err != nil {
		return nil, TunnelOutput{}, err
	}
	spec.NodeID, _, err = view.Resolve(spec.NodeID)
	if err != nil {
		return nil, TunnelOutput{}, err
	}
	if existing, found, err := r.tunnels.Retry(spec); found || err != nil {
		return nil, TunnelOutput{Tunnel: existing}, err
	}
	ctx, op, err := r.operationContext(ctx, view, "xops_tunnel_create", spec)
	if err != nil {
		return nil, TunnelOutput{}, err
	}
	operationID, pending, err := r.guardrail.Authorize(ctx, req, tunnelRisk(spec), spec)
	if pending != nil || err != nil {
		return pending, TunnelOutput{}, err
	}
	status, err := r.tunnels.CreateWithRunner(ctx, spec, operationID,
		func(taskCtx context.Context, captured tunnel.Spec, ready func(string) bool, report func(error)) error {
			return r.runCapturedTunnel(taskCtx, op.snapshot, op.binding, operationID, captured, ready, report)
		})
	return nil, TunnelOutput{Tunnel: status}, err
}

func (r *Runtime) listTunnels(ctx context.Context, req *mcp.CallToolRequest, input ListTunnelsInput) (*mcp.CallToolResult, ListTunnelsOutput, error) {
	ctx, cancel := r.toolContext(ctx)
	defer cancel()
	if r.tunnels == nil {
		return nil, ListTunnelsOutput{}, errors.New("SSH tunnel tools are available only over stdio")
	}
	if input.State != "" {
		switch input.State {
		case "starting", "running", "stopping", "stopped", "expired", "failed":
		default:
			return nil, ListTunnelsOutput{}, errors.New("invalid tunnel state filter")
		}
	}
	if input.NodeID != "" {
		var err error
		input.NodeID, err = r.resolveTunnelNode(ctx, input.NodeID)
		if err != nil {
			return nil, ListTunnelsOutput{}, err
		}
	}
	// Authorize the exact snapshot returned below. Refreshing after approval
	// could include tunnels on nodes whose policy has never been checked.
	snapshot := r.tunnels.List(input.NodeID, input.State)
	risk := guardrail.RiskInput{NodeID: input.NodeID, Details: "state=" + input.State}
	if input.NodeID == "" {
		for _, status := range snapshot {
			risk.NodeIDs = append(risk.NodeIDs, status.NodeID)
		}
		slices.Sort(risk.NodeIDs)
		risk.NodeIDs = slices.Compact(risk.NodeIDs)
	}
	return withMetadata(r, "xops_tunnel_list",
		func(ListTunnelsInput) guardrail.RiskInput { return risk },
		func(context.Context, *mcp.CallToolRequest, ListTunnelsInput) (*mcp.CallToolResult, ListTunnelsOutput, error) {
			return nil, ListTunnelsOutput{Tunnels: snapshot}, nil
		})(ctx, req, input)
}

func (r *Runtime) tunnelStatus(ctx context.Context, req *mcp.CallToolRequest, input TunnelInput) (*mcp.CallToolResult, TunnelOutput, error) {
	if r.tunnels == nil {
		return nil, TunnelOutput{}, errors.New("SSH tunnel tools are available only over stdio")
	}
	status, err := r.tunnels.Status(input.TunnelID)
	if err != nil {
		return nil, TunnelOutput{}, err
	}
	return withMetadata(r, "xops_tunnel_status",
		func(in TunnelInput) guardrail.RiskInput {
			return guardrail.RiskInput{NodeID: status.NodeID, Details: "tunnelID=" + in.TunnelID}
		},
		func(_ context.Context, _ *mcp.CallToolRequest, in TunnelInput) (*mcp.CallToolResult, TunnelOutput, error) {
			latest, err := r.tunnels.Status(in.TunnelID)
			return nil, TunnelOutput{Tunnel: latest}, err
		})(ctx, req, input)
}

func (r *Runtime) stopTunnel(ctx context.Context, req *mcp.CallToolRequest, input TunnelInput) (_ *mcp.CallToolResult, _ TunnelOutput, retErr error) {
	ctx, cancel := r.toolContext(ctx)
	defer cancel()
	if r.tunnels == nil {
		return nil, TunnelOutput{}, errors.New("SSH tunnel tools are available only over stdio")
	}
	status, err := r.tunnels.Status(input.TunnelID)
	if err != nil {
		return nil, TunnelOutput{}, err
	}
	risk := tunnelRisk(status.Spec)
	risk.ToolName = "xops_tunnel_stop"
	risk.Details += "; tunnelID=" + input.TunnelID
	view, err := r.resolve(ctx, nil)
	if err != nil {
		return nil, TunnelOutput{}, err
	}
	ctx, op, err := r.operationContext(ctx, view, "xops_tunnel_stop", struct {
		Input  TunnelInput
		NodeID string
	}{input, status.NodeID})
	if err != nil {
		return nil, TunnelOutput{}, err
	}
	opID, pending, err := r.guardrail.Authorize(ctx, req, risk, input)
	if err != nil || pending != nil {
		return pending, TunnelOutput{}, err
	}
	permission, err := r.enter(ctx, op.snapshot, op.binding, ports.Execute, opID)
	if err != nil {
		return nil, TunnelOutput{}, err
	}
	defer func() { retErr = errors.Join(retErr, permission.Close()) }()
	stopCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	status, err = r.tunnels.Stop(stopCtx, input.TunnelID)
	if auditErr := r.guardrail.RecordAuthorized(opID, risk, "stop_requested", err); auditErr != nil {
		// Cleanup may already be complete. Return the state and audit error so
		// callers do not mistake an audit failure for an unexecuted operation.
		status.AuditError = auditErr.Error()
	}
	return nil, TunnelOutput{Tunnel: status}, err
}

func (r *Runtime) registerTunnels(server *mcp.Server) {
	if r.http != nil {
		return
	}
	notDestructive, destructive := false, true
	mcp.AddTool(server, &mcp.Tool{Name: "xops_tunnel_create", Description: "Create a process-owned SSH TCP tunnel over stdio only (-L or -R). Returns after listening; running does not prove destination reachability. Local means the xops MCP process machine. The tunnel survives this call until stopped, expired, disconnected, or MCP exits. A failed state is terminal; use a new requestID after fixing the cause.", Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive, IdempotentHint: true}}, r.createTunnel)
	mcp.AddTool(server, &mcp.Tool{Name: "xops_tunnel_list", Description: "List SSH tunnels owned by this stdio MCP process, including retained terminal states.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, r.listTunnels)
	mcp.AddTool(server, &mcp.Tool{Name: "xops_tunnel_status", Description: "Query tunnel state, listener, expiry and connection errors. Remote listener addresses do not prove GatewayPorts exposure or remote port release.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, r.tunnelStatus)
	mcp.AddTool(server, &mcp.Tool{Name: "xops_tunnel_stop", Description: "Idempotently stop a tunnel owned by this stdio MCP process and close its existing connections. If waiting times out, query status; cleanup continues. Remote port release may remain unconfirmed after SSH closure.", Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive, IdempotentHint: true}}, r.stopTunnel)
}

func (r *Runtime) runCapturedTunnel(ctx context.Context, view ports.OperationSnapshot, binding ports.Binding, operationID string, spec tunnel.Spec, ready func(string) bool, report func(error)) (retErr error) {
	work, cancel := context.WithTimeout(ctx, tunnel.MaxTTL+time.Minute)
	defer cancel()
	permission, err := r.enter(work, view, binding, ports.Execute, operationID)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, permission.Close()) }()
	if r.tunnelRun != nil {
		active, stop, err := ports.WorkContext(work, permission, ports.Execute)
		if err != nil {
			return err
		}
		defer stop()
		return r.tunnelRun(active, spec, ready, report)
	}
	backend, ok := r.backend.(ports.TunnelBackend)
	if !ok {
		return errors.New("MCP backend does not provide dedicated SSH tunnels")
	}
	return backend.RunTunnel(work, permission, spec, ready, report)
}
