package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
)

type TunnelPolyInput struct {
	Action     string `json:"action" jsonschema:"Tunnel action: create, list, status, or stop"`
	RequestID  string `json:"requestID,omitempty" jsonschema:"Optional client-generated idempotency key for create (auto-generated if omitted). Reuse the same key and parameters to recover a lost response."`
	NodeID     string `json:"nodeID,omitempty" jsonschema:"Managed SSH node ID or alias (required for create, optional filter for list)"`
	Mode       string `json:"mode,omitempty" jsonschema:"For create: local (-L) or remote (-R). No dynamic forwarding."`
	ListenHost string `json:"listenHost,omitempty" jsonschema:"For create: IP literal or localhost; defaults to 127.0.0.1"`
	ListenPort int    `json:"listenPort,omitempty" jsonschema:"For create: listening TCP port, 0 to 65535 (0 allocates automatically)"`
	TargetHost string `json:"targetHost,omitempty" jsonschema:"For create: destination host name or unbracketed IP literal"`
	TargetPort int    `json:"targetPort,omitempty" jsonschema:"For create: destination TCP port, 1 to 65535"`
	TTLSeconds int    `json:"ttlSeconds,omitempty" jsonschema:"For create: lifetime after startup, 1 to 86400 seconds; default 3600"`
	TunnelID   string `json:"tunnelID,omitempty" jsonschema:"For status or stop: tunnel ID returned by create or list"`
	State      string `json:"state,omitempty" jsonschema:"For list: optional state filter (starting, running, stopping, stopped, expired, or failed)"`
}

type TunnelPolyOutput struct {
	Tunnel  *tunnel.Status  `json:"tunnel,omitempty"`
	Tunnels []tunnel.Status `json:"tunnels,omitempty"`
}

type CreateTunnelInput struct {
	Action     string `json:"action,omitempty"`
	RequestID  string `json:"requestID"`
	NodeID     string `json:"nodeID"`
	Mode       string `json:"mode"`
	ListenHost string `json:"listenHost,omitempty"`
	ListenPort int    `json:"listenPort"`
	TargetHost string `json:"targetHost"`
	TargetPort int    `json:"targetPort"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
}

type TunnelInput struct {
	Action   string `json:"action,omitempty"`
	TunnelID string `json:"tunnelID"`
}

type ListTunnelsInput struct {
	Action string `json:"action,omitempty"`
	NodeID string `json:"nodeID,omitempty"`
	State  string `json:"state,omitempty"`
}

type TunnelOutput struct {
	Tunnel tunnel.Status `json:"tunnel"`
}

type ListTunnelsOutput struct {
	Tunnels []tunnel.Status `json:"tunnels"`
}

func tunnelRisk(s tunnel.Spec) guardrail.RiskInput {
	return guardrail.RiskInput{
		ToolName:   "tunnel",
		Action:     "create",
		NodeID:     s.NodeID,
		TunnelMode: s.Mode,
		ListenHost: s.ListenHost,
		Details:    fmt.Sprintf("mode=%s; listen=%s; target=%s; ttlSeconds=%d; requestID=%s", s.Mode, s.ListenAddress(), s.TargetAddress(), s.TTLSeconds, s.RequestID),
	}
}

func resolveTunnelAction(input TunnelPolyInput) string {
	if input.Action != "" {
		return input.Action
	}
	switch {
	case input.Mode != "" || input.RequestID != "" || input.TargetHost != "" || input.TargetPort != 0:
		return "create"
	case input.TunnelID != "":
		return "status"
	default:
		return "list"
	}
}

func (r *Runtime) tunnelHandler(ctx context.Context, req *mcp.CallToolRequest, input TunnelPolyInput) (*mcp.CallToolResult, TunnelPolyOutput, error) {
	switch resolveTunnelAction(input) {
	case "create":
		res, out, err := r.createTunnel(ctx, req, CreateTunnelInput{
			RequestID:  input.RequestID,
			NodeID:     input.NodeID,
			Mode:       input.Mode,
			ListenHost: input.ListenHost,
			ListenPort: input.ListenPort,
			TargetHost: input.TargetHost,
			TargetPort: input.TargetPort,
			TTLSeconds: input.TTLSeconds,
		})
		if err != nil || res != nil {
			return res, TunnelPolyOutput{}, err
		}
		st := out.Tunnel
		return nil, TunnelPolyOutput{Tunnel: &st}, nil
	case "list":
		res, out, err := r.listTunnels(ctx, req, ListTunnelsInput{
			NodeID: input.NodeID,
			State:  input.State,
		})
		if err != nil || res != nil {
			return res, TunnelPolyOutput{}, err
		}
		tunnels := out.Tunnels
		if tunnels == nil {
			tunnels = []tunnel.Status{}
		}
		return nil, TunnelPolyOutput{Tunnels: tunnels}, nil
	case "status":
		res, out, err := r.tunnelStatus(ctx, req, TunnelInput{TunnelID: input.TunnelID})
		if err != nil || res != nil {
			return res, TunnelPolyOutput{}, err
		}
		st := out.Tunnel
		return nil, TunnelPolyOutput{Tunnel: &st}, nil
	case "stop":
		res, out, err := r.stopTunnel(ctx, req, TunnelInput{TunnelID: input.TunnelID})
		if err != nil && out.Tunnel.TunnelID == "" {
			return res, TunnelPolyOutput{}, err
		}
		if res != nil {
			return res, TunnelPolyOutput{}, err
		}
		st := out.Tunnel
		return nil, TunnelPolyOutput{Tunnel: &st}, err
	default:
		return nil, TunnelPolyOutput{}, fmt.Errorf("unsupported tunnel action %q (expected create, list, status, or stop)", input.Action)
	}
}

func (r *Runtime) resolveTunnelNode(ctx context.Context, selector string) (string, error) {
	if r.tunnels == nil {
		return "", errors.New("SSH tunnel tools are available only over stdio")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
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
	if r.tunnels == nil {
		return nil, TunnelOutput{}, errors.New("SSH tunnel tools are available only over stdio")
	}
	validateReqID := input.RequestID
	if validateReqID == "" {
		validateReqID = "unassigned-request-id"
	}
	spec, err := tunnel.Normalize(tunnel.Spec{
		RequestID:  validateReqID,
		NodeID:     input.NodeID,
		Mode:       input.Mode,
		ListenHost: input.ListenHost,
		ListenPort: input.ListenPort,
		TargetHost: input.TargetHost,
		TargetPort: input.TargetPort,
		TTLSeconds: input.TTLSeconds,
	})
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
	if input.RequestID == "" {
		spec.RequestID = r.deterministicTunnelRequestID(spec)
	} else {
		spec.RequestID = input.RequestID
	}
	if existing, found, err := r.tunnels.Retry(spec); found || err != nil {
		return nil, TunnelOutput{Tunnel: existing}, err
	}
	ctx, op, err := r.operationContext(ctx, view, "tunnel", spec)
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

func (r *Runtime) deterministicTunnelRequestID(spec tunnel.Spec) string {
	var existing []tunnel.Status
	if r.tunnels != nil {
		existing = r.tunnels.List(spec.NodeID, "")
	}
	existingByID := make(map[string]tunnel.Status, len(existing))
	for _, st := range existing {
		existingByID[st.RequestID] = st
	}
	for counter := 0; ; counter++ {
		data := fmt.Sprintf("tunnel:%s:%s:%s:%d:%s:%d:%d:%d",
			spec.NodeID, spec.Mode, spec.ListenHost, spec.ListenPort,
			spec.TargetHost, spec.TargetPort, spec.TTLSeconds, counter)
		sum := sha256.Sum256([]byte(data))
		reqID := hex.EncodeToString(sum[:16])
		st, ok := existingByID[reqID]
		if !ok {
			return reqID
		}
		if st.FinishedAt.IsZero() {
			return reqID
		}
	}
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
	snapshot := r.tunnels.List(input.NodeID, input.State)
	risk := guardrail.RiskInput{Action: "list", NodeID: input.NodeID, Details: "state=" + input.State}
	if input.NodeID == "" {
		for _, status := range snapshot {
			risk.NodeIDs = append(risk.NodeIDs, status.NodeID)
		}
		slices.Sort(risk.NodeIDs)
		risk.NodeIDs = slices.Compact(risk.NodeIDs)
	}
	return withMetadata(r, "tunnel",
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
	return withMetadata(r, "tunnel",
		func(in TunnelInput) guardrail.RiskInput {
			return guardrail.RiskInput{Action: "status", NodeID: status.NodeID, Details: "tunnelID=" + in.TunnelID}
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
	risk.ToolName = "tunnel"
	risk.Action = "stop"
	risk.Details += "; tunnelID=" + input.TunnelID
	view, err := r.resolve(ctx, nil)
	if err != nil {
		return nil, TunnelOutput{}, err
	}
	ctx, op, err := r.operationContext(ctx, view, "tunnel", struct {
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
		status.AuditError = auditErr.Error()
	}
	return nil, TunnelOutput{Tunnel: status}, err
}

func (r *Runtime) registerTunnels(server *mcp.Server) {
	if r.http != nil {
		return
	}
	notDestructive := false
	mcp.AddTool(server, &mcp.Tool{
		Name:        "tunnel",
		Description: "Manage process-owned SSH TCP port forwarding tunnels over stdio (-L local or -R remote). Actions: 'create', 'list', 'status', 'stop'.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive, IdempotentHint: true},
	}, r.tunnelHandler)
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
