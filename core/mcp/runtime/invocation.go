package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/ports"
)

type operationKey struct{}
type operation struct {
	snapshot ports.OperationSnapshot
	binding  ports.Binding
	permit   ports.Permit
}

// ClientIdentity is the verified client and credential attached to an HTTP
// tool invocation. IDs contain no bearer secret and survive detached SDK calls.
type ClientIdentity struct{ ClientID, TokenID string }
type clientIdentityKey struct{}

func ClientIdentityFromContext(ctx context.Context) (ClientIdentity, bool) {
	identity, ok := ctx.Value(clientIdentityKey{}).(ClientIdentity)
	return identity, ok
}

func (r *Runtime) scope(ctx context.Context) string {
	if r.http != nil {
		if r.http.TokenVerifier != nil {
			identity, _ := ClientIdentityFromContext(ctx)
			return identity.ClientID
		}
		return r.http.scope
	}
	return r.provider.DomainID()
}

func (r *Runtime) toolContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, r.toolTimeout)
	stop := context.AfterFunc(r.ctx, cancel)
	if r.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

func (r *Runtime) resolve(ctx context.Context, selectors []string) (ports.OperationSnapshot, error) {
	view, err := r.provider.Resolve(ctx, ports.ResolveRequest{Selectors: slices.Clone(selectors)})
	if err != nil {
		return ports.OperationSnapshot{}, fmt.Errorf("resolve MCP operation: %w", err)
	}
	view = view.Clone()
	if view.DomainID != r.provider.DomainID() {
		return ports.OperationSnapshot{}, errors.New("MCP operation publication domain changed")
	}
	if err := guardrail.ValidateConfig(&view.Policy); err != nil {
		return ports.OperationSnapshot{}, err
	}
	return view, nil
}

func (r *Runtime) operationContext(ctx context.Context, view ports.OperationSnapshot, tool string, input any) (context.Context, *operation, error) {
	binding, err := ports.Bind(view, r.scope(ctx), tool, input)
	if err != nil {
		return nil, nil, err
	}
	digest, err := binding.Digest()
	if err != nil {
		return nil, nil, err
	}
	op := &operation{snapshot: view.Clone(), binding: binding}
	return context.WithValue(guardrail.WithPolicy(ctx, view.Policy, digest), operationKey{}, op), op, nil
}

func withOperation[In, Out any](r *Runtime, g *guardrail.Guardrail, tool string, risk func(In) guardrail.RiskInput, handler mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(parent context.Context, request *mcp.CallToolRequest, input In) (*mcp.CallToolResult, Out, error) {
		var zero Out
		ctx, cancel := r.toolContext(parent)
		defer cancel()
		ri := risk(input)
		selectors := slices.Clone(ri.NodeIDs)
		if ri.NodeID != "" {
			selectors = append(selectors, ri.NodeID)
		}
		view, err := r.resolve(ctx, selectors)
		if err != nil {
			return nil, zero, err
		}
		if ri.NodeID != "" {
			ri.NodeID, _, err = view.Resolve(ri.NodeID)
			if err != nil {
				return nil, zero, err
			}
		}
		for i, id := range ri.NodeIDs {
			ri.NodeIDs[i], _, err = view.Resolve(id)
			if err != nil {
				return nil, zero, err
			}
		}
		ctx, op, err := r.operationContext(ctx, view, tool, input)
		if err != nil {
			return nil, zero, err
		}
		return guardrail.WithGuardrail(g, tool, func(In) guardrail.RiskInput { return ri },
			func(work context.Context, req *mcp.CallToolRequest, in In) (_ *mcp.CallToolResult, _ Out, retErr error) {
				permission, err := r.enter(work, op.snapshot, op.binding, ports.Execute, guardrail.OperationID(work))
				if err != nil {
					return nil, zero, err
				}
				defer func() { retErr = errors.Join(retErr, permission.Close()) }()
				active := *op
				active.permit = permission
				admitted, stop, err := ports.WorkContext(work, permission, ports.Execute)
				if err != nil {
					return nil, zero, err
				}
				defer stop()
				return handler(context.WithValue(admitted, operationKey{}, &active), req, in)
			})(ctx, request, input)
	}
}

// Metadata/history operations use current policy even when their recorded
// nodes have been deleted. They cannot acquire remote execution capabilities.
func withMetadata[In, Out any](r *Runtime, tool string, risk func(In) guardrail.RiskInput, handler mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(parent context.Context, request *mcp.CallToolRequest, input In) (*mcp.CallToolResult, Out, error) {
		var zero Out
		ctx, cancel := r.toolContext(parent)
		defer cancel()
		view, err := r.resolve(ctx, nil)
		if err != nil {
			return nil, zero, err
		}
		ri := risk(input)
		ctx, op, err := r.operationContext(ctx, view, tool, struct {
			Input In
			Risk  guardrail.RiskInput
		}{input, ri})
		if err != nil {
			return nil, zero, err
		}
		return guardrail.WithGuardrail(r.guardrail, tool, func(In) guardrail.RiskInput { return ri },
			func(work context.Context, request *mcp.CallToolRequest, input In) (_ *mcp.CallToolResult, _ Out, retErr error) {
				permission, err := r.enter(work, op.snapshot, op.binding, ports.Inspect, guardrail.OperationID(work))
				if err != nil {
					return nil, zero, err
				}
				defer func() { retErr = errors.Join(retErr, permission.Close()) }()
				admitted, stop, err := ports.WorkContext(work, permission, ports.Inspect)
				if err != nil {
					return nil, zero, err
				}
				defer stop()
				return handler(admitted, request, input)
			})(ctx, request, input)
	}
}

type ownedPermit struct {
	ports.Permit
	close func() error
}

func (p *ownedPermit) Close() error { return p.close() }

func (r *Runtime) enter(ctx context.Context, view ports.OperationSnapshot, binding ports.Binding, phase ports.Phase, operationID string, previous ...ports.Permit) (ports.Permit, error) {
	if len(previous) > 1 {
		return nil, errors.New("only one prior operation permit may be handed off")
	}
	if operationID == "" {
		var token [16]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, err
		}
		operationID = hex.EncodeToString(token[:])
	}
	work := ctx
	cancel := func() {}
	if _, ok := work.Deadline(); !ok {
		work, cancel = context.WithTimeout(ctx, r.toolTimeout)
	}
	admission := ports.Admission{OperationID: operationID, Phase: phase, Snapshot: view.Clone(), Binding: binding}
	if len(previous) == 1 {
		admission.Previous = previous[0]
	}
	permit, err := r.gate.Enter(work, admission)
	if err != nil || ports.Nil(permit) {
		cancel()
		if !ports.Nil(permit) {
			err = errors.Join(err, permit.Close())
		}
		if err == nil {
			err = errors.New("MCP gate returned no permit")
		}
		return nil, err
	}
	if err := validateGrantedPermit(work, permit, binding, phase); err != nil {
		cancel()
		return nil, errors.Join(err, permit.Close())
	}
	return &ownedPermit{Permit: permit, close: sync.OnceValue(func() error { defer cancel(); return permit.Close() })}, nil
}

func validateGrantedPermit(ctx context.Context, permit ports.Permit, binding ports.Binding, phase ports.Phase) error {
	if permit.Binding() != binding || permit.Phase() != phase {
		return ports.ErrStaleBinding
	}
	if err := binding.Validate(permit.Snapshot()); err != nil {
		return err
	}
	granted := permit.Context()
	if granted == nil {
		return errors.New("MCP gate returned a permit without context")
	}
	deadline, ok := granted.Deadline()
	if !ok {
		return errors.New("MCP gate returned an unbounded permit")
	}
	if requested, ok := ctx.Deadline(); ok && deadline.After(requested) {
		return errors.New("MCP gate extended the requested deadline")
	}
	return granted.Err()
}

func currentOperation(ctx context.Context) (*operation, error) {
	op, ok := ctx.Value(operationKey{}).(*operation)
	if !ok || ports.Nil(op.permit) {
		return nil, errors.New("MCP execution requires an admitted operation")
	}
	return op, nil
}

func (r *Runtime) runCommand(ctx context.Context, nodeID, command string, sudo bool) (string, error) {
	op, err := currentOperation(ctx)
	if err != nil {
		return "", err
	}
	result, err := r.backend.Run(ctx, op.permit, nodeID, ports.Command{Text: command, Sudo: sudo})
	return result.Output, FormatMCPError(err)
}

func (r *Runtime) getMCPSFTPClient(ctx context.Context, nodeID string) (ports.FileSession, error) {
	op, err := currentOperation(ctx)
	if err != nil {
		return nil, err
	}
	return r.backend.OpenFiles(ctx, op.permit, nodeID)
}

func (r *Runtime) commandResult(ctx context.Context, nodeID, command string, sudo bool) (ports.CommandResult, error) {
	op, err := currentOperation(ctx)
	if err != nil {
		return ports.CommandResult{}, err
	}
	result, err := r.backend.Run(ctx, op.permit, nodeID, ports.Command{Text: command, Sudo: sudo})
	return result, FormatMCPError(err)
}
