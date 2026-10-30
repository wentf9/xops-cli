package runtime

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/ports"
)

type ListNodesInput struct {
	Tag string `json:"tag,omitempty" jsonschema:"Filter nodes by tag. If empty, lists all nodes."`
}

type NodeInfo = ports.NodeInfo

type ListNodesOutput struct {
	Nodes  []NodeInfo `json:"nodes" jsonschema:"List of available nodes with detailed information"`
	Status string     `json:"status" jsonschema:"Operation status"`
}

func (r *Runtime) listNodesHandler(parent context.Context, req *mcp.CallToolRequest, input ListNodesInput) (*mcp.CallToolResult, ListNodesOutput, error) {
	ctx, cancel := r.toolContext(parent)
	defer cancel()
	inventory, err := r.provider.List(ctx, ports.NodeQuery{Tag: input.Tag})
	if err != nil {
		return nil, ListNodesOutput{}, err
	}
	inventory = inventory.Clone()
	if inventory.DomainID != r.provider.DomainID() {
		return nil, ListNodesOutput{}, errors.New("MCP inventory publication domain changed")
	}
	if err := guardrail.ValidateConfig(&inventory.Policy); err != nil {
		return nil, ListNodesOutput{}, err
	}
	view := ports.OperationSnapshot{DomainID: inventory.DomainID, Revision: inventory.Revision, PolicyRevision: inventory.PolicyRevision, Policy: inventory.Policy}
	ctx, op, err := r.operationContext(ctx, view, "nodes", input)
	if err != nil {
		return nil, ListNodesOutput{}, err
	}
	return guardrail.WithGuardrail(r.guardrail, "nodes", func(ListNodesInput) guardrail.RiskInput { return guardrail.RiskInput{} },
		func(work context.Context, _ *mcp.CallToolRequest, _ ListNodesInput) (_ *mcp.CallToolResult, _ ListNodesOutput, retErr error) {
			permit, err := r.enter(work, op.snapshot, op.binding, ports.Inspect, guardrail.OperationID(work))
			if err != nil {
				return nil, ListNodesOutput{}, err
			}
			defer func() { retErr = errors.Join(retErr, permit.Close()) }()
			return nil, ListNodesOutput{Nodes: inventory.Nodes, Status: "success"}, nil
		})(ctx, req, input)
}

func (r *Runtime) registerNodes(server *mcp.Server) {
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "nodes",
			Description: "List all available SSH nodes managed by XOps, optionally filtered by tag.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		},
		r.listNodesHandler,
	)
}
