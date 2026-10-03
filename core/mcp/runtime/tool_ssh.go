package runtime

import (
	"context"
	"fmt"

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
	ctx, op, err := r.operationContext(ctx, view, "xops_list_nodes", input)
	if err != nil {
		return nil, ListNodesOutput{}, err
	}
	return guardrail.WithGuardrail(r.guardrail, "xops_list_nodes", func(ListNodesInput) guardrail.RiskInput { return guardrail.RiskInput{} },
		func(work context.Context, _ *mcp.CallToolRequest, _ ListNodesInput) (_ *mcp.CallToolResult, _ ListNodesOutput, retErr error) {
			permit, err := r.enter(work, op.snapshot, op.binding, ports.Inspect, guardrail.OperationID(work))
			if err != nil {
				return nil, ListNodesOutput{}, err
			}
			defer func() { retErr = errors.Join(retErr, permit.Close()) }()
			return nil, ListNodesOutput{Nodes: inventory.Nodes, Status: "success"}, nil
		})(ctx, req, input)
}

type SshRunInput struct {
	NodeID  string `json:"nodeID" jsonschema:"The ID of the node to execute command on"`
	Command string `json:"command" jsonschema:"The shell command to execute"`
	Sudo    bool   `json:"sudo,omitempty" jsonschema:"Whether to use sudo to execute the command"`
}

type SshRunOutput struct {
	Output string `json:"output" jsonschema:"Command stdout/stderr"`
	Status string `json:"status" jsonschema:"Operation status"`
	Error  string `json:"error,omitempty" jsonschema:"Error message if failed"`
}

func (r *Runtime) sshRunHandler(ctx context.Context, req *mcp.CallToolRequest, input SshRunInput) (*mcp.CallToolResult, SshRunOutput, error) {
	if input.NodeID == "" || input.Command == "" {
		return nil, SshRunOutput{}, fmt.Errorf("nodeID and command are required")
	}

	result, execErr := r.commandResult(ctx, input.NodeID, input.Command, input.Sudo)
	if execErr != nil && !result.Connected {
		return nil, SshRunOutput{}, execErr
	}
	output := result.Output

	errStr := ""
	status := "success"
	if execErr != nil {
		errStr = FormatMCPError(execErr).Error()
		status = "failed"
	}

	return nil, SshRunOutput{
		Output: output,
		Status: status,
		Error:  errStr,
	}, nil
}

func (r *Runtime) registerSSH(server *mcp.Server, g *guardrail.Guardrail) {
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_list_nodes",
			Description: "List all available SSH nodes managed by XOps, optionally filtered by tag. Returns an array of node IDs that can be used with xops_ssh_run.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		},
		r.listNodesHandler,
	)

	destructive := true
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_ssh_run",
			Description: "Execute a shell command on a specific SSH node managed by XOps. Returns the command output.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive},
		},
		withOperation(r, g, "xops_ssh_run",
			func(in SshRunInput) guardrail.RiskInput {
				return guardrail.RiskInput{
					NodeID:  in.NodeID,
					Command: in.Command,
					Sudo:    in.Sudo,
				}
			},
			r.sshRunHandler,
		),
	)
}
