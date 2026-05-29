package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/models"
)

type ListNodesInput struct {
	Tag string `json:"tag,omitempty" jsonschema:"Filter nodes by tag. If empty, lists all nodes."`
}

type NodeInfo struct {
	ID        string   `json:"id" jsonschema:"Node ID / Name"`
	Alias     []string `json:"alias,omitempty" jsonschema:"Node aliases"`
	Address   string   `json:"address" jsonschema:"Host address and port"`
	User      string   `json:"user" jsonschema:"SSH user"`
	AuthType  string   `json:"authType" jsonschema:"Authentication type"`
	ProxyJump string   `json:"proxyJump,omitempty" jsonschema:"Proxy jump host"`
	Tags      []string `json:"tags,omitempty" jsonschema:"Node tags"`
}

type ListNodesOutput struct {
	Nodes  []NodeInfo `json:"nodes" jsonschema:"List of available nodes with detailed information"`
	Status string     `json:"status" jsonschema:"Operation status"`
}

func listNodesHandler(ctx context.Context, req *mcp.CallToolRequest, input ListNodesInput) (*mcp.CallToolResult, ListNodesOutput, error) {
	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, ListNodesOutput{}, fmt.Errorf("failed to load config: %w", err)
	}

	var nodeMap map[string]models.Node
	if input.Tag != "" {
		nodeMap = provider.GetNodesByTag(input.Tag)
	} else {
		nodeMap = provider.ListNodes()
	}

	var nodes []NodeInfo
	for nodeID, node := range nodeMap {
		host, _ := provider.GetHost(nodeID)
		identity, _ := provider.GetIdentity(nodeID)

		nodes = append(nodes, NodeInfo{
			ID:        nodeID,
			Alias:     node.Alias,
			Address:   fmt.Sprintf("%s:%d", host.Address, host.Port),
			User:      identity.User,
			AuthType:  identity.AuthType,
			ProxyJump: node.ProxyJump,
			Tags:      node.Tags,
		})
	}

	return nil, ListNodesOutput{
		Nodes:  nodes,
		Status: "success",
	}, nil
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

func sshRunHandler(ctx context.Context, req *mcp.CallToolRequest, input SshRunInput) (*mcp.CallToolResult, SshRunOutput, error) {
	if input.NodeID == "" || input.Command == "" {
		return nil, SshRunOutput{}, fmt.Errorf("nodeID and command are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, SshRunOutput{}, fmt.Errorf("failed to load config: %w", err)
	}

	_, ok := provider.GetNode(input.NodeID)
	if !ok {
		return nil, SshRunOutput{}, fmt.Errorf("node '%s' not found", input.NodeID)
	}

	connector := adapter.NewConnector(provider)
	defer connector.CloseAll()

	client, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, SshRunOutput{}, fmt.Errorf("failed to connect to node: %w", err)
	}

	var output string
	var execErr error

	if input.Sudo {
		output, execErr = client.RunWithSudo(ctx, input.Command)
	} else {
		output, execErr = client.Run(ctx, input.Command)
	}

	errStr := ""
	status := "success"
	if execErr != nil {
		errStr = execErr.Error()
		status = "failed"
	}

	return nil, SshRunOutput{
		Output: output,
		Status: status,
		Error:  errStr,
	}, nil
}

func RegisterSSH(server *mcp.Server, g *guardrail.Guardrail) {
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_list_nodes",
			Description: "List all available SSH nodes managed by XOps, optionally filtered by tag. Returns an array of node IDs that can be used with xops_ssh_run.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		},
		guardrail.WithGuardrail(g, "xops_list_nodes",
			func(in ListNodesInput) guardrail.RiskInput {
				return guardrail.RiskInput{}
			},
			listNodesHandler,
		),
	)

	destructive := true
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "xops_ssh_run",
			Description: "Execute a shell command on a specific SSH node managed by XOps. Returns the command output.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive},
		},
		guardrail.WithGuardrail(g, "xops_ssh_run",
			func(in SshRunInput) guardrail.RiskInput {
				return guardrail.RiskInput{
					NodeID:  in.NodeID,
					Command: in.Command,
					Sudo:    in.Sudo,
				}
			},
			sshRunHandler,
		),
	)
}
