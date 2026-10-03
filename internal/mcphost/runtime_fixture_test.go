package mcphost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	corelog "github.com/wentf9/xops-cli/core/log"
	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

func newTestRuntime(ctx context.Context, cfg Config) (*mcpruntime.Runtime, error) {
	opts, err := cfg.RuntimeOptions()
	if err != nil {
		return nil, err
	}
	return mcpruntime.NewRuntime(ctx, opts...)
}

// CLI integration fixtures traverse the actual public protocol entry
// point rather than constructing or invoking private runtime state.
type runtimeFixture struct {
	runtime   *mcpruntime.Runtime
	client    *mcp.ClientSession
	connector *ssh.Connector
}

func newRuntimeFixture(t *testing.T, ctx context.Context, provider config.ConfigProvider, log corelog.DebugLogger, connector *ssh.Connector) *runtimeFixture {
	t.Helper()
	cfg := provider.Snapshot()
	cfg.Guardrail = &corepolicy.Config{Enabled: false}
	r, err := newTestRuntime(ctx, Config{Provider: config.NewProviderWithoutOpenSSH(cfg), Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	client := protocolClient(t, r, "2025-11-25", nil)
	return &runtimeFixture{runtime: r, client: client, connector: connector}
}

func protocolClient(t *testing.T, r *mcpruntime.Runtime, protocol string, options *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	done := make(chan error, 1)
	// Runtime shutdown and transport closure terminate Run; cleanup joins it.
	go func() { done <- r.Run(serverTransport) }()
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("CLI protocol worker did not stop")
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "cli-contract", Version: "1"}, options)
	session, err := client.Connect(ctx, clientTransport, &mcp.ClientSessionOptions{ProtocolVersion: protocol})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Error(err)
		}
	})
	return session
}

func callTool(ctx context.Context, client *mcp.ClientSession, name string, input, output any) (*mcp.CallToolResult, error) {
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: input})
	if err != nil {
		return nil, err
	}
	if result.IsError {
		var messages []string
		for _, content := range result.Content {
			if text, ok := content.(*mcp.TextContent); ok {
				messages = append(messages, text.Text)
			}
		}
		return result, fmt.Errorf("MCP tool failed: %s", strings.Join(messages, "; "))
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return result, err
	}
	return result, json.Unmarshal(encoded, output)
}

func (f *runtimeFixture) listNodesHandler(ctx context.Context, _ *mcp.CallToolRequest, input mcpruntime.ListNodesInput) (*mcp.CallToolResult, mcpruntime.ListNodesOutput, error) {
	var output mcpruntime.ListNodesOutput
	result, err := callTool(ctx, f.client, "xops_list_nodes", input, &output)
	return result, output, err
}
func (f *runtimeFixture) sshRunHandler(ctx context.Context, _ *mcp.CallToolRequest, input mcpruntime.SshRunInput) (*mcp.CallToolResult, mcpruntime.SshRunOutput, error) {
	var output mcpruntime.SshRunOutput
	result, err := callTool(ctx, f.client, "xops_ssh_run", input, &output)
	return result, output, err
}
func (f *runtimeFixture) connectMCPNode(ctx context.Context, nodeID string) (*ssh.Client, error) {
	client, err := f.connector.Connect(ctx, nodeID)
	return client, mcpruntime.FormatMCPError(err)
}
