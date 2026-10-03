package mcpserver

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
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

// Legacy integration fixtures now traverse the actual public protocol entry
// point rather than constructing or invoking private runtime state.
type legacyRuntimeFixture struct {
	runtime   *Runtime
	client    *mcp.ClientSession
	connector *ssh.Connector
}

func newLegacyRuntimeFixture(t *testing.T, ctx context.Context, provider config.ConfigProvider, log logger.DebugLogger, connector *ssh.Connector) *legacyRuntimeFixture {
	t.Helper()
	cfg := provider.Snapshot()
	cfg.Guardrail = &config.GuardrailConfig{Enabled: false}
	r, err := NewRuntime(ctx, WithConfigProvider(config.NewProviderWithoutOpenSSH(cfg)), WithLogger(log))
	if err != nil {
		t.Fatal(err)
	}
	client := legacyProtocolClient(t, r, "2025-11-25", nil)
	return &legacyRuntimeFixture{runtime: r, client: client, connector: connector}
}

func legacyProtocolClient(t *testing.T, r *Runtime, protocol string, options *mcp.ClientOptions) *mcp.ClientSession {
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
			t.Error("legacy protocol worker did not stop")
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "legacy-contract", Version: "1"}, options)
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

func legacyCall(ctx context.Context, client *mcp.ClientSession, name string, input, output any) (*mcp.CallToolResult, error) {
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

func (f *legacyRuntimeFixture) listNodesHandler(ctx context.Context, _ *mcp.CallToolRequest, input ListNodesInput) (*mcp.CallToolResult, ListNodesOutput, error) {
	var output ListNodesOutput
	result, err := legacyCall(ctx, f.client, "xops_list_nodes", input, &output)
	return result, output, err
}
func (f *legacyRuntimeFixture) sshRunHandler(ctx context.Context, _ *mcp.CallToolRequest, input SshRunInput) (*mcp.CallToolResult, SshRunOutput, error) {
	var output SshRunOutput
	result, err := legacyCall(ctx, f.client, "xops_ssh_run", input, &output)
	return result, output, err
}
func (f *legacyRuntimeFixture) connectMCPNode(ctx context.Context, nodeID string) (*ssh.Client, error) {
	client, err := f.connector.Connect(ctx, nodeID)
	return client, FormatMCPError(err)
}
