package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"go.uber.org/goleak"
)

func runtimeTestProvider(nodeID string) *config.Provider {
	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)
	nodes.Set(nodeID, models.Node{HostRef: "host", IdentityRef: "identity"})
	hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	identities.Set("identity", models.Identity{User: "operator"})
	return config.NewProviderWithoutOpenSSH(&config.Configuration{
		Nodes: nodes, Hosts: hosts, Identities: identities,
		Guardrail: &config.GuardrailConfig{Enabled: false},
	})
}

func connectRuntimeTestClient(t *testing.T, r *Runtime) *mcp.ClientSession {
	t.Helper()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	if _, err := r.server.Connect(r.ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "runtime-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
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

func assertRuntimeNode(t *testing.T, session *mcp.ClientSession, nodeID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "xops_list_nodes", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("list nodes returned tool error: %+v", result)
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var output ListNodesOutput
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Nodes) != 1 || output.Nodes[0].ID != nodeID {
		t.Fatalf("nodes = %+v, want only %q", output.Nodes, nodeID)
	}
}

func TestRuntimeToolsAndShutdownAreIsolated(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	runtimes := make([]*Runtime, 2)
	sessions := make([]*mcp.ClientSession, 2)
	for i, nodeID := range []string{"first", "second"} {
		r, err := NewRuntime(t.Context(), WithConfigProvider(runtimeTestProvider(nodeID)))
		if err != nil {
			t.Fatal(err)
		}
		runtimes[i] = r
		t.Cleanup(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
		sessions[i] = connectRuntimeTestClient(t, r)
		assertRuntimeNode(t, sessions[i], nodeID)
	}
	if err := runtimes[0].Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtimes[0].Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
	if _, err := runtimes[0].getMCPConnector(); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed connector access = %v", err)
	}
	assertRuntimeNode(t, sessions[1], "second")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, err := sessions[1].ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"xops_list_nodes": true, "xops_ssh_run": true,
		"xops_read_file": true, "xops_write_file": true, "xops_upload": true, "xops_download": true,
		"xops_fs_ls": true, "xops_fs_mkdir": true, "xops_fs_touch": true,
		"xops_fs_mv": true, "xops_fs_rm": true, "xops_fs_cp": true,
	}
	for _, tool := range result.Tools {
		if !want[tool.Name] {
			t.Errorf("unexpected or duplicate tool %q", tool.Name)
		}
		delete(want, tool.Name)
	}
	if len(want) != 0 {
		t.Errorf("missing stdio tools: %v", want)
	}
}

func TestRuntimeRunStopsOnClose(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	r, err := NewRuntime(t.Context(), WithConfigProvider(runtimeTestProvider("node")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	done := make(chan error, 1)
	// Runtime cancellation closes the transport and joins this Run call below.
	go func() { done <- r.Run(serverTransport) }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "close-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Run did not stop after Close")
	}
}
