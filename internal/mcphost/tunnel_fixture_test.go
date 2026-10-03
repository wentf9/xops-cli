package mcphost

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/concurrent"
	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func runtimeTestProvider(id string) *config.Provider {
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Nodes = concurrent.NewMap[string, models.Node](concurrent.HashString)
	cfg.Nodes.Set(id, models.Node{HostRef: "host", IdentityRef: "identity"})
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "operator"})
	cfg.Guardrail = &corepolicy.Config{Enabled: false}
	return config.NewProviderWithoutOpenSSH(cfg)
}

func callTunnelList(t *testing.T, client *mcp.ClientSession, input mcpruntime.ListTunnelsInput) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "xops_tunnel_list", Arguments: input})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func decodeTunnelList(t *testing.T, result *mcp.CallToolResult) []tunnel.Status {
	t.Helper()
	if result.IsError {
		t.Fatalf("list failed: %+v", result.Content)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var output mcpruntime.ListTunnelsOutput
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatal(err)
	}
	return output.Tunnels
}
func newTunnelRuntime(t *testing.T, fixture *tunnelFixture) *mcpruntime.Runtime {
	t.Helper()
	r, err := newTestRuntime(t.Context(), Config{Provider: fixture.provider})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func connectRuntimeTestClient(t *testing.T, r *mcpruntime.Runtime) *mcp.ClientSession {
	return protocolClient(t, r, "2025-11-25", nil)
}
func tunnelListPolicyClient(t *testing.T, r *mcpruntime.Runtime, version string, options *mcp.ClientOptions) *mcp.ClientSession {
	return protocolClient(t, r, version, options)
}
func callTunnelTool(t *testing.T, client *mcp.ClientSession, name string, input any) tunnel.Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var output mcpruntime.TunnelOutput
	if _, err := callTool(ctx, client, name, input, &output); err != nil {
		t.Fatal(err)
	}
	return output.Tunnel
}
func tunnelTestInput(t *testing.T, address, mode, requestID string) mcpruntime.CreateTunnelInput {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return mcpruntime.CreateTunnelInput{RequestID: requestID, NodeID: "node", Mode: mode, ListenHost: "127.0.0.1", TargetHost: host, TargetPort: port, TTLSeconds: 60}
}
func startTunnelEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() {
					if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Error(err)
					}
				}()
				deadline, _ := ctx.Deadline()
				if err := conn.SetDeadline(deadline); err != nil {
					t.Error(err)
					return
				}
				stop := context.AfterFunc(ctx, func() {
					if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Error(err)
					}
				})
				defer stop()
				if _, err := io.Copy(conn, conn); err != nil && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
					t.Log(err)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		workers.Wait()
	})
	return listener.Addr().String()
}
func assertTunnelEcho(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	var data [4]byte
	if _, err := io.ReadFull(conn, data[:]); err != nil {
		t.Fatal(err)
	}
	if string(data[:]) != "ping" {
		t.Fatal("forward corrupted data")
	}
}
