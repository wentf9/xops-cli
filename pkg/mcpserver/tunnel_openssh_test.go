package mcpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptossh "golang.org/x/crypto/ssh"
)

func TestResolveTunnelOpenSSHNode(t *testing.T) {
	for _, collision := range []bool{false, true} {
		t.Run(fmt.Sprint(collision), func(t *testing.T) {
			cfg := runtimeTestProvider("node").Snapshot()
			aliases := []string{"alias"}
			if collision {
				aliases = append(aliases, "web", "openssh:web")
			}
			cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity", Alias: aliases})
			parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host web\n HostName 192.0.2.2\n User fixture\n Port 2222\nHost broken\n Port invalid\n"))
			if err != nil {
				t.Fatal(err)
			}
			r, err := NewRuntime(t.Context(), WithConfigProvider(config.NewProviderWithOpenSSHParser(cfg, parser)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			webID := "openssh:web"
			if collision {
				webID = "node"
			}
			for _, tc := range []struct{ selector, want string }{
				{"web", webID}, {"openssh:web", "openssh:web"}, {"node", "node"}, {"alias", "node"},
				{"openssh:operator@web:2200", "openssh:operator@web:2200"},
			} {
				if got, err := r.resolveTunnelNode(tc.selector); err != nil || got != tc.want {
					t.Errorf("resolve %q = %q, %v; want %q", tc.selector, got, err, tc.want)
				}
			}
			for _, selector := range []string{"openssh:", "openssh:broken", "openssh:web:65536"} {
				if _, err := r.resolveTunnelNode(selector); err == nil || !strings.Contains(err.Error(), "resolve tunnel connection") {
					t.Errorf("canonical ID %q did not reach connection validation: %v", selector, err)
				}
			}
			for _, selector := range []string{"openssh:web ", "openssh: web", "openssh:web\u00a0", "web ", "openssh:\tweb", "openssh:web\n", "openssh:fixture @web", "openssh:fixture@ web"} {
				if _, err := r.resolveTunnelNode(selector); err == nil || !strings.Contains(err.Error(), "whitespace or control") {
					t.Errorf("noncanonical ID %q was not rejected: %v", selector, err)
				}
			}
		})
	}
}

func tunnelOpenSSHFixture(t *testing.T, policy ...*config.GuardrailConfig) *tunnelSSHFixture {
	t.Helper()
	f := startTunnelSSHFixture(t, 0)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptossh.MarshalPrivateKey(key, "tunnel fixture")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(f.address)
	if err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("Host web\n HostName %s\n Port %s\n User fixture\n IdentityFile %q\n", host, port, filepath.ToSlash(keyPath))
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.provider.Snapshot()
	if len(policy) != 0 {
		cfg.Guardrail = policy[0]
	}
	f.provider = config.NewProviderWithOpenSSHParser(cfg, parser)
	return f
}

func TestMCPTunnelOpenSSHWhitespaceCannotBypassPolicy(t *testing.T) {
	for _, protocol := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(protocol, func(t *testing.T) {
			f := tunnelOpenSSHFixture(t, &config.GuardrailConfig{
				Enabled: true, ApprovalThreshold: "dangerous", NoElicitFallback: guardrail.FallbackDeny,
				NodeOverrides: map[string]config.NodeGuardrailCfg{
					"openssh:web": {ApprovalThreshold: "safe"}, "openssh:fixture@web": {ApprovalThreshold: "safe"},
				},
			})
			r := newTunnelRuntime(t, f)
			client := tunnelListPolicyClient(t, r, protocol, nil)
			target := startTunnelEcho(t)
			for i, nodeID := range []string{
				"openssh:web", "openssh:web ", "openssh: web", "openssh:web\u00a0", "web ",
				"openssh:fixture@web", "openssh:fixture @web", "openssh:fixture@ web", "openssh:fixture@web ",
			} {
				input := tunnelTestInput(t, target, "local", fmt.Sprintf("whitespace-%d", i))
				input.NodeID = nodeID
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "xops_tunnel_create", Arguments: input})
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				if !result.IsError {
					t.Errorf("node %q bypassed approval: %+v", nodeID, result.StructuredContent)
				}
			}
			for _, task := range r.tunnels.List("", "") {
				if task.State == "running" {
					assertTunnelEcho(t, task.ListenAddress)
				}
				t.Errorf("unapproved tunnel created: node=%q state=%s", task.NodeID, task.State)
			}
		})
	}
}

func TestMCPTunnelCanonicalOpenSSHIDReuse(t *testing.T) {
	for _, mode := range []string{"local", "remote"} {
		t.Run(mode, func(t *testing.T) {
			f := tunnelOpenSSHFixture(t)
			r := newTunnelRuntime(t, f)
			client := connectRuntimeTestClient(t, r)
			input := tunnelTestInput(t, startTunnelEcho(t), mode, "alias-create")
			input.NodeID = "web"
			created := callTunnelTool(t, client, "xops_tunnel_create", input)
			if created.State != "running" || created.NodeID != "openssh:web" {
				t.Fatalf("alias creation: %+v", created)
			}
			assertTunnelEcho(t, created.ListenAddress)
			input.NodeID = created.NodeID
			retry := callTunnelTool(t, client, "xops_tunnel_create", input)
			if retry.TunnelID != created.TunnelID || retry.ListenAddress != created.ListenAddress {
				t.Fatal("canonical retry did not return the existing tunnel")
			}
			for _, selector := range []string{"web", created.NodeID} {
				list := decodeTunnelList(t, callTunnelList(t, client, ListTunnelsInput{NodeID: selector}))
				if len(list) != 1 || list[0].TunnelID != created.TunnelID {
					t.Fatalf("filter %q returned %+v", selector, list)
				}
			}
			input.RequestID = "canonical-create"
			direct := callTunnelTool(t, client, "xops_tunnel_create", input)
			if direct.State != "running" || direct.NodeID != created.NodeID || direct.TunnelID == created.TunnelID {
				t.Fatalf("canonical creation: %+v", direct)
			}
			assertTunnelEcho(t, direct.ListenAddress)
		})
	}
}
