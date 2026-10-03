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
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
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
			provider := config.NewProviderWithOpenSSHParser(cfg, parser)
			host := newLegacyHost(legacyConfig{provider: provider})
			r, err := NewRuntime(t.Context(), WithConfigProvider(provider))
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
				if got, err := resolveLegacyTestNode(t.Context(), host, tc.selector); err != nil || got != tc.want {
					t.Errorf("resolve %q = %q, %v; want %q", tc.selector, got, err, tc.want)
				}
			}
			for _, selector := range []string{"openssh:", "openssh:broken", "openssh:web:65536"} {
				if _, err := resolveLegacyTestNode(t.Context(), host, selector); err == nil || !strings.Contains(err.Error(), "config") {
					t.Errorf("canonical ID %q did not reach connection validation: %v", selector, err)
				}
			}
			for _, selector := range []string{"openssh:web ", "openssh: web", "openssh:web\u00a0", "web ", "openssh:\tweb", "openssh:web\n", "openssh:fixture @web", "openssh:fixture@ web"} {
				if _, err := resolveLegacyTestNode(t.Context(), host, selector); err == nil || !strings.Contains(err.Error(), "whitespace or control") {
					t.Errorf("noncanonical ID %q was not rejected: %v", selector, err)
				}
			}
		})
	}
}

func tunnelOpenSSHFixture(t *testing.T, policies ...*config.GuardrailConfig) *legacyTunnelFixture {
	t.Helper()
	home := isolateMCPTestEnvironment(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptossh.MarshalPrivateKey(private, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{PublicKeys: []cryptossh.PublicKey{signer.PublicKey()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	hostname, port, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	writeKnownHosts(t, home, hostname, port, server.HostKey)
	text := fmt.Sprintf("Host web\n HostName %s\n Port %s\n User fixture\n IdentityFile %q\n", hostname, port, filepath.ToSlash(keyPath))
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	cfg := runtimeTestProvider("node").Snapshot()
	if len(policies) > 0 {
		cfg.Guardrail = policies[0]
	}
	return &legacyTunnelFixture{provider: config.NewProviderWithOpenSSHParser(cfg, parser), server: server}
}

type legacyTunnelFixture struct {
	provider *config.Provider
	server   *sshfixture.Server
}

func resolveLegacyTestNode(ctx context.Context, host *legacyHost, selector string) (string, error) {
	view, err := host.Resolve(ctx, ports.ResolveRequest{Selectors: []string{selector}})
	if err != nil {
		return "", err
	}
	id, _, err := view.Resolve(selector)
	return id, err
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
			if f.server.Forwards.Load() != 0 {
				t.Fatal("denied OpenSSH selector opened a forward")
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
