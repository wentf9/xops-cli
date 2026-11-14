package mcphost

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	cryptossh "golang.org/x/crypto/ssh"
)

func setupMCPGate4Providers(t *testing.T) (config.ConfigProvider, config.ConfigProvider, *sshfixture.Server) {
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
	block, err := cryptossh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 15*time.Second)
	t.Cleanup(cancel)
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		PublicKeys: []cryptossh.PublicKey{signer.PublicKey()},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})

	hostname, portStr, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	writeKnownHosts(t, home, hostname, portStr, server.HostKey)

	extraGlobalKH := filepath.Join(t.TempDir(), "custom_global_known_hosts")
	openSSHText := fmt.Sprintf(
		"Host web\n"+
			" HostName %s\n"+
			" Port %s\n"+
			" User fixture\n"+
			" IdentityFile %q\n"+
			" AddressFamily inet\n"+
			" ForwardAgent yes\n"+
			" Tunnel point-to-point\n"+
			" ExitOnForwardFailure yes\n"+
			" LocalForward 127.0.0.1:0 127.0.0.1:9\n"+
			" RemoteForward 127.0.0.1:0 127.0.0.1:9\n"+
			" DynamicForward 127.0.0.1:0\n"+
			" SendEnv *\n"+
			" SetEnv MCP_LEAK_OPENSSH=1\n"+
			" RemoteCommand echo leaked\n"+
			" EscapeChar ^A\n"+
			" RequestTTY force\n"+
			" VerifyHostKeyDNS yes\n"+
			" GlobalKnownHostsFile %q\n"+
			" StrictHostKeyChecking no\n"+
			" PermitLocalCommand yes\n"+
			" LocalCommand echo local-leak\n",
		hostname, portStr, filepath.ToSlash(keyPath), filepath.ToSlash(extraGlobalKH),
	)
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHText))
	if err != nil {
		t.Fatal(err)
	}
	cleanParser, err := config.NewOpenSSHParserFromReader(strings.NewReader(fmt.Sprintf(
		"Host web\n HostName %s\n Port %s\n User fixture\n IdentityFile %q\n AddressFamily inet\n",
		hostname, portStr, filepath.ToSlash(keyPath),
	)))
	if err != nil {
		t.Fatal(err)
	}

	cfg := runtimeTestProvider("node").Snapshot()
	cfg.SSHOptions = ssh.MustOptions(
		ssh.OptionSetEnv, "MCP_LEAK_GLOBAL=1",
		ssh.OptionSendEnv, "LANG",
		ssh.OptionRemoteCommand, "echo global-leak",
		ssh.OptionForwardAgent, "yes",
		ssh.OptionTunnel, "ethernet",
		ssh.OptionExitOnForwardFailure, "yes",
		ssh.OptionVerifyHostKeyDNS, "yes",
		ssh.OptionGlobalKnownHostsFile, extraGlobalKH,
		ssh.OptionStrictHostKeyChecking, "no",
	)
	node, _ := cfg.Nodes.Get("node")
	node.SSHOptions = ssh.MustOptions(
		ssh.OptionSetEnv, "MCP_LEAK_NODE=1",
		ssh.OptionEscapeChar, "~",
		ssh.OptionForwardAgent, "yes",
		ssh.OptionVerifyHostKeyDNS, "ask",
		ssh.OptionStrictHostKeyChecking, "accept-new",
	)
	cfg.Nodes.Set("node", node)

	cleanCfg := runtimeTestProvider("node").Snapshot()
	return config.NewProviderWithOpenSSHParser(cfg, parser), config.NewProviderWithOpenSSHParser(cleanCfg, cleanParser), server
}

func TestMCPGate4_StripsSessionForwardAndTrustOptionsOnDirectConnectorAndResolve(t *testing.T) {
	providerWithCLIOpts, cleanProvider, server := setupMCPGate4Providers(t)

	hWithCLI := newHost(Config{Provider: providerWithCLIOpts})
	hClean := newHost(Config{Provider: cleanProvider})

	snapCLI, err := hWithCLI.Resolve(t.Context(), ports.ResolveRequest{Selectors: []string{"web", "node"}})
	if err != nil {
		t.Fatalf("Resolve with forward/session/trust options failed: %v", err)
	}
	snapClean, err := hClean.Resolve(t.Context(), ports.ResolveRequest{Selectors: []string{"web", "node"}})
	if err != nil {
		t.Fatalf("Resolve with clean config failed: %v", err)
	}

	forbiddenKeys := []string{
		ssh.OptionLocalForward,
		ssh.OptionRemoteForward,
		ssh.OptionDynamicForward,
		ssh.OptionForwardAgent,
		ssh.OptionTunnel,
		ssh.OptionExitOnForwardFailure,
		ssh.OptionSendEnv,
		ssh.OptionSetEnv,
		ssh.OptionRemoteCommand,
		ssh.OptionEscapeChar,
		ssh.OptionRequestTTY,
		ssh.OptionVerifyHostKeyDNS,
		ssh.OptionGlobalKnownHostsFile,
		ssh.OptionStrictHostKeyChecking,
		ssh.OptionPermitLocalCommand,
		ssh.OptionLocalCommand,
	}

	for _, targetID := range []string{"openssh:web", "node"} {
		keyCLI, err := ssh.ConnectionKey(snapCLI.Targets[targetID].Plan)
		if err != nil {
			t.Fatalf("ConnectionKey(snapCLI[%s]): %v", targetID, err)
		}
		keyClean, err := ssh.ConnectionKey(snapClean.Targets[targetID].Plan)
		if err != nil {
			t.Fatalf("ConnectionKey(snapClean[%s]): %v", targetID, err)
		}
		if keyCLI != keyClean {
			t.Fatalf("Gate 4 resolve leaked forward/session/trust options into %s ConnectionKey: %q != %q", targetID, keyCLI, keyClean)
		}
		for _, hop := range snapCLI.Targets[targetID].Plan.Hops {
			for _, forbidden := range forbiddenKeys {
				if hop.Options != nil && (hop.Options.Get(forbidden) != "" || len(hop.Options.GetAll(forbidden)) > 0) {
					t.Fatalf("MCP Resolve snapshot for %s leaked forbidden option %q: %v", targetID, forbidden, hop.Options.GetAll(forbidden))
				}
			}
		}
	}

	// Verify MCP environment clears GlobalKnownHostsFiles so host-global files cannot widen trust.
	if mcpEnv := newMCPEnvironment(); len(mcpEnv.GlobalKnownHostsFiles) != 0 {
		t.Fatalf("expected newMCPEnvironment().GlobalKnownHostsFiles to be empty, got %v", mcpEnv.GlobalKnownHostsFiles)
	}

	// Direct connector path used by backend.files() and backend.RunTunnel().
	conn := newNonInteractiveMCPConnector(providerWithCLIOpts, corelog.NopLogger, nil)
	client, err := conn.Connect(t.Context(), "openssh:web")
	if err != nil {
		t.Fatalf("newNonInteractiveMCPConnector.Connect failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	gotOpts := client.ConnectionConfig().Options
	for _, forbidden := range forbiddenKeys {
		if gotOpts != nil && (gotOpts.Get(forbidden) != "" || len(gotOpts.GetAll(forbidden)) > 0) {
			t.Fatalf("MCP direct connector leaked forbidden option %q: %v", forbidden, gotOpts.GetAll(forbidden))
		}
	}
	if gotOpts.AddressFamily() != "inet" {
		t.Fatalf("expected Transport-class AddressFamily=inet preserved on MCP connector, got %q", gotOpts.AddressFamily())
	}
	if server.Forwards.Load() != 0 {
		t.Fatalf("MCP direct connector opened %d unexpected forwards from config", server.Forwards.Load())
	}
}

func TestMCPGate4_ProxyCommandFailsClosedWithErrLocalExecutionDisabled(t *testing.T) {
	isolateMCPTestEnvironment(t)
	openSSHText := "Host proxyhost\n" +
		" HostName 192.0.2.99\n" +
		" Port 22\n" +
		" User fixture\n" +
		" ProxyCommand sh -c 'exit 1'\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHText))
	if err != nil {
		t.Fatal(err)
	}
	cfg := runtimeTestProvider("node").Snapshot()
	node, _ := cfg.Nodes.Get("node")
	node.SSHOptions = ssh.MustOptions(ssh.OptionProxyCommand, "sh -c 'exit 1'")
	cfg.Nodes.Set("node", node)
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	h := newHost(Config{Provider: provider})
	for _, sel := range []string{"proxyhost", "node"} {
		_, err := h.Resolve(t.Context(), ports.ResolveRequest{Selectors: []string{sel}})
		if !errors.Is(err, adapter.ErrLocalExecutionDisabled) {
			t.Fatalf("MCP Resolve(%q) with ProxyCommand = %v, want ErrLocalExecutionDisabled", sel, err)
		}
	}

	conn := newNonInteractiveMCPConnector(provider, corelog.NopLogger, nil)
	defer func() { _ = conn.CloseAll() }()
	for _, id := range []string{"openssh:proxyhost", "node"} {
		_, err := conn.Connect(t.Context(), id)
		if !errors.Is(err, adapter.ErrLocalExecutionDisabled) {
			t.Fatalf("MCP direct Connect(%q) with ProxyCommand = %v, want ErrLocalExecutionDisabled", id, err)
		}
	}
}
