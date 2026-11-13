package mcphost

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

	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
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

	openSSHText := fmt.Sprintf(
		"Host web\n"+
			" HostName %s\n"+
			" Port %s\n"+
			" User fixture\n"+
			" IdentityFile %q\n"+
			" AddressFamily inet\n"+
			" LocalForward 127.0.0.1:0 127.0.0.1:9\n"+
			" RemoteForward 127.0.0.1:0 127.0.0.1:9\n"+
			" DynamicForward 127.0.0.1:0\n"+
			" SendEnv *\n"+
			" SetEnv MCP_LEAK_OPENSSH=1\n"+
			" RemoteCommand echo leaked\n"+
			" EscapeChar ^A\n"+
			" RequestTTY force\n",
		hostname, portStr, filepath.ToSlash(keyPath),
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
	)
	node, _ := cfg.Nodes.Get("node")
	node.SSHOptions = ssh.MustOptions(
		ssh.OptionSetEnv, "MCP_LEAK_NODE=1",
		ssh.OptionEscapeChar, "~",
	)
	cfg.Nodes.Set("node", node)

	cleanCfg := runtimeTestProvider("node").Snapshot()
	return config.NewProviderWithOpenSSHParser(cfg, parser), config.NewProviderWithOpenSSHParser(cleanCfg, cleanParser), server
}

func TestMCPGate4_StripsSessionAndForwardOptionsOnDirectConnectorAndResolve(t *testing.T) {
	providerWithCLIOpts, cleanProvider, server := setupMCPGate4Providers(t)

	hWithCLI := newHost(Config{Provider: providerWithCLIOpts})
	hClean := newHost(Config{Provider: cleanProvider})

	snapCLI, err := hWithCLI.Resolve(t.Context(), ports.ResolveRequest{Selectors: []string{"web"}})
	if err != nil {
		t.Fatalf("Resolve with forward/session options failed: %v", err)
	}
	snapClean, err := hClean.Resolve(t.Context(), ports.ResolveRequest{Selectors: []string{"web"}})
	if err != nil {
		t.Fatalf("Resolve with clean config failed: %v", err)
	}
	keyCLI, err := ssh.ConnectionKey(snapCLI.Targets["openssh:web"].Plan)
	if err != nil {
		t.Fatalf("ConnectionKey(snapCLI): %v", err)
	}
	keyClean, err := ssh.ConnectionKey(snapClean.Targets["openssh:web"].Plan)
	if err != nil {
		t.Fatalf("ConnectionKey(snapClean): %v", err)
	}
	if keyCLI != keyClean {
		t.Fatalf("Gate 4 resolve leaked forward/session options into ConnectionKey: %q != %q", keyCLI, keyClean)
	}

	// Direct connector path used by backend.files() and backend.RunTunnel().
	conn := newNonInteractiveMCPConnector(providerWithCLIOpts, corelog.NopLogger, nil)
	client, err := conn.Connect(t.Context(), "openssh:web")
	if err != nil {
		t.Fatalf("newNonInteractiveMCPConnector.Connect failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	gotOpts := client.ConnectionConfig().Options
	for _, forbidden := range []string{
		ssh.OptionLocalForward,
		ssh.OptionRemoteForward,
		ssh.OptionDynamicForward,
		ssh.OptionSendEnv,
		ssh.OptionSetEnv,
		ssh.OptionRemoteCommand,
		ssh.OptionEscapeChar,
		ssh.OptionRequestTTY,
	} {
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
