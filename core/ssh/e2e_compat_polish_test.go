package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type recordingNetDialer struct {
	mu       sync.Mutex
	addrs    []string
	networks []string
	fallback net.Dialer
}

func (d *recordingNetDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *recordingNetDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.networks = append(d.networks, network)
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	return d.fallback.DialContext(ctx, network, addr)
}

func (d *recordingNetDialer) recordedAddrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.addrs))
	copy(out, d.addrs)
	return out
}

func startInMemoryAgent(t *testing.T, keys ...any) func(context.Context, string) (net.Conn, error) {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	return func(context.Context, string) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		wg.Go(func() {
			defer func() { _ = serverConn.Close() }()
			_ = agent.ServeAgent(keyring, serverConn)
		})
		return clientConn, nil
	}
}

func TestDialAndHandshake_IPv6LiteralEndpoints(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable in test environment: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	fix := newPhase3CertFixture(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	_, pub := writeEd25519KeyFile(t, keyPath, "")

	serverCfg := &cryptoSSH.ServerConfig{
		PublicKeyCallback: func(_ cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			if bytes.Equal(key.Marshal(), pub.Marshal()) {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, os.ErrPermission
		},
	}
	serverCfg.AddHostKey(fix.hostSigner)

	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			rawConn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Go(func() { serveSimplePhase3ExecConn(rawConn, serverCfg) })
		}
	})

	env := fixtureEnvironment()
	env.HomeDir = dir
	opts := newPhase3TrustAllOptions(t, dir)

	for _, rawAddr := range []string{"::1", "[::1]"} {
		t.Run("addr_"+rawAddr, func(t *testing.T) {
			recDialer := &recordingNetDialer{}
			provider := &mapConfigProvider{configs: map[string]*ClientConfig{
				"v6": {
					NodeID:   "v6",
					Address:  rawAddr,
					Port:     port,
					User:     "alice",
					AuthType: "key",
					KeyPath:  keyPath,
					Options:  opts.Clone(),
				},
			}}
			conn := NewConnector(provider, WithEnvironment(env), WithDialer(recDialer))
			t.Cleanup(func() { _ = conn.CloseAll() })

			cli, err := conn.Connect(t.Context(), "v6")
			if err != nil {
				t.Fatalf("Connect(%q) failed: %v", rawAddr, err)
			}
			if gotAddr := cli.ConnectionConfig().Address; gotAddr != "::1" {
				t.Fatalf("ConnectionConfig().Address = %q, want %q", gotAddr, "::1")
			}
			addrs := recDialer.recordedAddrs()
			wantDial := joinHostPort("::1", port)
			if len(addrs) != 1 || addrs[0] != wantDial {
				t.Fatalf("dialed addresses = %v, want [%q]", addrs, wantDial)
			}
			out, err := cli.Run(t.Context(), "echo ok")
			if err != nil || strings.TrimSpace(out) != "ok" {
				t.Fatalf("Run over IPv6 failed: out=%q err=%v", out, err)
			}
		})
	}
}

func TestMultiKeyAuth_AgentFallbackAndIdentitiesOnly(t *testing.T) {
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()

	// Wrong disk key (rejected by server).
	wrongKeyPath := filepath.Join(dir, "id_wrong")
	writeEd25519KeyFile(t, wrongKeyPath, "")

	// Agent key 1: plain key accepted by server.
	agentPlainPubRaw, agentPlainPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentPlainPub, err := cryptoSSH.NewPublicKey(agentPlainPubRaw)
	if err != nil {
		t.Fatal(err)
	}

	// Agent key 2: paired with disk CertificateFile.
	agentCertPubRaw, agentCertPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentCertPub, err := cryptoSSH.NewPublicKey(agentCertPubRaw)
	if err != nil {
		t.Fatal(err)
	}
	userCert := signTestCertificate(t, fix.caSigner, agentCertPub, "alice", cryptoSSH.UserCert, 701)
	certPath := filepath.Join(dir, "agent-user-cert.pub")
	if err := os.WriteFile(certPath, cryptoSSH.MarshalAuthorizedKey(userCert), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("plain_agent_fallback_after_explicit_disk_key", func(t *testing.T) {
		port, _ := startPhase3CertSSHServer(t, fix.hostSigner, nil, agentPlainPub, nil)
		env := fixtureEnvironment()
		env.HomeDir = dir
		env.AgentSocket = "in-memory-agent"
		env.DialAgent = startInMemoryAgent(t, agentPlainPriv)

		opts := newPhase3TrustAllOptions(t, dir)
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"node": {
				NodeID:   "node",
				Address:  "127.0.0.1",
				Port:     port,
				User:     "alice",
				AuthType: "key",
				KeyPath:  wrongKeyPath,
				KeyPaths: []string{wrongKeyPath},
				Options:  opts,
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env))
		t.Cleanup(func() { _ = conn.CloseAll() })

		if _, err := conn.Connect(t.Context(), "node"); err != nil {
			t.Fatalf("expected ssh-agent fallback after rejected disk key to succeed, got: %v", err)
		}
	})

	t.Run("disk_certificate_paired_with_agent_key", func(t *testing.T) {
		port, certLogins := startPhase3CertSSHServer(t, fix.hostSigner, fix.caSigner.PublicKey(), nil, nil)
		env := fixtureEnvironment()
		env.HomeDir = dir
		env.AgentSocket = "in-memory-agent"
		env.DialAgent = startInMemoryAgent(t, agentCertPriv)

		opts := newPhase3TrustAllOptions(t, dir)
		if err := opts.Append(OptionCertificateFile, certPath); err != nil {
			t.Fatal(err)
		}
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"node-cert": {
				NodeID:   "node-cert",
				Address:  "127.0.0.1",
				Port:     port,
				User:     "alice",
				AuthType: "key",
				KeyPath:  wrongKeyPath,
				KeyPaths: []string{wrongKeyPath},
				Options:  opts,
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env))
		t.Cleanup(func() { _ = conn.CloseAll() })

		if _, err := conn.Connect(t.Context(), "node-cert"); err != nil {
			t.Fatalf("expected disk CertificateFile paired with ssh-agent key to succeed, got: %v", err)
		}
		if certLogins.Load() != 1 {
			t.Fatalf("certLogins = %d, want 1", certLogins.Load())
		}
	})

	t.Run("identities_only_blocks_unmatched_agent_fallback", func(t *testing.T) {
		port, _ := startPhase3CertSSHServer(t, fix.hostSigner, nil, agentPlainPub, nil)
		env := fixtureEnvironment()
		env.HomeDir = dir
		env.AgentSocket = "in-memory-agent"
		env.DialAgent = startInMemoryAgent(t, agentPlainPriv)

		opts := newPhase3TrustAllOptions(t, dir)
		if err := opts.Set(OptionIdentitiesOnly, "yes"); err != nil {
			t.Fatal(err)
		}
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"node-ident-only": {
				NodeID:   "node-ident-only",
				Address:  "127.0.0.1",
				Port:     port,
				User:     "alice",
				AuthType: "key",
				KeyPath:  wrongKeyPath,
				KeyPaths: []string{wrongKeyPath},
				Options:  opts,
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env))
		t.Cleanup(func() { _ = conn.CloseAll() })

		if _, err := conn.Connect(t.Context(), "node-ident-only"); err == nil {
			t.Fatal("expected IdentitiesOnly=yes to prevent unmatched ssh-agent fallback")
		}
	})
}
