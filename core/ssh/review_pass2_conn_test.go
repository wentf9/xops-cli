package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestPass2Conn_H1_LocalExecSanitizeEmptyHostAndHostToken(t *testing.T) {
	env := Environment{
		HomeDir:   "/home/alice",
		LocalUser: "alice",
		LocalHost: "workstation",
		LocalUID:  "1000",
	}

	// Empty target.Host must fail closed even when template does not reference %h.
	emptyHostTarget := TargetContext{Host: "", Port: 22, User: "alice", OriginalHost: "alias"}
	if _, err := ExpandProxyCommand("ssh -W 127.0.0.1:22 bastion", env, emptyHostTarget); !errors.Is(err, ErrUnsafeExecToken) {
		t.Fatalf("ExpandProxyCommand with empty Host = %v, want ErrUnsafeExecToken", err)
	}
	if _, err := ExpandLocalCommand("echo connected", env, emptyHostTarget); !errors.Is(err, ErrUnsafeExecToken) {
		t.Fatalf("ExpandLocalCommand with empty Host = %v, want ErrUnsafeExecToken", err)
	}

	invalidHosts := []string{
		"",
		"%TEMP%",
		"a%PATH%b",
		"127.0.0.1%eth0",
		"host.example.com%eth0",
		"fe80::1%eth0%bar",
		"fe80::1%",
		"fe80::1%eth$0",
		"[fe80::1%]",
		"[127.0.0.1]",
		"[host.example.com]",
		"host[0].example.com",
		"[[::1]]",
		"[::1",
		"::1]",
		"[:not:ipv6:zzzz]",
	}
	for _, bad := range invalidHosts {
		if err := ValidateSafeExecToken("%h", bad); !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("ValidateSafeExecToken(%%h, %q) = %v, want ErrUnsafeExecToken", bad, err)
		}
	}

	validHosts := []string{
		"host.example-1.com",
		"192.0.2.10",
		"::1",
		"[::1]",
		"fe80::1%eth0",
		"[fe80::1%eth0]",
		"[fe80::1%en0_1.vlan-2]",
	}
	for _, good := range validHosts {
		if err := ValidateSafeExecToken("%h", good); err != nil {
			t.Fatalf("ValidateSafeExecToken(%%h, %q) unexpected error: %v", good, err)
		}
	}
}

type swappableHostSigner struct {
	cur atomic.Pointer[cryptoSSH.Signer]
}

func newSwappableHostSigner(initial cryptoSSH.Signer) *swappableHostSigner {
	s := &swappableHostSigner{}
	s.cur.Store(&initial)
	return s
}

func (s *swappableHostSigner) Swap(next cryptoSSH.Signer) {
	s.cur.Store(&next)
}

func (s *swappableHostSigner) PublicKey() cryptoSSH.PublicKey {
	return (*s.cur.Load()).PublicKey()
}

func (s *swappableHostSigner) Sign(randReader io.Reader, data []byte) (*cryptoSSH.Signature, error) {
	return (*s.cur.Load()).Sign(randReader, data)
}

func startRekeySSHServer(t *testing.T, hostSigner cryptoSSH.Signer, password string) int {
	t.Helper()
	serverCfg := &cryptoSSH.ServerConfig{
		Config: cryptoSSH.Config{
			RekeyThreshold: 512,
		},
		PasswordCallback: func(c cryptoSSH.ConnMetadata, pass []byte) (*cryptoSSH.Permissions, error) {
			if string(pass) == password {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("bad password")
		},
	}
	serverCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
			wg.Go(func() {
				serveRekeyExecConn(rawConn, serverCfg)
			})
		}
	})
	return ln.Addr().(*net.TCPAddr).Port
}

func serveRekeyExecConn(rawConn net.Conn, serverCfg *cryptoSSH.ServerConfig) {
	defer func() { _ = rawConn.Close() }()
	sConn, chans, reqs, err := cryptoSSH.NewServerConn(rawConn, serverCfg)
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()
	go cryptoSSH.DiscardRequests(reqs)
	payload := strings.Repeat("rekey-payload-block-", 256) + "\n"
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, acceptErr := newCh.Accept()
		if acceptErr != nil {
			continue
		}
		go func(c cryptoSSH.Channel, r <-chan *cryptoSSH.Request) {
			defer func() { _ = c.Close() }()
			for req := range r {
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				if req.Type == "exec" {
					_, _ = io.WriteString(c, payload)
					_, _ = c.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
					return
				}
			}
		}(ch, chReqs)
	}
}

type spyHostKeyVerifier struct {
	calls     atomic.Int32
	ctxFailed atomic.Bool
}

func (v *spyHostKeyVerifier) Verify(ctx context.Context, _ HostKeyRequest, _ cryptoSSH.PublicKey) error {
	v.calls.Add(1)
	if ctx.Err() != nil {
		v.ctxFailed.Store(true)
		return ctx.Err()
	}
	return nil
}

type spyInteractionPrompter struct {
	confirmCalls atomic.Int32
	promptCalls  atomic.Int32
	passphrase   string
}

func (p *spyInteractionPrompter) PromptSecret(_ context.Context, _ SecretRequest) (string, error) {
	p.promptCalls.Add(1)
	return p.passphrase, nil
}

func (p *spyInteractionPrompter) ConfirmHostKey(ctx context.Context, _ HostKeyConfirmation) (bool, error) {
	p.confirmCalls.Add(1)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return true, nil
}

func (p *spyInteractionPrompter) ReportCredentialFailure(ctx context.Context, _ string) error {
	return ctx.Err()
}

func (p *spyInteractionPrompter) CredentialRecoveryAllowed() bool {
	return true
}

func runSimpleSessionExec(ctx context.Context, cli *Client, cmd string) (string, error) {
	if _, err := cli.Run(ctx, cmd+"-1"); err != nil {
		return "", err
	}
	return cli.Run(ctx, cmd+"-2")
}

func TestPass2Conn_H2_PostHandshakeRekeyLifecycleAndKeyPinning(t *testing.T) {
	fix := newPhase3CertFixture(t)
	_, altPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	altHostSigner, err := cryptoSSH.NewSignerFromKey(altPriv)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("verifier_rekey_uses_live_lifecycle_ctx", func(t *testing.T) {
		dir := t.TempDir()
		port := startRekeySSHServer(t, fix.hostSigner, "pw123")
		verifier := &spyHostKeyVerifier{}
		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = filepath.Join(dir, "known_hosts")

		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"rekey-v": {
				NodeID:   "rekey-v",
				Address:  "127.0.0.1",
				Port:     port,
				User:     "alice",
				AuthType: "password",
				Password: "pw123",
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env), WithHostKeyVerifier(verifier))
		t.Cleanup(func() { _ = conn.CloseAll() })

		cli, err := conn.Connect(t.Context(), "rekey-v")
		if err != nil {
			t.Fatalf("Connect failed: %v", err)
		}
		out, err := runSimpleSessionExec(t.Context(), cli, "echo rekey")
		if err != nil {
			t.Fatalf("exec across transport rekey failed: %v", err)
		}
		if len(out) < 2048 || verifier.calls.Load() < 2 || verifier.ctxFailed.Load() {
			t.Fatalf("unexpected rekey state: len=%d calls=%d ctxFailed=%v", len(out), verifier.calls.Load(), verifier.ctxFailed.Load())
		}
	})

	t.Run("ask_and_sshfp_rekey_no_reprompt_or_dup_known_hosts", func(t *testing.T) {
		dir := t.TempDir()
		khFile := filepath.Join(dir, "known_hosts")
		port := startRekeySSHServer(t, fix.hostSigner, "pw123")
		prompter := &spyInteractionPrompter{}
		var dnsCtxErr atomic.Bool

		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = khFile
		env.LookupSSHFP = func(ctx context.Context, _ string) (SSHFPResult, error) {
			if ctx.Err() != nil {
				dnsCtxErr.Store(true)
				return SSHFPResult{}, ctx.Err()
			}
			return SSHFPResult{}, nil
		}

		opts := MustOptions(
			OptionStrictHostKeyChecking, StrictHostKeyCheckingAsk,
			OptionUserKnownHostsFile, khFile,
			OptionGlobalKnownHostsFile, "none",
			OptionVerifyHostKeyDNS, "yes",
		)
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"rekey-ask": {
				NodeID:   "rekey-ask",
				Address:  "127.0.0.1",
				Port:     port,
				User:     "alice",
				AuthType: "password",
				Password: "pw123",
				Options:  opts,
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env), WithInteractionHandler(prompter))
		t.Cleanup(func() { _ = conn.CloseAll() })

		cli, err := conn.Connect(t.Context(), "rekey-ask")
		if err != nil {
			t.Fatalf("Connect failed: %v", err)
		}
		if _, err := runSimpleSessionExec(t.Context(), cli, "echo rekey"); err != nil {
			t.Fatalf("exec across transport rekey failed: %v", err)
		}
		if prompter.confirmCalls.Load() != 1 || dnsCtxErr.Load() {
			t.Fatalf("confirmCalls=%d (want 1), dnsCtxErr=%v", prompter.confirmCalls.Load(), dnsCtxErr.Load())
		}
		rawKH, err := os.ReadFile(khFile)
		if err != nil {
			t.Fatal(err)
		}
		if lines := strings.Split(strings.TrimSpace(string(rawKH)), "\n"); len(lines) != 1 {
			t.Fatalf("known_hosts line count = %d, want 1:\n%s", len(lines), string(rawKH))
		}
	})

	t.Run("rekey_rejects_swapped_peer_host_key", func(t *testing.T) {
		dir := t.TempDir()
		swapper := newSwappableHostSigner(fix.hostSigner)
		port := startRekeySSHServer(t, swapper, "pw123")
		prompter := &spyInteractionPrompter{}

		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = filepath.Join(dir, "known_hosts")

		opts := MustOptions(
			OptionStrictHostKeyChecking, StrictHostKeyCheckingAsk,
			OptionUserKnownHostsFile, "none",
			OptionGlobalKnownHostsFile, "none",
		)
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"rekey-swap": {
				NodeID:   "rekey-swap",
				Address:  "127.0.0.1",
				Port:     port,
				User:     "alice",
				AuthType: "password",
				Password: "pw123",
				Options:  opts,
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env), WithInteractionHandler(prompter))
		t.Cleanup(func() { _ = conn.CloseAll() })

		cli, err := conn.Connect(t.Context(), "rekey-swap")
		if err != nil {
			t.Fatalf("initial Connect failed: %v", err)
		}
		swapper.Swap(altHostSigner)
		if _, err := runSimpleSessionExec(t.Context(), cli, "echo should-fail-rekey"); err == nil {
			t.Fatal("expected post-handshake rekey with swapped host key to fail closed")
		}
	})
}

func TestPass2Conn_H3_HostCertFailClosedAndGlobalRevokedLinePreserved(t *testing.T) {
	fix := newPhase3CertFixture(t)

	t.Run("untrusted_host_cert_rejected_when_known_hosts_empty_or_none", func(t *testing.T) {
		dir := t.TempDir()
		hostCert := signTestCertificate(t, fix.caSigner, fix.hostSigner.PublicKey(), "127.0.0.1", cryptoSSH.HostCert, 5001)
		hostCertSigner, err := cryptoSSH.NewCertSigner(hostCert, fix.hostSigner)
		if err != nil {
			t.Fatal(err)
		}
		port := startRekeySSHServer(t, hostCertSigner, "pw123")

		nonExistentKH := filepath.Join(dir, "missing_known_hosts")
		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = nonExistentKH
		env.GlobalKnownHostsFiles = nil

		opts := MustOptions(
			OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew,
			OptionUserKnownHostsFile, nonExistentKH,
			OptionGlobalKnownHostsFile, "none",
		)
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"untrusted-cert": {
				NodeID:   "untrusted-cert",
				Address:  "127.0.0.1",
				Port:     port,
				User:     "alice",
				AuthType: "password",
				Password: "pw123",
				Options:  opts,
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env), WithInteractionHandler(&spyInteractionPrompter{}))
		conn.AcceptNewHostKey.Store(true)
		t.Cleanup(func() { _ = conn.CloseAll() })

		_, err = conn.Connect(t.Context(), "untrusted-cert")
		if err == nil || !strings.Contains(err.Error(), "no authorities") {
			t.Fatalf("Connect against untrusted host certificate = %v, want CertChecker 'no authorities' rejection", err)
		}
		if _, statErr := os.Stat(nonExistentKH); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("untrusted host certificate must never be written to known_hosts (statErr=%v)", statErr)
		}
		hkErr := conn.handleKnownHostsKeyError(
			t.Context(),
			nil,
			provider.configs["untrusted-cert"],
			&knownhosts.KeyError{},
			nonExistentKH,
			false,
			false,
			StrictHostKeyCheckingAcceptNew,
			"127.0.0.1",
			&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
			hostCert,
			nil,
		)
		if !errors.Is(hkErr, ErrHostKeyMismatch) {
			t.Fatalf("handleKnownHostsKeyError(*ssh.Certificate) = %v, want ErrHostKeyMismatch", hkErr)
		}
		if appendErr := appendKnownHost(nonExistentKH, "127.0.0.1", hostCert, false); !errors.Is(appendErr, ErrHostKeyMismatch) {
			t.Fatalf("appendKnownHost(*ssh.Certificate) = %v, want ErrHostKeyMismatch", appendErr)
		}
	})

	t.Run("malformed_line_in_global_known_hosts_preserves_revoked_ca_and_host_lines", func(t *testing.T) {
		dir := t.TempDir()
		revokedKey := newPhase4HostKey(t)
		goodKey := newPhase4HostKey(t)
		validHostCert := signTestCertificate(t, fix.caSigner, goodKey, "app.corp.example", cryptoSSH.HostCert, 5002)

		mixedGlobal := filepath.Join(dir, "ssh_known_hosts_mixed")
		var buf strings.Builder
		buf.WriteString("corrupt.example not-a-key-type !!!!\n")
		buf.WriteString("@revoked * " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(revokedKey))) + "\n")
		buf.WriteString("@cert-authority *.corp.example " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(fix.caSigner.PublicKey()))) + "\n")
		buf.WriteString(knownhosts.Line([]string{"pinned.corp.example"}, goodKey) + "\n")
		if err := os.WriteFile(mixedGlobal, []byte(buf.String()), 0o644); err != nil {
			t.Fatal(err)
		}

		emptyUser := filepath.Join(dir, "user_known_hosts")
		if err := os.WriteFile(emptyUser, nil, 0o600); err != nil {
			t.Fatal(err)
		}

		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = emptyUser
		env.GlobalKnownHostsFiles = []string{mixedGlobal}

		conn := NewConnector(nil, WithEnvironment(env))
		t.Cleanup(func() { _ = conn.CloseAll() })

		cfg := &ClientConfig{
			NodeID:  "corp",
			Address: "app.corp.example",
			Port:    22,
			User:    "alice",
			Options: MustOptions(OptionStrictHostKeyChecking, "yes"),
		}
		_, _, cb, err := conn.openKnownHostsCallback("", cfg)
		if err != nil {
			t.Fatalf("openKnownHostsCallback failed on mixed global known_hosts: %v", err)
		}
		remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 55), Port: 22}

		revErr := cb("any.corp.example:22", remote, revokedKey)
		if _, isRevoked := errors.AsType[*knownhosts.RevokedError](revErr); !isRevoked {
			t.Fatalf("expected *knownhosts.RevokedError for @revoked key in mixed global file, got %v", revErr)
		}
		if err := cb("app.corp.example:22", remote, validHostCert); err != nil {
			t.Fatalf("expected @cert-authority in mixed global file to accept valid host cert: %v", err)
		}
		if err := cb("pinned.corp.example:22", remote, goodKey); err != nil {
			t.Fatalf("expected valid host line in mixed global file to verify: %v", err)
		}
	})
}

func TestPass2Conn_H4_BoundedAgentNoIdleKillAndExplicitAgentFailsBeforeDial(t *testing.T) {
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()

	t.Run("synchronous_agent_survives_idle_gap_longer_than_op_timeout", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		dialFn := startInMemoryAgent(t, priv)
		ac, cleanup, err := dialBoundedAgentClient(t.Context(), nil, dialFn, "mem-agent", 25*time.Millisecond, nil)
		if err != nil {
			t.Fatalf("dialBoundedAgentClient failed: %v", err)
		}
		t.Cleanup(cleanup)

		signers, err := ac.Signers()
		if err != nil || len(signers) != 1 {
			t.Fatalf("Signers() = %d, %v; want 1, nil", len(signers), err)
		}
		time.Sleep(65 * time.Millisecond)
		if _, err := signers[0].Sign(rand.Reader, []byte("post-idle-sign-challenge")); err != nil {
			t.Fatalf("Sign after idle period > opTimeout failed: %v", err)
		}
	})

	t.Run("explicit_agent_auth_fails_fast_when_signers_errors_even_with_cert_file", func(t *testing.T) {
		_, pub := writeEd25519KeyFile(t, filepath.Join(dir, "dummy_key"), "")
		cert := signTestCertificate(t, fix.caSigner, pub, "alice", cryptoSSH.UserCert, 6001)
		certPath := filepath.Join(dir, "dummy-cert.pub")
		if err := os.WriteFile(certPath, cryptoSSH.MarshalAuthorizedKey(cert), 0o600); err != nil {
			t.Fatal(err)
		}

		hungAgent := func(_ context.Context, _ string) (net.Conn, error) {
			cConn, sConn := net.Pipe()
			go func() {
				defer func() { _ = sConn.Close() }()
				_, _ = io.Copy(io.Discard, sConn)
			}()
			return cConn, nil
		}

		var remoteDials atomic.Int32
		env := fixtureEnvironment()
		env.HomeDir = dir
		env.AgentSocket = "hung-sock"
		env.DialAgent = hungAgent
		env.DialProxyCommand = func(_ context.Context, _ string) (net.Conn, error) {
			remoteDials.Add(1)
			return nil, errors.New("unexpected remote dial")
		}

		opts := newPhase3TrustAllOptions(t, dir)
		_ = opts.Append(OptionCertificateFile, certPath)
		_ = opts.Set(OptionProxyCommand, "nc %h %p")

		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"agent-hung": {
				NodeID:   "agent-hung",
				Address:  "127.0.0.1",
				Port:     22,
				User:     "alice",
				AuthType: "agent",
				Options:  opts,
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env), WithHandshakeTimeout(80*time.Millisecond))
		t.Cleanup(func() { _ = conn.CloseAll() })

		if _, err := conn.Connect(t.Context(), "agent-hung"); err == nil {
			t.Fatal("expected AuthType=agent with hung agent to fail")
		}
		if remoteDials.Load() != 0 {
			t.Fatalf("expected 0 remote dials when explicit ssh-agent Signers() fails, got %d", remoteDials.Load())
		}
	})
}

func TestPass2Conn_M1_PlainNonAlgoCertSignerHandshakeAndBoundedMultiAlgo(t *testing.T) {
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := cryptoSSH.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	plainRSA := &plainOnlyRSASigner{pub: rsaPub, raw: rsaKey}
	rsaCert := signTestCertificate(t, fix.caSigner, rsaPub, "alice", cryptoSSH.UserCert, 7001)

	certPath := filepath.Join(dir, "plain-rsa-cert.pub")
	if err := os.WriteFile(certPath, cryptoSSH.MarshalAuthorizedKey(rsaCert), 0o600); err != nil {
		t.Fatal(err)
	}

	// Server accepts ssh-rsa as well as SHA-2 RSA signature algorithms.
	port, certLogins := startPhase3CertSSHServer(
		t,
		fix.hostSigner,
		fix.caSigner.PublicKey(),
		nil,
		[]string{cryptoSSH.KeyAlgoRSASHA512, cryptoSSH.KeyAlgoRSASHA256, cryptoSSH.KeyAlgoRSA},
	)

	opts := newPhase3TrustAllOptions(t, dir)
	if err := opts.Append(OptionCertificateFile, certPath); err != nil {
		t.Fatal(err)
	}
	provider := &mapConfigProvider{configs: map[string]*ClientConfig{
		"plain-rsa-cert": {
			NodeID:   "plain-rsa-cert",
			Address:  "127.0.0.1",
			Port:     port,
			User:     "alice",
			AuthType: "key",
			KeyRef:   "plain-rsa",
			Options:  opts,
		},
	}}
	env := fixtureEnvironment()
	env.HomeDir = dir
	conn := NewConnector(
		provider,
		WithEnvironment(env),
		WithKeySource(&fixtureKeySource{lease: &fixtureKeyLease{signer: plainRSA}}),
	)
	t.Cleanup(func() { _ = conn.CloseAll() })

	if _, err := conn.Connect(t.Context(), "plain-rsa-cert"); err != nil {
		t.Fatalf("Connect with non-AlgorithmSigner RSA key + CertificateFile failed: %v", err)
	}
	if certLogins.Load() != 1 {
		t.Fatalf("certLogins = %d, want 1", certLogins.Load())
	}

	// Verify boundedAgentSigner preserves MultiAlgorithmSigner.
	baseRSASigner, err := cryptoSSH.NewSignerFromSigner(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := cryptoSSH.NewSignerWithAlgorithms(
		baseRSASigner.(cryptoSSH.AlgorithmSigner),
		[]string{cryptoSSH.KeyAlgoRSASHA512},
	)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	bc := &boundedAgentClient{conn: clientConn, opTimeout: time.Second}
	wrappedAgentSigner := wrapBoundedAgentSigner(bc, restricted)
	mas, ok := wrappedAgentSigner.(cryptoSSH.MultiAlgorithmSigner)
	if !ok {
		t.Fatalf("boundedAgentSigner %T does not implement MultiAlgorithmSigner", wrappedAgentSigner)
	}
	if got := mas.Algorithms(); !slices.Equal(got, []string{cryptoSSH.KeyAlgoRSASHA512}) {
		t.Fatalf("boundedAgentSigner.Algorithms() = %v, want [rsa-sha2-512]", got)
	}
}

func startCustomKeyringAgent(t *testing.T, kr agent.Agent) func(context.Context, string) (net.Conn, error) {
	t.Helper()
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	return func(_ context.Context, _ string) (net.Conn, error) {
		cConn, sConn := net.Pipe()
		wg.Go(func() {
			defer func() { _ = sConn.Close() }()
			_ = agent.ServeAgent(kr, sConn)
		})
		return cConn, nil
	}
}

func TestPass2Conn_M2_PubSidecarCertAgentPreferenceAndCertDedup(t *testing.T) {
	fix := newPhase3CertFixture(t)
	portCert, certLogins := startPhase3CertSSHServer(t, fix.hostSigner, fix.caSigner.PublicKey(), nil, nil)

	t.Run("pub_identity_file_discovers_sidecar_cert_with_agent", func(t *testing.T) {
		assertPass2PubSidecarCertWithAgent(t, fix, portCert, certLogins)
	})

	t.Run("identities_only_no_prefers_unlocked_agent_over_encrypted_disk_key", func(t *testing.T) {
		assertPass2AgentPreferredOverEncryptedDiskKey(t, fix, portCert)
	})

	t.Run("cert_wire_dedup_and_cert_only_agent_key_indexing", func(t *testing.T) {
		assertPass2CertDedupAndCertOnlyAgentIndexing(t, fix, portCert)
	})
}

func assertPass2PubSidecarCertWithAgent(
	t *testing.T,
	fix phase3CertFixture,
	portCert int,
	certLogins *atomic.Int32,
) {
	t.Helper()
	dir := t.TempDir()
	pubRaw, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := cryptoSSH.NewPublicKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "id_ed25519.pub")
	if err := os.WriteFile(pubPath, cryptoSSH.MarshalAuthorizedKey(pub), 0o600); err != nil {
		t.Fatal(err)
	}
	cert := signTestCertificate(t, fix.caSigner, pub, "alice", cryptoSSH.UserCert, 8001)
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519-cert.pub"), cryptoSSH.MarshalAuthorizedKey(cert), 0o600); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.AgentSocket = "mem-agent"
	env.DialAgent = startInMemoryAgent(t, priv)

	before := certLogins.Load()
	for _, identOnly := range []string{"yes", "no"} {
		for _, authMode := range []string{"auto", "key"} {
			opts := newPhase3TrustAllOptions(t, dir)
			_ = opts.Set(OptionIdentitiesOnly, identOnly)
			_ = opts.Append(OptionIdentityFile, pubPath)
			nodeID := "pub-sidecar-" + identOnly + "-" + authMode
			provider := &mapConfigProvider{configs: map[string]*ClientConfig{
				nodeID: {
					NodeID:   nodeID,
					Address:  "127.0.0.1",
					Port:     portCert,
					User:     "alice",
					AuthType: authMode,
					Options:  opts,
				},
			}}
			conn := NewConnector(provider, WithEnvironment(env))
			if _, err := conn.Connect(t.Context(), nodeID); err != nil {
				_ = conn.CloseAll()
				t.Fatalf("Connect(%s) failed: %v", nodeID, err)
			}
			_ = conn.CloseAll()
		}
	}
	if got := certLogins.Load() - before; got != 4 {
		t.Fatalf("certLogins delta = %d, want 4", got)
	}
}

func assertPass2AgentPreferredOverEncryptedDiskKey(t *testing.T, fix phase3CertFixture, portCert int) {
	t.Helper()
	dir := t.TempDir()
	encKeyPath := filepath.Join(dir, "id_ed25519")
	priv, pub := writeEd25519KeyFile(t, encKeyPath, "disk-passphrase")
	cert := signTestCertificate(t, fix.caSigner, pub, "alice", cryptoSSH.UserCert, 8002)
	if err := os.WriteFile(encKeyPath+"-cert.pub", cryptoSSH.MarshalAuthorizedKey(cert), 0o600); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.AgentSocket = "mem-agent"
	env.DialAgent = startInMemoryAgent(t, priv)
	env.DefaultKeyPaths = []string{encKeyPath}

	for _, authMode := range []string{"auto", "key"} {
		opts := newPhase3TrustAllOptions(t, dir)
		_ = opts.Set(OptionBatchMode, "yes")
		cfg := &ClientConfig{
			NodeID:   "enc-agent-" + authMode,
			Address:  "127.0.0.1",
			Port:     portCert,
			User:     "alice",
			AuthType: authMode,
			Options:  opts,
		}
		if authMode == "key" {
			cfg.KeyPath = encKeyPath
		}
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{cfg.NodeID: cfg}}
		conn := NewConnector(provider, WithEnvironment(env))
		if _, err := conn.Connect(t.Context(), cfg.NodeID); err != nil {
			_ = conn.CloseAll()
			t.Fatalf("BatchMode Connect(%s) with encrypted disk key + unlocked agent + sidecar cert failed: %v", authMode, err)
		}
		_ = conn.CloseAll()
	}
}

func assertPass2CertDedupAndCertOnlyAgentIndexing(t *testing.T, fix phase3CertFixture, portCert int) {
	t.Helper()
	dir := t.TempDir()

	// 1) Cert-only agent entry paired with a different trusted CertificateFile on disk.
	_, untrustedCAPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	untrustedCA, err := cryptoSSH.NewSignerFromKey(untrustedCAPriv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "id_cert_only")
	priv, pub := writeEd25519KeyFile(t, keyPath, "")
	untrustedAgentCert := signTestCertificate(t, untrustedCA, pub, "alice", cryptoSSH.UserCert, 8003)
	trustedDiskCert := signTestCertificate(t, fix.caSigner, pub, "alice", cryptoSSH.UserCert, 8004)
	trustedCertPath := filepath.Join(dir, "trusted-disk-cert.pub")
	if err := os.WriteFile(trustedCertPath, cryptoSSH.MarshalAuthorizedKey(trustedDiskCert), 0o600); err != nil {
		t.Fatal(err)
	}

	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Certificate: untrustedAgentCert}); err != nil {
		t.Fatal(err)
	}
	env := fixtureEnvironment()
	env.HomeDir = dir
	env.AgentSocket = "cert-only-agent"
	env.DialAgent = startCustomKeyringAgent(t, kr)

	opts := newPhase3TrustAllOptions(t, dir)
	_ = opts.Set(OptionIdentitiesOnly, "yes")
	_ = opts.Append(OptionCertificateFile, trustedCertPath)
	provider := &mapConfigProvider{configs: map[string]*ClientConfig{
		"cert-only-agent": {
			NodeID:   "cert-only-agent",
			Address:  "127.0.0.1",
			Port:     portCert,
			User:     "alice",
			AuthType: "auto",
			Options:  opts,
		},
	}}
	conn := NewConnector(provider, WithEnvironment(env))
	if _, err := conn.Connect(t.Context(), "cert-only-agent"); err != nil {
		_ = conn.CloseAll()
		t.Fatalf("cert-only agent entry failed to pair with disk CertificateFile: %v", err)
	}
	_ = conn.CloseAll()

	// 2) Deduplicate offered certificate wire bytes between disk sidecar cert and ssh-agent cert.
	tracker := newOfferedPubKeyTracker()
	tracker.recordStatic(untrustedAgentCert)
	agentClient, cleanup, err := dialBoundedAgentClient(t.Context(), nil, env.DialAgent, env.AgentSocket, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	rawSigners, err := agentClient.Signers()
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := tracker.filterAgentSigners(func() ([]cryptoSSH.Signer, error) {
		return rawSigners, nil
	})()
	if err != nil || len(remaining) != 0 {
		t.Fatalf("expected offered cert wire bytes to deduplicate agent cert signer, got %d remaining (err=%v)", len(remaining), err)
	}
}

type spyCredentialStore struct {
	mu          sync.Mutex
	configs     map[string]*ClientConfig
	noSave      bool
	authUpdates []recordedAuthUpdate
}

type recordedAuthUpdate struct {
	nodeID     string
	token      string
	password   string
	keyPath    string
	passphrase string
}

func (s *spyCredentialStore) GetConfig(nodeID string) (*ClientConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, ok := s.configs[nodeID]
	if !ok {
		return nil, errors.New("node not found")
	}
	cp := *cfg
	cp.KeyPaths = slices.Clone(cfg.KeyPaths)
	cp.Options = cfg.Options.Clone()
	return &cp, nil
}

func (s *spyCredentialStore) UpdateAuth(_ context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authUpdates = append(s.authUpdates, recordedAuthUpdate{
		nodeID:     nodeID,
		token:      authUpdateToken,
		password:   password,
		keyPath:    keyPath,
		passphrase: passphrase,
	})
	if s.noSave {
		return authUpdateToken, nil
	}
	cfg := s.configs[nodeID]
	cfg.AuthUpdateToken = authUpdateToken + "-next"
	if keyPath != "" {
		cfg.KeyPath = keyPath
	}
	return cfg.AuthUpdateToken, nil
}

func (s *spyCredentialStore) UpdateSudo(_ context.Context, _, sudoUpdateToken string, _ SudoMode, _ string) (string, error) {
	return sudoUpdateToken, nil
}

func TestPass2Conn_M3_MultiKeyRejectClearsStaleCredsAndNoSaveRecorderToken(t *testing.T) {
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()

	wrongEncPath := filepath.Join(dir, "id_wrong_enc_pem")
	wrongPEMBytes, _ := generateTestEncryptedKey(t, "wrong-key-pass")
	if err := os.WriteFile(wrongEncPath, wrongPEMBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	goodPlainPath := filepath.Join(dir, "id_good_plain")
	_, goodPub := writeEd25519KeyFile(t, goodPlainPath, "")

	portPlain, _ := startPhase3CertSSHServer(t, fix.hostSigner, nil, goodPub, nil)

	t.Run("rejected_encrypted_key_not_persisted_when_later_key_succeeds", func(t *testing.T) {
		m3Opts := newPhase3TrustAllOptions(t, dir)
		_ = m3Opts.Set(OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew)
		store := &spyCredentialStore{
			configs: map[string]*ClientConfig{
				"multi-key": {
					NodeID:          "multi-key",
					Address:         "127.0.0.1",
					Port:            portPlain,
					User:            "alice",
					AuthType:        "key",
					KeyPath:         goodPlainPath,
					KeyPaths:        []string{wrongEncPath, goodPlainPath},
					AuthUpdateToken: "v1",
					Options:         m3Opts,
				},
			},
		}
		env := fixtureEnvironment()
		env.HomeDir = dir
		prompter := &spyInteractionPrompter{passphrase: "wrong-key-pass"}
		conn := NewConnector(
			store,
			WithCredentialRecorder(store),
			WithEnvironment(env),
			WithInteractionHandler(prompter),
		)
		t.Cleanup(func() { _ = conn.CloseAll() })

		if _, err := conn.Connect(t.Context(), "multi-key"); err != nil {
			t.Fatalf("Connect(multi-key) failed: %v", err)
		}
		if prompter.promptCalls.Load() == 0 {
			t.Fatal("expected encrypted PEM wrong key to prompt for passphrase before server rejection")
		}
		store.mu.Lock()
		updates := slices.Clone(store.authUpdates)
		store.mu.Unlock()
		for _, u := range updates {
			if u.passphrase != "" || u.keyPath != goodPlainPath {
				t.Fatalf("unexpected stale credential persisted after rejected encrypted key: %+v", u)
			}
		}
	})

	t.Run("no_save_recorder_unchanged_token_avoids_snapshot_mismatch", func(t *testing.T) {
		goodEncName := "id_good_enc"
		goodEncPath := filepath.Join(dir, goodEncName)
		_, goodEncPub := writeEd25519KeyFile(t, goodEncPath, "good-pass")
		portGoodEnc, _ := startPhase3CertSSHServer(t, fix.hostSigner, nil, goodEncPub, nil)

		noSaveOpts := newPhase3TrustAllOptions(t, dir)
		_ = noSaveOpts.Set(OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew)
		store := &spyCredentialStore{
			noSave: true,
			configs: map[string]*ClientConfig{
				"nosave-key": {
					NodeID:          "nosave-key",
					Address:         "127.0.0.1",
					Port:            portGoodEnc,
					User:            "alice",
					AuthType:        "key",
					KeyPath:         "~/" + goodEncName,
					AuthUpdateToken: "tok-1",
					Options:         noSaveOpts,
				},
			},
		}
		env := fixtureEnvironment()
		env.HomeDir = dir
		prompter := &spyInteractionPrompter{passphrase: "good-pass"}
		conn := NewConnector(
			store,
			WithCredentialRecorder(store),
			WithEnvironment(env),
			WithInteractionHandler(prompter),
		)
		t.Cleanup(func() { _ = conn.CloseAll() })

		if _, err := conn.Connect(t.Context(), "nosave-key"); err != nil {
			t.Fatalf("Connect(nosave-key) failed with no-save recorder: %v", err)
		}
	})
}

func TestPass2Conn_M4_DevNullPrimaryWriteFileAndPlainHostKeyAlgoOrdering(t *testing.T) {
	fix := newPhase3CertFixture(t)

	t.Run("dev_null_or_env_none_first_user_known_hosts_never_writes_second_file", func(t *testing.T) {
		dir := t.TempDir()
		secondKH := filepath.Join(dir, "readonly_known_hosts")
		pinnedKey := newPhase4HostKey(t)
		if err := appendKnownHost(secondKH, "pinned.example", pinnedKey, false); err != nil {
			t.Fatal(err)
		}
		beforeBytes, err := os.ReadFile(secondKH)
		if err != nil {
			t.Fatal(err)
		}

		port := startRekeySSHServer(t, fix.hostSigner, "pw123")
		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = filepath.Join(dir, "default_known_hosts")
		env.LookupEnv = func(k string) (string, bool) {
			if k == "KH_DISABLE" {
				return "none", true
			}
			return "", false
		}

		for _, rawOpt := range []string{"/dev/null " + secondKH, "${KH_DISABLE} " + secondKH} {
			opts := MustOptions(
				OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew,
				OptionUserKnownHostsFile, rawOpt,
				OptionGlobalKnownHostsFile, "none",
			)
			provider := &mapConfigProvider{configs: map[string]*ClientConfig{
				"ephemeral": {
					NodeID:   "ephemeral",
					Address:  "127.0.0.1",
					Port:     port,
					User:     "alice",
					AuthType: "password",
					Password: "pw123",
					Options:  opts,
				},
			}}
			conn := NewConnector(provider, WithEnvironment(env))
			// Secondary file must still be read for known hosts.
			_, _, cb, khErr := conn.openKnownHostsCallback(opts.UserKnownHostsFile(), provider.configs["ephemeral"])
			if khErr != nil {
				_ = conn.CloseAll()
				t.Fatalf("openKnownHostsCallback(%q) failed: %v", rawOpt, khErr)
			}
			if vErr := cb("pinned.example:22", &net.TCPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 22}, pinnedKey); vErr != nil {
				_ = conn.CloseAll()
				t.Fatalf("expected secondary known_hosts to remain readable for %q: %v", rawOpt, vErr)
			}
			if _, cErr := conn.Connect(t.Context(), "ephemeral"); cErr != nil {
				_ = conn.CloseAll()
				t.Fatalf("Connect with %q failed: %v", rawOpt, cErr)
			}
			_ = conn.CloseAll()

			afterBytes, rErr := os.ReadFile(secondKH)
			if rErr != nil {
				t.Fatal(rErr)
			}
			if !bytes.Equal(beforeBytes, afterBytes) {
				t.Fatalf("secondary UserKnownHostsFile was unexpectedly modified for %q:\n%s", rawOpt, string(afterBytes))
			}
		}
	})

	t.Run("pinned_plain_host_key_preferred_over_untrusted_host_cert", func(t *testing.T) {
		dir := t.TempDir()
		rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rsaHostSigner, err := cryptoSSH.NewSignerFromSigner(rsaPriv)
		if err != nil {
			t.Fatal(err)
		}
		untrustedCert := signTestCertificate(t, fix.caSigner, fix.hostSigner.PublicKey(), "127.0.0.1", cryptoSSH.HostCert, 9001)
		untrustedCertSigner, err := cryptoSSH.NewCertSigner(untrustedCert, fix.hostSigner)
		if err != nil {
			t.Fatal(err)
		}

		serverCfg := &cryptoSSH.ServerConfig{
			PasswordCallback: func(_ cryptoSSH.ConnMetadata, pass []byte) (*cryptoSSH.Permissions, error) {
				if string(pass) == "pw123" {
					return &cryptoSSH.Permissions{}, nil
				}
				return nil, errors.New("bad password")
			},
		}
		// Server advertises untrusted Ed25519 HostCert + unpinned Ed25519 plain key + pinned RSA plain key.
		serverCfg.AddHostKey(untrustedCertSigner)
		serverCfg.AddHostKey(fix.hostSigner)
		serverCfg.AddHostKey(rsaHostSigner)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		t.Cleanup(func() {
			_ = ln.Close()
			wg.Wait()
		})
		wg.Go(func() {
			for {
				c, aErr := ln.Accept()
				if aErr != nil {
					return
				}
				wg.Go(func() { serveRekeyExecConn(c, serverCfg) })
			}
		})
		port := ln.Addr().(*net.TCPAddr).Port

		khPath := filepath.Join(dir, "known_hosts")
		hostToken := knownhosts.Normalize(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err := appendKnownHost(khPath, hostToken, rsaHostSigner.PublicKey(), false); err != nil {
			t.Fatal(err)
		}

		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = khPath

		opts := MustOptions(
			OptionStrictHostKeyChecking, StrictHostKeyCheckingYes,
			OptionUserKnownHostsFile, khPath,
			OptionGlobalKnownHostsFile, "none",
		)
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"dual-host": {
				NodeID:   "dual-host",
				Address:  "127.0.0.1",
				Port:     port,
				User:     "alice",
				AuthType: "password",
				Password: "pw123",
				Options:  opts,
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env))
		t.Cleanup(func() { _ = conn.CloseAll() })

		if _, err := conn.Connect(t.Context(), "dual-host"); err != nil {
			t.Fatalf("Connect failed to negotiate pinned plain RSA host key over untrusted Ed25519 cert/key: %v", err)
		}
	})
}

func TestPass2Conn_M5_L1_M8_PlanShadowSnapshotOptionsAndAgentPipeNormalization(t *testing.T) {
	t.Run("normalize_plan_allows_shadowed_proxy_command_when_hop_has_proxy_jump", func(t *testing.T) {
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"bastion": {
				NodeID:   "bastion",
				Address:  "10.0.0.1",
				Port:     22,
				User:     "ops",
				AuthType: "agent",
			},
			"target": {
				NodeID:    "target",
				Address:   "10.0.1.5",
				Port:      22,
				User:      "ops",
				AuthType:  "agent",
				ProxyJump: "bastion",
				Options:   MustOptions(OptionProxyCommand, "nc %h %p"),
			},
		}}
		plan, err := CapturePlan(t.Context(), provider, "target", "test-scope")
		if err != nil {
			t.Fatalf("CapturePlan with ProxyJump shadowing ProxyCommand failed: %v", err)
		}
		if _, err := normalizePlan(plan); err != nil {
			t.Fatalf("normalizePlan rejected shadowed ProxyCommand on ProxyJump hop: %v", err)
		}
	})

	t.Run("validate_target_compatibility_checks_original_host_auth_and_canonicalize", func(t *testing.T) {
		assertPass2ValidateTargetCompatibility(t)
	})

	t.Run("user_known_hosts_validation_and_nil_ctx_proxy_dialer", func(t *testing.T) {
		assertPass2UserKnownHostsAndNilCtxDialer(t)
	})

	t.Run("agent_socket_and_windows_named_pipe_normalization", func(t *testing.T) {
		assertPass2ConnAgentPathNormalization(t)
	})
}

func assertPass2ValidateTargetCompatibility(t *testing.T) {
	t.Helper()
	makeBase := func() ClientConfig {
		return ClientConfig{
			NodeID:       "node-1",
			OriginalHost: "web.prod",
			Address:      "10.0.0.10",
			Port:         22,
			User:         "ops",
			Options: MustOptions(
				OptionPasswordAuthentication, "yes",
				OptionKbdInteractiveAuthentication, "yes",
				OptionPreferredAuthentications, "publickey,password",
				OptionCanonicalizeHostname, "no",
				OptionCanonicalDomains, "corp.example",
				OptionCanonicalizeMaxDots, "1",
				OptionCanonicalizeFallbackLocal, "yes",
				OptionCanonicalizePermittedCNAMEs, "*.a.example:*.b.example",
			),
		}
	}
	base := makeBase()
	cur := (&base).ToConnectionConfig()

	same := makeBase()
	if err := checkTargetDigestCompatibility(cur, &same); err != nil {
		t.Fatalf("identical config failed compatibility check: %v", err)
	}

	origMut := makeBase()
	origMut.OriginalHost = "other.prod"
	if err := checkTargetDigestCompatibility(cur, &origMut); !errors.Is(err, ErrSnapshotMismatch) {
		t.Fatalf("OriginalHost change = %v, want ErrSnapshotMismatch", err)
	}

	optMutations := [][2]string{
		{OptionPasswordAuthentication, "no"},
		{OptionKbdInteractiveAuthentication, "no"},
		{OptionPreferredAuthentications, "publickey"},
		{OptionCanonicalizeHostname, "always"},
		{OptionCanonicalDomains, "other.example"},
		{OptionCanonicalizeMaxDots, "2"},
		{OptionCanonicalizeFallbackLocal, "no"},
		{OptionCanonicalizePermittedCNAMEs, "*.x.example:*.y.example"},
	}
	for _, m := range optMutations {
		mut := makeBase()
		if err := mut.Options.Set(m[0], m[1]); err != nil {
			t.Fatal(err)
		}
		if err := checkTargetDigestCompatibility(cur, &mut); !errors.Is(err, ErrSnapshotMismatch) {
			t.Fatalf("mutation %s=%s: got %v, want ErrSnapshotMismatch", m[0], m[1], err)
		}
	}
}

func assertPass2UserKnownHostsAndNilCtxDialer(t *testing.T) {
	t.Helper()
	opts := &Options{}
	for _, bad := range []string{"   ", "/tmp/kh\n/tmp/kh2", "/tmp/kh\x00", "/tmp/%z/kh"} {
		if err := opts.Set(OptionUserKnownHostsFile, bad); err == nil {
			t.Fatalf("expected OptionUserKnownHostsFile.Set(%q) to fail", bad)
		}
	}
	if err := opts.Set(OptionUserKnownHostsFile, "  /tmp/a   ~/.ssh/kh_%h  "); err != nil {
		t.Fatalf("unexpected error on multi-path UserKnownHostsFile: %v", err)
	}
	if got := opts.UserKnownHostsFile(); got != "/tmp/a ~/.ssh/kh_%h" {
		t.Fatalf("normalized UserKnownHostsFile = %q, want %q", got, "/tmp/a ~/.ssh/kh_%h")
	}
	if err := opts.Set(OptionUserKnownHostsFile, "NONE"); err != nil || opts.UserKnownHostsFile() != "none" {
		t.Fatalf("NONE normalization failed: got %q, err=%v", opts.UserKnownHostsFile(), err)
	}
	if err := opts.Set(OptionUserKnownHostsFile, "none /tmp/fallback"); err != nil {
		t.Fatalf("expected 'none /tmp/fallback' to remain valid for UserKnownHostsFile: %v", err)
	}

	var sawNonNilCtx bool
	env := fixtureEnvironment()
	env.DialProxyCommand = func(ctx context.Context, _ string) (net.Conn, error) {
		sawNonNilCtx = ctx != nil
		return nil, errors.New("dial aborted")
	}
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })
	d := &proxyCommandDialer{
		connector: conn,
		planNode: connectionPlanNode{
			name: "p",
			cfg: &ClientConfig{
				NodeID:  "p",
				Address: "127.0.0.1",
				Port:    22,
				User:    "alice",
				Options: MustOptions(OptionProxyCommand, "nc %h %p"),
			},
		},
	}
	var nilCtx context.Context
	_, _ = d.DialContext(nilCtx, "tcp", "127.0.0.1:22")
	if !sawNonNilCtx {
		t.Fatal("expected proxyCommandDialer.DialContext(nil, ...) to substitute context.Background()")
	}
}

func assertPass2ConnAgentPathNormalization(t *testing.T) {
	t.Helper()
	env := Environment{
		HomeDir:     "/home/alice",
		AgentSocket: "  /tmp/ssh-agent//agent.123  ",
	}
	gotDefault, disabled, err := ResolveIdentityAgent("", env, TargetContext{Host: "example.com"})
	if err != nil || disabled || gotDefault != filepath.Clean("/tmp/ssh-agent/agent.123") {
		t.Fatalf("ResolveIdentityAgent default = %q, disabled=%v, err=%v", gotDefault, disabled, err)
	}

	pipeCases := [][2]string{
		{`\\.\pipe\openssh-ssh-agent`, `\\.\pipe\openssh-ssh-agent`},
		{`//./PIPE/openssh-ssh-agent`, `\\.\pipe\openssh-ssh-agent`},
		{`\\.\Pipe\sub//agent`, `\\.\pipe\sub\agent`},
		{`//?/pipe/CustomAgent`, `\\?\pipe\CustomAgent`},
	}
	for _, tc := range pipeCases {
		if got := normalizeExpandedAgentSocketPath(tc[0], env); got != tc[1] {
			t.Fatalf("normalizeExpandedAgentSocketPath(%q) = %q, want %q", tc[0], got, tc[1])
		}
	}
}
