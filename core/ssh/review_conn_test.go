package ssh

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestReviewConn_M2_HungSSHAgentTimesOutAndCancels(t *testing.T) {
	dir := t.TempDir()
	fix := newPhase3CertFixture(t)

	// Fake agent that accepts a connection, drains reads, and never replies.
	newSilentHungAgentDialer := func(closedCount *atomic.Int32) func(context.Context, string) (net.Conn, error) {
		return func(_ context.Context, _ string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go func() {
				defer func() {
					closedCount.Add(1)
					_ = serverConn.Close()
				}()
				_, _ = io.Copy(io.Discard, serverConn)
			}()
			return clientConn, nil
		}
	}

	t.Run("filtered_agent_signers_timeout", func(t *testing.T) {
		var serverClosed atomic.Int32
		pubPath := filepath.Join(dir, "id_only.pub")
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sshPub, err := cryptoSSH.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pubPath, cryptoSSH.MarshalAuthorizedKey(sshPub), 0o600); err != nil {
			t.Fatal(err)
		}

		env := fixtureEnvironment()
		env.HomeDir = dir
		env.AgentSocket = "hung-agent"
		env.DialAgent = newSilentHungAgentDialer(&serverClosed)

		opts := newPhase3TrustAllOptions(t, dir)
		if err := opts.Set(OptionIdentitiesOnly, "yes"); err != nil {
			t.Fatal(err)
		}
		if err := opts.Append(OptionIdentityFile, pubPath); err != nil {
			t.Fatal(err)
		}
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"hung-filtered": {
				NodeID:   "hung-filtered",
				Address:  "127.0.0.1",
				Port:     22,
				User:     "alice",
				AuthType: "agent",
				Options:  opts,
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env), WithHandshakeTimeout(100*time.Millisecond))
		t.Cleanup(func() { _ = conn.CloseAll() })

		start := time.Now()
		_, err = conn.Connect(t.Context(), "hung-filtered")
		elapsed := time.Since(start)
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Connect error = %v, want context.DeadlineExceeded", err)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("hung ssh-agent blocked for %v, expected ~100ms timeout", elapsed)
		}
	})

	t.Run("lazy_agent_callback_timeout", func(t *testing.T) {
		var serverClosed atomic.Int32
		port, _ := startPhase3CertSSHServer(t, fix.hostSigner, nil, fix.caSigner.PublicKey(), nil)

		env := fixtureEnvironment()
		env.HomeDir = dir
		env.AgentSocket = "hung-agent"
		env.DialAgent = newSilentHungAgentDialer(&serverClosed)

		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"hung-cb": {
				NodeID:   "hung-cb",
				Address:  "127.0.0.1",
				Port:     port,
				User:     "alice",
				AuthType: "agent",
				Options:  newPhase3TrustAllOptions(t, dir),
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env), WithHandshakeTimeout(120*time.Millisecond))
		t.Cleanup(func() { _ = conn.CloseAll() })

		start := time.Now()
		_, err := conn.Connect(t.Context(), "hung-cb")
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("expected hung ssh-agent callback to fail")
		}
		if elapsed > 2*time.Second {
			t.Fatalf("hung ssh-agent callback blocked for %v", elapsed)
		}
	})

	t.Run("agent_hangs_on_sign_request", func(t *testing.T) {
		verifyHungAgentSignRequestTimeout(t, dir, fix)
	})

	t.Run("context_cancel_interrupts_hung_agent", func(t *testing.T) {
		var serverClosed atomic.Int32
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(60*time.Millisecond, cancel)

		start := time.Now()
		agentByPub, cleanup := dialAgentSignersByPubKey(
			ctx, nil, newSilentHungAgentDialer(&serverClosed), "hung-agent", 10*time.Second, nil,
		)
		if cleanup != nil {
			cleanup()
		}
		elapsed := time.Since(start)
		if len(agentByPub) != 0 {
			t.Fatalf("expected empty agentByPub on canceled context, got %d", len(agentByPub))
		}
		if elapsed > 2*time.Second {
			t.Fatalf("context cancel took %v to interrupt hung agent", elapsed)
		}
	})
}

func verifyHungAgentSignRequestTimeout(t *testing.T, dir string, fix phase3CertFixture) {
	t.Helper()
	pubRaw, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentPub, err := cryptoSSH.NewPublicKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := startPhase3CertSSHServer(t, fix.hostSigner, nil, agentPub, nil)

	// Fake agent answers REQUEST_IDENTITIES (11) with IDENTITIES_ANSWER (12)
	// containing agentPub, then stalls forever on SIGN_REQUEST (13).
	hangOnSignDialer := func(_ context.Context, _ string) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			defer func() { _ = serverConn.Close() }()
			var hdr [4]byte
			for {
				if _, rErr := io.ReadFull(serverConn, hdr[:]); rErr != nil {
					return
				}
				msgLen := binary.BigEndian.Uint32(hdr[:])
				if msgLen == 0 || msgLen > 65536 {
					return
				}
				req := make([]byte, msgLen)
				if _, rErr := io.ReadFull(serverConn, req); rErr != nil {
					return
				}
				const (
					agentRequestIdentities = 11
					agentIdentitiesAnswer  = 12
				)
				if req[0] != agentRequestIdentities {
					_, _ = io.Copy(io.Discard, serverConn)
					return
				}
				keyBlob := agentPub.Marshal()
				var payload []byte
				payload = append(payload, agentIdentitiesAnswer)
				payload = binary.BigEndian.AppendUint32(payload, 1)
				payload = binary.BigEndian.AppendUint32(payload, uint32(len(keyBlob)))
				payload = append(payload, keyBlob...)
				payload = binary.BigEndian.AppendUint32(payload, 0)

				var frame []byte
				frame = binary.BigEndian.AppendUint32(frame, uint32(len(payload)))
				frame = append(frame, payload...)
				if _, wErr := serverConn.Write(frame); wErr != nil {
					return
				}
			}
		}()
		return clientConn, nil
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.AgentSocket = "hang-on-sign"
	env.DialAgent = hangOnSignDialer

	provider := &mapConfigProvider{configs: map[string]*ClientConfig{
		"hang-sign": {
			NodeID:   "hang-sign",
			Address:  "127.0.0.1",
			Port:     port,
			User:     "alice",
			AuthType: "agent",
			Options:  newPhase3TrustAllOptions(t, dir),
		},
	}}
	conn := NewConnector(provider, WithEnvironment(env), WithHandshakeTimeout(120*time.Millisecond))
	t.Cleanup(func() { _ = conn.CloseAll() })

	start := time.Now()
	_, err = conn.Connect(t.Context(), "hang-sign")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected hang-on-sign ssh-agent to fail")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("hang-on-sign ssh-agent blocked for %v", elapsed)
	}
}

func TestReviewConn_M4_L4_L7_KeyModeUnificationPubOnlyAndAgentDedup(t *testing.T) {
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()

	wrongKeyPath := filepath.Join(dir, "id_wrong")
	wrongRawKey, wrongPub := writeEd25519KeyFile(t, wrongKeyPath, "")

	acceptedPubRaw, acceptedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	acceptedPub, err := cryptoSSH.NewPublicKey(acceptedPubRaw)
	if err != nil {
		t.Fatal(err)
	}

	// 1. M4: Plain single-key AuthType="key" (only KeyPath set, no KeyPaths/IdentityFile/cert)
	// falls back to ssh-agent when IdentitiesOnly=no, matching multi-key branch.
	t.Run("single_key_and_multi_key_agent_fallback_parity", func(t *testing.T) {
		port, _ := startPhase3CertSSHServer(t, fix.hostSigner, nil, acceptedPub, nil)
		env := fixtureEnvironment()
		env.HomeDir = dir
		env.AgentSocket = "in-memory-agent"
		env.DialAgent = startInMemoryAgent(t, acceptedPriv)

		singleCfg := &ClientConfig{
			NodeID:   "single-key",
			Address:  "127.0.0.1",
			Port:     port,
			User:     "alice",
			AuthType: "key",
			KeyPath:  wrongKeyPath,
			Options:  newPhase3TrustAllOptions(t, dir),
		}
		singleIdentOnlyOpts := newPhase3TrustAllOptions(t, dir)
		if err := singleIdentOnlyOpts.Set(OptionIdentitiesOnly, "yes"); err != nil {
			t.Fatal(err)
		}
		singleIdentOnlyCfg := &ClientConfig{
			NodeID:   "single-key-ident-only",
			Address:  "127.0.0.1",
			Port:     port,
			User:     "alice",
			AuthType: "key",
			KeyPath:  wrongKeyPath,
			Options:  singleIdentOnlyOpts,
		}
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"single-key":            singleCfg,
			"single-key-ident-only": singleIdentOnlyCfg,
		}}
		conn := NewConnector(provider, WithEnvironment(env))
		t.Cleanup(func() { _ = conn.CloseAll() })

		if _, err := conn.Connect(t.Context(), "single-key"); err != nil {
			t.Fatalf("single-key AuthType=key should fall back to ssh-agent when IdentitiesOnly=no, got: %v", err)
		}
		if _, err := conn.Connect(t.Context(), "single-key-ident-only"); err == nil {
			t.Fatal("single-key AuthType=key with IdentitiesOnly=yes must not offer unmatched ssh-agent keys")
		}
	})

	// 2. L4: AuthType="key" with IdentitiesOnly=yes supports .pub on disk + private key in ssh-agent,
	// as well as CertificateFile-only + private key in ssh-agent.
	t.Run("key_mode_identities_only_supports_pub_file_and_cert_with_agent", func(t *testing.T) {
		pubOnlyPath := filepath.Join(dir, "agent_backed.pub")
		if err := os.WriteFile(pubOnlyPath, cryptoSSH.MarshalAuthorizedKey(acceptedPub), 0o600); err != nil {
			t.Fatal(err)
		}
		cert := signTestCertificate(t, fix.caSigner, acceptedPub, "alice", cryptoSSH.UserCert, 901)
		certPath := filepath.Join(dir, "only-cert.pub")
		if err := os.WriteFile(certPath, cryptoSSH.MarshalAuthorizedKey(cert), 0o600); err != nil {
			t.Fatal(err)
		}

		portPlain, _ := startPhase3CertSSHServer(t, fix.hostSigner, nil, acceptedPub, nil)
		portCert, certLogins := startPhase3CertSSHServer(t, fix.hostSigner, fix.caSigner.PublicKey(), nil, nil)

		env := fixtureEnvironment()
		env.HomeDir = dir
		env.AgentSocket = "in-memory-agent"
		env.DialAgent = startInMemoryAgent(t, wrongRawKey, acceptedPriv)

		pubOnlyOpts := newPhase3TrustAllOptions(t, dir)
		_ = pubOnlyOpts.Set(OptionIdentitiesOnly, "yes")

		certOnlyOpts := newPhase3TrustAllOptions(t, dir)
		_ = certOnlyOpts.Set(OptionIdentitiesOnly, "yes")
		_ = certOnlyOpts.Append(OptionCertificateFile, certPath)

		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"pub-only": {
				NodeID:   "pub-only",
				Address:  "127.0.0.1",
				Port:     portPlain,
				User:     "alice",
				AuthType: "key",
				KeyPath:  pubOnlyPath,
				Options:  pubOnlyOpts,
			},
			"cert-only": {
				NodeID:   "cert-only",
				Address:  "127.0.0.1",
				Port:     portCert,
				User:     "alice",
				AuthType: "key",
				Options:  certOnlyOpts,
			},
		}}
		conn := NewConnector(provider, WithEnvironment(env))
		t.Cleanup(func() { _ = conn.CloseAll() })

		if _, err := conn.Connect(t.Context(), "pub-only"); err != nil {
			t.Fatalf("AuthType=key + IdentitiesOnly=yes with .pub file + agent failed: %v", err)
		}
		if _, err := conn.Connect(t.Context(), "cert-only"); err != nil {
			t.Fatalf("AuthType=key + IdentitiesOnly=yes with CertificateFile + agent failed: %v", err)
		}
		if certLogins.Load() != 1 {
			t.Fatalf("certLogins = %d, want 1", certLogins.Load())
		}
	})

	// 3. L7: Deduplicate ssh-agent signers already offered by file keys in both "key" and "auto" modes.
	for _, authMode := range []string{"key", "auto"} {
		t.Run("dedup_file_and_agent_keys_"+authMode, func(t *testing.T) {
			verifyFileAndAgentKeyDeduplication(t, dir, fix, authMode, wrongKeyPath, wrongRawKey, wrongPub, acceptedPriv, acceptedPub)
		})
	}
}

func verifyFileAndAgentKeyDeduplication(
	t *testing.T,
	dir string,
	fix phase3CertFixture,
	authMode string,
	wrongKeyPath string,
	wrongRawKey ed25519.PrivateKey,
	wrongPub cryptoSSH.PublicKey,
	acceptedPriv ed25519.PrivateKey,
	acceptedPub cryptoSSH.PublicKey,
) {
	t.Helper()
	var mu sync.Mutex
	offeredCounts := make(map[string]int)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srvCfg := &cryptoSSH.ServerConfig{
		PublicKeyCallback: func(_ cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			raw := string(key.Marshal())
			mu.Lock()
			offeredCounts[raw]++
			mu.Unlock()
			if raw == string(acceptedPub.Marshal()) {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("rejected")
		},
	}
	srvCfg.AddHostKey(fix.hostSigner)
	go func() {
		for {
			nc, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				sc, chans, reqs, sErr := cryptoSSH.NewServerConn(c, srvCfg)
				if sErr != nil {
					return
				}
				go cryptoSSH.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(cryptoSSH.Prohibited, "no channels")
				}
				_ = sc.Wait()
			}(nc)
		}
	}()

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.AgentSocket = "in-memory-agent"
	env.DialAgent = startInMemoryAgent(t, wrongRawKey, acceptedPriv)
	env.DefaultKeyPaths = []string{wrongKeyPath}

	provider := &mapConfigProvider{configs: map[string]*ClientConfig{
		"dedup": {
			NodeID:   "dedup",
			Address:  "127.0.0.1",
			Port:     ln.Addr().(*net.TCPAddr).Port,
			User:     "alice",
			AuthType: authMode,
			KeyPath:  wrongKeyPath,
			Options:  newPhase3TrustAllOptions(t, dir),
		},
	}}
	conn := NewConnector(provider, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	if _, err := conn.Connect(t.Context(), "dedup"); err != nil {
		t.Fatalf("Connect(%s) failed: %v", authMode, err)
	}

	mu.Lock()
	wrongOffers := offeredCounts[string(wrongPub.Marshal())]
	acceptedOffers := offeredCounts[string(acceptedPub.Marshal())]
	mu.Unlock()

	if wrongOffers != 1 {
		t.Fatalf("%s mode offered duplicate wrong key %d times, want 1", authMode, wrongOffers)
	}
	if acceptedOffers < 1 {
		t.Fatalf("%s mode did not offer accepted agent key", authMode)
	}
}

func TestReviewConn_L2_MalformedGlobalKnownHostsSkippedUserRemainsStrict(t *testing.T) {
	dir := t.TempDir()
	hostKey := newPhase4HostKey(t)

	badGlobal := filepath.Join(dir, "ssh_known_hosts_bad")
	if err := os.WriteFile(badGlobal, []byte("example.com not-a-valid-key-type AAAA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	goodGlobal := filepath.Join(dir, "ssh_known_hosts_good")
	if err := appendKnownHost(goodGlobal, "good.example.com", hostKey, false); err != nil {
		t.Fatal(err)
	}
	emptyUser := filepath.Join(dir, "user_known_hosts")
	if err := os.WriteFile(emptyUser, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = emptyUser
	env.GlobalKnownHostsFiles = []string{badGlobal, goodGlobal}

	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	cfg := &ClientConfig{
		NodeID:  "good",
		Address: "good.example.com",
		Port:    22,
		User:    "alice",
		Options: MustOptions(OptionStrictHostKeyChecking, "yes"),
	}
	_, _, cb, err := conn.openKnownHostsCallback("", cfg)
	if err != nil {
		t.Fatalf("openKnownHostsCallback failed despite malformed global file: %v", err)
	}
	if err := cb("good.example.com:22", &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}, hostKey); err != nil {
		t.Fatalf("expected valid global known_hosts entry to verify after skipping malformed global file: %v", err)
	}

	// UserKnownHostsFile must remain strict!
	badUser := filepath.Join(dir, "bad_user_known_hosts")
	if err := os.WriteFile(badUser, []byte("corrupt user known hosts line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := conn.openKnownHostsCallback(badUser, cfg); err == nil {
		t.Fatal("expected malformed UserKnownHostsFile to fail strictly")
	}
}

type plainOnlyRSASigner struct {
	pub cryptoSSH.PublicKey
	raw *rsa.PrivateKey
}

func (s *plainOnlyRSASigner) PublicKey() cryptoSSH.PublicKey { return s.pub }

func (s *plainOnlyRSASigner) Sign(randReader io.Reader, data []byte) (*cryptoSSH.Signature, error) {
	base, err := cryptoSSH.NewSignerFromSigner(s.raw)
	if err != nil {
		return nil, err
	}
	return base.Sign(randReader, data)
}

func TestReviewConn_L3_CertSignerMultiAlgorithmPassthroughAndNonAlgoError(t *testing.T) {
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := cryptoSSH.NewSignerFromSigner(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaAlgoSigner, ok := rsaSigner.(cryptoSSH.AlgorithmSigner)
	if !ok {
		t.Fatal("expected rsa Signer to implement AlgorithmSigner")
	}
	restricted, err := cryptoSSH.NewSignerWithAlgorithms(rsaAlgoSigner, []string{cryptoSSH.KeyAlgoRSASHA512})
	if err != nil {
		t.Fatal(err)
	}

	rsaCert := signTestCertificate(t, fix.caSigner, rsaSigner.PublicKey(), "alice", cryptoSSH.UserCert, 1001)
	wrapped, err := newWrappedCertSigner(rsaCert, restricted)
	if err != nil {
		t.Fatalf("newWrappedCertSigner failed: %v", err)
	}
	mas, ok := wrapped.(cryptoSSH.MultiAlgorithmSigner)
	if !ok {
		t.Fatalf("wrapped cert signer %T does not implement MultiAlgorithmSigner", wrapped)
	}
	if got := mas.Algorithms(); !slices.Equal(got, []string{cryptoSSH.KeyAlgoRSASHA512}) {
		t.Fatalf("Algorithms() = %v, want [%q]", got, cryptoSSH.KeyAlgoRSASHA512)
	}

	// End-to-end handshake with restricted RSA-SHA2-512 KeySource + CertificateFile.
	certPath := filepath.Join(dir, "rsa512-cert.pub")
	if err := os.WriteFile(certPath, cryptoSSH.MarshalAuthorizedKey(rsaCert), 0o600); err != nil {
		t.Fatal(err)
	}
	port, certLogins := startPhase3CertSSHServer(t, fix.hostSigner, fix.caSigner.PublicKey(), nil, nil)
	opts := newPhase3TrustAllOptions(t, dir)
	if err := opts.Append(OptionCertificateFile, certPath); err != nil {
		t.Fatal(err)
	}
	provider := &mapConfigProvider{configs: map[string]*ClientConfig{
		"rsa512": {
			NodeID:   "rsa512",
			Address:  "127.0.0.1",
			Port:     port,
			User:     "alice",
			AuthType: "key",
			KeyRef:   "restricted-rsa512",
			Options:  opts,
		},
	}}
	env := fixtureEnvironment()
	env.HomeDir = dir
	conn := NewConnector(
		provider,
		WithEnvironment(env),
		WithKeySource(&fixtureKeySource{lease: &fixtureKeyLease{signer: restricted}}),
	)
	t.Cleanup(func() { _ = conn.CloseAll() })
	if _, err := conn.Connect(t.Context(), "rsa512"); err != nil {
		t.Fatalf("Connect with restricted MultiAlgorithmSigner RSA cert failed: %v", err)
	}
	if certLogins.Load() != 1 {
		t.Fatalf("certLogins = %d, want 1", certLogins.Load())
	}

	// Non-AlgorithmSigner RSA key must return an error when rsa-sha2-* is requested, never SHA-1 Sign().
	plainRSA := &plainOnlyRSASigner{pub: rsaSigner.PublicKey(), raw: rsaKey}
	wrappedPlain, err := newWrappedCertSigner(rsaCert, plainRSA)
	if err != nil {
		t.Fatalf("newWrappedCertSigner(plainRSA) failed: %v", err)
	}
	algoWrapped := wrappedPlain.(cryptoSSH.AlgorithmSigner)
	if _, err := algoWrapped.SignWithAlgorithm(rand.Reader, []byte("challenge"), cryptoSSH.KeyAlgoRSASHA256); err == nil {
		t.Fatal("expected non-AlgorithmSigner RSA cert signer to reject rsa-sha2-256 instead of falling back to SHA-1")
	}
	if _, err := algoWrapped.SignWithAlgorithm(rand.Reader, []byte("challenge"), cryptoSSH.CertAlgoRSASHA512v01); err == nil {
		t.Fatal("expected non-AlgorithmSigner RSA cert signer to reject rsa-sha2-512-cert-v01@openssh.com")
	}
	// Ensure crypto.Signer interface compile check isn't unused.
	var _ crypto.Signer = rsaKey
}

func TestReviewConn_L5_LazyLocalExecTokenValidation(t *testing.T) {
	env := Environment{
		HomeDir:   `C:\Users\John Doe`,
		LocalUser: `CORP\John Doe`,
		LocalHost: "workstation",
		LocalUID:  "1000",
	}
	target := TargetContext{
		Host:         "10.20.30.40",
		Port:         2222,
		User:         `CORP\jdoe`,
		OriginalHost: "Prod Web 01",
	}

	gotProxy, err := ExpandProxyCommand("nc %h %p", env, target)
	if err != nil || gotProxy != "nc 10.20.30.40 2222" {
		t.Fatalf("ExpandProxyCommand(\"nc %%h %%p\") = %q, %v; want \"nc 10.20.30.40 2222\", nil", gotProxy, err)
	}
	gotLocal, err := ExpandLocalCommand("echo %h:%p", env, target)
	if err != nil || gotLocal != "echo 10.20.30.40:2222" {
		t.Fatalf("ExpandLocalCommand(\"echo %%h:%%p\") = %q, %v; want \"echo 10.20.30.40:2222\", nil", gotLocal, err)
	}

	// Referencing any of the unsafe tokens still fails closed with ErrUnsafeExecToken.
	for _, badCmd := range []string{"nc %h %p -l %r", "nc %n %p"} {
		if _, err := ExpandProxyCommand(badCmd, env, target); !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("ExpandProxyCommand(%q) error = %v, want ErrUnsafeExecToken", badCmd, err)
		}
	}
	for _, badCmd := range []string{"echo %r", "echo %n", "echo %u", "echo %d"} {
		if _, err := ExpandLocalCommand(badCmd, env, target); !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("ExpandLocalCommand(%q) error = %v, want ErrUnsafeExecToken", badCmd, err)
		}
	}

	// End-to-end Connector.Connect with Windows DOMAIN\user and ProxyCommand="nc %h %p".
	var dialedCmd string
	store := &mapTestProvider{configs: map[string]*ClientConfig{
		`CORP\jdoe@10.20.30.40:2222`: {
			NodeID:       `CORP\jdoe@10.20.30.40:2222`,
			OriginalHost: "Prod Web 01",
			Address:      "10.20.30.40",
			Port:         2222,
			User:         `CORP\jdoe`,
			AuthType:     "password",
			Password:     "pw",
			Options: MustOptions(
				OptionProxyCommand, "nc %h %p",
				OptionStrictHostKeyChecking, "no",
			),
		},
	}}
	envWithDial := env
	envWithDial.DialProxyCommand = func(_ context.Context, cmd string) (net.Conn, error) {
		dialedCmd = cmd
		cSide, sSide := newLoopbackConnPair(t)
		startInMemoryPipeSSHServer(t, sSide, "pw")
		return cSide, nil
	}
	conn := NewConnector(store, WithHostKeyVerifier(trustAnyFixtureHostKey{}), WithEnvironment(envWithDial))
	t.Cleanup(func() { _ = conn.CloseAll() })

	if _, err := conn.Connect(t.Context(), `CORP\jdoe@10.20.30.40:2222`); err != nil {
		t.Fatalf("Connect with unused DOMAIN\\user and ProxyCommand 'nc %%h %%p' failed: %v", err)
	}
	if dialedCmd != "nc 10.20.30.40 2222" {
		t.Fatalf("dialedCmd = %q, want %q", dialedCmd, "nc 10.20.30.40 2222")
	}
}

func TestReviewConn_L6_ValidateTargetCompatibilityCoversTrustAuthAndCryptoOptions(t *testing.T) {
	baseCfg := func() ClientConfig {
		opts := MustOptions(
			OptionStrictHostKeyChecking, "accept-new",
			OptionUserKnownHostsFile, "~/.ssh/known_hosts",
			OptionGlobalKnownHostsFile, "/etc/ssh/ssh_known_hosts",
			OptionVerifyHostKeyDNS, "no",
			OptionHashKnownHosts, "no",
			OptionIdentityAgent, "SSH_AUTH_SOCK",
			OptionIdentitiesOnly, "no",
			OptionPubkeyAuthentication, "yes",
			OptionCiphers, "chacha20-poly1305@openssh.com",
			OptionMACs, "hmac-sha2-256",
			OptionKexAlgorithms, "curve25519-sha256",
			OptionHostKeyAlgorithms, "ssh-ed25519",
		)
		_ = opts.Append(OptionCertificateFile, "~/.ssh/id_ed25519-cert.pub")
		return ClientConfig{
			NodeID:  "web",
			Address: "10.0.0.10",
			Port:    22,
			User:    "ops",
			Options: opts,
		}
	}

	bc := baseCfg()
	cur := (&bc).ToConnectionConfig()
	identical := baseCfg()
	if err := validateTargetCompatibility(cur, &identical); err != nil {
		t.Fatalf("validateTargetCompatibility on identical config failed: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*Options)
	}{
		{"GlobalKnownHostsFile", func(o *Options) { _ = o.Set(OptionGlobalKnownHostsFile, "none") }},
		{"VerifyHostKeyDNS", func(o *Options) { _ = o.Set(OptionVerifyHostKeyDNS, "yes") }},
		{"HashKnownHosts", func(o *Options) { _ = o.Set(OptionHashKnownHosts, "yes") }},
		{"CertificateFile", func(o *Options) { _ = o.Append(OptionCertificateFile, "~/.ssh/extra-cert.pub") }},
		{"IdentityAgent", func(o *Options) { _ = o.Set(OptionIdentityAgent, "none") }},
		{"IdentitiesOnly", func(o *Options) { _ = o.Set(OptionIdentitiesOnly, "yes") }},
		{"PubkeyAuthentication", func(o *Options) { _ = o.Set(OptionPubkeyAuthentication, "no") }},
		{"Ciphers", func(o *Options) { _ = o.Set(OptionCiphers, "aes256-gcm@openssh.com") }},
		{"MACs", func(o *Options) { _ = o.Set(OptionMACs, "hmac-sha2-512") }},
		{"KexAlgorithms", func(o *Options) { _ = o.Set(OptionKexAlgorithms, "ecdh-sha2-nistp256") }},
		{"HostKeyAlgorithms", func(o *Options) { _ = o.Set(OptionHostKeyAlgorithms, "rsa-sha2-512") }},
	}

	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			mut := baseCfg()
			tc.mutate(mut.Options)
			err := validateTargetCompatibility(cur, &mut)
			if !errors.Is(err, ErrSnapshotMismatch) {
				t.Fatalf("mutation %s: error = %v, want ErrSnapshotMismatch", tc.name, err)
			}
		})
	}
}
