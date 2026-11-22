package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestRound4_ProxyJumpHelpers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw      string
		wantDis  bool
		wantKind ProxyKind
		wantErr  bool
	}{
		{"", false, ProxyUnset, true},
		{" , ", false, ProxyUnset, true},
		{"none,", false, ProxyUnset, true},
		{"none", true, ProxyDisabled, false},
		{"NONE", true, ProxyDisabled, false},
		{"none,none", true, ProxyDisabled, false},
		{" none , NONE ", true, ProxyDisabled, false},
		{"bastion", false, ProxyJump, false},
		{"none,bastion", false, ProxyUnset, true},
	} {
		if got := IsDisabledProxyJump(tc.raw); got != tc.wantDis {
			t.Errorf("IsDisabledProxyJump(%q) = %v, want %v", tc.raw, got, tc.wantDis)
		}
		ps, err := ParseProxyJump(tc.raw)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseProxyJump(%q) err = %v, wantErr=%v", tc.raw, err, tc.wantErr)
			continue
		}
		if err == nil && ps.Kind() != tc.wantKind {
			t.Errorf("ParseProxyJump(%q).Kind() = %v, want %v", tc.raw, ps.Kind(), tc.wantKind)
		}
	}
}

type round4SlowDirectTCPIPConn struct {
	*dummySSHConn
	openStarted chan struct{}
	unblockOpen chan struct{}
	openOnce    sync.Once
	closeCount  atomic.Int32
}

func (c *round4SlowDirectTCPIPConn) Close() error {
	c.closeCount.Add(1)
	return c.dummySSHConn.Close()
}

func (c *round4SlowDirectTCPIPConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name == "direct-tcpip" {
		c.openOnce.Do(func() { close(c.openStarted) })
		<-c.unblockOpen
		return nil, nil, errors.New("connect timeout")
	}
	return nil, nil, errors.New("unsupported")
}

func TestRound4_P1_4_SlowProxyChannelOpenAndRequestDoNotKillSharedMaster(t *testing.T) {
	t.Run("slow direct-tcpip open does not kill master past handshake timeout", func(t *testing.T) {
		chans := make(chan cryptoSSH.NewChannel)
		reqs := make(chan *cryptoSSH.Request)
		conn := &round4SlowDirectTCPIPConn{
			dummySSHConn: &dummySSHConn{chans: chans, reqs: reqs},
			openStarted:  make(chan struct{}),
			unblockOpen:  make(chan struct{}),
		}
		sshClient := cryptoSSH.NewClient(conn, chans, reqs)
		defer func() {
			close(conn.unblockOpen)
			_ = sshClient.Close()
		}()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		srv := &MuxServer{
			serverCtx:      ctx,
			serverCancel:   cancel,
			sshClient:      sshClient,
			requestTimeout: 50 * time.Millisecond,
			idleNotify:     make(chan struct{}),
			shutdownChan:   make(chan struct{}),
		}
		c1, c2 := net.Pipe()
		defer func() {
			_ = c1.Close()
			_ = c2.Close()
		}()
		ps := &proxySessionState{
			server: srv,
			conn:   c1,
			global: newOrderedQueue[proxyGlobalRequest](),
		}

		openDone := make(chan error, 1)
		go func() {
			_, _, err := ps.openRemoteChannelContext("direct-tcpip", nil)
			openDone <- err
		}()
		<-conn.openStarted

		// Exceed srv.requestTimeout multiple times: shared master must remain alive.
		time.Sleep(150 * time.Millisecond)
		if srv.isShuttingDown() || conn.closeCount.Load() != 0 {
			t.Fatalf("slow OpenChannel killed healthy MuxServer (shuttingDown=%v closeCount=%d)", srv.isShuttingDown(), conn.closeCount.Load())
		}

		// Proxy client disconnecting must abort wait promptly without killing master.
		ps.closeAll()
		select {
		case err := <-openDone:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("openRemoteChannelContext after disconnect = %v, want net.ErrClosed", err)
			}
		case <-time.After(time.Second):
			t.Fatal("openRemoteChannelContext did not return promptly after proxy disconnect")
		}
		if srv.isShuttingDown() || conn.closeCount.Load() != 0 {
			t.Fatalf("abandoned OpenChannel killed shared MuxServer (shuttingDown=%v closeCount=%d)", srv.isShuttingDown(), conn.closeCount.Load())
		}
	})

	t.Run("sendBoundedProxyChannelRequest timeout with healthy Close keeps master alive", func(t *testing.T) {
		chans := make(chan cryptoSSH.NewChannel)
		reqs := make(chan *cryptoSSH.Request)
		conn := &globalReqBlockingConn{
			dummySSHConn: &dummySSHConn{chans: chans, reqs: reqs},
			reqStarted:   make(chan struct{}),
			release:      make(chan struct{}),
		}
		sshClient := cryptoSSH.NewClient(conn, chans, reqs)
		defer func() {
			close(conn.release)
			_ = sshClient.Close()
		}()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		srv := &MuxServer{
			serverCtx:      ctx,
			serverCancel:   cancel,
			sshClient:      sshClient,
			requestTimeout: 50 * time.Millisecond,
			idleNotify:     make(chan struct{}),
			shutdownChan:   make(chan struct{}),
		}
		c1, c2 := net.Pipe()
		defer func() {
			_ = c1.Close()
			_ = c2.Close()
		}()
		ps := &proxySessionState{server: srv, conn: c1, global: newOrderedQueue[proxyGlobalRequest]()}
		ch := &blockingSendRequestChannel{
			reqStarted: make(chan struct{}),
			releaseReq: make(chan struct{}),
		}
		defer close(ch.releaseReq)
		pc := &proxyChan{remoteCh: ch}

		ok, _, err := ps.sendBoundedProxyChannelRequest(pc, "exec", true, nil)
		if ok || err == nil {
			t.Fatalf("expected timeout error on stuck channel request, got ok=%v err=%v", ok, err)
		}
		if srv.isShuttingDown() || conn.closeCount.Load() != 0 {
			t.Fatalf("per-channel SendRequest timeout killed shared MuxServer (shuttingDown=%v closeCount=%d)", srv.isShuttingDown(), conn.closeCount.Load())
		}
	})
}

func TestRound4_P1_5_HandleRemoteRequestReplyRoutesByServerChannelID(t *testing.T) {
	t.Parallel()

	ps := &proxySessionState{}
	// Channel A: clientCh=0, serverCh=1; Channel B: clientCh=1, serverCh=2.
	pcA := &proxyChan{clientCh: 0, serverCh: 1, pendingRemoteReqs: newRemoteRequestQueue()}
	pcB := &proxyChan{clientCh: 1, serverCh: 2, pendingRemoteReqs: newRemoteRequestQueue()}
	ps.channels.Store(pcA.serverCh, pcA)
	ps.channels.Store(pcB.serverCh, pcB)

	reqA := &cryptoSSH.Request{Type: "exit-status"}
	reqB := &cryptoSSH.Request{Type: "keepalive@openssh.com"}
	pcA.pendingRemoteReqs.push(reqA)
	pcB.pendingRemoteReqs.push(reqB)

	// RFC 4254: client reply carries recipient's serverCh (1 for A), NOT clientCh!
	w := newMuxWriter()
	w.WriteUint32(pcA.serverCh)
	ps.handleRemoteRequestReply(w.Bytes(), true)

	if pcA.pendingRemoteReqs.popOkForTest() {
		t.Fatal("pcA request was NOT popped by serverCh=1 reply")
	}
	if !pcB.pendingRemoteReqs.popOkForTest() {
		t.Fatal("pcB request (clientCh=1, serverCh=2) was wrongly popped by serverCh=1 reply")
	}
}

func (q *remoteRequestQueue) popOkForTest() bool {
	_, ok := q.pop()
	return ok
}

type round4PartialWriteChannel struct {
	cryptoSSH.Channel
	writeN  int
	writeCB func([]byte) (int, error)
}

func (c *round4PartialWriteChannel) Write(p []byte) (int, error) {
	if c.writeCB != nil {
		return c.writeCB(p)
	}
	if c.writeN > 0 && c.writeN < len(p) {
		return c.writeN, nil
	}
	return len(p), nil
}
func (c *round4PartialWriteChannel) Stderr() io.ReadWriter { return nil }
func (c *round4PartialWriteChannel) CloseWrite() error     { return nil }

func TestRound4_P3_1_RelayChannelInputCreditsWrittenBytesOnlyAndStopsOnError(t *testing.T) {
	t.Parallel()

	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()
	ps := &proxySessionState{conn: c1}

	var mu sync.Mutex
	var gotAdjusts []uint32
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			pkt, err := readUnpaddedPacket(c2)
			if err != nil {
				return
			}
			if len(pkt) >= 9 && pkt[0] == msgChannelWindowAdjust {
				r := newMuxReader(pkt[1:])
				_, _ = r.ReadUint32()
				if delta, err := r.ReadUint32(); err == nil {
					mu.Lock()
					gotAdjusts = append(gotAdjusts, delta)
					mu.Unlock()
				}
			}
		}
	}()

	calls := 0
	pc := &proxyChan{
		clientCh: 7,
		serverCh: 1,
		remoteCh: &round4PartialWriteChannel{
			writeCB: func(p []byte) (int, error) {
				calls++
				if calls == 1 {
					return 3, nil // short write
				}
				return 0, errors.New("write broken")
			},
		},
		input: newOrderedQueue[proxyChannelInput](),
	}
	pc.input.push(proxyChannelInput{kind: msgChannelData, payload: []byte("abcdef")})
	pc.input.push(proxyChannelInput{kind: msgChannelData, payload: []byte("second")})
	pc.input.push(proxyChannelInput{kind: msgChannelData, payload: []byte("third")})
	pc.input.close()

	ps.relayChannelInput(pc)
	_ = c1.Close()
	<-readDone

	if calls != 2 {
		t.Fatalf("remoteCh.Write called %d times after error, want 2", calls)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(gotAdjusts) != 1 || gotAdjusts[0] != 3 {
		t.Fatalf("window adjusts = %v, want [3]", gotAdjusts)
	}
}

func TestRound4_P1_6_And_P2_5_KeySourceBindingAgentSuppressionAndCertDedup(t *testing.T) {
	fileKeyPath := filepath.Join(t.TempDir(), "id_disk")
	fileSigner := writeAuthTestPrivateKey(t, fileKeyPath)

	vaultSigner, vaultPriv, vaultKeyPath, vaultCert, vaultCertPath, agentPriv, agentSigner := prepareRound4KeySourceMaterials(t)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: agentPriv}); err != nil {
		t.Fatal(err)
	}

	var agentCalls atomic.Int32
	var mu sync.Mutex
	var offeredKeys []string
	var acceptVaultKey bool

	addr, stop := startTestMultiAuthSSHServer(t, nil, "", func(sc *cryptoSSH.ServerConfig) {
		sc.PublicKeyCallback = func(conn cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			raw := string(key.Marshal())
			mu.Lock()
			offeredKeys = append(offeredKeys, raw)
			allowVault := acceptVaultKey
			mu.Unlock()
			if allowVault && raw == string(vaultSigner.PublicKey().Marshal()) {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("rejected")
		}
	})
	defer stop()
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	for i := 0; i < len(portStr); i++ {
		port = port*10 + int(portStr[i]-'0')
	}

	env := Environment{
		AgentSocket: "/tmp/mock-agent.sock",
		DialAgent: func(context.Context, string) (net.Conn, error) {
			agentCalls.Add(1)
			c1, c2 := net.Pipe()
			go func() {
				_ = agent.ServeAgent(keyring, c2)
				_ = c2.Close()
			}()
			return c1, nil
		},
	}

	t.Run("KeyRef bound key with IdentitiesOnly unset must never fall back to ssh-agent", func(t *testing.T) {
		mu.Lock()
		offeredKeys = nil
		acceptVaultKey = false
		mu.Unlock()
		agentCalls.Store(0)

		ks := &fixtureKeySource{lease: &fixtureKeyLease{signer: vaultSigner}}
		cfg := &ClientConfig{
			NodeID:   "vault-bound",
			Address:  host,
			Port:     port,
			User:     "ops",
			AuthType: "key",
			KeyRef:   "vault://key-1",
			Options:  MustOptions(OptionStrictHostKeyChecking, "no", OptionUserKnownHostsFile, "none"),
		}
		conn := NewConnector(&mockConfigStore{cfg: cfg}, WithEnvironment(env), WithKeySource(ks), WithHostKeyVerifier(staticTestVerifier{}))
		defer closePlanConnector(t, conn)

		_, err := conn.Connect(t.Context(), "vault-bound")
		if err == nil {
			t.Fatal("expected authentication failure when bound KeyRef is rejected")
		}
		if agentCalls.Load() != 0 {
			t.Fatalf("KeyRef-bound AuthType=key dialed ambient ssh-agent %d times, want 0", agentCalls.Load())
		}
		mu.Lock()
		gotOffered := len(offeredKeys)
		mu.Unlock()
		if gotOffered != 1 {
			t.Fatalf("KeyRef-bound AuthType=key offered %d keys (possibly fell back to agentSigner=%v), want 1", gotOffered, agentSigner != nil)
		}
	})

	t.Run("auto with sourced cert filters SSHOptions.IdentityFiles and deduplicates agent certs", func(t *testing.T) {
		verifyRound4AutoCertDedup(
			t, host, port,
			vaultSigner, vaultPriv, vaultKeyPath, vaultCert, vaultCertPath, agentPriv,
			&mu, &offeredKeys, &acceptVaultKey,
		)
	})

	t.Run("NodeID-keyed KeySource runs even with IdentityFile and falls back only on ErrKeyNotFound", func(t *testing.T) {
		mu.Lock()
		offeredKeys = nil
		acceptVaultKey = true
		mu.Unlock()

		ksHit := &fixtureKeySource{lease: &fixtureKeyLease{signer: vaultSigner}}
		cfg := &ClientConfig{
			NodeID:   "nodeid-over-idfile",
			Address:  host,
			Port:     port,
			User:     "ops",
			AuthType: "key",
			KeyPaths: []string{fileKeyPath},
			Options:  MustOptions(OptionStrictHostKeyChecking, "no", OptionUserKnownHostsFile, "none"),
		}
		connHit := NewConnector(&mockConfigStore{cfg: cfg}, WithKeySource(ksHit), WithHostKeyVerifier(staticTestVerifier{}))
		defer closePlanConnector(t, connHit)

		cli, err := connHit.Connect(t.Context(), "nodeid-over-idfile")
		if err != nil || cli == nil {
			t.Fatalf("expected NodeID KeySource to authenticate despite KeyPaths, got cli=%v err=%v", cli, err)
		}

		// When KeySource returns ErrKeyNotFound with empty KeyRef/KeyPath, falls back to fileKeyPath.
		ksNotFound := &fixtureKeySource{err: ErrKeyNotFound}
		_ = os.WriteFile(fileKeyPath+".pub", cryptoSSH.MarshalAuthorizedKey(fileSigner.PublicKey()), 0o600)
		// Non-ErrKeyNotFound must fail closed.
		ksOtherErr := &fixtureKeySource{err: errors.New("backend unavailable")}
		connErr := NewConnector(&mockConfigStore{cfg: cfg}, WithKeySource(ksOtherErr), WithHostKeyVerifier(staticTestVerifier{}))
		defer closePlanConnector(t, connErr)
		if _, err := connErr.Connect(t.Context(), "nodeid-over-idfile"); err == nil {
			t.Fatal("expected non-ErrKeyNotFound KeySource error to fail closed")
		}

		// With ErrKeyNotFound and empty KeyRef/KeyPath, attempts fileSigner.
		mu.Lock()
		offeredKeys = nil
		acceptVaultKey = false
		mu.Unlock()
		connNF := NewConnector(&mockConfigStore{cfg: cfg}, WithKeySource(ksNotFound), WithHostKeyVerifier(staticTestVerifier{}))
		defer closePlanConnector(t, connNF)
		_, _ = connNF.Connect(t.Context(), "nodeid-over-idfile")
		mu.Lock()
		sawFile := len(offeredKeys) > 0 && offeredKeys[0] == string(fileSigner.PublicKey().Marshal())
		mu.Unlock()
		if !sawFile {
			t.Fatalf("expected fallback to fileSigner on ErrKeyNotFound, offered=%d", len(offeredKeys))
		}
	})
}

func verifyRound4AutoCertDedup(
	t *testing.T,
	host string,
	port int,
	vaultSigner cryptoSSH.Signer,
	vaultPriv ed25519.PrivateKey,
	vaultKeyPath string,
	vaultCert *cryptoSSH.Certificate,
	vaultCertPath string,
	agentPriv ed25519.PrivateKey,
	mu *sync.Mutex,
	offeredKeys *[]string,
	acceptVaultKey *bool,
) {
	t.Helper()
	mu.Lock()
	*offeredKeys = nil
	*acceptVaultKey = false
	mu.Unlock()

	// Use an agent keyring that ALSO holds vaultPriv and vaultCert so we actually
	// exercise agent cert/key deduplication alongside KeySource and IdentityFile.
	dedupKeyring := agent.NewKeyring()
	if err := dedupKeyring.Add(agent.AddedKey{PrivateKey: agentPriv}); err != nil {
		t.Fatal(err)
	}
	if err := dedupKeyring.Add(agent.AddedKey{PrivateKey: vaultPriv}); err != nil {
		t.Fatal(err)
	}
	if err := dedupKeyring.Add(agent.AddedKey{PrivateKey: vaultPriv, Certificate: vaultCert}); err != nil {
		t.Fatal(err)
	}
	var dedupAgentCalls atomic.Int32
	dedupEnv := Environment{
		AgentSocket: "/tmp/dedup-agent.sock",
		DialAgent: func(ctx context.Context, socket string) (net.Conn, error) {
			dedupAgentCalls.Add(1)
			c1, c2 := net.Pipe()
			go func() {
				_ = agent.ServeAgent(dedupKeyring, c2)
				_ = c2.Close()
			}()
			return c1, nil
		},
	}

	ks := &fixtureKeySource{lease: &fixtureKeyLease{signer: vaultSigner}}
	cfg := &ClientConfig{
		NodeID:   "auto-cert-dedup",
		Address:  host,
		Port:     port,
		User:     "ops",
		AuthType: "auto",
		KeyRef:   "vault://cert-owner",
		KeyPath:  vaultKeyPath,
		Options: MustOptions(
			OptionStrictHostKeyChecking, "no",
			OptionUserKnownHostsFile, "none",
			OptionIdentityFile, vaultKeyPath,
			OptionCertificateFile, vaultCertPath,
		),
	}
	conn := NewConnector(&mockConfigStore{cfg: cfg}, WithEnvironment(dedupEnv), WithKeySource(ks), WithHostKeyVerifier(staticTestVerifier{}))
	defer closePlanConnector(t, conn)

	_, _ = conn.Connect(t.Context(), "auto-cert-dedup")
	if dedupAgentCalls.Load() == 0 {
		t.Fatal("expected auto mode dedup test to dial agent")
	}
	vaultCertRaw := string(vaultCert.Marshal())
	vaultPubRaw := string(vaultSigner.PublicKey().Marshal())
	mu.Lock()
	var certOffers, plainOffers int
	for _, k := range *offeredKeys {
		if k == vaultCertRaw {
			certOffers++
		}
		if k == vaultPubRaw {
			plainOffers++
		}
	}
	mu.Unlock()
	if certOffers != 1 || plainOffers != 1 {
		t.Fatalf("dedup offers failed: certOffers=%d (want 1), plainOffers=%d (want 1)", certOffers, plainOffers)
	}
}

func prepareRound4KeySourceMaterials(t *testing.T) (cryptoSSH.Signer, ed25519.PrivateKey, string, *cryptoSSH.Certificate, string, ed25519.PrivateKey, cryptoSSH.Signer) {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := cryptoSSH.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, vaultPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vaultSigner, err := cryptoSSH.NewSignerFromKey(vaultPriv)
	if err != nil {
		t.Fatal(err)
	}
	vaultRawPriv, err := cryptoSSH.MarshalPrivateKey(vaultPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	vaultCert := &cryptoSSH.Certificate{
		Key:             vaultSigner.PublicKey(),
		Serial:          1,
		CertType:        cryptoSSH.UserCert,
		KeyId:           "vault-cert",
		ValidPrincipals: []string{"ops"},
		ValidAfter:      1,
		ValidBefore:     cryptoSSH.CertTimeInfinity,
	}
	if err := vaultCert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	vaultCertPath := filepath.Join(dir, "vault-cert.pub")
	if err := os.WriteFile(vaultCertPath, cryptoSSH.MarshalAuthorizedKey(vaultCert), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultKeyPath := filepath.Join(dir, "id_vault")
	if err := os.WriteFile(vaultKeyPath, pem.EncodeToMemory(vaultRawPriv), 0o600); err != nil {
		t.Fatal(err)
	}
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentSigner, err := cryptoSSH.NewSignerFromKey(agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	return vaultSigner, vaultPriv, vaultKeyPath, vaultCert, vaultCertPath, agentPriv, agentSigner
}

func TestRound4_P2_1_AcquireForegroundSessionDecouplesExtraForegroundFromInitialNStop(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "xops-r4-fg-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "m.sock")

	raw := newDummySSHClient()
	defer func() { _ = raw.Close() }()

	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:           sock,
		SSHClient:             raw,
		PersistEnabled:        false,
		InitialActiveSessions: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown() }()

	rel, ok := srv.AcquireForegroundSession()
	if !ok {
		t.Fatal("AcquireForegroundSession failed")
	}

	// Simulate -O stop + ReleaseForegroundOnStop (releases initial -N slot).
	srv.idleMu.Lock()
	srv.stoppedListening = true
	srv.phase = muxPhaseStoppingListen
	srv.idleMu.Unlock()
	srv.ReleaseForegroundOnStop()

	// Initial -N deferred RemoveForegroundSession runs while extra session is STILL active.
	srv.RemoveForegroundSession()
	select {
	case <-srv.Wait():
		t.Fatal("MuxServer shut down prematurely while acquired extra foreground session is still active")
	case <-time.After(40 * time.Millisecond):
	}

	// Releasing extra foreground session cleanly shuts down master.
	rel()
	select {
	case <-srv.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("MuxServer did not shut down after releasing extra foreground session")
	}
}

func TestRound4_P2_4_CloseChannelBoundedNilReceiverDoesNotDeadlock(t *testing.T) {
	t.Parallel()

	stalled := &blockingChannelCloseStub{
		closeEntered: make(chan struct{}),
		unblock:      make(chan struct{}),
	}
	defer close(stalled.unblock)

	done := make(chan error, 2)
	go func() {
		var s *MuxServer
		done <- s.closeMuxChannelBounded(stalled, nil)
	}()
	go func() {
		var c *Client
		done <- c.closeChannelBounded(stalled, nil, "nil-client")
	}()

	for i := range 2 {
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("call %d expected timeout error, got nil", i)
			}
		case <-time.After(sessionShutdownTimeout + 2*time.Second):
			t.Fatalf("nil receiver close*Bounded deadlocked past timeout")
		}
	}
}
