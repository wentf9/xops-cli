package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// keepAliveBarrierServer is a lightweight in-process SSH server supporting
// password auth, "session" exec checks, RFC 4254 "direct-tcpip" jump
// forwarding, and deterministic stalling/releasing of "keepalive@openssh.com"
// global requests without blocking normal channel traffic.
type keepAliveBarrierServer struct {
	addr       string
	listener   net.Listener
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.Mutex
	stalling   bool
	releaseCh  chan struct{}
	probeCh    chan struct{}
	probeCount atomic.Int32
}

func newKeepAliveBarrierServer(t *testing.T, parentCtx context.Context) *keepAliveBarrierServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	srvCfg := &cryptoSSH.ServerConfig{
		PasswordCallback: func(_ cryptoSSH.ConnMetadata, pass []byte) (*cryptoSSH.Permissions, error) {
			if string(pass) == sshfixture.Password {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("invalid password")
		},
	}
	srvCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen barrier server: %v", err)
	}
	ctx, cancel := context.WithCancel(parentCtx)
	s := &keepAliveBarrierServer{
		addr:      ln.Addr().String(),
		listener:  ln,
		ctx:       ctx,
		cancel:    cancel,
		releaseCh: make(chan struct{}),
		probeCh:   make(chan struct{}, 64),
	}
	close(s.releaseCh)

	s.wg.Go(func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			s.wg.Go(func() {
				s.serveConn(conn, srvCfg)
			})
		}
	})
	t.Cleanup(func() {
		s.setStall(false)
		s.cancel()
		_ = s.listener.Close()
		s.wg.Wait()
	})
	return s
}

func (s *keepAliveBarrierServer) setStall(stall bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stall == s.stalling {
		return
	}
	s.stalling = stall
	if stall {
		s.releaseCh = make(chan struct{})
		for {
			select {
			case <-s.probeCh:
			default:
				return
			}
		}
	} else {
		close(s.releaseCh)
	}
}

func (s *keepAliveBarrierServer) waitProbeInFlight(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-s.probeCh:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for in-flight keepalive probe")
	}
}

func (s *keepAliveBarrierServer) serveConn(raw net.Conn, cfg *cryptoSSH.ServerConfig) {
	defer func() { _ = raw.Close() }()
	stopClose := context.AfterFunc(s.ctx, func() { _ = raw.Close() })
	defer stopClose()

	sConn, chans, reqs, err := cryptoSSH.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()

	var connWG sync.WaitGroup
	connWG.Go(func() {
		for req := range reqs {
			r := req
			if r.Type == "keepalive@openssh.com" {
				s.probeCount.Add(1)
				s.mu.Lock()
				stalling := s.stalling
				rel := s.releaseCh
				s.mu.Unlock()
				if stalling {
					select {
					case s.probeCh <- struct{}{}:
					default:
					}
					connWG.Go(func() {
						select {
						case <-rel:
							if r.WantReply {
								_ = r.Reply(true, nil)
							}
						case <-s.ctx.Done():
						}
					})
					continue
				}
			}
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
		}
	})

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "session":
			ch, chReqs, acceptErr := newCh.Accept()
			if acceptErr != nil {
				continue
			}
			connWG.Go(func() { s.handleSession(ch, chReqs) })
		case "direct-tcpip":
			s.handleDirectTCPIP(newCh, &connWG)
		default:
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
		}
	}
	connWG.Wait()
}

func (s *keepAliveBarrierServer) handleSession(ch cryptoSSH.Channel, reqs <-chan *cryptoSSH.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = ch.Write([]byte("barrier-ok"))
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (s *keepAliveBarrierServer) handleDirectTCPIP(newCh cryptoSSH.NewChannel, wg *sync.WaitGroup) {
	var payload struct {
		Host       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := cryptoSSH.Unmarshal(newCh.ExtraData(), &payload); err != nil {
		_ = newCh.Reject(cryptoSSH.Prohibited, "bad payload")
		return
	}
	targetAddr := net.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port)))
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(s.ctx, "tcp", targetAddr)
	if err != nil {
		_ = newCh.Reject(cryptoSSH.ConnectionFailed, err.Error())
		return
	}
	ch, chReqs, err := newCh.Accept()
	if err != nil {
		_ = upstream.Close()
		return
	}
	wg.Go(func() { cryptoSSH.DiscardRequests(chReqs) })
	wg.Go(func() {
		defer func() {
			_ = upstream.Close()
			_ = ch.Close()
		}()
		var copyWG sync.WaitGroup
		copyWG.Go(func() {
			_, _ = io.Copy(upstream, ch)
			if tcp, ok := upstream.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		})
		copyWG.Go(func() {
			_, _ = io.Copy(ch, upstream)
			_ = ch.CloseWrite()
		})
		copyWG.Wait()
	})
}

func dialBarrierTestClient(t *testing.T, addr string) *cryptoSSH.Client {
	t.Helper()
	clientConfig := &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := cryptoSSH.Dial("tcp", addr, clientConfig)
	if err != nil {
		t.Fatalf("dial barrier server: %v", err)
	}
	return client
}

func runBarrierExecCheck(client *Client) error {
	session, err := client.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	out, err := session.Output("check")
	if err != nil {
		return err
	}
	if string(out) != "barrier-ok" {
		return errors.New("unexpected output: " + string(out))
	}
	return nil
}

// TestC_H1_NonDisruptiveKeepAliveCancel_InFlightProbePreservesLiveTransport verifies
// C-H1 Root Cause A: Publish displacement, Retire, and StopGlobalKeepAlives
// while a keepalive@openssh.com probe is in flight MUST detach keepalive cleanly
// without calling interrupt(), without closing RootConn, and without triggering onDead.
func TestC_H1_NonDisruptiveKeepAliveCancel_InFlightProbePreservesLiveTransport(t *testing.T) {
	t.Run("publish_displacement", testCH1PublishDisplacement)
	t.Run("retire_bastion_and_child", testCH1RetireBastionAndChild)
	t.Run("stop_global_keepalives", testCH1StopGlobalKeepAlives)
}

func testCH1PublishDisplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	srv := newKeepAliveBarrierServer(t, ctx)
	host, port := fixtureEndpoint(t, srv.addr)
	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"node": {
				NodeID: "node", Address: host, Port: port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
		},
	}
	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 15*time.Millisecond, 500*time.Millisecond)
	t.Cleanup(func() { _ = connector.CloseAll() })

	srv.setStall(true)
	c1, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(node) #1: %v", err)
	}
	key := connector.pool.DigestOf(c1.pooled)
	_, kaDone1 := c1.pooled.keepAliveState()

	// Wait until c1's keepalive@openssh.com probe is genuinely in flight.
	srv.waitProbeInFlight(t, 2*time.Second)

	// Publish a replacement pooled client at the same HopDigest to displace c1.
	c2SSH := dialBarrierTestClient(t, srv.addr)
	t.Cleanup(func() { _ = c2SSH.Close() })
	replacement := &PooledClient{
		SSHClient:    c2SSH,
		RootConn:     &physicalSSHConn{Conn: &stubCloseConn{}},
		publishedCfg: NewClientConfig(*provider.cfgs["node"]),
	}
	if _, err := connector.publishPooled(key, replacement, nil, nil); err != nil {
		t.Fatalf("publishPooled replacement: %v", err)
	}

	// Displaced client's keepalive must exit promptly without closing c1.RootConn.
	select {
	case <-kaDone1:
	case <-time.After(2 * time.Second):
		t.Fatal("displaced client's keepalive did not exit promptly")
	}
	if isRootConnClosed(c1.rootConn) {
		t.Fatal("C-H1 reproduced: Publish displacement closed displaced client's live RootConn while keepalive probe was in flight")
	}
	if err := runBarrierExecCheck(c1); err != nil {
		t.Fatalf("C-H1 reproduced: active session on displaced client failed after non-disruptive keepalive cancel: %v", err)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("CheckInvariants(true) failed after displacement: %v", err)
	}

	srv.setStall(false)
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
}

func testCH1RetireBastionAndChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
	}
	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 15*time.Millisecond, 500*time.Millisecond)
	t.Cleanup(func() { _ = connector.CloseAll() })

	targetClient, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	bastionClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	_, bDone := bastionClient.pooled.keepAliveState()
	_, tDone := targetClient.pooled.keepAliveState()

	// Stall keepalive replies AFTER both hops are cached so only background
	// keepalive probes are held in flight (not Connect's cache revalidation).
	bastionSrv.setStall(true)
	targetSrv.setStall(true)
	bastionSrv.waitProbeInFlight(t, 2*time.Second)
	targetSrv.waitProbeInFlight(t, 2*time.Second)

	connector.pool.Retire(ZeroHopDigest, bastionClient.pooled)

	for label, ch := range map[string]<-chan struct{}{"bastion": bDone, "target": tDone} {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("retired %s keepalive did not exit promptly", label)
		}
	}
	if isRootConnClosed(bastionClient.rootConn) {
		t.Fatal("C-H1 reproduced: Retire closed shared RootConn while keepalive probe was in flight")
	}
	if err := runBarrierExecCheck(bastionClient); err != nil {
		t.Fatalf("retired bastion session failed: %v", err)
	}
	if err := runBarrierExecCheck(targetClient); err != nil {
		t.Fatalf("retired target session failed: %v", err)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("CheckInvariants(true) after Retire failed: %v", err)
	}

	bastionSrv.setStall(false)
	targetSrv.setStall(false)
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
}

func testCH1StopGlobalKeepAlives(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	srv := newKeepAliveBarrierServer(t, ctx)
	host, port := fixtureEndpoint(t, srv.addr)
	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"node": {
				NodeID: "node", Address: host, Port: port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
		},
	}
	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	connector.EnableKeepAlive(kaCtx, 15*time.Millisecond, 500*time.Millisecond)
	t.Cleanup(func() {
		cancelKA()
		_ = connector.CloseAll()
	})

	srv.setStall(true)
	client, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(node): %v", err)
	}
	_, kaDone := client.pooled.keepAliveState()
	srv.waitProbeInFlight(t, 2*time.Second)

	cancelKA()
	select {
	case <-kaDone:
	case <-time.After(2 * time.Second):
		t.Fatal("keepalive did not detach after StopGlobalKeepAlives / kaCtx cancel")
	}
	if isRootConnClosed(client.rootConn) {
		t.Fatal("C-H1 reproduced: StopGlobalKeepAlives closed live RootConn while probe was in flight")
	}
	if connector.pool.Count() != 1 {
		t.Fatalf("C-H1 reproduced: StopGlobalKeepAlives evicted healthy active client (count=%d)", connector.pool.Count())
	}
	if err := runBarrierExecCheck(client); err != nil {
		t.Fatalf("healthy client session failed after StopGlobalKeepAlives: %v", err)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants(false) failed: %v", err)
	}

	srv.setStall(false)
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
}

// TestC_H1_ChildHopKeepAliveTimeout_PreservesBastionAndSibling verifies C-H1
// Root Cause B: when a child hop genuinely times out on keepalive, only that
// child hop's transport is closed and evicted; the shared upstream bastion and
// healthy sibling targets continue working untouched.
func TestC_H1_ChildHopKeepAliveTimeout_PreservesBastionAndSibling(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	target1Srv := newKeepAliveBarrierServer(t, ctx)
	target2Srv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	t1Host, t1Port := fixtureEndpoint(t, target1Srv.addr)
	t2Host, t2Port := fixtureEndpoint(t, target2Srv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target1": {
				NodeID: "target1", Address: t1Host, Port: t1Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
			"target2": {
				NodeID: "target2", Address: t2Host, Port: t2Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 15*time.Millisecond, 80*time.Millisecond)
	t.Cleanup(func() { _ = connector.CloseAll() })

	c1, err := connector.Connect(ctx, "target1")
	if err != nil {
		t.Fatalf("Connect(target1): %v", err)
	}
	c2, err := connector.Connect(ctx, "target2")
	if err != nil {
		t.Fatalf("Connect(target2): %v", err)
	}
	bClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	if c1.rootConn != bClient.rootConn || c2.rootConn != bClient.rootConn {
		t.Fatal("expected bastion, target1, target2 to share RootConn")
	}

	target1Key := connector.pool.DigestOf(c1.pooled)
	bastionKey := connector.pool.DigestOf(bClient.pooled)
	target2Key := connector.pool.DigestOf(c2.pooled)

	// Blackhole ONLY target1's keepalive responses.
	target1Srv.setStall(true)

	waitForCondition(t, 3*time.Second, func() bool {
		_, ok := connector.pool.Get(target1Key)
		return !ok
	}, "timed-out child hop target1 was not evicted")

	if isRootConnClosed(bClient.rootConn) {
		t.Fatal("C-H1 reproduced: child-hop keepalive timeout closed shared bastion RootConn")
	}
	if _, ok := connector.pool.Get(bastionKey); !ok {
		t.Fatal("healthy bastion was evicted by child-hop keepalive timeout")
	}
	if _, ok := connector.pool.Get(target2Key); !ok {
		t.Fatal("healthy sibling target2 was evicted by target1 keepalive timeout")
	}
	if err := runBarrierExecCheck(bClient); err != nil {
		t.Fatalf("bastion unusable after child timeout: %v", err)
	}
	if err := runBarrierExecCheck(c2); err != nil {
		t.Fatalf("sibling target2 unusable after child timeout: %v", err)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("CheckInvariants(true) failed after child timeout: %v", err)
	}
}

// TestC_H1_RootHopKeepAliveTimeout_CascadeEvictsAndClosesChildren verifies that
// when a root bastion hop dies via keepalive timeout, connPool.Evict atomically
// evicts all active descendants riding on that generation and closes their hop
// transports as well, leaving zero stranded entries.
func TestC_H1_RootHopKeepAliveTimeout_CascadeEvictsAndClosesChildren(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	target1Srv := newKeepAliveBarrierServer(t, ctx)
	target2Srv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	t1Host, t1Port := fixtureEndpoint(t, target1Srv.addr)
	t2Host, t2Port := fixtureEndpoint(t, target2Srv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target1": {
				NodeID: "target1", Address: t1Host, Port: t1Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
				Options:   MustOptions(OptionServerAliveCountMax, "50"),
			},
			"target2": {
				NodeID: "target2", Address: t2Host, Port: t2Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
				Options:   MustOptions(OptionServerAliveCountMax, "50"),
			},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 15*time.Millisecond, 60*time.Millisecond)
	t.Cleanup(func() { _ = connector.CloseAll() })

	c1, err := connector.Connect(ctx, "target1")
	if err != nil {
		t.Fatalf("Connect(target1): %v", err)
	}
	c2, err := connector.Connect(ctx, "target2")
	if err != nil {
		t.Fatalf("Connect(target2): %v", err)
	}
	bClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	if connector.pool.Count() != 3 {
		t.Fatalf("expected 3 active hops (bastion, target1, target2), got %d", connector.pool.Count())
	}

	// Stall all keepalive replies so bastion receives zero bytes (no receive progress)
	// and bastion's shorter keepalive timeout (60ms vs children's 750ms) triggers first.
	bastionSrv.setStall(true)
	target1Srv.setStall(true)
	target2Srv.setStall(true)

	waitForCondition(t, 3*time.Second, func() bool {
		return connector.pool.Count() == 0
	}, "root hop timeout did not cascade-evict bastion and all active children")

	if !isRootConnClosed(bClient.rootConn) {
		t.Fatal("expected dead root hop's RootConn to be closed")
	}
	for name, cli := range map[string]*Client{"target1": c1, "target2": c2} {
		if active, _ := cli.pooled.keepAliveState(); active {
			t.Errorf("evicted descendant %s still has active keepalive", name)
		}
		if err := runBarrierExecCheck(cli); err == nil {
			t.Errorf("evicted descendant %s transport was not closed", name)
		}
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("CheckInvariants(true) after root timeout cascade failed: %v", err)
	}
}

// TestC_H1_ClosedRootConnRejectedByPredicatesAndInvariants verifies that
// isConsistentParentChildTransport and CheckInvariants reject closed physical RootConns.
func TestC_H1_ClosedRootConnRejectedByPredicatesAndInvariants(t *testing.T) {
	t.Parallel()

	root := &physicalSSHConn{Conn: &stubCloseConn{}}
	parent := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: root, hopConn: root}
	child := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: root, hopConn: &stubCloseConn{}, parent: parent}
	if !isConsistentParentChildTransport(parent, child) {
		t.Fatal("expected live shared RootConn to be consistent")
	}
	_ = root.Close()
	if isConsistentParentChildTransport(parent, child) {
		t.Fatal("isConsistentParentChildTransport must reject closed physical RootConn")
	}

	pool := newConnPool()
	key := DigestClientConfig(&ClientConfig{NodeID: "dead-root"}, ZeroHopDigest)
	if _, err := pool.Publish(key, &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: root}, nil, nil); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := pool.CheckInvariants(false); err == nil {
		t.Fatal("CheckInvariants must reject active entry with closed physical RootConn")
	}
}

type mutableControlProvider struct {
	mu   sync.Mutex
	ctrl map[string]*ControlConfig
}

func (p *mutableControlProvider) GetControlConfig(nodeID string) (*ControlConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ctrl[nodeID].Clone(), nil
}

// TestC_M1_ControlProviderAndAllowReuseAffectHopDigestAndPoolIsolation verifies
// C-M1: ControlConfig (including ControlProvider overrides and AllowReuse for
// -S vs -M) enters ClientConfig/ConnectionConfig and HopDigest, while unset and
// disabled configs normalize equivalently to nil, and CapturePlan/normalizePlan
// strip Control alongside OptionClassMux.
func TestC_M1_ControlProviderAndAllowReuseAffectHopDigestAndPoolIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	srv, host, port := newP0SSHFixture(t, ctx, "cm1")
	sockA := filepath.Join(shortSocketDir(t), "cm1-a.sock")
	sockB := filepath.Join(shortSocketDir(t), "cm1-b.sock")

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"node": {
				NodeID: "node", Address: host, Port: port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
		},
	}
	ctrlProv := &mutableControlProvider{ctrl: map[string]*ControlConfig{}}
	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}), WithControlProvider(ctrlProv))
	t.Cleanup(func() { _ = connector.CloseAll() })

	// 1. nil vs disabled ("none") ControlProvider must normalize equivalently and reuse pool entry.
	cNil, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(nil control): %v", err)
	}
	if cNil.Config().Control != nil || cNil.ConnectionConfig().Control != nil {
		t.Fatalf("expected nil ControlConfig for unset control, got %+v", cNil.Config().Control)
	}
	ctrlProv.mu.Lock()
	ctrlProv.ctrl["node"] = &ControlConfig{Master: ControlMasterNo, Path: "none", Persist: "no"}
	ctrlProv.mu.Unlock()
	cNone, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(disabled none control): %v", err)
	}
	if cNone.sshClient != cNil.sshClient || srv.Authenticated.Load() != 1 {
		t.Fatalf("unset and disabled (none) ControlConfig must share HopDigest and reuse pooled client (auth=%d)", srv.Authenticated.Load())
	}

	// 2. Switching ControlProvider to -M (AllowReuse=false) vs -S (AllowReuse=true)
	// on the same socket path must produce distinct HopDigests.
	assertCM1AllowReuseDigestIsolation(t, ctx, connector, ctrlProv, sockA)

	// 3. Connecting with ControlProvider enabled must not reuse the non-mux pooled entry,
	// and switching socket path in ControlProvider must dial a distinct pooled entry.
	ctrlProv.mu.Lock()
	ctrlProv.ctrl["node"] = &ControlConfig{Master: ControlMasterNo, Path: sockA, AllowReuse: true}
	ctrlProv.mu.Unlock()
	cSockA, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(sockA): %v", err)
	}
	if cSockA.sshClient == cNil.sshClient {
		t.Fatal("C-M1 reproduced: ControlProvider change reused non-mux pooled client")
	}
	if got := cSockA.Config().Control; got == nil || got.Path != sockA || !got.AllowReuse {
		t.Fatalf("Client.Config().Control = %+v, want Path=%q AllowReuse=true", got, sockA)
	}
	ctrlProv.mu.Lock()
	ctrlProv.ctrl["node"] = &ControlConfig{Master: ControlMasterNo, Path: sockB, AllowReuse: true}
	ctrlProv.mu.Unlock()
	cSockB, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(sockB): %v", err)
	}
	if cSockB.sshClient == cSockA.sshClient {
		t.Fatal("C-M1 reproduced: ControlProvider socket path change reused prior pooled client")
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants(false): %v", err)
	}

	// 4. NewClientConfig / ToConnectionConfig / toClientConfig / ConnectionConfig.Clone /
	// dialPolicy deep-clone and normalize Control; CapturePlan / normalizePlan strip Control.
	assertCM1ControlConfigRoundTripAndPlanStrip(t, sockA)
}

func assertCM1AllowReuseDigestIsolation(t *testing.T, ctx context.Context, connector *Connector, ctrlProv *mutableControlProvider, sockA string) {
	t.Helper()
	ctrlProv.mu.Lock()
	ctrlProv.ctrl["node"] = &ControlConfig{Master: ControlMasterYes, Path: sockA, AllowReuse: false}
	ctrlProv.mu.Unlock()
	planM, err := connector.resolveConnectionPlan(ctx, "node")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(-M): %v", err)
	}
	if planM[0].cfg.Control == nil || planM[0].cfg.Control.AllowReuse {
		t.Fatalf("expected resolved Control with AllowReuse=false, got %+v", planM[0].cfg.Control)
	}

	ctrlProv.mu.Lock()
	ctrlProv.ctrl["node"] = &ControlConfig{Master: ControlMasterYes, Path: sockA, AllowReuse: true}
	ctrlProv.mu.Unlock()
	planS, err := connector.resolveConnectionPlan(ctx, "node")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(-S): %v", err)
	}
	if planS[0].cfg.Control == nil || !planS[0].cfg.Control.AllowReuse {
		t.Fatalf("expected resolved Control with AllowReuse=true, got %+v", planS[0].cfg.Control)
	}
	if planM[0].hopDigest().Equal(planS[0].hopDigest()) {
		t.Fatal("C-M1 reproduced: AllowReuse=false (-M) and AllowReuse=true (-S) collided in HopDigest")
	}
}

func assertCM1ControlConfigRoundTripAndPlanStrip(t *testing.T, sockA string) {
	t.Helper()
	rawCtrl := &ControlConfig{Master: ControlMasterAuto, Path: sockA, Persist: "10m", AllowReuse: true}
	cfgA := NewClientConfig(ClientConfig{NodeID: "n", Address: "10.0.0.1", User: "u", Control: rawCtrl})
	rawCtrl.Path = "/mutated"
	if cfgA.Control.Path != sockA {
		t.Fatal("NewClientConfig did not deep-clone Control")
	}
	roundTrip := cfgA.ToConnectionConfig().Clone().toClientConfig()
	if roundTrip.Control == nil || roundTrip.Control.Path != sockA || !roundTrip.Control.AllowReuse {
		t.Fatalf("ConnectionConfig round-trip lost Control: %+v", roundTrip.Control)
	}
	policy := freezeDialPolicy(cfgA)
	if policy.readOnlyConfig().Control == nil || !policy.readOnlyConfig().Control.AllowReuse {
		t.Fatalf("dialPolicy lost Control: %+v", policy.readOnlyConfig().Control)
	}

	planWithCtrl := ConnectionPlan{
		Scope: "cm1-scope",
		Hops: []ConnectionConfig{{
			NodeID: "n", Address: "10.0.0.1", Port: 22, User: "u",
			Control: &ControlConfig{Master: ControlMasterAuto, Path: sockA, AllowReuse: true},
		}},
	}
	planWithoutCtrl := ConnectionPlan{
		Scope: "cm1-scope",
		Hops:  []ConnectionConfig{{NodeID: "n", Address: "10.0.0.1", Port: 22, User: "u"}},
	}
	k1, err := ConnectionKey(planWithCtrl)
	if err != nil {
		t.Fatalf("ConnectionKey(withCtrl): %v", err)
	}
	k2, err := ConnectionKey(planWithoutCtrl)
	if err != nil {
		t.Fatalf("ConnectionKey(withoutCtrl): %v", err)
	}
	if k1 != k2 {
		t.Fatalf("normalizePlan did not strip Control before ConnectionKey: %s != %s", k1, k2)
	}
	if fromPlan := clientConfigFromPlan(planWithCtrl.Hops[0]); fromPlan.Control != nil {
		t.Fatalf("clientConfigFromPlan leaked Control: %+v", fromPlan.Control)
	}
}

// TestC_M2_ControlMasterJumpTargetPreservesParentKeyAcrossReindex verifies C-M2:
// tryDialAndPublishProxy preserves planNode.parentDigest on ControlMaster-attached
// jump targets, connPool.Publish permits publishing them without an active in-memory
// parent, and post-connect Reindex keeps planNode.parentDigest intact.
func TestC_M2_ControlMasterJumpTargetPreservesParentKeyAcrossReindex(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	bastion, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("bastion fixture: %v", err)
	}
	defer func() { _ = bastion.Close() }()
	target, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("target fixture: %v", err)
	}
	defer func() { _ = target.Close() }()

	bastionHost, bastionPort := fixtureEndpoint(t, bastion.Address)
	targetHost, targetPort := fixtureEndpoint(t, target.Address)
	socketPath := filepath.Join(shortSocketDir(t), "cm2-chain.sock")

	provider := &jumpChainProvider{
		cfgs: map[string]*ClientConfig{
			"jump": {
				NodeID: "jump", Address: bastionHost, Port: bastionPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: targetHost, Port: targetPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "jump", AuthUpdateToken: "tok-v1",
			},
		},
		ctrl: map[string]*ControlConfig{
			"target": {Master: ControlMasterAuto, Path: socketPath},
		},
	}

	first := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { _ = first.CloseAll() })
	if _, err := first.Connect(ctx, "target"); err != nil {
		t.Fatalf("initial Connect(target): %v", err)
	}
	waitForCondition(t, 10*time.Second, func() bool {
		return GetActiveMuxServer(socketPath) != nil
	}, "control master did not start on target")

	second := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { _ = second.CloseAll() })

	planBefore, err := second.resolveConnectionPlan(ctx, "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan: %v", err)
	}
	wantParentKey := planBefore[0].parentDigest
	if wantParentKey.IsZero() {
		t.Fatal("expected non-zero parentDigest for jump-chained target")
	}

	attached, err := second.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("second.Connect(target) via ControlMaster: %v", err)
	}
	if !attached.IsMultiplexed() {
		t.Fatal("expected second.Connect(target) to attach via ControlMaster")
	}
	if got := bastion.Authenticated.Load(); got != 1 {
		t.Fatalf("bastion auth count = %d, want 1 (must attach without dialing bastion)", got)
	}
	if attached.pooled.parentKey != wantParentKey {
		t.Fatalf("C-M2 reproduced: mux-attached jump target parentKey = %s, want %s", attached.pooled.parentKey, wantParentKey)
	}
	if err := second.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after mux attach: %v", err)
	}

	// Post-connect Reindex (SetExecution + ApplyRecordedAuth) MUST preserve wantParentKey!
	execCfg := &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX}
	attached.SetExecution(execCfg)
	attached.ApplyRecordedAuth("tok-v2", "", nil)

	if attached.pooled.parentKey != wantParentKey {
		t.Fatalf("post-Reindex parentKey = %s, want %s", attached.pooled.parentKey, wantParentKey)
	}
	if err := second.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after mux Reindex: %v", err)
	}

	// Update provider to match committed metadata and verify second.Connect reuses the
	// reindexed mux pool entry directly!
	provider.cfgs["target"].Execution = execCfg.Clone()
	provider.cfgs["target"].AuthUpdateToken = "tok-v2"
	planAfter, err := second.resolveConnectionPlan(ctx, "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan after metadata commit: %v", err)
	}
	if got, ok := second.pool.Get(planAfter[0].hopDigest()); !ok || got != attached.pooled {
		t.Fatalf("C-M2 reproduced: reindexed mux jump target missed expected HopDigest %s (actual=%s)",
			planAfter[0].hopDigest(), second.pool.DigestOf(attached.pooled))
	}
	reused, err := second.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("second.Connect(target) after Reindex: %v", err)
	}
	if reused.pooled != attached.pooled {
		t.Fatal("expected subsequent Connect to reuse the reindexed mux PooledClient")
	}
	if got := bastion.Authenticated.Load(); got != 1 {
		t.Fatalf("bastion auth count = %d after mux reuse, want 1", got)
	}

	// Verify non-mux jump child still fails closed on Publish without expectParent.
	nonMuxChild := &PooledClient{
		SSHClient: &cryptoSSH.Client{Conn: &closeResultConn{}},
		hopConn:   &stubCloseConn{},
		parentKey: wantParentKey,
	}
	if _, err := second.pool.Publish(planAfter[0].hopDigest(), nonMuxChild, nil, nil); !errors.Is(err, errStaleParentGeneration) {
		t.Fatalf("non-mux jump child without expectParent = %v, want errStaleParentGeneration", err)
	}
}

// TestC_M3_RefreshConnectionTokensReindexesPooledClient verifies C-M3:
// Client.refreshConnectionTokens updates pooled snapshot + publishedCfg and
// reindexes PooledClient so subsequent Connects reuse it instead of stranding.
func TestC_M3_RefreshConnectionTokensReindexesPooledClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	srv, host, port := newP0SSHFixture(t, ctx, "cm3")
	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"node": {
				NodeID: "node", Address: host, Port: port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				KeyRef: "kr-1", TrustVersion: "tv-1",
				AuthUpdateToken: "auth-v1", SudoMode: SudoModeAuto, SudoUpdateToken: "sudo-v1",
			},
		},
	}
	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { _ = connector.CloseAll() })

	client, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(node): %v", err)
	}
	if srv.Authenticated.Load() != 1 {
		t.Fatalf("initial auth count = %d, want 1", srv.Authenticated.Load())
	}

	// 1. Sudo token + SudoMode refresh must reindex PooledClient.
	provider.mu.Lock()
	provider.cfgs["node"].SudoMode = SudoModeSudo
	provider.cfgs["node"].SudoUpdateToken = "sudo-v2"
	provider.mu.Unlock()

	if err := client.refreshConnectionTokens(tokenRefreshKindSudo, "sudo-v2"); err != nil {
		t.Fatalf("refreshConnectionTokens(sudo): %v", err)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after sudo refresh: %v", err)
	}
	reused1, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(node) after sudo refresh: %v", err)
	}
	if reused1.pooled != client.pooled || srv.Authenticated.Load() != 1 {
		t.Fatalf("C-M3 reproduced: sudo refresh stranded pooled client (reused=%v auth=%d)", reused1.pooled == client.pooled, srv.Authenticated.Load())
	}

	// 2. Auth token refresh must also reindex PooledClient without clobbering Sudo.
	provider.mu.Lock()
	provider.cfgs["node"].AuthUpdateToken = "auth-v2"
	provider.mu.Unlock()
	if err := client.refreshConnectionTokens(tokenRefreshKindAuth, "auth-v2"); err != nil {
		t.Fatalf("refreshConnectionTokens(auth): %v", err)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after auth refresh: %v", err)
	}
	reused2, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(node) after auth refresh: %v", err)
	}
	if reused2.pooled != client.pooled || srv.Authenticated.Load() != 1 {
		t.Fatalf("C-M3 reproduced: auth refresh stranded pooled client (reused=%v auth=%d)", reused2.pooled == client.pooled, srv.Authenticated.Load())
	}
}

type threeHopReindexFixture struct {
	pool                *connPool
	bastionCfg, midCfg  *ClientConfig
	leafCfg             *ClientConfig
	bKey1, mKey1, lKey1 HopDigest
	bPooled, mPooled    *PooledClient
	lPooled             *PooledClient
}

func newThreeHopReindexFixture(t *testing.T) *threeHopReindexFixture {
	t.Helper()
	pool := newConnPool()
	rootConn := &physicalSSHConn{Conn: &stubCloseConn{}}

	bastionCfg := NewClientConfig(ClientConfig{
		NodeID: "bastion", Address: "10.0.0.1", Port: 22, User: "ops",
		AuthType: "password", AuthUpdateToken: "b1",
	})
	midCfg := NewClientConfig(ClientConfig{
		NodeID: "mid", Address: "10.0.0.2", Port: 22, User: "ops",
		AuthType: "password", ProxyJump: "bastion",
	})
	leafCfg := NewClientConfig(ClientConfig{
		NodeID: "leaf", Address: "10.0.0.3", Port: 22, User: "ops",
		AuthType: "password", ProxyJump: "mid",
	})

	bKey1 := DigestClientConfig(bastionCfg, ZeroHopDigest)
	mKey1 := DigestClientConfig(midCfg, bKey1)
	lKey1 := DigestClientConfig(leafCfg, mKey1)

	bPooled := &PooledClient{
		SSHClient:    &cryptoSSH.Client{},
		RootConn:     rootConn,
		hopConn:      rootConn,
		pool:         pool,
		publishedCfg: NewClientConfig(*bastionCfg),
		Snapshot:     bastionCfg.ToConnectionConfig(),
		hasSnapshot:  true,
	}
	mPooled := &PooledClient{
		SSHClient:    &cryptoSSH.Client{},
		RootConn:     rootConn,
		hopConn:      &stubCloseConn{},
		parentKey:    bKey1,
		pool:         pool,
		publishedCfg: NewClientConfig(*midCfg),
		Snapshot:     midCfg.ToConnectionConfig(),
		hasSnapshot:  true,
	}
	lPooled := &PooledClient{
		SSHClient:    &cryptoSSH.Client{},
		RootConn:     rootConn,
		hopConn:      &stubCloseConn{},
		parentKey:    mKey1,
		pool:         pool,
		publishedCfg: NewClientConfig(*leafCfg),
		Snapshot:     leafCfg.ToConnectionConfig(),
		hasSnapshot:  true,
	}

	if _, err := pool.Publish(bKey1, bPooled, nil, nil); err != nil {
		t.Fatalf("Publish(bastion): %v", err)
	}
	if _, err := pool.Publish(mKey1, mPooled, bPooled, nil); err != nil {
		t.Fatalf("Publish(mid): %v", err)
	}
	if _, err := pool.Publish(lKey1, lPooled, mPooled, nil); err != nil {
		t.Fatalf("Publish(leaf): %v", err)
	}
	return &threeHopReindexFixture{
		pool: pool, bastionCfg: bastionCfg, midCfg: midCfg, leafCfg: leafCfg,
		bKey1: bKey1, mKey1: mKey1, lKey1: lKey1,
		bPooled: bPooled, mPooled: mPooled, lPooled: lPooled,
	}
}

func assertPoolHasExactEntry(t *testing.T, pool *connPool, label string, key HopDigest, want *PooledClient) {
	t.Helper()
	if got, ok := pool.Get(key); !ok || got != want {
		t.Fatalf("%s missing or mismatched at key %s", label, key)
	}
}

// TestC_L1_ReindexCascadeAndCollisionRollback verifies C-L1:
//  1. Reindexing a parent with active descendants (child + grandchild) atomically
//     moves the entire descendant tree to its recomputed Merkle keys.
//  2. A collision on EITHER the parent's target key OR a descendant's target key
//     rolls back cleanly, leaving active map keys and publishedCfg untouched.
func TestC_L1_ReindexCascadeAndCollisionRollback(t *testing.T) {
	t.Parallel()

	fx := newThreeHopReindexFixture(t)

	// 1. Cascade Reindex across all 3 hops (bastion -> mid -> leaf).
	bClient := &Client{connCfg: fx.bastionCfg.ToConnectionConfig(), pooled: fx.bPooled}
	bClient.ApplyRecordedAuth("b2", "", nil)

	wantB := NewClientConfig(*fx.bastionCfg)
	wantB.AuthUpdateToken = "b2"
	bKey2 := DigestClientConfig(wantB, ZeroHopDigest)
	mKey2 := DigestClientConfig(fx.midCfg, bKey2)
	lKey2 := DigestClientConfig(fx.leafCfg, mKey2)

	for label, oldK := range map[string]HopDigest{"bastion": fx.bKey1, "mid": fx.mKey1, "leaf": fx.lKey1} {
		if _, ok := fx.pool.Get(oldK); ok {
			t.Fatalf("stale old key for %s remained active after cascade Reindex", label)
		}
	}
	assertPoolHasExactEntry(t, fx.pool, "bastion", bKey2, fx.bPooled)
	assertPoolHasExactEntry(t, fx.pool, "mid", mKey2, fx.mPooled)
	assertPoolHasExactEntry(t, fx.pool, "leaf", lKey2, fx.lPooled)
	if fx.mPooled.parentKey != bKey2 || fx.lPooled.parentKey != mKey2 {
		t.Fatal("descendant parentKeys were not updated after cascade Reindex")
	}
	if err := fx.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after 3-hop cascade Reindex: %v", err)
	}

	// 2. Descendant-level collision must atomically roll back bastion, mid, leaf,
	// AND bastion.publishedCfg!
	wantB3 := NewClientConfig(*wantB)
	wantB3.AuthUpdateToken = "b3"
	bKey3 := DigestClientConfig(wantB3, ZeroHopDigest)
	mKey3 := DigestClientConfig(fx.midCfg, bKey3)
	lKey3 := DigestClientConfig(fx.leafCfg, mKey3)

	// Install an unrelated active occupant at lKey3 (grandchild destination key),
	// while bKey3 and mKey3 are completely free.
	occupantRoot := &physicalSSHConn{Conn: &stubCloseConn{}}
	occupant := &PooledClient{
		SSHClient: &cryptoSSH.Client{},
		RootConn:  occupantRoot,
		hopConn:   occupantRoot,
	}
	if _, err := fx.pool.Publish(lKey3, occupant, nil, nil); err != nil {
		t.Fatalf("Publish(occupant at lKey3): %v", err)
	}

	bClient.ApplyRecordedAuth("b3", "", nil)

	assertPoolHasExactEntry(t, fx.pool, "bastion rollback", bKey2, fx.bPooled)
	assertPoolHasExactEntry(t, fx.pool, "mid rollback", mKey2, fx.mPooled)
	assertPoolHasExactEntry(t, fx.pool, "leaf rollback", lKey2, fx.lPooled)
	assertPoolHasExactEntry(t, fx.pool, "unrelated occupant", lKey3, occupant)
	if fx.bPooled.publishedCfg.AuthUpdateToken != "b2" {
		t.Fatalf("C-L1 reproduced: rolled-back Reindex mutated publishedCfg.AuthUpdateToken = %q, want %q",
			fx.bPooled.publishedCfg.AuthUpdateToken, "b2")
	}
	if err := fx.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after grandchild collision rollback: %v", err)
	}
}
