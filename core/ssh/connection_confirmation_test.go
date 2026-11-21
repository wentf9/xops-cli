package ssh

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type unusedConfirmationProvider struct {
	mockConfigStore
	calls atomic.Int32
}

func (p *unusedConfirmationProvider) ConfirmConnection(context.Context, string) error {
	p.calls.Add(1)
	return errors.New("connector must not invoke confirmation callbacks")
}

func (p *unusedConfirmationProvider) ConfirmAuthenticatedConnection(context.Context, string, *Client) (*ExecutionConfig, error) {
	p.calls.Add(1)
	return nil, errors.New("connector must not invoke confirmation callbacks")
}

type disconnectedReloadProvider struct {
	mockConfigStore
	calls   atomic.Int32
	onDrop  func()
	dropped atomic.Bool
}

func (p *disconnectedReloadProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	if p.calls.Add(1) == 2 && p.onDrop != nil && p.dropped.CompareAndSwap(false, true) {
		p.onDrop()
	}
	return p.mockConfigStore.GetConfig(nodeID)
}

func TestDisconnectedPostAuthReloadDoesNotPublishTransport(t *testing.T) {
	setTestHome(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	peerCtx, dropPeer := context.WithCancel(ctx)
	defer dropPeer()
	server, err := sshfixture.NewWithOptions(peerCtx, sshfixture.Options{ExecHandler: func(_ string, _ cryptoSSH.Channel) {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, server) })
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	provider := &disconnectedReloadProvider{
		mockConfigStore: mockConfigStore{cfg: &ClientConfig{
			NodeID: "node", Address: host, Port: port, User: "fixture",
			AuthType: "password", Password: sshfixture.Password,
		}},
		onDrop: func() {
			dropPeer()
			time.Sleep(50 * time.Millisecond)
		},
	}
	connector := newTestConnector(provider, WithHandshakeTimeout(time.Second))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	client, err := connector.Connect(ctx, "node")
	if client != nil {
		t.Cleanup(func() { closeTestResource(t, client) })
	}
	var connectionErr *ConnectionError
	if client != nil || !errors.As(err, &connectionErr) || connectionErr.NodeID != "node" {
		t.Fatalf("disconnected post-auth reload returned client=%v, error=%v", client != nil, err)
	}
	if connector.pool.Count() != 0 {
		t.Fatal("disconnected transport was published to pool")
	}
	if server.Authenticated.Load() != 1 || server.Executed.Load() != 0 {
		t.Fatal("disconnected transport retried authentication or ran user work")
	}
}

func TestConnectorDoesNotInvokeConfirmationAndEvictClientClosesTransport(t *testing.T) {
	setTestHome(t)
	address, disconnected, stop := startTestAutoSSHServer(t, "valid")
	t.Cleanup(stop)
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	provider := &unusedConfirmationProvider{
		mockConfigStore: mockConfigStore{cfg: &ClientConfig{
			NodeID: "node", Address: host, Port: port, User: "root",
			AuthType: "password", Password: "valid",
		}},
	}
	connector := newTestConnector(provider, WithHandshakeTimeout(time.Second))
	connector.AcceptNewHostKey.Store(true)
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Errorf("close connector: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	if provider.calls.Load() != 0 {
		t.Fatalf("Connector.Connect called confirmation %d times, want 0 (caller owns confirmation)", provider.calls.Load())
	}
	if connector.pool.Count() != 1 {
		t.Fatalf("expected 1 pooled client before eviction, got %d", connector.pool.Count())
	}
	if err := connector.EvictClient(client); err != nil {
		t.Fatalf("EvictClient() error = %v", err)
	}
	if connector.pool.Count() != 0 {
		t.Fatalf("EvictClient() left %d client(s) in pool", connector.pool.Count())
	}
	select {
	case <-disconnected:
	case <-ctx.Done():
		t.Fatal("EvictClient() did not close underlying transport")
	}
}

func TestClientMetadataUpdateReindexesPoolAndPreservesEviction(t *testing.T) {
	pool := newConnPool()
	baseCfg := NewClientConfig(ClientConfig{
		NodeID:          "node-reindex",
		Address:         "10.0.0.10",
		Port:            22,
		User:            "ops",
		AuthType:        "auto",
		AuthUpdateToken: "v1",
	})
	oldKey := DigestClientConfig(baseCfg, HopDigest{})
	pooled := &PooledClient{
		SSHClient:    &cryptoSSH.Client{},
		pool:         pool,
		publishedCfg: NewClientConfig(*baseCfg),
		Snapshot:     baseCfg.ToConnectionConfig(),
		hasSnapshot:  true,
	}
	if _, err := pool.Publish(oldKey, pooled, nil, nil); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	client := &Client{connCfg: baseCfg.ToConnectionConfig(), pooled: pooled}

	// Simulate post-confirm enrollment execution + deferred auth commit.
	execCfg := &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX}
	client.SetExecution(execCfg)
	client.ApplyRecordedAuth("v2", "/tmp/id_ed25519", []string{"/tmp/id_ed25519"})

	expectedCfg := NewClientConfig(*baseCfg)
	expectedCfg.Execution = execCfg.Clone()
	expectedCfg.AuthUpdateToken = "v2"
	expectedCfg.KeyPath = "/tmp/id_ed25519"
	expectedCfg.KeyPaths = []string{"/tmp/id_ed25519"}
	newKey := DigestClientConfig(expectedCfg, HopDigest{})
	if newKey == oldKey {
		t.Fatal("expected metadata updates to advance HopDigest")
	}
	if _, ok := pool.Get(oldKey); ok {
		t.Fatal("stale pre-confirm HopDigest remained active in pool")
	}
	got, ok := pool.Get(newKey)
	if !ok || got != pooled {
		t.Fatalf("pool.Get(newKey) = (%v, %v), want reindexed pooled client", got, ok)
	}

	// Reindex must never clobber a fresher active entry occupying the target key.
	fresherCfg := NewClientConfig(*expectedCfg)
	fresherCfg.AuthUpdateToken = ""
	fresherCfg.SudoUpdateToken = ""
	fresherKey := DigestClientConfig(fresherCfg, HopDigest{})
	fresher := &PooledClient{SSHClient: &cryptoSSH.Client{}}
	if _, err := pool.Publish(fresherKey, fresher, nil, nil); err != nil {
		t.Fatalf("Publish(fresher) error = %v", err)
	}
	client.ClearUpdateTokens()
	if cur, ok := pool.Get(fresherKey); !ok || cur != fresher {
		t.Fatal("Reindex clobbered an existing active entry at the destination HopDigest")
	}
	if cur, ok := pool.Get(newKey); !ok || cur != pooled {
		t.Fatal("Reindex dropped original entry when destination HopDigest was already occupied")
	}

	// EvictByClient still finds and removes the reindexed client cleanly.
	pool.EvictByClient(pooled)
	if _, ok := pool.Get(newKey); ok {
		t.Fatal("EvictByClient did not remove reindexed client")
	}
	if pool.Count() != 1 {
		t.Fatalf("pool.Count() = %d, want 1 (fresher entry preserved)", pool.Count())
	}
	// Reindex after eviction is a safe no-op.
	client.SetExecution(&ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX})
	if pool.Count() != 1 {
		t.Fatalf("Reindex resurrected an evicted client: pool.Count() = %d", pool.Count())
	}
}

func TestReindexParentRefusalAndStaleKeyRetirePreserveInvariants(t *testing.T) {
	pool := newConnPool()

	// Reindex on a parent hop with an active descendant must leave the parent
	// at its existing key so child.parentKey never points to a missing parent.
	parentCfg := NewClientConfig(ClientConfig{
		NodeID: "bastion", Address: "10.0.0.1", Port: 22, User: "ops", AuthType: "password", AuthUpdateToken: "b1",
	})
	parentKey := DigestClientConfig(parentCfg, ZeroHopDigest)
	rootConn := &stubCloseConn{}
	parentPooled := &PooledClient{
		SSHClient:    &cryptoSSH.Client{},
		RootConn:     rootConn,
		hopConn:      rootConn,
		pool:         pool,
		publishedCfg: NewClientConfig(*parentCfg),
		Snapshot:     parentCfg.ToConnectionConfig(),
		hasSnapshot:  true,
	}
	if _, err := pool.Publish(parentKey, parentPooled, nil, nil); err != nil {
		t.Fatalf("Publish(parent) error = %v", err)
	}
	childCfg := NewClientConfig(ClientConfig{
		NodeID: "leaf", Address: "10.0.0.2", Port: 22, User: "ops", AuthType: "password", ProxyJump: "bastion",
	})
	childKey := DigestClientConfig(childCfg, parentKey)
	childPooled := &PooledClient{
		SSHClient: &cryptoSSH.Client{},
		RootConn:  rootConn,
		hopConn:   &stubCloseConn{},
		parentKey: parentKey,
		pool:      pool,
	}
	if _, err := pool.Publish(childKey, childPooled, parentPooled, nil); err != nil {
		t.Fatalf("Publish(child) error = %v", err)
	}
	parentClient := &Client{connCfg: parentCfg.ToConnectionConfig(), pooled: parentPooled}
	parentClient.ApplyRecordedAuth("b2", "", nil)
	if cur, ok := pool.Get(parentKey); !ok || cur != parentPooled {
		t.Fatal("Reindex moved parent out from under an active descendant")
	}
	if err := pool.CheckInvariants(false); err != nil {
		t.Fatalf("pool invariants violated after parent Reindex refusal: %v", err)
	}

	// Stale-key Retire after a leaf Reindex still removes the active entry
	// atomically without leaving a retired client in active.
	leafCfg := NewClientConfig(ClientConfig{
		NodeID: "leaf-retire", Address: "10.0.0.3", Port: 22, User: "ops", AuthType: "password", AuthUpdateToken: "r1",
	})
	leafOldKey := DigestClientConfig(leafCfg, ZeroHopDigest)
	leafPooled := &PooledClient{
		SSHClient:    &cryptoSSH.Client{},
		pool:         pool,
		publishedCfg: NewClientConfig(*leafCfg),
		Snapshot:     leafCfg.ToConnectionConfig(),
		hasSnapshot:  true,
	}
	if _, err := pool.Publish(leafOldKey, leafPooled, nil, nil); err != nil {
		t.Fatalf("Publish(leaf-retire) error = %v", err)
	}
	leafClient := &Client{connCfg: leafCfg.ToConnectionConfig(), pooled: leafPooled}
	leafClient.ApplyRecordedAuth("r2", "", nil)
	pool.Retire(leafOldKey, leafPooled)
	if err := pool.CheckInvariants(false); err != nil {
		t.Fatalf("stale-key Retire after Reindex violated pool invariants: %v", err)
	}
}
