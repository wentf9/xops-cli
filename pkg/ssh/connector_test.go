package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type mockConfigStore struct {
	cfg *ClientConfig
}

type coordinatedDeadConn struct {
	ssh.Conn
	requestCount atomic.Int32
	closeCount   atomic.Int32
	requestSeen  chan struct{}
	release      chan struct{}
}

type coordinatedHealthyConn struct {
	ssh.Conn
	requestCount atomic.Int32
	closeCount   atomic.Int32
	requestSeen  chan struct{}
	release      chan struct{}
}

func (c *coordinatedHealthyConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	if c.requestCount.Add(1) == 1 {
		close(c.requestSeen)
	}
	<-c.release
	return true, nil, nil
}

func (c *coordinatedHealthyConn) Close() error {
	c.closeCount.Add(1)
	return nil
}

func (c *coordinatedDeadConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	if c.requestCount.Add(1) == 1 {
		close(c.requestSeen)
	}
	<-c.release
	return false, nil, fmt.Errorf("connection lost")
}

func (c *coordinatedDeadConn) Close() error {
	c.closeCount.Add(1)
	return nil
}

func TestConnector_Connect_ConcurrentStaleProbeRunsOnce(t *testing.T) {
	store := &mockConfigStore{cfg: &ClientConfig{
		NodeID:   "node-1",
		Address:  "127.0.0.1",
		Port:     1,
		User:     "admin",
		AuthType: "password",
		Password: "mockpassword",
	}}
	connector := NewConnector(store, &mockUI{})
	defer connector.CloseAll()

	deadConn := &coordinatedDeadConn{
		requestSeen: make(chan struct{}),
		release:     make(chan struct{}),
	}
	connector.clients.Set("node-1", &ssh.Client{Conn: deadConn})

	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() {
		_, err := connector.Connect(context.Background(), "node-1")
		firstDone <- err
	}()
	<-deadConn.requestSeen
	go func() {
		_, err := connector.Connect(context.Background(), "node-1")
		secondDone <- err
	}()

	// 给第二个调用进入 singleflight 的机会，再放行唯一的缓存探测。
	time.Sleep(20 * time.Millisecond)
	close(deadConn.release)
	for index, result := range []<-chan error{firstDone, secondDone} {
		select {
		case err := <-result:
			if err == nil {
				t.Errorf("Connect call %d unexpectedly succeeded", index+1)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("Connect call %d did not return", index+1)
		}
	}
	if got := deadConn.requestCount.Load(); got != 1 {
		t.Errorf("expected one serialized stale probe, got %d", got)
	}
	if _, ok := connector.clients.Get("node-1"); ok {
		t.Error("stale client remained in pool")
	}
}

func TestConnector_Connect_CallerCancellationDoesNotCloseSharedClient(t *testing.T) {
	store := &mockConfigStore{cfg: &ClientConfig{
		NodeID:   "node-1",
		Address:  "127.0.0.1",
		Port:     22,
		User:     "admin",
		AuthType: "password",
		Password: "mockpassword",
	}}
	connector := NewConnector(store, &mockUI{})
	defer connector.CloseAll()

	healthyConn := &coordinatedHealthyConn{
		requestSeen: make(chan struct{}),
		release:     make(chan struct{}),
	}
	connector.clients.Set("node-1", &ssh.Client{Conn: healthyConn})

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := connector.Connect(firstCtx, "node-1")
		firstDone <- err
	}()
	<-healthyConn.requestSeen

	secondDone := make(chan error, 1)
	go func() {
		_, err := connector.Connect(context.Background(), "node-1")
		secondDone <- err
	}()

	cancelFirst()
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected first caller cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled caller remained blocked in shared connect")
	}
	if got := healthyConn.closeCount.Load(); got != 0 {
		t.Fatalf("caller cancellation closed shared client %d times", got)
	}

	close(healthyConn.release)
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("live caller failed after first caller cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("live caller did not receive shared connect result")
	}
	if got := healthyConn.closeCount.Load(); got != 0 {
		t.Errorf("healthy shared client was closed %d times", got)
	}
}

func TestConnector_CloseAllCancelsInFlightHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer func() { _ = listener.Close() }()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address failed: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse listener port failed: %v", err)
	}

	store := &mockConfigStore{cfg: &ClientConfig{
		NodeID:   "node-1",
		Address:  host,
		Port:     port,
		User:     "admin",
		AuthType: "password",
		Password: "mockpassword",
	}}
	connector := NewConnector(store, &mockUI{})
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	connectDone := make(chan error, 1)
	go func() {
		_, connectErr := connector.Connect(context.Background(), "node-1")
		connectDone <- connectErr
	}()
	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
		defer func() { _ = serverConn.Close() }()
	case <-time.After(2 * time.Second):
		t.Fatal("connector did not reach SSH handshake")
	}

	closeDone := make(chan struct{})
	go func() {
		connector.CloseAll()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("CloseAll blocked on in-flight SSH handshake")
	}
	select {
	case connectErr := <-connectDone:
		if connectErr == nil {
			t.Fatal("in-flight Connect unexpectedly succeeded during CloseAll")
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight Connect did not return after CloseAll")
	}
	if connector.clients.Count() != 0 {
		t.Errorf("expected empty client pool after CloseAll, got %d", connector.clients.Count())
	}
	if _, connectErr := connector.Connect(context.Background(), "node-1"); !errors.Is(connectErr, ErrConnectorClosed) {
		t.Errorf("expected ErrConnectorClosed after CloseAll, got %v", connectErr)
	}
}

func (m *mockConfigStore) GetConfig(nodeID string) (*ClientConfig, error) {
	return m.cfg, nil
}

func (m *mockConfigStore) UpdateAuth(nodeID string, password, keyPath, passphrase string) error {
	return nil
}

func (m *mockConfigStore) UpdateSudo(nodeID string, mode SudoMode, suPwd string) error {
	return nil
}

type mockUI struct{}

func (m *mockUI) PromptPassword(prompt string) (string, error) {
	return "mockpass", nil
}

func (m *mockUI) ConfirmHostKey(hostname string, fingerprint string) (bool, error) {
	return true, nil
}

func TestConnector_Connect_Cached(t *testing.T) {
	store := &mockConfigStore{
		cfg: &ClientConfig{
			NodeID:   "node-1",
			Address:  "10.0.0.1",
			Port:     22,
			User:     "admin",
			AuthType: "password",
			Password: "mockpassword",
		},
	}
	ui := &mockUI{}

	connector := NewConnector(store, ui)

	// 模拟已存在缓存连接
	dummyClient := &ssh.Client{}
	connector.clients.Set("node-1", dummyClient)

	ctx := context.Background()
	client, err := connector.Connect(ctx, "node-1")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if client == nil {
		t.Fatal("expected non-nil client")
		return
	}

	// 验证在缓存命中时，配置是否正确附加
	if client.cfg.Address != "10.0.0.1" {
		t.Errorf("expected host address '10.0.0.1', got %q", client.cfg.Address)
	}
	if client.cfg.User != "admin" {
		t.Errorf("expected identity user 'admin', got %q", client.cfg.User)
	}
}

type mockConn struct {
	ssh.Conn
	closeCalled bool
}

func (m *mockConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return false, nil, fmt.Errorf("connection lost")
}

func (m *mockConn) Close() error {
	m.closeCalled = true
	return nil
}

func TestConnector_Connect_Reconnection(t *testing.T) {
	store := &mockConfigStore{
		cfg: &ClientConfig{
			NodeID:   "node-1",
			Address:  "127.0.0.1",
			Port:     9999, // 使用一个不会有真实服务的端口
			User:     "admin",
			AuthType: "password",
			Password: "mockpassword",
		},
	}
	ui := &mockUI{}

	connector := NewConnector(store, ui)

	// 模拟已存在缓存连接，但该连接已经失效
	mc := &mockConn{}
	dummyClient := &ssh.Client{
		Conn: mc,
	}
	connector.clients.Set("node-1", dummyClient)

	ctx := context.Background()
	_, err := connector.Connect(ctx, "node-1")
	if err == nil {
		t.Fatal("expected connect to fail because connection is stale and dial will fail")
	}

	// 验证连接是否已从缓存中移除
	if _, ok := connector.clients.Get("node-1"); ok {
		t.Error("expected node-1 to be evicted from clients cache")
	}

	// 验证旧连接是否被 Close
	if !mc.closeCalled {
		t.Error("expected stale client to be closed")
	}
}

func TestConnector_Connect_ProxyJumpCycle(t *testing.T) {
	// 模拟一个形成了 ProxyJump 环的配置：node-1 依赖 node-2，node-2 依赖 node-1
	cfg1 := &ClientConfig{
		NodeID:    "node-1",
		Address:   "127.0.0.1",
		Port:      22,
		User:      "admin",
		AuthType:  "password",
		Password:  "pass",
		ProxyJump: "node-2",
	}
	cfg2 := &ClientConfig{
		NodeID:    "node-2",
		Address:   "127.0.0.2",
		Port:      22,
		User:      "admin",
		AuthType:  "password",
		Password:  "pass",
		ProxyJump: "node-1",
	}

	store := &mockProxyJumpStore{
		cfgs: map[string]*ClientConfig{
			"node-1": cfg1,
			"node-2": cfg2,
		},
	}
	ui := &mockUI{}

	connector := NewConnector(store, ui)
	ctx := context.Background()
	_, err := connector.Connect(ctx, "node-1")
	if err == nil {
		t.Fatal("expected Connect to fail due to proxy jump cycle, got nil error")
	}

	// 验证错误消息中是否包含 "cycle detected"
	expectedSub := "proxy jump cycle detected"
	if !strings.Contains(err.Error(), expectedSub) {
		t.Errorf("expected error message to contain %q, got %q", expectedSub, err.Error())
	}
}

func TestConnector_Connect_ResolvedProxyChainUsesRootClient(t *testing.T) {
	store := &mockProxyJumpStore{cfgs: map[string]*ClientConfig{
		"target": {
			NodeID:    "target",
			Address:   "192.0.2.10",
			ProxyJump: "jump",
		},
		"jump": {
			NodeID:  "jump",
			Address: "192.0.2.20",
		},
	}}
	connector := NewConnector(store, &mockUI{})
	// nil Conn 的客户端仅用于验证计划顺序和包装结果，不执行网络探测。
	connector.clients.Set("target", &ssh.Client{})
	connector.clients.Set("jump", &ssh.Client{})

	client, err := connector.Connect(context.Background(), "target")
	if err != nil {
		t.Fatalf("connect resolved proxy chain failed: %v", err)
	}
	if client.cfg.NodeID != "target" || client.cfg.ProxyJump != "jump" {
		t.Fatalf("expected target client after resolving proxy chain, got %+v", client.cfg)
	}

	// 测试客户端没有底层 Conn，清空后再关闭 Connector，避免对无效 mock 执行 Close。
	connector.clients.Clear()
	connector.CloseAll()
}

func TestConnector_Connect_ConcurrentProxyJumpCycleDoesNotDeadlock(t *testing.T) {
	store := &mockProxyJumpStore{cfgs: map[string]*ClientConfig{
		"node-1": {
			NodeID:    "node-1",
			ProxyJump: "node-2",
		},
		"node-2": {
			NodeID:    "node-2",
			ProxyJump: "node-1",
		},
	}}
	connector := NewConnector(store, &mockUI{})

	results := make(chan error, 2)
	for _, nodeName := range []string{"node-1", "node-2"} {
		go func() {
			_, err := connector.Connect(context.Background(), nodeName)
			results <- err
		}()
	}
	for range 2 {
		select {
		case err := <-results:
			if err == nil || !strings.Contains(err.Error(), "proxy jump cycle detected") {
				t.Fatalf("expected proxy cycle error, got %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent proxy cycle deadlocked")
		}
	}

	closeDone := make(chan struct{})
	go func() {
		connector.CloseAll()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("CloseAll deadlocked after concurrent proxy cycle")
	}
}

type mockProxyJumpStore struct {
	cfgs map[string]*ClientConfig
}

func (m *mockProxyJumpStore) GetConfig(nodeID string) (*ClientConfig, error) {
	if cfg, ok := m.cfgs[nodeID]; ok {
		return cfg, nil
	}
	return nil, fmt.Errorf("node not found: %s", nodeID)
}

func (m *mockProxyJumpStore) UpdateAuth(nodeID string, password, keyPath, passphrase string) error {
	return nil
}

func (m *mockProxyJumpStore) UpdateSudo(nodeID string, mode SudoMode, suPwd string) error {
	return nil
}
