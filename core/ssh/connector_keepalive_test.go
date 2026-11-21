package ssh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newKeepAliveTestConnector 创建启用了心跳的 Connector（白盒测试辅助）
func newKeepAliveTestConnector(t *testing.T, interval, timeout time.Duration) *Connector {
	t.Helper()
	c := newTestConnector(&mockConfigStore{}, WithInteractionHandler(&mockUI{}))
	c.EnableKeepAlive(context.Background(), interval, timeout)
	t.Cleanup(func() {
		if err := c.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
	})
	return c
}

// startHealthyServer 启动一个保持连接存活的 mock SSH 服务端并返回一个已连接的客户端。
// 服务端在测试结束后由 t.Cleanup 关闭
func startHealthyServer(t *testing.T) *ssh.Client {
	t.Helper()
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	var wg sync.WaitGroup
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
		wg.Wait()
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		sConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			if err := conn.Close(); err != nil {
				fmt.Printf("Close failed: %v\n", err)
			}
			return
		}
		defer func() {
			if err := sConn.Close(); err != nil {
				fmt.Printf("Close failed: %v\n", err)
			}
		}()
		go ssh.DiscardRequests(reqs)
		for range chans {
		}
	}()

	return dialKeepAliveTestClient(t, listener.Addr().String())
}

// TestConnector_KeepAlive_EvictsDeadClient 验证连接死亡后心跳将其从池与注册表中驱逐
func TestConnector_KeepAlive_EvictsDeadClient(t *testing.T) {
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	defer func() {
		if err := listener.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
	}()

	serverClosed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		sConn, _, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			if err := conn.Close(); err != nil {
				fmt.Printf("Close failed: %v\n", err)
			}
			return
		}
		go ssh.DiscardRequests(reqs)
		if err := sConn.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		} // 握手完成即关闭，模拟服务端断开
		close(serverClosed)
	}()

	c := newKeepAliveTestConnector(t, 50*time.Millisecond, time.Second)
	client := dialKeepAliveTestClient(t, listener.Addr().String())
	<-serverClosed

	nodeKey := DigestClientConfig(&ClientConfig{NodeID: "node-1"}, ZeroHopDigest)
	pooled := &PooledClient{SSHClient: client}
	if _, err := c.publishPooled(nodeKey, pooled, nil, nil); err != nil {
		t.Fatalf("publishPooled failed: %v", err)
	}

	// 轮询断言：心跳失败后池与客户端心跳均被驱逐停止
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := c.pool.Get(nodeKey); !ok {
			if active, _ := pooled.keepAliveState(); active {
				t.Error("expected evicted client's keepalive to be stopped")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("dead client was not evicted from pool within 3s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestConnector_KeepAlive_CloseAllStopsAll 验证 CloseAll 级联终止全部心跳并清理连接池
func TestConnector_KeepAlive_CloseAllStopsAll(t *testing.T) {
	c := newKeepAliveTestConnector(t, 50*time.Millisecond, time.Second)

	client1 := startHealthyServer(t)
	client2 := startHealthyServer(t)
	defer func() {
		if err := client1.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
	}()
	defer func() {
		if err := client2.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
	}()

	key1 := DigestClientConfig(&ClientConfig{NodeID: "node-1"}, ZeroHopDigest)
	key2 := DigestClientConfig(&ClientConfig{NodeID: "node-2"}, ZeroHopDigest)
	pooled1 := &PooledClient{SSHClient: client1}
	if _, err := c.publishPooled(key1, pooled1, nil, nil); err != nil {
		t.Fatalf("publishPooled node-1 failed: %v", err)
	}
	pooled2 := &PooledClient{SSHClient: client2}
	if _, err := c.publishPooled(key2, pooled2, nil, nil); err != nil {
		t.Fatalf("publishPooled node-2 failed: %v", err)
	}

	active1, _ := pooled1.keepAliveState()
	active2, _ := pooled2.keepAliveState()
	if !active1 || !active2 {
		t.Fatalf("expected both keepalives active before CloseAll, got (%v, %v)", active1, active2)
	}

	if err := c.CloseAll(); err != nil {
		t.Logf("CloseAll failed: %v", err)
	}

	if c.pool.Count() != 0 {
		t.Errorf("expected pool cleared after CloseAll, got %d", c.pool.Count())
	}
	if active1, _ := pooled1.keepAliveState(); active1 {
		t.Error("expected pooled1 keepalive stopped after CloseAll")
	}
	if active2, _ := pooled2.keepAliveState(); active2 {
		t.Error("expected pooled2 keepalive stopped after CloseAll")
	}
	c.kaMu.Lock()
	cfgNil := c.keepAliveCfg == nil
	c.kaMu.Unlock()
	if !cfgNil {
		t.Error("expected keepAliveCfg to be nil after CloseAll")
	}

	// CloseAll 后底层连接均被关闭，SendRequest 应失败
	for name, client := range map[string]*ssh.Client{"node-1": client1, "node-2": client2} {
		if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err == nil {
			t.Errorf("expected client %s to be closed after CloseAll", name)
		}
	}
}

// TestConnector_KeepAlive_DoesNotEvictReplacedClient 验证旧连接的心跳不会误删池中已重建的新连接
func TestConnector_KeepAlive_DoesNotEvictReplacedClient(t *testing.T) {
	c := newKeepAliveTestConnector(t, 50*time.Millisecond, time.Second)

	newClient := startHealthyServer(t)
	defer func() {
		if err := newClient.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
	}()

	// 池中已换成 newClient，旧连接 staleClient 的心跳失败回调不应误删
	staleClient := startHealthyServer(t)
	defer func() {
		if err := staleClient.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
	}()

	key := DigestClientConfig(&ClientConfig{NodeID: "node-1"}, ZeroHopDigest)
	newPooled := &PooledClient{SSHClient: newClient}
	if _, err := c.publishPooled(key, newPooled, nil, nil); err != nil {
		t.Fatalf("publishPooled newClient failed: %v", err)
	}

	// 旧心跳的失败回调携带旧连接（模拟探测失败与重连并发）
	c.pool.Evict(key, &PooledClient{SSHClient: staleClient}, false)

	current, ok := c.pool.Get(key)
	if !ok || current.SSHClient != newClient {
		t.Error("expected new client to remain in pool after stale client eviction attempt")
	}
	if active, _ := current.keepAliveState(); !active {
		t.Error("expected new client keepalive to remain active after stale client eviction attempt")
	}
}

// TestConnector_KeepAlive_ReconnectReplacesHeartbeat 验证同节点重连时旧心跳被替换且旧连接被退休
func TestConnector_KeepAlive_ReconnectReplacesHeartbeat(t *testing.T) {
	c := newKeepAliveTestConnector(t, 50*time.Millisecond, time.Second)

	client1 := startHealthyServer(t)
	client2 := startHealthyServer(t)
	defer func() {
		if err := client1.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
	}()
	defer func() {
		if err := client2.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
	}()

	key := DigestClientConfig(&ClientConfig{NodeID: "node-1"}, ZeroHopDigest)
	pooled1 := &PooledClient{SSHClient: client1}
	if _, err := c.publishPooled(key, pooled1, nil, nil); err != nil {
		t.Fatalf("publishPooled client1 failed: %v", err)
	}
	_, done1 := pooled1.keepAliveState()

	pooled2 := &PooledClient{SSHClient: client2}
	if _, err := c.publishPooled(key, pooled2, nil, nil); err != nil {
		t.Fatalf("publishPooled client2 failed: %v", err)
	}

	select {
	case <-done1:
	case <-time.After(time.Second):
		t.Fatal("expected replaced client's keepalive to stop on reconnect")
	}
	if c.pool.Count() != 1 {
		t.Fatalf("expected exactly 1 active pool entry after reconnect, got %d", c.pool.Count())
	}
	cur, ok := c.pool.Get(key)
	if !ok || cur != pooled2 || cur.SSHClient != client2 {
		t.Fatal("expected pool entry to point to the new client after reconnect")
	}
	if active, _ := pooled2.keepAliveState(); !active {
		t.Error("expected new client keepalive to be active after reconnect")
	}

	// 清理由 CloseAll 兜底
	if err := c.CloseAll(); err != nil {
		t.Logf("CloseAll failed: %v", err)
	}
}

// TestConnector_KeepAlive_DisabledByDefault 验证未启用时 publishPooled 不启动心跳，且 CloseAll 不 panic
func TestConnector_KeepAlive_DisabledByDefault(t *testing.T) {
	c := newTestConnector(&mockConfigStore{}, WithInteractionHandler(&mockUI{}))

	client := startHealthyServer(t)
	defer func() {
		if err := client.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
	}()

	key := DigestClientConfig(&ClientConfig{NodeID: "node-1"}, ZeroHopDigest)
	pooled := &PooledClient{SSHClient: client}
	if _, err := c.publishPooled(key, pooled, nil, nil); err != nil {
		t.Fatalf("publishPooled failed: %v", err)
	}

	if active, _ := pooled.keepAliveState(); active {
		t.Error("expected no keepalive started when disabled")
	}

	// nil 防御：CloseAll 不应 panic
	if err := c.CloseAll(); err != nil {
		t.Logf("CloseAll failed: %v", err)
	}
}

// TestConnector_EnableKeepAlive_Idempotent 验证重复启用为 no-op，参数保持首次值
func TestConnector_EnableKeepAlive_Idempotent(t *testing.T) {
	c := newTestConnector(&mockConfigStore{}, WithInteractionHandler(&mockUI{}))
	c.EnableKeepAlive(context.Background(), 15*time.Second, 10*time.Second)
	c.EnableKeepAlive(context.Background(), time.Second, time.Second)

	c.kaMu.Lock()
	interval := c.keepAliveCfg.interval
	timeout := c.keepAliveCfg.timeout
	c.kaMu.Unlock()

	if interval != 15*time.Second || timeout != 10*time.Second {
		t.Errorf("expected first EnableKeepAlive params to win (15s/10s), got %v/%v", interval, timeout)
	}

	if err := c.CloseAll(); err != nil {
		t.Logf("CloseAll failed: %v", err)
	}
}

// TestConnector_EnableKeepAlive_DefaultsOnInvalidParams 验证非正参数回退到默认值
func TestConnector_EnableKeepAlive_DefaultsOnInvalidParams(t *testing.T) {
	c := newTestConnector(&mockConfigStore{}, WithInteractionHandler(&mockUI{}))
	c.EnableKeepAlive(context.Background(), 0, -time.Second)

	c.kaMu.Lock()
	interval := c.keepAliveCfg.interval
	timeout := c.keepAliveCfg.timeout
	c.kaMu.Unlock()

	if interval != DefaultKeepAliveInterval {
		t.Errorf("expected interval fallback to %v, got %v", DefaultKeepAliveInterval, interval)
	}
	if timeout != DefaultKeepAliveTimeout {
		t.Errorf("expected timeout fallback to %v, got %v", DefaultKeepAliveTimeout, timeout)
	}
	if err := c.CloseAll(); err != nil {
		t.Logf("CloseAll failed: %v", err)
	}
}

func TestConnector_EnableKeepAlive_ContextCancelCleansStateAndAllowsReenable(t *testing.T) {
	c := newTestConnector(&mockConfigStore{}, WithInteractionHandler(&mockUI{}))
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	c.EnableKeepAlive(rootCtx, time.Hour, time.Second)

	client := startHealthyServer(t)
	key := DigestClientConfig(&ClientConfig{NodeID: "node-1"}, ZeroHopDigest)
	pooled := &PooledClient{SSHClient: client}
	if _, err := c.publishPooled(key, pooled, nil, nil); err != nil {
		t.Fatalf("publishPooled failed: %v", err)
	}
	if active, _ := pooled.keepAliveState(); !active {
		t.Fatal("expected active keepalive before cancellation")
	}

	cancelRoot()
	deadline := time.Now().Add(time.Second)
	for {
		c.kaMu.Lock()
		cfgCleared := c.keepAliveCfg == nil
		c.kaMu.Unlock()
		active, _ := pooled.keepAliveState()
		if cfgCleared && !active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("keepalive state was not cleaned after root context cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}

	c.EnableKeepAlive(context.Background(), 2*time.Hour, 2*time.Second)
	c.kaMu.Lock()
	reenabled := c.keepAliveCfg != nil && c.keepAliveCfg.interval == 2*time.Hour
	c.kaMu.Unlock()
	if !reenabled {
		t.Fatal("keepalive could not be re-enabled after root context cancellation")
	}
	pooled2 := &PooledClient{SSHClient: client}
	if _, err := c.publishPooled(key, pooled2, nil, nil); err != nil {
		t.Fatalf("publishPooled after re-enable failed: %v", err)
	}
	if active, _ := pooled2.keepAliveState(); !active {
		t.Fatal("expected active keepalive after re-enable")
	}
	if err := c.CloseAll(); err != nil {
		t.Logf("CloseAll failed: %v", err)
	}
}

// TestConnector_Connect_CachedProbeHasTimeout 验证 Connect 的缓存探测复用心跳超时，
// 不会因服务端不响应全局请求而无限阻塞。
func TestConnector_Connect_CachedProbeHasTimeout(t *testing.T) {
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	defer func() {
		if err := listener.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
	}()

	requestSeen := make(chan struct{})
	releaseServer := make(chan struct{})
	defer close(releaseServer)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		sConn, _, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			if err := conn.Close(); err != nil {
				fmt.Printf("Close failed: %v\n", err)
			}
			return
		}
		defer func() {
			if err := sConn.Close(); err != nil {
				fmt.Printf("Close failed: %v\n", err)
			}
		}()
		for range reqs {
			close(requestSeen)
			<-releaseServer
			return
		}
	}()

	cachedClient := dialKeepAliveTestClient(t, listener.Addr().String())
	store := &mockConfigStore{cfg: &ClientConfig{
		NodeID:   "node-1",
		Address:  "127.0.0.1",
		Port:     1,
		User:     "test",
		AuthType: "password",
		Password: "test",
	}}
	connector := newTestConnector(store, WithInteractionHandler(&mockUI{}))
	connector.EnableKeepAlive(context.Background(), time.Hour, 100*time.Millisecond)
	nodeKey := DigestClientConfig(NewClientConfig(*store.cfg), ZeroHopDigest)
	if _, err := connector.pool.Publish(nodeKey, &PooledClient{SSHClient: cachedClient}, nil, nil); err != nil {
		t.Fatalf("publish cached client failed: %v", err)
	}
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
	}()

	started := time.Now()
	_, err := connector.Connect(context.Background(), "node-1")
	if err == nil {
		t.Fatal("expected reconnect to fail after cached probe timeout")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("cached probe exceeded bounded timeout: %v", elapsed)
	}
	select {
	case <-requestSeen:
	default:
		t.Error("server did not observe cached keepalive probe")
	}
}

func TestConnector_CloseAllConcurrentCallsAreIdempotent(t *testing.T) {
	c := newKeepAliveTestConnector(t, time.Hour, time.Second)
	client := startHealthyServer(t)
	key := DigestClientConfig(&ClientConfig{NodeID: "node-1"}, ZeroHopDigest)
	pooled := &PooledClient{SSHClient: client}
	if _, err := c.publishPooled(key, pooled, nil, nil); err != nil {
		t.Fatalf("publishPooled failed: %v", err)
	}

	done := make(chan struct{}, 2)
	for range 2 {
		go func() {
			if err := c.CloseAll(); err != nil {
				t.Logf("CloseAll failed: %v", err)
			}
			done <- struct{}{}
		}()
	}
	for range 2 {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent CloseAll call did not return")
		}
	}
}

// TestConnector_KeepAlive_StartAfterCloseAllIsNoop 验证 CloseAll 之后入池连接被拒绝且不再挂载心跳
func TestConnector_KeepAlive_StartAfterCloseAllIsNoop(t *testing.T) {
	c := newKeepAliveTestConnector(t, 50*time.Millisecond, time.Second)

	client := startHealthyServer(t)
	defer func() {
		if err := client.Close(); err != nil {
			fmt.Printf("Close failed: %v\n", err)
		}
	}()

	if err := c.CloseAll(); err != nil {
		t.Logf("CloseAll failed: %v", err)
	}
	key := DigestClientConfig(&ClientConfig{NodeID: "node-1"}, ZeroHopDigest)
	late := &PooledClient{SSHClient: client}
	if _, err := c.publishPooled(key, late, nil, nil); !errors.Is(err, ErrConnectorClosed) {
		t.Errorf("expected ErrConnectorClosed publishing after CloseAll, got %v", err)
	}

	if c.pool.Count() != 0 {
		t.Errorf("expected empty pool after CloseAll, got %d", c.pool.Count())
	}
	if active, _ := late.keepAliveState(); active {
		t.Error("expected no keepalive started on client rejected after CloseAll")
	}
}
