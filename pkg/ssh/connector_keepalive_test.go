package ssh

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newKeepAliveTestConnector 创建启用了心跳的 Connector（白盒测试辅助）
func newKeepAliveTestConnector(t *testing.T, interval, timeout time.Duration) *Connector {
	t.Helper()
	c := NewConnector(&mockConfigStore{}, &mockUI{})
	c.EnableKeepAlive(context.Background(), interval, timeout)
	t.Cleanup(c.CloseAll)
	return c
}

// startHealthyServer 启动一个保持连接存活的 mock SSH 服务端并返回一个已连接的客户端。
// 服务端在测试结束后由 t.Cleanup 关闭
func startHealthyServer(t *testing.T) *ssh.Client {
	t.Helper()
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		sConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		defer func() { _ = sConn.Close() }()
		go ssh.DiscardRequests(reqs)
		for range chans {
		}
	}()

	return dialKeepAliveTestClient(t, listener.Addr().String())
}

// TestConnector_KeepAlive_EvictsDeadClient 验证连接死亡后心跳将其从池与注册表中驱逐
func TestConnector_KeepAlive_EvictsDeadClient(t *testing.T) {
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	defer func() { _ = listener.Close() }()

	serverClosed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		sConn, _, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		go ssh.DiscardRequests(reqs)
		_ = sConn.Close() // 握手完成即关闭，模拟服务端断开
		close(serverClosed)
	}()

	c := newKeepAliveTestConnector(t, 50*time.Millisecond, time.Second)
	client := dialKeepAliveTestClient(t, listener.Addr().String())
	<-serverClosed

	c.clients.Set("node-1", client)
	c.startKeepAliveFor("node-1", client)

	// 轮询断言：心跳失败后池与注册表均被驱逐
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := c.clients.Get("node-1"); !ok {
			if c.keepAlives.Count() != 0 {
				t.Error("expected keepAlives registry to be empty after eviction")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("dead client was not evicted from pool within 3s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestConnector_KeepAlive_CloseAllStopsAll 验证 CloseAll 级联终止全部心跳并清理注册表
func TestConnector_KeepAlive_CloseAllStopsAll(t *testing.T) {
	c := newKeepAliveTestConnector(t, 50*time.Millisecond, time.Second)

	client1 := startHealthyServer(t)
	client2 := startHealthyServer(t)
	defer func() { _ = client1.Close() }()
	defer func() { _ = client2.Close() }()

	c.clients.Set("node-1", client1)
	c.startKeepAliveFor("node-1", client1)
	c.clients.Set("node-2", client2)
	c.startKeepAliveFor("node-2", client2)

	if c.keepAlives.Count() != 2 {
		t.Fatalf("expected 2 keepalive entries before CloseAll, got %d", c.keepAlives.Count())
	}

	c.CloseAll()

	if c.keepAlives.Count() != 0 {
		t.Errorf("expected keepAlives registry cleared after CloseAll, got %d", c.keepAlives.Count())
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
	defer func() { _ = newClient.Close() }()

	// 池中已换成 newClient，旧连接 staleClient 的心跳失败回调不应误删
	staleClient := startHealthyServer(t)
	defer func() { _ = staleClient.Close() }()

	c.clients.Set("node-1", newClient)
	c.keepAlives.Set("node-1", &keepAliveEntry{
		cancel: func() {},
		client: newClient,
	})

	// 旧心跳的失败回调携带旧连接与旧注册条目（模拟探测失败与重连并发）
	c.evictDeadClient("node-1", staleClient, &keepAliveEntry{
		cancel: func() {},
		client: staleClient,
	})

	current, ok := c.clients.Get("node-1")
	if !ok || current != newClient {
		t.Error("expected new client to remain in pool after stale client eviction attempt")
	}
	entry, ok := c.keepAlives.Get("node-1")
	if !ok || entry.client != newClient {
		t.Error("expected new keepalive entry to remain after stale client eviction attempt")
	}
}

// TestConnector_KeepAlive_ReconnectReplacesHeartbeat 验证同节点重连时旧心跳被替换
func TestConnector_KeepAlive_ReconnectReplacesHeartbeat(t *testing.T) {
	c := newKeepAliveTestConnector(t, 50*time.Millisecond, time.Second)

	client1 := startHealthyServer(t)
	client2 := startHealthyServer(t)
	defer func() { _ = client1.Close() }()
	defer func() { _ = client2.Close() }()

	c.clients.Set("node-1", client1)
	c.startKeepAliveFor("node-1", client1)
	c.clients.Set("node-1", client2)
	c.startKeepAliveFor("node-1", client2)

	if c.keepAlives.Count() != 1 {
		t.Fatalf("expected exactly 1 keepalive entry after reconnect, got %d", c.keepAlives.Count())
	}
	entry, ok := c.keepAlives.Get("node-1")
	if !ok {
		t.Fatal("expected keepalive entry for node-1")
	}
	if entry.client != client2 {
		t.Error("expected keepalive entry to point to the new client after reconnect")
	}

	// 清理由 CloseAll 兜底
	c.CloseAll()
}

// TestConnector_KeepAlive_DisabledByDefault 验证未启用时 startKeepAliveFor 为 no-op，且 CloseAll 不 panic
func TestConnector_KeepAlive_DisabledByDefault(t *testing.T) {
	c := NewConnector(&mockConfigStore{}, &mockUI{})

	client := startHealthyServer(t)
	defer func() { _ = client.Close() }()

	c.clients.Set("node-1", client)
	c.startKeepAliveFor("node-1", client) // 未启用心跳，应无副作用

	if c.keepAlives.Count() != 0 {
		t.Errorf("expected no keepalive entries when disabled, got %d", c.keepAlives.Count())
	}

	// nil 防御：CloseAll 不应 panic
	c.CloseAll()
}

// TestConnector_EnableKeepAlive_Idempotent 验证重复启用为 no-op，参数保持首次值
func TestConnector_EnableKeepAlive_Idempotent(t *testing.T) {
	c := NewConnector(&mockConfigStore{}, &mockUI{})
	c.EnableKeepAlive(context.Background(), 15*time.Second, 10*time.Second)
	c.EnableKeepAlive(context.Background(), time.Second, time.Second)

	c.kaMu.Lock()
	interval := c.keepAliveCfg.interval
	timeout := c.keepAliveCfg.timeout
	c.kaMu.Unlock()

	if interval != 15*time.Second || timeout != 10*time.Second {
		t.Errorf("expected first EnableKeepAlive params to win (15s/10s), got %v/%v", interval, timeout)
	}

	c.CloseAll()
}

// TestConnector_EnableKeepAlive_DefaultsOnInvalidParams 验证非正参数回退到默认值
func TestConnector_EnableKeepAlive_DefaultsOnInvalidParams(t *testing.T) {
	c := NewConnector(&mockConfigStore{}, &mockUI{})
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
	c.CloseAll()
}

func TestConnector_EnableKeepAlive_ContextCancelCleansStateAndAllowsReenable(t *testing.T) {
	c := NewConnector(&mockConfigStore{}, &mockUI{})
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	c.EnableKeepAlive(rootCtx, time.Hour, time.Second)

	client := startHealthyServer(t)
	c.clients.Set("node-1", client)
	c.startKeepAliveFor("node-1", client)
	if c.keepAlives.Count() != 1 {
		t.Fatalf("expected one keepalive entry before cancellation, got %d", c.keepAlives.Count())
	}

	cancelRoot()
	deadline := time.Now().Add(time.Second)
	for {
		c.kaMu.Lock()
		cfgCleared := c.keepAliveCfg == nil
		c.kaMu.Unlock()
		if cfgCleared && c.keepAlives.Count() == 0 {
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
	c.startKeepAliveFor("node-1", client)
	if c.keepAlives.Count() != 1 {
		t.Fatalf("expected one keepalive entry after re-enable, got %d", c.keepAlives.Count())
	}
	c.CloseAll()
}

// TestConnector_Connect_CachedProbeHasTimeout 验证 Connect 的缓存探测复用心跳超时，
// 不会因服务端不响应全局请求而无限阻塞。
func TestConnector_Connect_CachedProbeHasTimeout(t *testing.T) {
	listener, serverConfig := startKeepAliveTestSSHServer(t)
	defer func() { _ = listener.Close() }()

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
			_ = conn.Close()
			return
		}
		defer func() { _ = sConn.Close() }()
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
	connector := NewConnector(store, &mockUI{})
	connector.EnableKeepAlive(context.Background(), time.Hour, 100*time.Millisecond)
	connector.clients.Set("node-1", cachedClient)
	defer connector.CloseAll()

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
	c.clients.Set("node-1", client)
	c.startKeepAliveFor("node-1", client)

	done := make(chan struct{}, 2)
	for range 2 {
		go func() {
			c.CloseAll()
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

// TestConnector_KeepAlive_StartAfterCloseAllIsNoop 验证 CloseAll 之后入池连接不再挂载心跳
// （覆盖 startKeepAliveFor 与 CloseAll 的互斥窗口：后者已清空 cfg，前者必须 no-op）
func TestConnector_KeepAlive_StartAfterCloseAllIsNoop(t *testing.T) {
	c := newKeepAliveTestConnector(t, 50*time.Millisecond, time.Second)

	client := startHealthyServer(t)
	defer func() { _ = client.Close() }()

	c.CloseAll()
	c.startKeepAliveFor("node-1", client)

	if c.keepAlives.Count() != 0 {
		t.Errorf("expected no keepalive entries after CloseAll, got %d", c.keepAlives.Count())
	}
}
