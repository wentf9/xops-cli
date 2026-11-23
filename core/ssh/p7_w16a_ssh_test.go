package ssh

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// w16aSignalCloseConn is a concurrency-safe rootConn test double whose Close()
// signals closedCh at most once via sync.Once.
type w16aSignalCloseConn struct {
	stubCloseConn
	closedCh  chan struct{}
	closeOnce sync.Once
}

func (c *w16aSignalCloseConn) Close() error {
	err := c.stubCloseConn.Close()
	if c.closedCh != nil {
		c.closeOnce.Do(func() { close(c.closedCh) })
	}
	return err
}

// w16aWedgedRawConn simulates a direct-tcpip channel over a write-wedged
// bastion: both Read and Close block until release (rootConn closure) closes.
type w16aWedgedRawConn struct {
	stubCloseConn
	release    <-chan struct{}
	closeCalls atomic.Int32
}

func (c *w16aWedgedRawConn) Read([]byte) (int, error) {
	if c.release != nil {
		<-c.release
	}
	return 0, net.ErrClosed
}

func (c *w16aWedgedRawConn) Close() error {
	c.closeCalls.Add(1)
	if c.release != nil {
		<-c.release
	}
	return c.stubCloseConn.Close()
}

func publishW16aChildWithParent(
	t *testing.T,
	pool *connPool,
	nodeID string,
	parentKey HopDigest,
	parent *PooledClient,
	hopConn net.Conn,
) (HopDigest, *PooledClient) {
	t.Helper()
	childCfg := NewClientConfig(ClientConfig{NodeID: nodeID, ProxyJump: parent.publishedCfg.NodeID})
	childKey := DigestClientConfig(childCfg, parentKey)
	child := &PooledClient{
		RootConn:     parent.RootConn,
		hopConn:      hopConn,
		parentKey:    parentKey,
		publishedCfg: childCfg,
	}
	if _, err := pool.Publish(childKey, child, parent, nil); err != nil {
		t.Fatalf("Publish(%s): %v", nodeID, err)
	}
	return childKey, child
}

func startBlockedProxyRead(pc *proxyChanConn) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := pc.Read(make([]byte, 16))
		done <- err
	}()
	return done
}

func runWithinTimeout(t *testing.T, label string, limit time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s timed out after %v (deadlock suspected)", label, limit)
	}
}

func closeConcurrently(t *testing.T, label string, conns ...*proxyChanConn) {
	t.Helper()
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(len(conns))
	for _, pc := range conns {
		go func(c *proxyChanConn) {
			defer wg.Done()
			<-start
			_ = c.Close()
		}(pc)
	}
	runWithinTimeout(t, label, 2*time.Second, func() {
		close(start)
		wg.Wait()
	})
}

func assertReadExits(t *testing.T, label string, ch <-chan error) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("%s blocked Read did not exit", label)
	}
}

func assertPoolAndCloseAllClean(t *testing.T, label string, connector *Connector, wantRetired int) {
	t.Helper()
	if connector.pool.Count() != 0 || connector.pool.ClosingCount() != 0 || connector.pool.RetiredCount() != wantRetired {
		t.Fatalf("%s pool counts = (active=%d, closing=%d, retired=%d), want (0, 0, %d)",
			label, connector.pool.Count(), connector.pool.ClosingCount(), connector.pool.RetiredCount(), wantRetired)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("%s CheckInvariants: %v", label, err)
	}
	runWithinTimeout(t, label+" Connector.CloseAll", 2*time.Second, func() {
		if err := connector.CloseAll(); err != nil {
			t.Errorf("%s CloseAll(): %v", label, err)
		}
	})
}

// TestP7W16a_C16H1_ConcurrentProxyChanCloseEscalationNoDeadlock verifies C16-H1:
// concurrent proxyChanConn.Close() escalations into (*connPool).detachAndAbortRoot
// never deadlock in a mutual sync.Once AB-BA cycle across:
//   - Scenario A: two retired proxyChanConn children closing concurrently;
//   - Scenario B: one retired proxyChanConn + one active proxyChanConn closing concurrently;
//   - Scenario C: multi-level chain (active intermediate + retired leaf) closing concurrently.
//
// In all scenarios, p.closing drains to 0, pool invariants hold, and Connector.CloseAll()
// completes cleanly without blocking.
func TestP7W16a_C16H1_ConcurrentProxyChanCloseEscalationNoDeadlock(t *testing.T) {
	prevGrace := proxyChanCloseGrace
	proxyChanCloseGrace = 15 * time.Millisecond
	t.Cleanup(func() { proxyChanCloseGrace = prevGrace })

	t.Run("scenario_a_two_retired_children_concurrent_close", assertC16H1ScenarioATwoRetired)
	t.Run("scenario_b_retired_and_active_children_concurrent_close", assertC16H1ScenarioBRetiredAndActive)
	t.Run("scenario_c_two_level_chain_active_mid_and_retired_leaf_concurrent_close", assertC16H1ScenarioCTwoLevelChain)
}

func assertC16H1ScenarioATwoRetired(t *testing.T) {
	connector := NewConnector(nil, nil)
	rootClosedCh := make(chan struct{})
	rootConn := &w16aSignalCloseConn{closedCh: rootClosedCh}
	rootKey, rootPooled := publishW15aRoot(t, connector.pool, rootConn)

	raw1 := &w16aWedgedRawConn{release: rootClosedCh}
	raw2 := &w16aWedgedRawConn{release: rootClosedCh}
	proxy1 := newProxyChanConn(raw1, connector.upstreamAbortFunc(rootPooled, rootConn))
	proxy2 := newProxyChanConn(raw2, connector.upstreamAbortFunc(rootPooled, rootConn))

	key1, child1 := publishW15aChild(t, connector.pool, "retired-1", rootKey, rootPooled, proxy1)
	key2, child2 := publishW15aChild(t, connector.pool, "retired-2", rootKey, rootPooled, proxy2)

	var hookRoot, hook1, hook2 atomic.Int32
	rootPooled.setEvictHook(func() { hookRoot.Add(1) })
	child1.setEvictHook(func() { hook1.Add(1) })
	child2.setEvictHook(func() { hook2.Add(1) })

	connector.pool.Retire(key1, child1)
	connector.pool.Retire(key2, child2)

	readDone1 := startBlockedProxyRead(proxy1)
	readDone2 := startBlockedProxyRead(proxy2)
	closeConcurrently(t, "scenario A concurrent Close", proxy1, proxy2)
	assertReadExits(t, "proxy1", readDone1)
	assertReadExits(t, "proxy2", readDone2)

	if !rootConn.closed.Load() || raw1.closeCalls.Load() != 1 || raw2.closeCalls.Load() != 1 {
		t.Fatalf("closed=(root=%v, raw1=%d, raw2=%d), want (true, 1, 1)",
			rootConn.closed.Load(), raw1.closeCalls.Load(), raw2.closeCalls.Load())
	}
	if hookRoot.Load() != 1 || hook1.Load() != 1 || hook2.Load() != 1 {
		t.Fatalf("evict hooks = (root=%d, c1=%d, c2=%d), want (1, 1, 1)", hookRoot.Load(), hook1.Load(), hook2.Load())
	}
	assertPoolAndCloseAllClean(t, "scenario A", connector, 2)
}

func assertC16H1ScenarioBRetiredAndActive(t *testing.T) {
	connector := NewConnector(nil, nil)
	rootClosedCh := make(chan struct{})
	rootConn := &w16aSignalCloseConn{closedCh: rootClosedCh}
	rootKey, rootPooled := publishW15aRoot(t, connector.pool, rootConn)

	rawRetired := &w16aWedgedRawConn{release: rootClosedCh}
	rawActive := &w16aWedgedRawConn{release: rootClosedCh}
	proxyRetired := newProxyChanConn(rawRetired, connector.upstreamAbortFunc(rootPooled, rootConn))
	proxyActive := newProxyChanConn(rawActive, connector.upstreamAbortFunc(rootPooled, rootConn))

	retiredKey, retiredChild := publishW15aChild(t, connector.pool, "retired-child", rootKey, rootPooled, proxyRetired)
	_, activeChild := publishW15aChild(t, connector.pool, "active-child", rootKey, rootPooled, proxyActive)

	var hookRoot, hookRetired, hookActive atomic.Int32
	rootPooled.setEvictHook(func() { hookRoot.Add(1) })
	retiredChild.setEvictHook(func() { hookRetired.Add(1) })
	activeChild.setEvictHook(func() { hookActive.Add(1) })

	connector.pool.Retire(retiredKey, retiredChild)

	readDone1 := startBlockedProxyRead(proxyRetired)
	readDone2 := startBlockedProxyRead(proxyActive)
	closeConcurrently(t, "scenario B concurrent Close", proxyRetired, proxyActive)
	assertReadExits(t, "proxyRetired", readDone1)
	assertReadExits(t, "proxyActive", readDone2)

	if !rootConn.closed.Load() || rawRetired.closeCalls.Load() != 1 || rawActive.closeCalls.Load() != 1 {
		t.Fatalf("closed=(root=%v, retired=%d, active=%d), want (true, 1, 1)",
			rootConn.closed.Load(), rawRetired.closeCalls.Load(), rawActive.closeCalls.Load())
	}
	if hookRoot.Load() != 1 || hookRetired.Load() != 1 || hookActive.Load() != 1 {
		t.Fatalf("evict hooks = (root=%d, retired=%d, active=%d), want (1, 1, 1)",
			hookRoot.Load(), hookRetired.Load(), hookActive.Load())
	}
	assertPoolAndCloseAllClean(t, "scenario B", connector, 1)
}

func assertC16H1ScenarioCTwoLevelChain(t *testing.T) {
	connector := NewConnector(nil, nil)
	rootClosedCh := make(chan struct{})
	rootConn := &w16aSignalCloseConn{closedCh: rootClosedCh}
	rootKey, rootPooled := publishW15aRoot(t, connector.pool, rootConn)

	rawMid := &w16aWedgedRawConn{release: rootClosedCh}
	rawLeaf := &w16aWedgedRawConn{release: rootClosedCh}
	proxyMid := newProxyChanConn(rawMid, connector.upstreamAbortFunc(rootPooled, rootConn))
	midKey, midPooled := publishW16aChildWithParent(t, connector.pool, "mid-hop", rootKey, rootPooled, proxyMid)
	proxyLeaf := newProxyChanConn(rawLeaf, connector.upstreamAbortFunc(midPooled, rootConn))
	leafKey, leafPooled := publishW16aChildWithParent(t, connector.pool, "leaf-hop", midKey, midPooled, proxyLeaf)

	connector.pool.Retire(leafKey, leafPooled)

	closeConcurrently(t, "scenario C concurrent Close", proxyMid, proxyLeaf)

	if !rootConn.closed.Load() || rawMid.closeCalls.Load() != 1 || rawLeaf.closeCalls.Load() != 1 {
		t.Fatalf("closed=(root=%v, mid=%d, leaf=%d), want (true, 1, 1)",
			rootConn.closed.Load(), rawMid.closeCalls.Load(), rawLeaf.closeCalls.Load())
	}
	assertPoolAndCloseAllClean(t, "scenario C", connector, 1)
}

func TestP7W16a_C16L1_ClientWaitNilAndUnconnectedGuards(t *testing.T) {
	t.Run("nil_receiver", func(t *testing.T) {
		var c *Client
		if err := c.Wait(t.Context()); err == nil {
			t.Fatal("nil Client.Wait returned nil error")
		}
	})

	t.Run("nil_ssh_client", func(t *testing.T) {
		c := &Client{}
		if err := c.Wait(t.Context()); err == nil {
			t.Fatal("unconnected Client.Wait (nil sshClient) returned nil error")
		}
	})

	t.Run("nil_ssh_conn", func(t *testing.T) {
		c := &Client{sshClient: &cryptoSSH.Client{}}
		if err := c.Wait(t.Context()); err == nil {
			t.Fatal("unconnected Client.Wait (nil sshClient.Conn) returned nil error")
		}
	})

	t.Run("nil_context_on_connected_client", func(t *testing.T) {
		conn := &monitoredTestConn{closed: make(chan struct{}), probeSeen: make(chan struct{})}
		c := &Client{sshClient: &cryptoSSH.Client{Conn: conn}}
		//nolint:staticcheck // intentionally testing nil context guard
		if err := c.Wait(nil); err == nil {
			t.Fatal("Client.Wait(nil) returned nil error")
		}
		select {
		case <-conn.closed:
			t.Fatal("Client.Wait(nil) must not close transport on invalid nil context")
		default:
		}
	})

	t.Run("nil_receiver_and_nil_context", func(t *testing.T) {
		var c *Client
		//nolint:staticcheck // intentionally testing nil receiver + nil context guard
		if err := c.Wait(nil); err == nil {
			t.Fatal("nil Client.Wait(nil) returned nil error")
		}
	})
}
