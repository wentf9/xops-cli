package ssh

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

type w15aBlockingCloseConn struct {
	stubCloseConn
	release    <-chan struct{}
	closeCalls atomic.Int32
}

func (c *w15aBlockingCloseConn) Close() error {
	c.closeCalls.Add(1)
	if c.release != nil {
		<-c.release
	}
	return c.stubCloseConn.Close()
}

type w15aSignalCloseConn struct {
	stubCloseConn
	closedCh chan struct{}
}

func (c *w15aSignalCloseConn) Close() error {
	err := c.stubCloseConn.Close()
	if c.closedCh != nil {
		select {
		case <-c.closedCh:
		default:
			close(c.closedCh)
		}
	}
	return err
}

func publishW15aRoot(t *testing.T, pool *connPool, rootConn net.Conn) (HopDigest, *PooledClient) {
	t.Helper()
	rootCfg := NewClientConfig(ClientConfig{NodeID: "root"})
	rootKey := DigestClientConfig(rootCfg, ZeroHopDigest)
	rootPooled := &PooledClient{
		SSHClient:    &cryptoSSH.Client{},
		RootConn:     rootConn,
		publishedCfg: rootCfg,
	}
	if _, err := pool.Publish(rootKey, rootPooled, nil, nil); err != nil {
		t.Fatalf("Publish(root): %v", err)
	}
	return rootKey, rootPooled
}

func publishW15aChild(t *testing.T, pool *connPool, nodeID string, rootKey HopDigest, rootPooled *PooledClient, hopConn net.Conn) (HopDigest, *PooledClient) {
	t.Helper()
	childCfg := NewClientConfig(ClientConfig{NodeID: nodeID, ProxyJump: "root"})
	childKey := DigestClientConfig(childCfg, rootKey)
	child := &PooledClient{
		RootConn:     rootPooled.RootConn,
		hopConn:      hopConn,
		parentKey:    rootKey,
		publishedCfg: childCfg,
	}
	if _, err := pool.Publish(childKey, child, rootPooled, nil); err != nil {
		t.Fatalf("Publish(%s): %v", nodeID, err)
	}
	return childKey, child
}

func assertW15aDetachClosesRetiredSkippingClient(t *testing.T) {
	pool := newConnPool()
	rootConn := &stubCloseConn{}
	rootKey, rootPooled := publishW15aRoot(t, pool, rootConn)

	activeHop := &stubCloseConn{}
	publishW15aChild(t, pool, "active-child", rootKey, rootPooled, activeHop)

	retiredHop := &stubCloseConn{}
	retiredKey, retiredChild := publishW15aChild(t, pool, "retired-child", rootKey, rootPooled, retiredHop)

	skipClientHop := &stubCloseConn{}
	skipClientKey, retiredSkipClient := publishW15aChild(t, pool, "retired-skip-client", rootKey, rootPooled, skipClientHop)

	var retiredHookCalls atomic.Int32
	retiredChild.setEvictHook(func() { retiredHookCalls.Add(1) })

	pool.Retire(retiredKey, retiredChild)
	pool.Retire(skipClientKey, retiredSkipClient)

	if err := pool.detachAndAbortRoot(rootPooled, rootConn, retiredSkipClient, nil); err != nil {
		t.Fatalf("detachAndAbortRoot: %v", err)
	}

	if !rootConn.closed.Load() || !activeHop.closed.Load() || !retiredHop.closed.Load() {
		t.Fatalf("closed flags = (root=%v, active=%v, retired=%v), want all true", rootConn.closed.Load(), activeHop.closed.Load(), retiredHop.closed.Load())
	}
	if got := retiredHookCalls.Load(); got != 1 {
		t.Fatalf("retired descendant evict hook calls = %d, want 1", got)
	}
	if skipClientHop.closed.Load() {
		t.Fatal("skipClient retired descendant hopConn was closed despite skipClient guard")
	}
	if pool.Count() != 0 || pool.ClosingCount() != 0 || pool.RetiredCount() != 2 {
		t.Fatalf("pool counts = (active=%d, closing=%d, retired=%d), want (0, 0, 2)", pool.Count(), pool.ClosingCount(), pool.RetiredCount())
	}
	if err := pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants: %v", err)
	}
}

func assertW15aDetachSkipsRetiredMatchingSkipHop(t *testing.T) {
	pool := newConnPool()
	rootConn := &stubCloseConn{}
	rootKey, rootPooled := publishW15aRoot(t, pool, rootConn)

	skipRaw := &w15aBlockingCloseConn{}
	skipHop := newProxyChanConn(skipRaw, nil)
	skipKey, retiredSkipHop := publishW15aChild(t, pool, "retired-skip-hop", rootKey, rootPooled, skipHop)

	otherHop := &stubCloseConn{}
	otherKey, retiredOther := publishW15aChild(t, pool, "retired-other-hop", rootKey, rootPooled, otherHop)

	pool.Retire(skipKey, retiredSkipHop)
	pool.Retire(otherKey, retiredOther)

	if err := pool.detachAndAbortRoot(rootPooled, rootConn, nil, skipHop); err != nil {
		t.Fatalf("detachAndAbortRoot: %v", err)
	}

	if !otherHop.closed.Load() {
		t.Fatal("other retired descendant hopConn was not closed")
	}
	if skipHop.closed.Load() || skipRaw.closeCalls.Load() != 0 {
		t.Fatalf("skipHop was unexpectedly closed (closed=%v, rawCloseCalls=%d)", skipHop.closed.Load(), skipRaw.closeCalls.Load())
	}
	if pool.Count() != 0 || pool.ClosingCount() != 0 {
		t.Fatalf("pool counts = (active=%d, closing=%d), want (0, 0)", pool.Count(), pool.ClosingCount())
	}
	if err := pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants: %v", err)
	}
}

func assertW15aBoundedCloseEscalationClosesRetiredSibling(t *testing.T) {
	prevGrace := proxyChanCloseGrace
	proxyChanCloseGrace = 20 * time.Millisecond
	t.Cleanup(func() { proxyChanCloseGrace = prevGrace })

	pool := newConnPool()
	rootClosedCh := make(chan struct{})
	rootConn := &w15aSignalCloseConn{closedCh: rootClosedCh}
	rootKey, rootPooled := publishW15aRoot(t, pool, rootConn)

	wedgedHop := &w15aBlockingCloseConn{release: rootClosedCh}
	_, wedgedChild := publishW15aChild(t, pool, "wedged-child", rootKey, rootPooled, wedgedHop)

	retiredHop := &stubCloseConn{}
	retiredKey, retiredSibling := publishW15aChild(t, pool, "retired-sibling", rootKey, rootPooled, retiredHop)
	var retiredHookCalls atomic.Int32
	retiredSibling.setEvictHook(func() { retiredHookCalls.Add(1) })
	pool.Retire(retiredKey, retiredSibling)

	// Closing wedgedChild exceeds proxyChanCloseGrace and escalates via
	// closeHopTransportBounded -> detachAndAbortRoot(root, rootConn, wedgedChild, nil).
	if err := wedgedChild.closeSelf(); err != nil {
		t.Fatalf("wedgedChild.closeSelf(): %v", err)
	}

	if !rootConn.closed.Load() || !retiredHop.closed.Load() {
		t.Fatalf("closed flags = (root=%v, retired=%v), want both true", rootConn.closed.Load(), retiredHop.closed.Load())
	}
	if wedgedHop.closeCalls.Load() != 1 {
		t.Fatalf("wedgedHop Close calls = %d, want 1 (must not re-enter skipClient)", wedgedHop.closeCalls.Load())
	}
	if got := retiredHookCalls.Load(); got != 1 {
		t.Fatalf("retired sibling evict hook calls = %d, want 1", got)
	}
	if err := pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants: %v", err)
	}
}

// TestP7W15a_C15L1_DetachAndAbortRootClosesRetiredDescendants verifies C15-L1:
// (*connPool).detachAndAbortRoot performs a symmetric closeSelf() pass over
// batch.retiredDescendants with the identical skipClient/skipHop guards used
// for batch.descendants, ensuring retired siblings riding on the aborted root
// transport are torn down immediately without re-entering an already-closing
// child or mutating p.retired/p.closing.
func TestP7W15a_C15L1_DetachAndAbortRootClosesRetiredDescendants(t *testing.T) {
	t.Run("closes_active_and_retired_descendants_while_skipping_skipClient", assertW15aDetachClosesRetiredSkippingClient)
	t.Run("skips_retired_descendant_matching_skipHop", assertW15aDetachSkipsRetiredMatchingSkipHop)
	t.Run("bounded_close_escalation_closes_retired_sibling_descendant", assertW15aBoundedCloseEscalationClosesRetiredSibling)
}
