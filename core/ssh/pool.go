package ssh

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// errStaleParentGeneration reports that a jump-chained hop attempted to publish
// into the pool over a parent transport that is no longer the current published
// generation for its parent HopDigest.
var errStaleParentGeneration = errors.New("stale parent transport generation")

// PooledClient retains the outermost transport, including for ProxyJump clients,
// and owns its own background keepalive lifecycle (started atomically on pool
// Publish and stopped on retire, eviction, or CloseAll).
type PooledClient struct {
	SSHClient          *ssh.Client
	RootConn           net.Conn
	hopConn            net.Conn
	digest             HopDigest
	parentKey          HopDigest
	parent             *PooledClient
	pool               *connPool
	probeMu            sync.Mutex
	probeCache         *executionProbeCache
	publishedCfg       *ClientConfig
	ControlSocketPath  string
	ControlExpectedUID uint32
	Snapshot           ConnectionConfig
	hasSnapshot        bool

	// kaMu guards this client's owned keepalive lifecycle.
	// Lock ordering: connPool.mu -> Connector.kaMu -> PooledClient.kaMu.
	// PooledClient.probeMu guards Snapshot, hasSnapshot, and probeCache only and
	// is never held across connPool.mu; publishedCfg/digest/parentKey/parent are
	// guarded by connPool.mu once published.
	kaMu         sync.Mutex
	kaCancel     context.CancelFunc
	kaDone       <-chan struct{}
	kaNodeScoped bool

	// evictMu is a strict leaf lock guarding evicted and onEvict (the reverse
	// PooledClient -> MuxServer teardown hook installed when a Connector-owned
	// MuxServer attaches to this pooled transport). Never held across connPool.mu,
	// kaMu, probeMu, MuxServer.idleMu, or any I/O.
	evictMu sync.Mutex
	evicted bool
	onEvict func()

	// retiredAborted claims single-winner teardown ownership when a retired
	// PooledClient is collected by concurrent detachForEvict /
	// detachActiveForEvict / detachActiveForInterrupt calls while remaining in
	// connPool.retired for RetiredCount() and CloseAll().
	retiredAborted atomic.Bool
}

// setEvictHook registers a reverse teardown callback invoked synchronously upon
// pool eviction (outside connPool.mu). If c was already evicted before the hook
// was attached, fn is invoked immediately.
func (c *PooledClient) setEvictHook(fn func()) {
	if c == nil || fn == nil {
		return
	}
	c.evictMu.Lock()
	if c.evicted {
		c.evictMu.Unlock()
		fn()
		return
	}
	c.onEvict = fn
	c.evictMu.Unlock()
}

// triggerEvictHook marks c as evicted and runs any attached reverse teardown
// hook at most once outside evictMu.
func (c *PooledClient) triggerEvictHook() {
	if c == nil {
		return
	}
	c.evictMu.Lock()
	c.evicted = true
	fn := c.onEvict
	c.onEvict = nil
	c.evictMu.Unlock()
	if fn != nil {
		fn()
	}
}

func (c *PooledClient) updateSnapshot(fn func(*ConnectionConfig, *ClientConfig)) {
	if c == nil || fn == nil {
		return
	}
	c.probeMu.Lock()
	if c.hasSnapshot {
		fn(&c.Snapshot, nil)
	}
	pool := c.pool
	c.probeMu.Unlock()

	if pool != nil {
		pool.Reindex(c, func(cfg *ClientConfig) {
			fn(nil, cfg)
		})
		return
	}
	c.probeMu.Lock()
	if c.publishedCfg != nil {
		cloned := NewClientConfig(*c.publishedCfg)
		fn(nil, cloned)
		c.publishedCfg = NewClientConfig(*cloned)
	}
	c.probeMu.Unlock()
}

func (c *PooledClient) interrupt() error {
	if c == nil {
		return nil
	}
	var sshClient *ssh.Client
	if c.SSHClient != nil && c.SSHClient.Conn != nil {
		sshClient = c.SSHClient
	}
	return interruptSSHTransport(c.RootConn, sshClient)
}

// isJumpChildLocked reports whether c rides on an upstream in-memory parent
// hop. Callers must hold c.pool.mu (or own c exclusively before publication).
func (c *PooledClient) isJumpChildLocked() bool {
	if c == nil || c.ControlSocketPath != "" {
		return false
	}
	return c.parent != nil || !c.parentKey.IsZero()
}

// isJumpChild reports whether c rides on an upstream in-memory parent hop,
// reading parentKey under c.pool.mu when pooled so concurrent Reindex never races.
func (c *PooledClient) isJumpChild() bool {
	if c == nil || c.ControlSocketPath != "" {
		return false
	}
	if c.parent != nil {
		return true
	}
	if c.pool != nil {
		c.pool.mu.Lock()
		hasParent := !c.parentKey.IsZero()
		c.pool.mu.Unlock()
		return hasParent
	}
	return !c.parentKey.IsZero()
}

// closeHopTransport closes this hop's own SSH client and hop connection without
// tearing down a shared upstream bastion's RootConn that other sessions may
// still use. For a direct root hop (or an external ControlMaster proxy), this
// closes its own RootConn + SSHClient.
func (c *PooledClient) closeHopTransport() error {
	if c == nil {
		return nil
	}
	var sshClient *ssh.Client
	if c.SSHClient != nil && c.SSHClient.Conn != nil {
		sshClient = c.SSHClient
	}
	ownConn := c.hopConn
	if ownConn == nil && !c.isJumpChild() {
		ownConn = c.RootConn
	}
	return interruptSSHTransport(ownConn, sshClient)
}

// closeSelf stops this hop's keepalive and closes its own hop transport without
// tearing down a shared upstream bastion's RootConn that other sessions may still use.
// Jump children whose hopConn is not already a bounded proxyChanConn are bounded
// behind proxyChanCloseGrace with escalation to RootConn so eviction/rejection
// can never block indefinitely over a write-wedged bastion.
func (c *PooledClient) closeSelf() error {
	if c == nil {
		return nil
	}
	c.stopKeepAlive()
	c.triggerEvictHook()
	if !c.isJumpChild() || c.RootConn == nil {
		return c.closeHopTransport()
	}
	if _, ok := c.hopConn.(*proxyChanConn); ok {
		return c.closeHopTransport()
	}
	return c.closeHopTransportBounded()
}

func (c *PooledClient) closeHopTransportBounded() error {
	done := make(chan error, 1)
	go func() {
		done <- c.closeHopTransport()
	}()

	grace := proxyChanCloseGrace
	if grace <= 0 {
		grace = 90 * time.Millisecond
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()

	select {
	case err := <-done:
		return err
	case <-timer.C:
		root := c.parent
		if root == nil {
			root = c
		}
		abortErr := c.pool.detachAndAbortRoot(root, c.RootConn, c, nil)
		return errors.Join(abortErr, <-done)
	}
}

// startKeepAlive starts this pooled client's background keepalive while
// c.pool.mu is held (from Publish's onPublished callback).
func (c *PooledClient) startKeepAlive(
	stopParentCtx context.Context,
	abortCtx context.Context,
	interval, timeout time.Duration,
	nodeScoped bool,
	onDead func(error),
	wg *sync.WaitGroup,
) {
	if c == nil || c.SSHClient == nil || c.SSHClient.Conn == nil || stopParentCtx == nil || stopParentCtx.Err() != nil || interval <= 0 {
		return
	}
	if abortCtx != nil && abortCtx.Err() != nil {
		return
	}
	c.kaMu.Lock()
	defer c.kaMu.Unlock()
	if c.kaCancel != nil {
		return
	}
	stopCtx, cancel := context.WithCancel(stopParentCtx)
	c.kaCancel = cancel
	c.kaNodeScoped = nodeScoped
	if wg != nil {
		wg.Add(1)
	}
	hopScopedClose := c.isJumpChildLocked()
	var beforeClose func() func()
	if c.pool != nil {
		beforeClose = func() func() {
			batch := c.pool.detachForEvict(ZeroHopDigest, c, true)
			return batch.closeDescendantsAndRelease
		}
	}
	c.kaDone = startKeepAliveWithContexts(stopCtx, abortCtx, c.SSHClient, interval, timeout, onDead, c.closeHopTransport, beforeClose, hopScopedClose, wg)
}

func (c *PooledClient) detachKeepAlive() context.CancelFunc {
	if c == nil {
		return nil
	}
	c.kaMu.Lock()
	cancel := c.kaCancel
	c.kaCancel = nil
	c.kaNodeScoped = false
	c.kaMu.Unlock()
	return cancel
}

func (c *PooledClient) stopKeepAlive() {
	if cancel := c.detachKeepAlive(); cancel != nil {
		cancel()
	}
}

func (c *PooledClient) stopGlobalKeepAlive() {
	if c == nil {
		return
	}
	c.kaMu.Lock()
	var cancel context.CancelFunc
	if !c.kaNodeScoped && c.kaCancel != nil {
		cancel = c.kaCancel
		c.kaCancel = nil
	}
	c.kaMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *PooledClient) keepAliveState() (active bool, done <-chan struct{}) {
	if c == nil {
		return false, nil
	}
	c.kaMu.Lock()
	defer c.kaMu.Unlock()
	if c.kaCancel == nil || c.kaDone == nil {
		return false, c.kaDone
	}
	select {
	case <-c.kaDone:
		return false, c.kaDone
	default:
		return true, c.kaDone
	}
}

func isRootConnClosed(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	root, ok := conn.(*physicalSSHConn)
	return ok && root.closed.Load()
}

func isSameParentGeneration(cur, expected *PooledClient) bool {
	if cur == nil || expected == nil || cur != expected {
		return false
	}
	if expected.RootConn != nil && (cur.RootConn != expected.RootConn || isRootConnClosed(cur.RootConn)) {
		return false
	}
	return true
}

// isConsistentParentChildTransport is a pure predicate verifying that child rides
// on the exact live transport generation owned by parent.
func isConsistentParentChildTransport(parent, child *PooledClient) bool {
	if parent == nil || child == nil {
		return false
	}
	if child.ControlSocketPath != "" {
		return true
	}
	if isRootConnClosed(parent.RootConn) || isRootConnClosed(child.RootConn) {
		return false
	}
	if parent.RootConn != nil || child.RootConn != nil {
		if parent.RootConn == nil || child.RootConn == nil || parent.RootConn != child.RootConn {
			return false
		}
	}
	if child.parent != nil && child.parent != parent {
		return false
	}
	return true
}

// canReuseCachedChain is a pure decision over a resolved plan and its pool
// snapshot: reuse is permitted iff every hop digest hits (or the final target
// is an active external ControlMaster proxy) and every parent/child pair shares
// a live, consistent RootConn generation.
func canReuseCachedChain(plan []connectionPlanNode, cached []*PooledClient) bool {
	if len(plan) == 0 || len(cached) != len(plan) {
		return false
	}
	target := cached[0]
	if target == nil || target.SSHClient == nil || isRootConnClosed(target.RootConn) {
		return false
	}
	if target.ControlSocketPath != "" {
		return true
	}
	for i := len(plan) - 1; i >= 0; i-- {
		entry := cached[i]
		if entry == nil || entry.SSHClient == nil || isRootConnClosed(entry.RootConn) {
			return false
		}
		if i < len(plan)-1 && !isConsistentParentChildTransport(cached[i+1], entry) {
			return false
		}
	}
	return true
}

// connPool stores live, retired, and closing PooledClients keyed solely by
// Merkle HopDigest. All membership transitions (Publish CAS, Retire, Evict,
// Close) execute under a single mutex so displaced clients are never leaked,
// evicted-but-not-yet-closed transports remain visible to CloseAll(), and stale
// parent generations can never publish into the pool.
type connPool struct {
	mu      sync.Mutex
	closed  bool
	active  map[HopDigest]*PooledClient
	retired []*PooledClient
	closing map[*PooledClient]int
}

func newConnPool() *connPool {
	return &connPool{
		active:  make(map[HopDigest]*PooledClient),
		closing: make(map[*PooledClient]int),
	}
}

func (p *connPool) Get(key HopDigest) (*PooledClient, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	client, ok := p.active[key]
	return client, ok
}

// DigestOf returns target's current pool HopDigest under p.mu so concurrent
// Reindex transitions never race callers reading parent digests.
func (p *connPool) DigestOf(target *PooledClient) HopDigest {
	if p == nil || target == nil {
		return ZeroHopDigest
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return target.digest
}

func (p *connPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.active)
}

func (p *connPool) RetiredCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.retired)
}

func (p *connPool) ClosingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.closing)
}

func (p *connPool) trackClosingLocked(c *PooledClient) {
	if c == nil || p.closed {
		return
	}
	if p.closing == nil {
		p.closing = make(map[*PooledClient]int)
	}
	p.closing[c]++
}

func (p *connPool) releaseClosing(c *PooledClient) {
	if p == nil || c == nil {
		return
	}
	p.mu.Lock()
	if n := p.closing[c]; n <= 1 {
		delete(p.closing, c)
	} else {
		p.closing[c] = n - 1
	}
	p.mu.Unlock()
}

func closeBatchDescendantsSkipping(children []*PooledClient, skipClient *PooledClient, skipHop *proxyChanConn) {
	for _, child := range children {
		if child == nil || (skipClient != nil && child == skipClient) || (skipHop != nil && child.hopConn == skipHop) {
			continue
		}
		// rootConn has already been aborted by detachAndAbortRoot before this
		// pass, so any sibling proxyChanConn that has already entered
		// closeOnceBody() is guaranteed to drain on its own goroutine; skipping
		// closeSelf() prevents mutual proxyChanConn.closeOnce.Do AB-BA cycles.
		if pc, ok := child.hopConn.(*proxyChanConn); ok && pc.isClosing() {
			child.stopKeepAlive()
			child.triggerEvictHook()
			continue
		}
		_ = child.closeSelf()
	}
}

// detachAndAbortRoot atomically detaches the outermost root hop (and any active
// in-memory descendants, while also collecting matching retired descendants)
// into p.closing, aborts the physical rootConn FIRST so a write-wedged or
// blackholed upstream unblocks immediately, closes the root and remaining
// active and retired descendants (skipping skipClient / skipHop to avoid
// re-entering an already-closing child), and releases all closing entries.
func (p *connPool) detachAndAbortRoot(root *PooledClient, rootConn net.Conn, skipClient *PooledClient, skipHop *proxyChanConn) error {
	if root != nil {
		for root.parent != nil {
			root = root.parent
		}
		if rootConn == nil {
			rootConn = root.RootConn
		}
	}
	var batch *evictionBatch
	if p != nil && root != nil {
		batch = p.detachForEvict(ZeroHopDigest, root, true)
	}
	var errs []error
	if rootConn != nil {
		if err := closeResource(rootConn, "upstream root SSH transport"); err != nil {
			errs = append(errs, err)
		}
	}
	if root != nil && (skipClient == nil || root != skipClient) {
		if err := root.closeSelf(); err != nil {
			errs = append(errs, err)
		}
	}
	if batch != nil {
		defer batch.release()
		closeBatchDescendantsSkipping(batch.descendants, skipClient, skipHop)
		closeBatchDescendantsSkipping(batch.retiredDescendants, skipClient, skipHop)
	}
	return errors.Join(errs...)
}

func (p *connPool) SnapshotChain(plan []connectionPlanNode) []*PooledClient {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*PooledClient, len(plan))
	for i, hop := range plan {
		out[i] = p.active[hop.digest]
	}
	return out
}

// Publish atomically verifies parent generation consistency (when expectParent
// is non-nil or next declares a parentKey), installs next at key, moves any
// displaced client to retired (closed on CloseAll), and invokes onPublished
// under the pool lock so keepalive attachment cannot race retirement or close.
// On rejection, next is closed before returning.
func (p *connPool) Publish(
	key HopDigest,
	next *PooledClient,
	expectParent *PooledClient,
	onPublished func(*PooledClient),
) (*PooledClient, error) {
	if next == nil {
		return nil, errors.New("pooled client is nil")
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = next.closeSelf()
		return nil, ErrConnectorClosed
	}
	if expectParent != nil || (!next.parentKey.IsZero() && next.ControlSocketPath == "") {
		parentKey := next.parentKey
		if parentKey.IsZero() || expectParent == nil {
			p.trackClosingLocked(next)
			p.mu.Unlock()
			defer p.releaseClosing(next)
			_ = next.closeSelf()
			return nil, errStaleParentGeneration
		}
		curParent, ok := p.active[parentKey]
		if !ok || !isSameParentGeneration(curParent, expectParent) {
			p.trackClosingLocked(next)
			p.mu.Unlock()
			defer p.releaseClosing(next)
			_ = next.closeSelf()
			return nil, errStaleParentGeneration
		}
		next.parent = curParent
	}

	var cancels []context.CancelFunc
	displaced := p.active[key]
	if displaced != nil && displaced != next {
		if !slices.Contains(p.retired, displaced) {
			p.retired = append(p.retired, displaced)
		}
		if cancel := displaced.detachKeepAlive(); cancel != nil {
			cancels = append(cancels, cancel)
		}
		// Retire any active descendants that rode on the displaced parent so
		// active entries never reference a retired parent generation.
		descKeys, descClients := p.collectDescendantsLocked(displaced)
		for i, k := range descKeys {
			delete(p.active, k)
			child := descClients[i]
			if !slices.Contains(p.retired, child) {
				p.retired = append(p.retired, child)
			}
			if cancel := child.detachKeepAlive(); cancel != nil {
				cancels = append(cancels, cancel)
			}
		}
	}
	next.pool = p
	next.digest = key
	p.active[key] = next
	if onPublished != nil {
		onPublished(next)
	}
	p.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	return displaced, nil
}

// isDescendantLocked reports whether candidate is a downstream in-memory hop
// riding on ancestor. Every published in-memory jump child carries an exact
// parent pointer chain set atomically in Publish, so lineage is established by
// pointer identity (never HopDigest key matching, which would conflate replaced
// intermediate hops sharing a healthy upstream bastion). When ancestor is a
// root hop owning a physical RootConn, any in-memory hop sharing that exact
// RootConn is also treated as a descendant of that root generation.
func (p *connPool) isDescendantLocked(candidate, ancestor *PooledClient) bool {
	if candidate == nil || ancestor == nil || candidate == ancestor || candidate.ControlSocketPath != "" {
		return false
	}
	for cur := candidate.parent; cur != nil; cur = cur.parent {
		if cur == ancestor {
			if ancestor.RootConn != nil {
				return candidate.RootConn == ancestor.RootConn
			}
			return true
		}
	}
	if ancestor.parent == nil && ancestor.parentKey.IsZero() && ancestor.ControlSocketPath == "" && ancestor.RootConn != nil {
		return candidate.RootConn == ancestor.RootConn
	}
	return false
}

func (p *connPool) collectDescendantsLocked(ancestor *PooledClient) ([]HopDigest, []*PooledClient) {
	var keys []HopDigest
	var clients []*PooledClient
	for k, child := range p.active {
		if p.isDescendantLocked(child, ancestor) {
			keys = append(keys, k)
			clients = append(clients, child)
		}
	}
	return keys, clients
}

func (p *connPool) collectRetiredDescendantsLocked(ancestor *PooledClient, claimForClose bool) []*PooledClient {
	var clients []*PooledClient
	for _, child := range p.retired {
		if !p.isDescendantLocked(child, ancestor) {
			continue
		}
		if claimForClose {
			if !child.retiredAborted.CompareAndSwap(false, true) {
				continue
			}
		} else if child.retiredAborted.Load() {
			continue
		}
		clients = append(clients, child)
	}
	return clients
}

func (p *connPool) collectRetiredForInterruptLocked(
	root, target *PooledClient,
	rootConn net.Conn,
	comparableRoot bool,
) []*PooledClient {
	var clients []*PooledClient
	for _, entry := range p.retired {
		if entry == nil || entry == target {
			continue
		}
		if entry == root || p.matchesInterruptedEntryLocked(entry, root, target, rootConn, comparableRoot) {
			if !entry.retiredAborted.CompareAndSwap(false, true) {
				continue
			}
			clients = append(clients, entry)
		}
	}
	return clients
}

func parentDepth(c *PooledClient) int {
	depth := 0
	for cur := c; cur != nil && cur.parent != nil; cur = cur.parent {
		depth++
	}
	return depth
}

func sortByParentDepth(clients []*PooledClient) {
	if len(clients) < 2 {
		return
	}
	slices.SortFunc(clients, func(a, b *PooledClient) int {
		return cmp.Compare(parentDepth(a), parentDepth(b))
	})
}

// activeKeyLocked resolves the active map key currently holding target under
// p.mu, tolerating a stale caller hint after a concurrent Reindex while never
// matching a different fresher occupant.
func (p *connPool) activeKeyLocked(hint HopDigest, target *PooledClient) (HopDigest, bool) {
	if target == nil {
		return ZeroHopDigest, false
	}
	if cur, ok := p.active[hint]; ok && cur == target {
		return hint, true
	}
	if cur, ok := p.active[target.digest]; ok && cur == target {
		return target.digest, true
	}
	return ZeroHopDigest, false
}

// Retire non-disruptively removes displaced (and any active downstream hops
// riding on its lineage) from active, stops their keepalives, and tracks them
// in retired so CloseAll shuts them down without interrupting live sessions.
func (p *connPool) Retire(key HopDigest, displaced *PooledClient) []*PooledClient {
	if displaced == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		displaced.stopKeepAlive()
		_ = displaced.closeSelf()
		return []*PooledClient{displaced}
	}

	var toStop []*PooledClient
	var cancels []context.CancelFunc
	activeKey, isActive := p.activeKeyLocked(key, displaced)
	descKeys, descClients := p.collectDescendantsLocked(displaced)
	if isActive {
		delete(p.active, activeKey)
	}
	if !slices.Contains(p.retired, displaced) {
		p.retired = append(p.retired, displaced)
	}
	toStop = append(toStop, displaced)
	if cancel := displaced.detachKeepAlive(); cancel != nil {
		cancels = append(cancels, cancel)
	}

	for i, k := range descKeys {
		delete(p.active, k)
		child := descClients[i]
		if !slices.Contains(p.retired, child) {
			p.retired = append(p.retired, child)
		}
		toStop = append(toStop, child)
		if cancel := child.detachKeepAlive(); cancel != nil {
			cancels = append(cancels, cancel)
		}
	}
	p.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	return toStop
}

// evictionBatch holds pooled clients atomically detached from p.active and
// recorded in p.closing so connPool.Close() / Connector.CloseAll() always
// observes their RootConn even while eviction or keepalive abort is in progress.
// Matching p.retired entries are recorded separately in retiredDescendants so
// their reverse MuxServer hooks and transports tear down without mutating
// p.retired or p.closing.
type evictionBatch struct {
	pool               *connPool
	dead               *PooledClient
	descendants        []*PooledClient
	retiredDescendants []*PooledClient
	tracked            []*PooledClient
}

func (b *evictionBatch) closeDescendants() {
	if b == nil {
		return
	}
	for _, child := range b.descendants {
		_ = child.closeSelf()
	}
	for _, child := range b.retiredDescendants {
		_ = child.closeSelf()
	}
}

func (b *evictionBatch) release() {
	if b == nil || b.pool == nil || len(b.tracked) == 0 {
		return
	}
	b.pool.mu.Lock()
	for _, c := range b.tracked {
		if n := b.pool.closing[c]; n <= 1 {
			delete(b.pool.closing, c)
		} else {
			b.pool.closing[c] = n - 1
		}
	}
	b.tracked = nil
	b.pool.mu.Unlock()
}

func (b *evictionBatch) closeDescendantsAndRelease() {
	if b == nil {
		return
	}
	defer b.release()
	b.closeDescendants()
}

func (p *connPool) finalizeEvictionBatch(
	dead *PooledClient,
	triggerDeadHook bool,
	descendants []*PooledClient,
	retiredDescendants []*PooledClient,
	tracked []*PooledClient,
	cancels []context.CancelFunc,
) *evictionBatch {
	for _, cancel := range cancels {
		cancel()
	}
	sortByParentDepth(descendants)
	sortByParentDepth(retiredDescendants)
	// Synchronously tear down any Connector-owned MuxServer listeners attached
	// to evicted or matching retired entries (unlinking control sockets and
	// closing Unix listeners without blocking on SSH transport I/O) before
	// returning to callers.
	if triggerDeadHook && dead != nil {
		dead.triggerEvictHook()
	}
	for _, child := range descendants {
		child.triggerEvictHook()
	}
	for _, child := range retiredDescendants {
		child.triggerEvictHook()
	}
	return &evictionBatch{
		pool:               p,
		dead:               dead,
		descendants:        descendants,
		retiredDescendants: retiredDescendants,
		tracked:            tracked,
	}
}

// detachForEvict atomically removes dead (if currently active) and any active
// in-memory descendants from p.active, detaches their keepalives, and tracks
// all detached entries (plus dead when trackDead is true) in p.closing without
// performing any blocking transport I/O. Callers must close dead BEFORE closing
// descendants so a dead parent's RootConn aborts before child channel closes.
func (p *connPool) detachForEvict(key HopDigest, dead *PooledClient, trackDead bool) *evictionBatch {
	if p == nil || dead == nil {
		return nil
	}
	p.mu.Lock()
	var descKeys []HopDigest
	var descendants []*PooledClient
	var retiredDescendants []*PooledClient
	activeKey, removedSelf := p.activeKeyLocked(key, dead)
	if removedSelf || trackDead || dead.RootConn != nil {
		descKeys, descendants = p.collectDescendantsLocked(dead)
		retiredDescendants = p.collectRetiredDescendantsLocked(dead, trackDead)
	}
	if removedSelf {
		delete(p.active, activeKey)
	}
	var cancels []context.CancelFunc
	if removedSelf || trackDead {
		if cancel := dead.detachKeepAlive(); cancel != nil {
			cancels = append(cancels, cancel)
		}
	}
	for i, k := range descKeys {
		delete(p.active, k)
		if cancel := descendants[i].detachKeepAlive(); cancel != nil {
			cancels = append(cancels, cancel)
		}
	}
	var tracked []*PooledClient
	if !p.closed {
		if removedSelf || trackDead {
			p.trackClosingLocked(dead)
			tracked = append(tracked, dead)
		}
		for _, child := range descendants {
			p.trackClosingLocked(child)
			tracked = append(tracked, child)
		}
	}
	p.mu.Unlock()

	return p.finalizeEvictionBatch(dead, removedSelf || trackDead, descendants, retiredDescendants, tracked, cancels)
}

// detachActiveForEvict atomically detaches target and any active in-memory
// descendants ONLY when target is currently in p.active. When target is already
// retired, closing, or closed, it preserves p.retired and p.closing untouched
// while still synchronously triggering evict hooks (and returning any matching
// retired descendants for transport teardown after target closes).
func (p *connPool) detachActiveForEvict(target *PooledClient) *evictionBatch {
	if p == nil || target == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		target.triggerEvictHook()
		return nil
	}
	retiredDescendants := p.collectRetiredDescendantsLocked(target, true)
	activeKey, isActive := p.activeKeyLocked(ZeroHopDigest, target)
	if !isActive {
		p.mu.Unlock()
		batch := p.finalizeEvictionBatch(target, true, nil, retiredDescendants, nil, nil)
		if len(retiredDescendants) == 0 {
			return nil
		}
		return batch
	}
	descKeys, descendants := p.collectDescendantsLocked(target)
	delete(p.active, activeKey)
	var cancels []context.CancelFunc
	if cancel := target.detachKeepAlive(); cancel != nil {
		cancels = append(cancels, cancel)
	}
	tracked := make([]*PooledClient, 0, 1+len(descendants))
	p.trackClosingLocked(target)
	tracked = append(tracked, target)
	for i, k := range descKeys {
		delete(p.active, k)
		child := descendants[i]
		if cancel := child.detachKeepAlive(); cancel != nil {
			cancels = append(cancels, cancel)
		}
		p.trackClosingLocked(child)
		tracked = append(tracked, child)
	}
	p.mu.Unlock()

	return p.finalizeEvictionBatch(target, true, descendants, retiredDescendants, tracked, cancels)
}

func (p *connPool) resolveInterruptRootLocked(target *PooledClient, rootConn net.Conn) (*PooledClient, net.Conn) {
	root := target
	for root.parent != nil {
		root = root.parent
	}
	if rootConn == nil {
		rootConn = root.RootConn
	}
	if rootConn == nil {
		rootConn = target.RootConn
	}
	return root, rootConn
}

func (p *connPool) matchesInterruptedEntryLocked(
	entry, root, target *PooledClient,
	rootConn net.Conn,
	comparableRoot bool,
) bool {
	if entry == target || p.isDescendantLocked(entry, root) {
		return true
	}
	if target != root && p.isDescendantLocked(entry, target) {
		return true
	}
	return comparableRoot && entry.RootConn == rootConn
}

func (p *connPool) detachEntriesLocked(
	detachedRoot *PooledClient,
	descendants []*PooledClient,
	toDelete []HopDigest,
) ([]*PooledClient, []context.CancelFunc) {
	for _, k := range toDelete {
		delete(p.active, k)
	}
	var cancels []context.CancelFunc
	tracked := make([]*PooledClient, 0, len(toDelete))
	detachOne := func(c *PooledClient) {
		if c == nil {
			return
		}
		if cancel := c.detachKeepAlive(); cancel != nil {
			cancels = append(cancels, cancel)
		}
		p.trackClosingLocked(c)
		tracked = append(tracked, c)
	}
	detachOne(detachedRoot)
	for _, child := range descendants {
		detachOne(child)
	}
	return tracked, cancels
}

// detachActiveForInterrupt atomically detaches the outermost root hop of target
// and any active entries in p.active riding on that lineage or sharing rootConn
// before Client.Interrupt forcefully closes rootConn. Matching p.retired
// entries (and target/root themselves) still have their reverse MuxServer evict
// hooks triggered synchronously without mutating p.retired or p.closing.
func (p *connPool) detachActiveForInterrupt(target *PooledClient, rootConn net.Conn) *evictionBatch {
	if p == nil || target == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		target.triggerEvictHook()
		return nil
	}
	root, effectiveRootConn := p.resolveInterruptRootLocked(target, rootConn)
	comparableRoot := isComparableConn(effectiveRootConn)

	var (
		detachedRoot *PooledClient
		descendants  []*PooledClient
		toDelete     []HopDigest
	)
	if rootKey, ok := p.activeKeyLocked(ZeroHopDigest, root); ok {
		detachedRoot = root
		toDelete = append(toDelete, rootKey)
	}
	for k, entry := range p.active {
		if entry == nil || entry == detachedRoot {
			continue
		}
		if p.matchesInterruptedEntryLocked(entry, root, target, effectiveRootConn, comparableRoot) {
			toDelete = append(toDelete, k)
			descendants = append(descendants, entry)
		}
	}
	retiredMatches := p.collectRetiredForInterruptLocked(root, target, effectiveRootConn, comparableRoot)
	if detachedRoot == nil && len(descendants) == 0 {
		p.mu.Unlock()
		target.triggerEvictHook()
		if root != nil && root != target {
			root.triggerEvictHook()
		}
		batch := p.finalizeEvictionBatch(nil, false, nil, retiredMatches, nil, nil)
		if len(retiredMatches) == 0 {
			return nil
		}
		return batch
	}

	tracked, cancels := p.detachEntriesLocked(detachedRoot, descendants, toDelete)
	p.mu.Unlock()

	target.triggerEvictHook()
	if root != nil && root != target && root != detachedRoot {
		root.triggerEvictHook()
	}
	return p.finalizeEvictionBatch(detachedRoot, detachedRoot != nil, descendants, retiredMatches, tracked, cancels)
}

// Evict removes a dead client and any active downstream hops riding on its
// lineage, stops their keepalives, and closes evicted transports (closing dead
// FIRST when closeDead is true so a dead root hop's RootConn aborts before
// closing multiplexed child channels) without killing healthy upstream
// ancestors. Evicted clients remain tracked in p.closing until teardown
// completes so a concurrent connPool.Close() / Connector.CloseAll() always
// interrupts their RootConn.
func (p *connPool) Evict(key HopDigest, dead *PooledClient, closeDead bool) []*PooledClient {
	if dead == nil {
		return nil
	}
	batch := p.detachForEvict(key, dead, closeDead)
	if batch == nil {
		return nil
	}
	if closeDead {
		defer batch.release()
		_ = dead.closeSelf()
		batch.closeDescendants()
		return batch.descendants
	}
	// When closeDead is false, dead's transport has not been closed yet; never
	// block synchronously closing multiplexed child channels over an unclosed
	// parent transport. Detached entries remain tracked in p.closing for CloseAll.
	return batch.descendants
}

type reindexStep struct {
	client       *PooledClient
	oldKey       HopDigest
	newKey       HopDigest
	newParentKey HopDigest
	newCfg       *ClientConfig
}

func (p *connPool) buildReindexStepsLocked(
	target *PooledClient,
	oldKey, newKey HopDigest,
	nextCfg *ClientConfig,
) ([]reindexStep, bool) {
	steps := []reindexStep{{
		client:       target,
		oldKey:       oldKey,
		newKey:       newKey,
		newParentKey: target.parentKey,
		newCfg:       nextCfg,
	}}
	moving := map[*PooledClient]HopDigest{target: newKey}
	frontier := map[HopDigest]*PooledClient{oldKey: target}

	for len(frontier) > 0 {
		nextFrontier := make(map[HopDigest]*PooledClient)
		for k, child := range p.active {
			if child == nil || (child.parentKey.IsZero() && child.ControlSocketPath != "") {
				continue
			}
			if _, seen := moving[child]; seen {
				continue
			}
			parent, ok := frontier[child.parentKey]
			if !ok || !isConsistentParentChildTransport(parent, child) {
				continue
			}
			if child.publishedCfg == nil {
				return nil, false
			}
			parentNewKey := moving[parent]
			childNewKey := DigestClientConfig(child.publishedCfg, parentNewKey)
			if childNewKey.IsZero() {
				return nil, false
			}
			steps = append(steps, reindexStep{
				client:       child,
				oldKey:       k,
				newKey:       childNewKey,
				newParentKey: parentNewKey,
			})
			moving[child] = childNewKey
			nextFrontier[k] = child
		}
		frontier = nextFrontier
	}

	// Fail closed if any descendant riding on target was not reached via active parentKey links.
	for _, child := range p.active {
		if _, seen := moving[child]; !seen && p.isDescendantLocked(child, target) {
			return nil, false
		}
	}

	seenNew := make(map[HopDigest]struct{}, len(steps))
	for _, step := range steps {
		if _, dup := seenNew[step.newKey]; dup {
			return nil, false
		}
		seenNew[step.newKey] = struct{}{}
		if existing, occupied := p.active[step.newKey]; occupied {
			if _, isMoving := moving[existing]; !isMoving {
				return nil, false
			}
		}
	}
	return steps, true
}

// Reindex atomically applies mutate to a cloned copy of target.publishedCfg and
// moves target (along with any active in-memory descendants riding on target)
// from their current HopDigest keys to their recomputed Merkle keys under p.mu.
// If target is no longer active, any descendant lacks publishedCfg, or any
// target key collides with an unrelated active occupant, active membership and
// target.publishedCfg are left untouched in full sync with target.digest.
func (p *connPool) Reindex(target *PooledClient, mutate func(*ClientConfig)) bool {
	if p == nil || target == nil || mutate == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	oldKey := target.digest
	if cur, ok := p.active[oldKey]; !ok || cur != target || target.publishedCfg == nil {
		return false
	}
	nextCfg := NewClientConfig(*target.publishedCfg)
	mutate(nextCfg)
	nextCfg = NewClientConfig(*nextCfg)
	newKey := DigestClientConfig(nextCfg, target.parentKey)
	if newKey.IsZero() {
		return false
	}
	if newKey == oldKey {
		target.publishedCfg = nextCfg
		return true
	}
	steps, ok := p.buildReindexStepsLocked(target, oldKey, newKey, nextCfg)
	if !ok {
		return false
	}
	for _, step := range steps {
		delete(p.active, step.oldKey)
	}
	for _, step := range steps {
		if step.newCfg != nil {
			step.client.publishedCfg = step.newCfg
		}
		step.client.parentKey = step.newParentKey
		step.client.digest = step.newKey
		p.active[step.newKey] = step.client
	}
	return true
}

// EvictByClient atomically removes target (if currently active in the pool)
// and any active same-generation descendants, stops their keepalives, and
// closes target plus evicted descendants without tearing down healthy upstream
// ancestors.
func (p *connPool) EvictByClient(target *PooledClient) []*PooledClient {
	if target == nil {
		return nil
	}
	return p.Evict(ZeroHopDigest, target, true)
}

func (p *connPool) StopGlobalKeepAlives() {
	p.mu.Lock()
	clients := make([]*PooledClient, 0, len(p.active))
	for _, c := range p.active {
		clients = append(clients, c)
	}
	p.mu.Unlock()

	for _, c := range clients {
		c.stopGlobalKeepAlive()
	}
}

// Clear removes all active entries without interrupting their transports.
// Intended exclusively for synthetic unit tests with stub ssh.Client values.
func (p *connPool) Clear() {
	p.mu.Lock()
	var cancels []context.CancelFunc
	for _, c := range p.active {
		if cancel := c.detachKeepAlive(); cancel != nil {
			cancels = append(cancels, cancel)
		}
	}
	clear(p.active)
	p.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
}

// Close marks the pool closed, drains all active, retired, and in-flight
// closing clients, stops their keepalives, and returns them ordered from roots
// to descendants so root transports always abort before multiplexed children.
func (p *connPool) Close() []*PooledClient {
	p.mu.Lock()
	p.closed = true
	all := make([]*PooledClient, 0, len(p.active)+len(p.retired)+len(p.closing))
	seen := make(map[*PooledClient]struct{}, len(p.active)+len(p.retired)+len(p.closing))
	var cancels []context.CancelFunc
	collect := func(c *PooledClient) {
		if c == nil {
			return
		}
		if _, dup := seen[c]; dup {
			return
		}
		seen[c] = struct{}{}
		all = append(all, c)
		if cancel := c.detachKeepAlive(); cancel != nil {
			cancels = append(cancels, cancel)
		}
	}
	for _, c := range p.active {
		collect(c)
	}
	for _, c := range p.retired {
		collect(c)
	}
	for c := range p.closing {
		collect(c)
	}
	clear(p.active)
	p.retired = nil
	clear(p.closing)
	p.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	sortByParentDepth(all)
	return all
}

func checkInactivePoolClient(label string, client *PooledClient, activeSet map[*PooledClient]HopDigest) error {
	if client == nil {
		return nil
	}
	if key, stillActive := activeSet[client]; stillActive {
		return fmt.Errorf("pool invariant violated: %s client %p is also active at %s", label, client, key)
	}
	if active, _ := client.keepAliveState(); active {
		return fmt.Errorf("pool invariant violated: %s client %p still has an active keepalive", label, client)
	}
	return nil
}

// CheckInvariants verifies structural pool safety properties under p.mu:
//  1. Every active client has a live (unclosed) RootConn and consistent digest/publishedCfg.
//  2. Every active jump-chained client references a live active parent with matching RootConn.
//  3. No retired or closing client remains in active or retains an active keepalive.
//  4. When requireKeepAlive is true, every active client has an active keepalive.
func (p *connPool) CheckInvariants(requireKeepAlive bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	activeSet := make(map[*PooledClient]HopDigest, len(p.active))
	for key, client := range p.active {
		if err := p.checkActiveClientLocked(key, client, requireKeepAlive); err != nil {
			return err
		}
		activeSet[client] = key
	}

	for _, r := range p.retired {
		if err := checkInactivePoolClient("retired", r, activeSet); err != nil {
			return err
		}
	}
	for c := range p.closing {
		if err := checkInactivePoolClient("closing", c, activeSet); err != nil {
			return err
		}
	}
	return nil
}

func (p *connPool) checkActiveClientLocked(key HopDigest, client *PooledClient, requireKeepAlive bool) error {
	if client == nil {
		return fmt.Errorf("pool invariant violated: nil client at key %s", key)
	}
	if client.digest != key {
		return fmt.Errorf("pool invariant violated: active client %p digest %s != map key %s", client, client.digest, key)
	}
	if isRootConnClosed(client.RootConn) {
		return fmt.Errorf("pool invariant violated: active client %s has closed RootConn", key)
	}
	if client.publishedCfg != nil {
		if wantKey := DigestClientConfig(client.publishedCfg, client.parentKey); wantKey != key {
			return fmt.Errorf("pool invariant violated: active client %p DigestClientConfig(publishedCfg, parentKey) %s != map key %s", client, wantKey, key)
		}
	}
	if !client.parentKey.IsZero() {
		if client.ControlSocketPath == "" {
			parent, ok := p.active[client.parentKey]
			if !ok || parent == nil {
				return fmt.Errorf("pool invariant violated: active child %s missing active parent %s", key, client.parentKey)
			}
			if client.parent != parent || !isConsistentParentChildTransport(parent, client) {
				return fmt.Errorf("pool invariant violated: active child %s has stale parent generation (parent=%p child.parent=%p)", key, parent, client.parent)
			}
		} else if client.parent != nil {
			parent, ok := p.active[client.parentKey]
			if !ok || parent != client.parent {
				return fmt.Errorf("pool invariant violated: active mux child %s has stale parent pointer %p", key, client.parent)
			}
		}
	}
	if requireKeepAlive && client.SSHClient != nil && client.SSHClient.Conn != nil {
		if active, _ := client.keepAliveState(); !active {
			return fmt.Errorf("pool invariant violated: active client %s missing live keepalive", key)
		}
	}
	return nil
}
