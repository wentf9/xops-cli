package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
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
	// Lock ordering: PooledClient.probeMu -> connPool.mu -> Connector.kaMu -> PooledClient.kaMu.
	kaMu         sync.Mutex
	kaCancel     context.CancelFunc
	kaDone       <-chan struct{}
	kaNodeScoped bool
}

func (c *PooledClient) updateSnapshot(fn func(*ConnectionConfig, *ClientConfig)) {
	if c == nil || fn == nil {
		return
	}
	c.probeMu.Lock()
	defer c.probeMu.Unlock()
	if !c.hasSnapshot && c.publishedCfg == nil {
		return
	}
	var snapPtr *ConnectionConfig
	if c.hasSnapshot {
		snapPtr = &c.Snapshot
	}
	fn(snapPtr, c.publishedCfg)
	if c.publishedCfg != nil && c.pool != nil {
		newKey := DigestClientConfig(c.publishedCfg, c.parentKey)
		c.pool.Reindex(c, newKey)
	}
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

// closeSelf closes this hop's own SSH client and hop connection without tearing
// down a shared upstream bastion's RootConn that other sessions may still use.
func (c *PooledClient) closeSelf() error {
	if c == nil {
		return nil
	}
	c.stopKeepAlive()
	var sshClient *ssh.Client
	if c.SSHClient != nil && c.SSHClient.Conn != nil {
		sshClient = c.SSHClient
	}
	ownConn := c.hopConn
	if ownConn == nil && c.parentKey.IsZero() && c.parent == nil {
		ownConn = c.RootConn
	}
	return interruptSSHTransport(ownConn, sshClient)
}

func (c *PooledClient) startKeepAlive(
	parentCtx context.Context,
	interval, timeout time.Duration,
	nodeScoped bool,
	onDead func(error),
	wg *sync.WaitGroup,
) {
	if c == nil || c.SSHClient == nil || parentCtx == nil || parentCtx.Err() != nil || interval <= 0 {
		return
	}
	c.kaMu.Lock()
	defer c.kaMu.Unlock()
	if c.kaCancel != nil {
		return
	}
	nodeCtx, cancel := context.WithCancel(parentCtx)
	c.kaCancel = cancel
	c.kaNodeScoped = nodeScoped
	done := startKeepAlive(nodeCtx, c.SSHClient, interval, timeout, onDead, c.interrupt)
	c.kaDone = done
	if wg != nil {
		wg.Add(1)
		go func() {
			<-done
			wg.Done()
		}()
	}
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

// connPool stores live and retired PooledClients keyed solely by Merkle HopDigest.
// All membership transitions (Publish CAS, Retire, Evict, Close) execute under a
// single mutex so displaced clients are never leaked and stale parent generations
// can never publish into the pool.
type connPool struct {
	mu      sync.Mutex
	closed  bool
	active  map[HopDigest]*PooledClient
	retired []*PooledClient
}

func newConnPool() *connPool {
	return &connPool{
		active: make(map[HopDigest]*PooledClient),
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
	if expectParent != nil || !next.parentKey.IsZero() {
		parentKey := next.parentKey
		if parentKey.IsZero() || expectParent == nil {
			p.mu.Unlock()
			_ = next.closeSelf()
			return nil, errStaleParentGeneration
		}
		curParent, ok := p.active[parentKey]
		if !ok || !isSameParentGeneration(curParent, expectParent) {
			p.mu.Unlock()
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
		// Collect keys in a read-only pass first so map iteration order cannot
		// sever parentKey links before grandchildren are visited.
		descKeys, descClients := p.collectDescendantsLocked(key, displaced)
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

func (p *connPool) isLineageDescendantLocked(candidateKey HopDigest, candidate *PooledClient, ancestorKey HopDigest, ancestor *PooledClient) bool {
	if candidate == nil || candidateKey == ancestorKey || candidate == ancestor {
		return false
	}
	for cur := candidate.parent; cur != nil; cur = cur.parent {
		if cur == ancestor {
			return true
		}
	}
	curKey := candidate.parentKey
	for steps := 0; !curKey.IsZero() && steps < len(p.active); steps++ {
		if curKey == ancestorKey {
			return true
		}
		parent, ok := p.active[curKey]
		if !ok || parent == nil {
			break
		}
		if parent == ancestor {
			return true
		}
		curKey = parent.parentKey
	}
	return false
}

func (p *connPool) isDescendantLocked(candidateKey HopDigest, candidate *PooledClient, ancestorKey HopDigest, ancestor *PooledClient) bool {
	if !p.isLineageDescendantLocked(candidateKey, candidate, ancestorKey, ancestor) {
		return false
	}
	if ancestor.RootConn != nil {
		// Match strictly by transport generation so fresher generations sharing
		// the same parentKey are preserved.
		return candidate.RootConn == ancestor.RootConn
	}
	return true
}

func (p *connPool) collectDescendantsLocked(ancestorKey HopDigest, ancestor *PooledClient) ([]HopDigest, []*PooledClient) {
	var keys []HopDigest
	var clients []*PooledClient
	for k, child := range p.active {
		if p.isDescendantLocked(k, child, ancestorKey, ancestor) {
			keys = append(keys, k)
			clients = append(clients, child)
		}
	}
	return keys, clients
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
// sharing its generation) from active, stops their keepalives, and tracks them
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
	effectiveKey := key
	if isActive {
		effectiveKey = activeKey
	} else if effectiveKey.IsZero() {
		effectiveKey = displaced.digest
	}
	descKeys, descClients := p.collectDescendantsLocked(effectiveKey, displaced)
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

// Evict removes a dead client and any active downstream hops sharing its
// transport generation, stops their keepalives, and closes evicted downstream
// hop transports (plus dead itself when closeDead is true) without killing
// healthy upstream ancestors.
func (p *connPool) Evict(key HopDigest, dead *PooledClient, closeDead bool) []*PooledClient {
	if dead == nil {
		return nil
	}
	p.mu.Lock()
	var descKeys []HopDigest
	var descendants []*PooledClient
	activeKey, removedSelf := p.activeKeyLocked(key, dead)
	effectiveKey := key
	if removedSelf {
		effectiveKey = activeKey
	} else if effectiveKey.IsZero() {
		effectiveKey = dead.digest
	}
	if removedSelf || dead.RootConn != nil {
		descKeys, descendants = p.collectDescendantsLocked(effectiveKey, dead)
	}
	if removedSelf {
		delete(p.active, activeKey)
	}
	var cancels []context.CancelFunc
	if removedSelf || closeDead {
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
	p.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	if closeDead {
		_ = dead.closeSelf()
	}
	for _, child := range descendants {
		_ = child.closeSelf()
	}
	return descendants
}

// Reindex atomically moves an active pooled entry from its current HopDigest
// key to newKey when caller-side post-connect confirmation updates committed
// metadata (such as Execution or AuthUpdateToken) without replacing the
// underlying transport. If target is no longer active, another entry already
// occupies newKey, or active descendants depend on target's current parent key,
// active membership is left untouched.
func (p *connPool) Reindex(target *PooledClient, newKey HopDigest) {
	if p == nil || target == nil || newKey.IsZero() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	oldKey := target.digest
	if cur, ok := p.active[oldKey]; !ok || cur != target {
		return
	}
	if newKey == oldKey {
		return
	}
	if existing, occupied := p.active[newKey]; occupied && existing != target {
		return
	}
	if descKeys, _ := p.collectDescendantsLocked(oldKey, target); len(descKeys) > 0 {
		return
	}
	delete(p.active, oldKey)
	target.digest = newKey
	p.active[newKey] = target
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

// Close marks the pool closed, drains all active and retired clients, stops
// their keepalives, and returns them for transport shutdown.
func (p *connPool) Close() []*PooledClient {
	p.mu.Lock()
	p.closed = true
	all := make([]*PooledClient, 0, len(p.active)+len(p.retired))
	var cancels []context.CancelFunc
	for _, c := range p.active {
		all = append(all, c)
		if cancel := c.detachKeepAlive(); cancel != nil {
			cancels = append(cancels, cancel)
		}
	}
	for _, c := range p.retired {
		all = append(all, c)
		if cancel := c.detachKeepAlive(); cancel != nil {
			cancels = append(cancels, cancel)
		}
	}
	clear(p.active)
	p.retired = nil
	p.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	return all
}

// CheckInvariants verifies structural pool safety properties under p.mu:
//  1. Every active jump-chained client references a live active parent with matching RootConn.
//  2. No retired client remains in active or retains an active keepalive.
//  3. When requireKeepAlive is true, every active client has an active keepalive.
func (p *connPool) CheckInvariants(requireKeepAlive bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	activeSet := make(map[*PooledClient]HopDigest, len(p.active))
	for key, client := range p.active {
		if client == nil {
			return fmt.Errorf("pool invariant violated: nil client at key %s", key)
		}
		if client.digest != key {
			return fmt.Errorf("pool invariant violated: active client %p digest %s != map key %s", client, client.digest, key)
		}
		activeSet[client] = key
		if !client.parentKey.IsZero() && client.ControlSocketPath == "" {
			parent, ok := p.active[client.parentKey]
			if !ok || parent == nil {
				return fmt.Errorf("pool invariant violated: active child %s missing active parent %s", key, client.parentKey)
			}
			if !isConsistentParentChildTransport(parent, client) {
				return fmt.Errorf("pool invariant violated: active child %s has stale parent generation (parent=%p child.parent=%p)", key, parent, client.parent)
			}
		}
		if requireKeepAlive && client.SSHClient != nil {
			if active, _ := client.keepAliveState(); !active {
				return fmt.Errorf("pool invariant violated: active client %s missing live keepalive", key)
			}
		}
	}

	for _, r := range p.retired {
		if r == nil {
			continue
		}
		if key, stillActive := activeSet[r]; stillActive {
			return fmt.Errorf("pool invariant violated: retired client %p is also active at %s", r, key)
		}
		if active, _ := r.keepAliveState(); active {
			return fmt.Errorf("pool invariant violated: retired client %p still has an active keepalive", r)
		}
	}
	return nil
}
