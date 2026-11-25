package pool

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/ports"
)

// simClock 是纯内存确定性虚拟时钟桩，用于零 time.Sleep 验证 90ms 有界拆断、保活与空闲过期。
type simClock struct {
	mu           sync.Mutex
	now          time.Time
	timers       []*simTimer
	createdCount int
	armedCount   int
	createdCh    chan struct{}
}

type simTimer struct {
	clk    *simClock
	ch     chan time.Time
	fireAt time.Time
	active bool
}

func newSimClock() *simClock {
	return &simClock{
		now:       time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC),
		createdCh: make(chan struct{}, 64),
	}
}

func (c *simClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *simClock) Since(t time.Time) time.Duration { return c.Now().Sub(t) }

func (c *simClock) NewTimer(d time.Duration) ports.Timer {
	c.mu.Lock()
	tm := &simTimer{clk: c, ch: make(chan time.Time, 1), fireAt: c.now.Add(d), active: true}
	if d <= 0 {
		tm.active = false
		tm.ch <- c.now
	}
	c.timers = append(c.timers, tm)
	c.createdCount++
	c.armedCount++
	c.mu.Unlock()
	select {
	case c.createdCh <- struct{}{}:
	default:
	}
	return tm
}

func (c *simClock) Sleep(ctx context.Context, d time.Duration) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tm := c.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C():
		return nil
	}
}

func (c *simClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, tm := range c.timers {
		if tm.active && !c.now.Before(tm.fireAt) {
			tm.active = false
			select {
			case tm.ch <- c.now:
			default:
			}
		}
	}
}

func (c *simClock) WaitTimerCreated(t *testing.T, target int) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		c.mu.Lock()
		n := c.createdCount
		c.mu.Unlock()
		if n >= target {
			return
		}
		select {
		case <-c.createdCh:
		case <-deadline:
			t.Fatalf("等待虚拟时钟注册第 %d 个定时器超时（当前=%d）", target, n)
		}
	}
}

func (c *simClock) WaitTimerArmed(t *testing.T, target int) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		c.mu.Lock()
		n := c.armedCount
		c.mu.Unlock()
		if n >= target {
			return
		}
		select {
		case <-c.createdCh:
		case <-deadline:
			t.Fatalf("等待虚拟时钟第 %d 次装弹定时器超时（当前=%d）", target, n)
		}
	}
}

func (t *simTimer) C() <-chan time.Time { return t.ch }
func (t *simTimer) Stop() bool {
	t.clk.mu.Lock()
	defer t.clk.mu.Unlock()
	was := t.active
	t.active = false
	return was
}
func (t *simTimer) Reset(d time.Duration) bool {
	t.clk.mu.Lock()
	was := t.active
	select {
	case <-t.ch:
	default:
	}
	t.fireAt = t.clk.now.Add(d)
	if d <= 0 {
		t.active = false
		t.ch <- t.clk.now
	} else {
		t.active = true
	}
	t.clk.armedCount++
	t.clk.mu.Unlock()
	select {
	case t.clk.createdCh <- struct{}{}:
	default:
	}
	return was
}

// seqEntropy 为并发安全确定性熵源，驱动池级 TraceID 与 SlotMap HandleID 生成。
type seqEntropy struct {
	mu   sync.Mutex
	next byte
}

func newSeqEntropy(seed byte) *seqEntropy {
	if seed == 0 {
		seed = 1
	}
	return &seqEntropy{next: seed}
}

func (e *seqEntropy) Read(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range p {
		e.next++
		if e.next == 0 {
			e.next = 1
		}
		p[i] = e.next
	}
	return len(p), nil
}

type mockSession struct {
	closed atomic.Bool
}

func (s *mockSession) StdinPipe() (io.WriteCloser, error) { return nil, ports.ErrUnsupported }
func (s *mockSession) StdoutPipe() (io.Reader, error)     { return nil, ports.ErrUnsupported }
func (s *mockSession) StderrPipe() (io.Reader, error)     { return nil, ports.ErrUnsupported }
func (s *mockSession) Start(context.Context, execution.CommandPlan, ports.ExecStreams) error {
	return nil
}
func (s *mockSession) StartShell(context.Context, ports.ExecStreams) error {
	return nil
}
func (s *mockSession) ResizePTY(context.Context, ports.TerminalSize) error { return nil }
func (s *mockSession) Signal(context.Context, string) error                { return nil }
func (s *mockSession) Wait(context.Context) (execution.ExecutionOutcome, error) {
	return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
}
func (s *mockSession) Close() error {
	s.closed.Store(true)
	return nil
}

type mockConn struct {
	digest       plan.HopDigest
	endpoint     netaddr.Endpoint
	alive        atomic.Bool
	closeCount   atomic.Int32
	sessionCount atomic.Int64
	kaCount      atomic.Int32
	closeHook    func() error
	kaHook       func(ctx context.Context) error
	closedCh     chan struct{}
	closeOnce    sync.Once
}

func newMockConn(digest plan.HopDigest, ep netaddr.Endpoint) *mockConn {
	c := &mockConn{digest: digest, endpoint: ep, closedCh: make(chan struct{})}
	c.alive.Store(true)
	return c
}

func (c *mockConn) HopDigest() plan.HopDigest  { return c.digest }
func (c *mockConn) Endpoint() netaddr.Endpoint { return c.endpoint }
func (c *mockConn) IsAlive() bool              { return c.alive.Load() }
func (c *mockConn) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	c.sessionCount.Add(1)
	return &mockSession{}, nil
}
func (c *mockConn) DialTCP(ctx context.Context, _ netaddr.HostPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}
func (c *mockConn) ListenTCP(ctx context.Context, _ string) (net.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	return nil, ports.ErrUnsupported
}
func (c *mockConn) DialStreamLocal(ctx context.Context, p pathalg.RemotePath) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	if !p.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}
func (c *mockConn) ListenStreamLocal(ctx context.Context, p pathalg.RemotePath) (net.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	if !p.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	return nil, ports.ErrUnsupported
}
func (c *mockConn) OpenTUN(ctx context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	if !spec.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}
func (c *mockConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	return nil, ports.ErrUnsupported
}
func (c *mockConn) SendKeepalive(ctx context.Context) error {
	c.kaCount.Add(1)
	if c.kaHook != nil {
		return c.kaHook(ctx)
	}
	if !c.alive.Load() {
		return ports.ErrClosed
	}
	return ctx.Err()
}
func (c *mockConn) Close() error {
	c.closeCount.Add(1)
	c.alive.Store(false)
	var err error
	if c.closeHook != nil {
		err = c.closeHook()
	}
	c.closeOnce.Do(func() { close(c.closedCh) })
	return err
}

type mockDialer struct {
	mu                  sync.Mutex
	dialCount           atomic.Int64
	sawLeaseScopeInDial atomic.Bool
	conns               []*mockConn
	hook                func(ctx context.Context, hop plan.HopSpec, digest plan.HopDigest, parent ports.TransportConn) (ports.TransportConn, error)
}

func (d *mockDialer) DialHop(ctx context.Context, hop plan.HopSpec, digest plan.HopDigest, parent ports.TransportConn) (ports.TransportConn, error) {
	d.dialCount.Add(1)
	if trace.InLeaseScope(ctx) {
		d.sawLeaseScopeInDial.Store(true)
	}
	if d.hook != nil {
		conn, err := d.hook(ctx, hop, digest, parent)
		if mc, ok := conn.(*mockConn); ok && mc != nil {
			d.mu.Lock()
			d.conns = append(d.conns, mc)
			d.mu.Unlock()
		}
		return conn, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mc := newMockConn(digest, hop.Endpoint())
	d.mu.Lock()
	d.conns = append(d.conns, mc)
	d.mu.Unlock()
	return mc, nil
}

func (d *mockDialer) lastConn() *mockConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.conns) == 0 {
		return nil
	}
	return d.conns[len(d.conns)-1]
}

type mockManagedRes struct {
	label      string
	invalid    atomic.Bool
	closeCount atomic.Int32
	closeHook  func() error
}

func (r *mockManagedRes) IsValid() bool {
	return r != nil && !r.invalid.Load()
}

func (r *mockManagedRes) Close() error {
	r.closeCount.Add(1)
	r.invalid.Store(true)
	if r.closeHook != nil {
		return r.closeHook()
	}
	return nil
}

// mockValueRes 为可比较的值类型托管资源桩，用于验证零值与非零无效结构体的失败关闭拦截。
type mockValueRes struct {
	label string
	valid bool
}

func (r mockValueRes) IsValid() bool { return r.valid }
func (r mockValueRes) Close() error  { return nil }

func mustHop(t *testing.T, idx uint32, nodeID, host string, port uint16, keepalive time.Duration, kaMax uint32) plan.HopSpec {
	t.Helper()
	var optMax algebraic.Option[uint32]
	if kaMax > 0 {
		optMax = algebraic.Some(kaMax)
	}
	return mustHopWithCountMax(t, idx, nodeID, host, port, keepalive, optMax)
}

func mustHopWithCountMax(t *testing.T, idx uint32, nodeID, host string, port uint16, keepalive time.Duration, kaMax algebraic.Option[uint32]) plan.HopSpec {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost(host)
	requireNoErr(t, err, "ParseCanonicalHost")
	ep, err := netaddr.NewEndpoint(ch, port)
	requireNoErr(t, err, "NewEndpoint")
	user, err := option.ParseUsername("ops")
	requireNoErr(t, err, "ParseUsername")
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	requireNoErr(t, err, "NewAuthAgent")

	t1 := option.UnsetOptionLayer()
	if keepalive > 0 {
		t1 = t1.WithServerAliveInterval(algebraic.FromStdDuration(keepalive))
	}
	if maxVal, ok := kaMax.Get(); ok {
		t1 = t1.WithServerAliveCountMax(maxVal)
	}
	unset := option.UnsetOptionLayer()
	eff, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, t1, unset, unset, unset)
	requireNoErr(t, err, "ResolveEffectivePolicy")
	hop, err := plan.NewHopSpecFromAuth(idx, nodeID, user, auth, eff)
	requireNoErr(t, err, "NewHopSpecFromAuth")
	return hop
}

func mustPlan(t *testing.T, hops ...plan.HopSpec) plan.SealedConnectionPlan {
	t.Helper()
	pl, err := plan.SealConnectionPlan(hops...)
	requireNoErr(t, err, "SealConnectionPlan")
	return pl
}

func mustBindingForPlan(t *testing.T, pd plan.PlanDigest, tool, action string) security.OperationBinding {
	t.Helper()
	b, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute,
		Tool:       tool,
		Action:     action,
		NodeID:     "node-a",
		PlanDigest: algebraic.Some(pd.SecurityDigest()),
	})
	requireNoErr(t, err, "NewOperationBinding")
	return b
}

func newTestPool(t *testing.T, cfg PoolConfig) (*Pool, *mockDialer, *simClock) {
	t.Helper()
	var dialer *mockDialer
	if cfg.Dialer == nil {
		dialer = &mockDialer{}
		cfg.Dialer = dialer
	} else if md, ok := cfg.Dialer.(*mockDialer); ok {
		dialer = md
	}
	var clk *simClock
	if cfg.Clock == nil {
		clk = newSimClock()
		cfg.Clock = clk
	} else if sc, ok := cfg.Clock.(*simClock); ok {
		clk = sc
	}
	if cfg.Entropy == nil {
		cfg.Entropy = newSeqEntropy(11)
	}
	p, err := NewPool(context.Background(), cfg)
	requireNoErr(t, err, "NewPool")
	return p, dialer, clk
}

func requireNoErr(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s 返回非预期错误: %v", label, err)
	}
}

func requireErrIs(t *testing.T, err, target error, label string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s 期望错误匹配 %v，实际=%v", label, target, err)
	}
}

func requireTrue(t *testing.T, cond bool, msg string) {
	t.Helper()
	if !cond {
		t.Fatal(msg)
	}
}

func TestPoolConfigValidation(t *testing.T) {
	defer goleak.VerifyNone(t)
	clk := newSimClock()
	ent := newSeqEntropy(1)
	dial := &mockDialer{}

	var nilCtx context.Context
	_, err := NewPool(nilCtx, PoolConfig{Dialer: dial, Clock: clk, Entropy: ent})
	requireErrIs(t, err, ErrNilContext, "NewPool(nil ctx)")

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = NewPool(canceled, PoolConfig{Dialer: dial, Clock: clk, Entropy: ent})
	requireErrIs(t, err, context.Canceled, "NewPool(canceled ctx)")

	_, err = NewPool(context.Background(), PoolConfig{Clock: clk, Entropy: ent})
	requireErrIs(t, err, ErrInvalidPoolConfig, "missing Dialer")
	_, err = NewPool(context.Background(), PoolConfig{Dialer: dial, Entropy: ent})
	requireErrIs(t, err, ErrInvalidPoolConfig, "missing Clock")
	_, err = NewPool(context.Background(), PoolConfig{Dialer: dial, Clock: clk})
	requireErrIs(t, err, ErrInvalidPoolConfig, "missing Entropy")
	_, err = NewPool(context.Background(), PoolConfig{Dialer: dial, Clock: clk, Entropy: ent, MaxConns: -1})
	requireErrIs(t, err, ErrInvalidPoolConfig, "negative MaxConns")
	_, err = NewPool(context.Background(), PoolConfig{Dialer: dial, Clock: clk, Entropy: ent, TeardownGrace: -time.Millisecond})
	requireErrIs(t, err, ErrInvalidPoolConfig, "negative TeardownGrace")
	_, err = NewPool(context.Background(), PoolConfig{Dialer: dial, Clock: clk, Entropy: ent, Domain: "bad domain"})
	requireErrIs(t, err, ErrInvalidPoolConfig, "invalid domain")

	closedBus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 4})
	requireNoErr(t, err, "NewSystemBus")
	closedBus.Close()
	_, err = NewPool(context.Background(), PoolConfig{Dialer: dial, Clock: clk, Entropy: ent, Bus: closedBus})
	requireErrIs(t, err, ErrInvalidPoolConfig, "closed SystemBus")
}

func TestWithLeaseMultiHopPrefixSharingAndScopeIsolation(t *testing.T) {
	defer goleak.VerifyNone(t)
	p, dialer, _ := newTestPool(t, PoolConfig{Domain: "ssh-pool"})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	hop0 := mustHop(t, 0, "bastion", "198.51.100.1", 22, 0, 0)
	hop1A := mustHop(t, 1, "app-a", "198.51.100.10", 22, 0, 0)
	hop1B := mustHop(t, 1, "app-b", "198.51.100.11", 22, 0, 0)
	planA := mustPlan(t, hop0, hop1A)
	planB := mustPlan(t, hop0, hop1B)

	ctx := context.Background()
	err := p.WithLease(ctx, planA, func(scopedCtx context.Context, lease *Lease) error {
		requireTrue(t, trace.InLeaseScope(scopedCtx), "用户回调内必须已注入 trace.LeaseScope")
		sc, ok := trace.LeaseScopeFromContext(scopedCtx)
		requireTrue(t, ok && sc.Domain() == "ssh-pool" && sc.LeaseID() == lease.LeaseID(), "LeaseScope 标签与 LeaseID 须一致")
		requireTrue(t, lease.IsValid() && lease.IsAlive() && lease.PlanDigest().Equal(planA.PlanDigest()), "lease 元信息不匹配")
		sess, sErr := lease.OpenSession(scopedCtx)
		requireNoErr(t, sErr, "OpenSession(planA)")
		return sess.Close()
	})
	requireNoErr(t, err, "WithLease(planA#1)")
	requireTrue(t, !dialer.sawLeaseScopeInDial.Load(), "多跳拨号期间绝不能注入 trace.LeaseScope")
	requireTrue(t, dialer.dialCount.Load() == 2, "planA 首次拨号应触发 2 跳 DialHop")

	// planB 共享 bastion 前缀：仅应额外拨号 hop1B（总拨号数变为 3，而非 4）。
	err = p.WithLease(ctx, planB, func(scopedCtx context.Context, lease *Lease) error {
		requireTrue(t, lease.Endpoint().Equal(hop1B.Endpoint()), "planB 端点不匹配")
		return nil
	})
	requireNoErr(t, err, "WithLease(planB#1)")
	requireTrue(t, dialer.dialCount.Load() == 3, "planB 应复用公共 bastion 仅增加 1 次拨号")

	// 再次访问 planA 应走整链快路径命中缓存（0 新增拨号）。
	err = p.WithLease(ctx, planA, func(scopedCtx context.Context, lease *Lease) error {
		requireTrue(t, lease.IsAlive(), "缓存命中 lease 必须存活")
		return nil
	})
	requireNoErr(t, err, "WithLease(planA#2)")
	requireTrue(t, dialer.dialCount.Load() == 3, "planA 二次申请必须命中缓存")
	requireTrue(t, p.Stats().ActiveLeases == 0 && p.Stats().ActiveConns == 3, "租约归还后 ActiveLeases 必须归零")
}

func TestWithLeaseReentrantBlockedSameAndCrossPool(t *testing.T) {
	defer goleak.VerifyNone(t)
	p1, _, _ := newTestPool(t, PoolConfig{Domain: "pool-alpha"})
	defer func() { requireNoErr(t, p1.Close(), "p1.Close") }()
	p2, _, _ := newTestPool(t, PoolConfig{Domain: "pool-beta"})
	defer func() { requireNoErr(t, p2.Close(), "p2.Close") }()

	pl1 := mustPlan(t, mustHop(t, 0, "n1", "198.51.100.21", 22, 0, 0))
	pl2 := mustPlan(t, mustHop(t, 0, "n2", "198.51.100.22", 22, 0, 0))

	err := p1.WithLease(context.Background(), pl1, func(scopedCtx context.Context, _ *Lease) error {
		// 同池重入必须失败关闭返回 trace.ErrReentrantLease。
		sameErr := p1.WithLease(scopedCtx, pl2, func(context.Context, *Lease) error { return nil })
		requireErrIs(t, sameErr, trace.ErrReentrantLease, "同池嵌套 WithLease")
		// 跨池不同 domain 重入同样必须失败关闭返回 trace.ErrReentrantLease。
		crossErr := p2.WithLease(scopedCtx, pl2, func(context.Context, *Lease) error { return nil })
		requireErrIs(t, crossErr, trace.ErrReentrantLease, "跨池嵌套 WithLease")
		// 嵌套 WithMultiLease 同样必须失败关闭返回 trace.ErrReentrantLease。
		multiErr := p1.WithMultiLease(scopedCtx, []plan.SealedConnectionPlan{pl1, pl2}, func(context.Context, []*Lease) error { return nil })
		requireErrIs(t, multiErr, trace.ErrReentrantLease, "嵌套 WithMultiLease")
		return nil
	})
	requireNoErr(t, err, "外层 WithLease")
}

func TestLeaseRuntimeInvalidationSentinelAndABASafeRetire(t *testing.T) {
	defer goleak.VerifyNone(t)
	p, dialer, _ := newTestPool(t, PoolConfig{})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	pl := mustPlan(t, mustHop(t, 0, "edge", "198.51.100.30", 22, 0, 0))
	hopDig, _ := pl.HopDigestAt(0)
	ctx := context.Background()

	// 先建立连接并获取实例进行白盒运行时哨兵测试（避免在 WithLease 回调内逃逸触犯 linearlease）。
	inst1, err := p.acquirePlan(ctx, pl)
	requireNoErr(t, err, "acquirePlan#1")
	l1 := newLease(p, inst1, pl.PlanDigest(), "lease-sentinel")
	requireTrue(t, l1.IsValid() && l1.IsAlive() && l1.Epoch() == inst1.epoch, "有效租约断言")
	sess, err := l1.OpenSession(ctx)
	requireNoErr(t, err, "OpenSession(active)")
	requireNoErr(t, sess.Close(), "sess.Close")
	conn, err := l1.DialTCP(ctx, mustHostPort(t, "127.0.0.1", 8080))
	requireNoErr(t, err, "DialTCP(active)")
	requireNoErr(t, conn.Close(), "conn.Close")
	_, err = l1.ListenTCP(ctx, "127.0.0.1:0")
	requireErrIs(t, err, ports.ErrUnsupported, "ListenTCP 透传")
	rp, err := pathalg.ParseRemotePath("/run/test.sock")
	requireNoErr(t, err, "ParseRemotePath")
	slConn, err := l1.DialStreamLocal(ctx, rp)
	requireNoErr(t, err, "DialStreamLocal(active)")
	requireNoErr(t, slConn.Close(), "slConn.Close")
	_, err = l1.ListenStreamLocal(ctx, rp)
	requireErrIs(t, err, ports.ErrUnsupported, "ListenStreamLocal 透传")
	tunSpec, err := ports.NewTUNSpec(ports.TUNModePointToPoint, 0, 0)
	requireNoErr(t, err, "NewTUNSpec")
	tunCh, err := l1.OpenTUN(ctx, tunSpec)
	requireNoErr(t, err, "OpenTUN(active)")
	requireNoErr(t, tunCh.Close(), "tunCh.Close")
	_, err = l1.OpenRemoteFS(ctx)
	requireErrIs(t, err, ports.ErrUnsupported, "OpenRemoteFS 透传")

	// 使借用哨兵失效：所有数据面操作必须无锁返回 ErrLeaseExpired。
	l1.invalidate()
	requireTrue(t, !l1.IsValid() && l1.IsZero() && !l1.IsAlive(), "失效后 IsValid/IsAlive 必须为 false")
	requireTrue(t, l1.Epoch() == 0 && l1.LeaseID() == "" && l1.PlanDigest().IsZero() && l1.HopDigest().IsZero() && l1.Endpoint().IsZero(), "失效后访问器须返回零值")
	_, err = l1.OpenSession(ctx)
	requireErrIs(t, err, ErrLeaseExpired, "失效后 OpenSession")
	_, err = l1.DialTCP(ctx, mustHostPort(t, "127.0.0.1", 8080))
	requireErrIs(t, err, ErrLeaseExpired, "失效后 DialTCP")
	_, err = l1.ListenTCP(ctx, "127.0.0.1:0")
	requireErrIs(t, err, ErrLeaseExpired, "失效后 ListenTCP")
	_, err = l1.DialStreamLocal(ctx, rp)
	requireErrIs(t, err, ErrLeaseExpired, "失效后 DialStreamLocal")
	_, err = l1.ListenStreamLocal(ctx, rp)
	requireErrIs(t, err, ErrLeaseExpired, "失效后 ListenStreamLocal")
	_, err = l1.OpenTUN(ctx, tunSpec)
	requireErrIs(t, err, ErrLeaseExpired, "失效后 OpenTUN")
	_, err = l1.OpenRemoteFS(ctx)
	requireErrIs(t, err, ErrLeaseExpired, "失效后 OpenRemoteFS")
	p.releaseHopLease(inst1)

	// 验证 Lease.Retire 的世代防 ABA 保护：先退役 inst1 并重建 inst2，再对旧 l1 调用 Retire 绝不误杀 inst2。
	requireNoErr(t, p.RetireHop(hopDig), "RetireHop(inst1)")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns")
	var ep2 uint64
	err = p.WithLease(ctx, pl, func(_ context.Context, l2 *Lease) error {
		ep2 = l2.Epoch()
		return nil
	})
	requireNoErr(t, err, "WithLease(gen2)")
	requireTrue(t, ep2 > inst1.epoch && dialer.dialCount.Load() == 2, "重建后世代号必须单调递增")

	l1.Retire() // 指向旧代 inst1，必须被 Actor 忽略
	err = p.WithLease(ctx, pl, func(_ context.Context, l3 *Lease) error {
		requireTrue(t, l3.Epoch() == ep2, "旧代 Lease.Retire 不得误杀新代连接")
		return nil
	})
	requireNoErr(t, err, "WithLease(verify gen2 intact)")
}

func mustHostPort(t *testing.T, host string, port uint16) netaddr.HostPort {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost(host)
	requireNoErr(t, err, "ParseCanonicalHost")
	hp, err := netaddr.NewHostPort(ch, port)
	requireNoErr(t, err, "NewHostPort")
	return hp
}

func TestDeadAncestorAutoReplacementAndInvalidConnRejected(t *testing.T) {
	defer goleak.VerifyNone(t)
	dialer := &mockDialer{}
	p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	hop0 := mustHop(t, 0, "bastion", "198.51.100.40", 22, 0, 0)
	hop1 := mustHop(t, 1, "app", "198.51.100.41", 22, 0, 0)
	pl := mustPlan(t, hop0, hop1)
	ctx := context.Background()

	requireNoErr(t, p.WithLease(ctx, pl, func(context.Context, *Lease) error { return nil }), "initial dial")
	requireTrue(t, dialer.dialCount.Load() == 2, "初始应拨 2 跳")

	// 模拟中间跳板底层连接意外死亡：下次整链申请必须自动感知、级联退役并重新拨号。
	dialer.mu.Lock()
	bastionConn := dialer.conns[0]
	dialer.mu.Unlock()
	bastionConn.alive.Store(false)

	requireNoErr(t, p.WithLease(ctx, pl, func(_ context.Context, l *Lease) error {
		requireTrue(t, l.IsAlive(), "自动重连后租约必须存活")
		return nil
	}), "redial after dead ancestor")
	requireTrue(t, dialer.dialCount.Load() == 4, "祖先失活后应重新拨号全部 2 跳")

	// 验证非法拨号结果（摘要不匹配）被失败关闭拦截且连接被回收。
	badPlan := mustPlan(t, mustHop(t, 0, "bad-host", "198.51.100.42", 22, 0, 0))
	wrongDig, _ := pl.HopDigestAt(0)
	var orphan *mockConn
	dialer.hook = func(_ context.Context, hop plan.HopSpec, _ plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
		orphan = newMockConn(wrongDig, hop.Endpoint())
		return orphan, nil
	}
	err := p.WithLease(ctx, badPlan, func(context.Context, *Lease) error { return nil })
	requireErrIs(t, err, ErrInvalidTransportConn, "摘要不匹配连接须拒绝")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(orphan)")
	requireTrue(t, orphan != nil && orphan.closeCount.Load() == 1, "被拒孤儿连接必须被关闭")
}

func TestWithMultiLeaseOrderDedupAndPartialFailureRollback(t *testing.T) {
	defer goleak.VerifyNone(t)
	dialer := &mockDialer{}
	p, _, _ := newTestPool(t, PoolConfig{Dialer: dialer})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()

	hop0 := mustHop(t, 0, "b", "198.51.100.50", 22, 0, 0)
	plA := mustPlan(t, hop0, mustHop(t, 1, "a", "198.51.100.51", 22, 0, 0))
	plB := mustPlan(t, mustHop(t, 0, "c", "198.51.100.52", 22, 0, 0))
	ctx := context.Background()

	// 传入含重复项与多跳混合顺序 [plA, plB, plA]，验证返回切片严格保持原始顺序且 plA 去重仅占 1 租约。
	err := p.WithMultiLease(ctx, []plan.SealedConnectionPlan{plA, plB, plA}, func(scopedCtx context.Context, leases []*Lease) error {
		requireTrue(t, trace.InLeaseScope(scopedCtx), "WithMultiLease 须注入 trace.LeaseScope")
		requireTrue(t, len(leases) == 3, "返回租约数须等于入参计划数")
		requireTrue(t, leases[0].PlanDigest().Equal(plA.PlanDigest()), "leases[0] 须对应 plA")
		requireTrue(t, leases[1].PlanDigest().Equal(plB.PlanDigest()), "leases[1] 须对应 plB")
		requireTrue(t, leases[2].PlanDigest().Equal(plA.PlanDigest()), "leases[2] 须对应 plA")
		requireTrue(t, p.Stats().ActiveLeases == 2, "去重后底层唯一活跃租约数应为 2")
		return nil
	})
	requireNoErr(t, err, "WithMultiLease(dedup)")
	requireTrue(t, p.Stats().ActiveLeases == 0, "退出后活跃租约须归零")

	// 部分申请失败时必须回滚已申请的租约，确保 0 租约泄漏。
	plFail := mustPlan(t, mustHop(t, 0, "fail", "198.51.100.53", 22, 0, 0))
	failDig, _ := plFail.HopDigestAt(0)
	dialErr := errors.New("dial boom")
	dialer.hook = func(c context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
		if dig.Equal(failDig) {
			return nil, dialErr
		}
		return newMockConn(dig, hop.Endpoint()), nil
	}
	err = p.WithMultiLease(ctx, []plan.SealedConnectionPlan{plB, plFail}, func(context.Context, []*Lease) error { return nil })
	requireErrIs(t, err, dialErr, "部分失败须透传拨号错误")
	requireTrue(t, p.Stats().ActiveLeases == 0, "部分失败回滚后 ActiveLeases 必须为 0")
}

func TestRetirePlanCapacityLRUAndIdleTTLSweep(t *testing.T) {
	defer goleak.VerifyNone(t)
	clk := newSimClock()
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 64})
	requireNoErr(t, err, "NewSystemBus")
	defer bus.Close()
	sub, err := bus.Subscribe()
	requireNoErr(t, err, "Subscribe")
	defer sub.Close()

	p, dialer, _ := newTestPool(t, PoolConfig{
		Clock:    clk,
		Bus:      bus,
		MaxConns: 2,
		IdleTTL:  40 * time.Millisecond,
	})
	defer func() { requireNoErr(t, p.Close(), "Pool.Close") }()
	ctx := context.Background()

	p1 := mustPlan(t, mustHop(t, 0, "h1", "198.51.100.61", 22, 0, 0))
	p2 := mustPlan(t, mustHop(t, 0, "h2", "198.51.100.62", 22, 0, 0))
	p3 := mustPlan(t, mustHop(t, 0, "h3", "198.51.100.63", 22, 0, 0))

	// 等待后台空闲扫描器装弹首个定时器，避免虚拟时钟推进与协程启动竞态。
	clk.WaitTimerArmed(t, 1)

	requireNoErr(t, p.WithLease(ctx, p1, func(context.Context, *Lease) error { return nil }), "p1")
	clk.Advance(10 * time.Millisecond)
	requireNoErr(t, p.WithLease(ctx, p2, func(context.Context, *Lease) error { return nil }), "p2")
	clk.Advance(10 * time.Millisecond)
	// 容量为 2，申请 p3 应自动驱逐最久未用的空闲叶子 p1。
	requireNoErr(t, p.WithLease(ctx, p3, func(context.Context, *Lease) error { return nil }), "p3")
	p3Conn := dialer.lastConn()
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(lru)")
	requireTrue(t, p.Stats().ActiveConns == 2, "LRU 驱逐后活跃连接数应维持上限 2")

	// 当全部 2 条连接均被活跃租约占用时，再申请第 3 条必须返回 ErrPoolCapacityExceeded。
	err = p.WithMultiLease(ctx, []plan.SealedConnectionPlan{p2, p3}, func(_ context.Context, _ []*Lease) error {
		// 使用干净上下文（模拟另一个并发请求）触发容量满载检查。
		capErr := p.WithLease(context.Background(), p1, func(context.Context, *Lease) error { return nil })
		requireErrIs(t, capErr, ErrPoolCapacityExceeded, "全部连接忙碌时须返回容量超限")
		requireTrue(t, p.EvictIdle() == 0, "存在活跃租约时 EvictIdle 不得驱逐忙碌连接")
		return nil
	})
	requireNoErr(t, err, "WithMultiLease(busy cap)")

	// RetirePlan 仅退役 p2，保留 p3；随后推进虚拟时钟超过 IdleTTL 触发后台自动清理（以 closedCh 确定同步，零忙等）。
	requireNoErr(t, p.RetirePlan(p2.PlanDigest()), "RetirePlan(p2)")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(retire p2)")
	requireTrue(t, p.Stats().ActiveConns == 1, "RetirePlan(p2) 后应剩余 1 条连接")

	clk.Advance(100 * time.Millisecond)
	waitConnClosedCh(t, p3Conn, "IdleTTL 定时扫描清理空闲连接 p3")
	requireNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns(idle)")
	requireTrue(t, p.Stats().ActiveConns == 0 && dialer.dialCount.Load() == 3, "空闲清理后活跃连接须归零且总拨号为 3")

	// 核验 SystemBus 已收到脱敏的 PoolStateEvent（含 dial_succeeded 与 evicted/retired）。
	seenActions := drainPoolActions(ctx, sub)
	requireTrue(t, seenActions[events.PoolActionDialSucceeded] && seenActions[events.PoolActionEvicted] && seenActions[events.PoolActionRetired], "SystemBus 须观测到连接池生命周期事件")
}

func waitConnClosedCh(t *testing.T, mc *mockConn, label string) {
	t.Helper()
	select {
	case <-mc.closedCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s 超时：连接未关闭", label)
	}
}

func drainPoolActions(ctx context.Context, sub *events.SystemSubscription) map[events.PoolEventAction]bool {
	seen := make(map[events.PoolEventAction]bool)
	for {
		ev, ok, err := sub.Next(ctx)
		if !ok || err != nil {
			return seen
		}
		if ps, isPS := ev.(*events.PoolStateEvent); isPS {
			seen[ps.Action()] = true
		}
		if seen[events.PoolActionDialSucceeded] && seen[events.PoolActionLeaseAcquired] &&
			seen[events.PoolActionLeaseReleased] && seen[events.PoolActionRetired] &&
			seen[events.PoolActionEvicted] {
			return seen
		}
	}
}
