package pool_test

import (
	"context"
	"errors"
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
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期接口断言集中于外置测试文件，验证包外契约与 xopsvet Fact 导出。
var (
	_ pool.ManagedResource = (*extManagedRes)(nil)
	_ ports.DialerPort     = (*extDialer)(nil)
	_ ports.Clock          = (*extClock)(nil)
	_ ports.Entropy        = (*extEntropy)(nil)
)

type extManagedRes struct{ closed atomic.Bool }

func (r *extManagedRes) IsValid() bool { return r != nil && !r.closed.Load() }
func (r *extManagedRes) Close() error {
	r.closed.Store(true)
	return nil
}

type extClock struct{}
type extTimer struct{ t *time.Timer }

func (t extTimer) C() <-chan time.Time           { return t.t.C }
func (t extTimer) Stop() bool                    { return t.t.Stop() }
func (t extTimer) Reset(d time.Duration) bool    { return t.t.Reset(d) }
func (extClock) Now() time.Time                  { return time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC) }
func (extClock) Since(t time.Time) time.Duration { return time.Millisecond }
func (extClock) NewTimer(d time.Duration) ports.Timer {
	return extTimer{t: time.NewTimer(d)}
}
func (extClock) Sleep(ctx context.Context, _ time.Duration) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	return ctx.Err()
}

type extEntropy struct {
	mu sync.Mutex
	n  byte
}

func (e *extEntropy) Read(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range p {
		e.n++
		if e.n == 0 {
			e.n = 1
		}
		p[i] = e.n
	}
	return len(p), nil
}

type extSession struct{}

func (extSession) Start(context.Context, execution.CommandPlan, ports.ExecStreams) error { return nil }
func (extSession) StartShell(context.Context, algebraic.Option[ports.PTYRequest], ports.ExecStreams) error {
	return nil
}
func (extSession) ResizePTY(context.Context, ports.TerminalSize) error { return nil }
func (extSession) Signal(context.Context, string) error                { return nil }
func (extSession) Wait(context.Context) (execution.ExecutionOutcome, error) {
	return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
}
func (extSession) Close() error { return nil }

type extConn struct {
	dig   plan.HopDigest
	ep    netaddr.Endpoint
	alive atomic.Bool
}

func (c *extConn) HopDigest() plan.HopDigest  { return c.dig }
func (c *extConn) Endpoint() netaddr.Endpoint { return c.ep }
func (c *extConn) OpenSession(context.Context) (ports.RemoteSession, error) {
	return extSession{}, nil
}
func (c *extConn) DialTCP(context.Context, netaddr.HostPort) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *extConn) ListenTCP(context.Context, string) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *extConn) OpenRemoteFS(context.Context) (ports.RemoteFSPort, error) {
	return nil, ports.ErrUnsupported
}
func (c *extConn) SendKeepalive(context.Context) error { return nil }
func (c *extConn) IsAlive() bool                       { return c.alive.Load() }
func (c *extConn) Close() error {
	c.alive.Store(false)
	return nil
}

type extDialer struct{}

func (extDialer) DialHop(_ context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
	c := &extConn{dig: dig, ep: hop.Endpoint()}
	c.alive.Store(true)
	return c, nil
}

func mustExtPlan(t *testing.T, host string) plan.SealedConnectionPlan {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost(host)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := netaddr.NewEndpoint(ch, 22)
	if err != nil {
		t.Fatal(err)
	}
	u, err := option.ParseUsername("ext")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatal(err)
	}
	unset := option.UnsetOptionLayer()
	eff, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	if err != nil {
		t.Fatal(err)
	}
	hop, err := plan.NewHopSpecFromAuth(0, "ext-node", u, auth, eff)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := plan.SealConnectionPlan(hop)
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

func TestZeroValueAndNilReceiversFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	pl := mustExtPlan(t, "198.51.100.210")
	dig, _ := pl.HopDigestAt(0)

	var zeroPool pool.Pool
	var nilPool *pool.Pool
	for _, p := range []*pool.Pool{&zeroPool, nilPool} {
		assertFailClosedPool(t, ctx, p, pl, dig)
	}

	var zeroLease pool.Lease
	var nilLease *pool.Lease
	for _, l := range []*pool.Lease{&zeroLease, nilLease} {
		assertFailClosedLease(t, ctx, l)
	}

	var zeroStatus pool.HandleStatus
	extRequire(t, !zeroStatus.IsValid() && zeroStatus.IsZero() && !zeroStatus.Active() &&
		zeroStatus.Kind() == plan.HandleKindInvalid && zeroStatus.Generation() == 0, "零值 HandleStatus 必须失败关闭")
}

func assertFailClosedPool(t *testing.T, ctx context.Context, p *pool.Pool, pl plan.SealedConnectionPlan, dig plan.HopDigest) {
	t.Helper()
	extRequire(t, p.IsHalted() && p.IsClosed() && p.Stats().Closed, "nil 或零值 Pool 必须失败关闭")
	extErrIs(t, p.WithLease(ctx, pl, func(context.Context, *pool.Lease) error { return nil }), pool.ErrPoolNotInitialized, "WithLease")
	extErrIs(t, p.WithMultiLease(ctx, []plan.SealedConnectionPlan{pl}, func(context.Context, []*pool.Lease) error { return nil }), pool.ErrPoolNotInitialized, "WithMultiLease")
	extErrIs(t, p.RetireHop(dig), pool.ErrPoolNotInitialized, "RetireHop")
	extErrIs(t, p.RetirePlan(pl.PlanDigest()), pool.ErrPoolNotInitialized, "RetirePlan")
	extErrIs(t, p.WaitPendingTeardowns(ctx), pool.ErrPoolNotInitialized, "WaitPendingTeardowns")
	extErrIs(t, p.Close(), pool.ErrPoolNotInitialized, "Close")
	extRequire(t, p.EvictIdle() == 0 && p.RevokeHandlesByPlan(pl.PlanDigest()) == 0, "EvictIdle/RevokeHandlesByPlan 须返回 0")
	p.GateHalted(nil)
}

func assertFailClosedLease(t *testing.T, ctx context.Context, l *pool.Lease) {
	t.Helper()
	extRequire(t, !l.IsValid() && l.IsZero() && !l.IsAlive() && l.Epoch() == 0 && l.LeaseID() == "", "nil 或零值 Lease 必须失败关闭")
	_, err := l.OpenSession(ctx)
	extErrIs(t, err, pool.ErrLeaseInvalid, "OpenSession")
	l.Retire()
}

func TestExternalScopedBorrowAndSlotMapEndToEnd(t *testing.T) {
	defer goleak.VerifyNone(t)
	p, err := pool.NewPool(context.Background(), pool.PoolConfig{
		Dialer:  extDialer{},
		Clock:   extClock{},
		Entropy: &extEntropy{n: 5},
	})
	extNoErr(t, err, "NewPool")
	defer func() { extNoErr(t, p.Close(), "Close") }()

	ctx := context.Background()
	pl := mustExtPlan(t, "198.51.100.211")
	verifyExtLeaseFlow(t, ctx, p, pl)
	verifyExtSlotMapFlow(t, ctx, p, pl)
}

func verifyExtLeaseFlow(t *testing.T, ctx context.Context, p *pool.Pool, pl plan.SealedConnectionPlan) {
	t.Helper()
	err := p.WithLease(ctx, pl, func(scopedCtx context.Context, l *pool.Lease) error {
		if !trace.InLeaseScope(scopedCtx) || !l.IsValid() {
			return errors.New("外置包借用 Lease 或 LeaseScope 校验失败")
		}
		sess, sErr := l.OpenSession(scopedCtx)
		if sErr != nil {
			return sErr
		}
		return sess.Close()
	})
	extNoErr(t, err, "WithLease")

	err = p.WithMultiLease(ctx, []plan.SealedConnectionPlan{pl}, func(scopedCtx context.Context, ls []*pool.Lease) error {
		if len(ls) != 1 || !ls[0].IsAlive() || !trace.InLeaseScope(scopedCtx) {
			return errors.New("外置包 WithMultiLease 校验失败")
		}
		return nil
	})
	extNoErr(t, err, "WithMultiLease")
}

func verifyExtSlotMapFlow(t *testing.T, ctx context.Context, p *pool.Pool, pl plan.SealedConnectionPlan) {
	t.Helper()
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute,
		Tool:       "session",
		Action:     "open",
		PlanDigest: algebraic.Some(pl.PlanDigest().SecurityDigest()),
	})
	extNoErr(t, err, "NewOperationBinding")
	// 验证包外传入 typed-nil 指针被失败关闭拦截且零 panic。
	var typedNil *extManagedRes
	_, err = pool.RegisterHandle[plan.KindSession](p, pl.PlanDigest(), binding, typedNil)
	extErrIs(t, err, pool.ErrInvalidResource, "RegisterHandle(typed-nil)")

	res := &extManagedRes{}
	h, err := pool.RegisterHandle[plan.KindSession](p, pl.PlanDigest(), binding, res)
	extNoErr(t, err, "RegisterHandle")
	err = pool.WithManagedHandle[plan.KindSession, *extManagedRes](ctx, p, h, func(_ context.Context, borrowed *extManagedRes) error {
		if borrowed == nil || borrowed.closed.Load() {
			return errors.New("托管资源借用状态异常")
		}
		return nil
	})
	extNoErr(t, err, "WithManagedHandle")
	extNoErr(t, pool.ReleaseHandle[plan.KindSession](p, h), "ReleaseHandle")
	extNoErr(t, p.WaitPendingTeardowns(ctx), "WaitPendingTeardowns")
	extRequire(t, res.closed.Load(), "ReleaseHandle 后托管资源必须已关闭")
}

func extNoErr(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
}

func extErrIs(t *testing.T, err, target error, label string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s 期望 %v，实际=%v", label, target, err)
	}
}

func extRequire(t *testing.T, cond bool, msg string) {
	t.Helper()
	if !cond {
		t.Fatal(msg)
	}
}
