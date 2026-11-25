package memtree

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// ClockCore 封装 100% 确定性并发安全虚拟时钟与定时器队列内核，供 core/internal/sim.SimClock 复用。
type ClockCore struct {
	mu      sync.Mutex
	now     time.Time
	nextSeq uint64
	timers  []*ClockTimer
	notify  chan struct{}
}

// NewClockCore 构造从 start 起步的确定性虚拟时钟内核。
func NewClockCore(start time.Time) *ClockCore {
	return &ClockCore{now: start.UTC().Round(0), notify: make(chan struct{})}
}

// Now / Since / PendingTimers / Advance / AdvanceToNext / NewTimer / Sleep / WaitPending 驱动虚拟时钟（nil 接收者安全失败关闭）。
func (c *ClockCore) Now() time.Time {
	if c == nil {
		return time.Time{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *ClockCore) Since(t time.Time) time.Duration {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Sub(t)
}
func (c *ClockCore) PendingTimers() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}
func (c *ClockCore) Advance(d time.Duration) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.now = c.now.Add(max(d, 0))
	c.fireDueLocked()
	c.mu.Unlock()
}
func (c *ClockCore) AdvanceToNext() (delta time.Duration, ok bool) {
	if c == nil {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, tm := range c.timers {
		if tm.active && (!ok || tm.fireAt.Before(c.now.Add(delta))) {
			delta, ok = max(tm.fireAt.Sub(c.now), 0), true
		}
	}
	if ok {
		c.now = c.now.Add(delta)
		c.fireDueLocked()
	}
	return delta, ok
}
func (c *ClockCore) NewTimer(d time.Duration) ports.Timer {
	if c == nil {
		return &ClockTimer{}
	}
	tm := &ClockTimer{clk: c, ch: make(chan time.Time, 1)}
	c.mu.Lock()
	c.armTimerLocked(tm, d)
	c.mu.Unlock()
	return tm
}
func (c *ClockCore) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
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
func (c *ClockCore) WaitPending(ctx context.Context, n int) error {
	for {
		c.mu.Lock()
		done, ch := len(c.timers) >= n, c.notify
		c.mu.Unlock()
		if done {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func (c *ClockCore) armTimerLocked(tm *ClockTimer, d time.Duration) {
	c.nextSeq++
	tm.seq, tm.fireAt = c.nextSeq, c.now.Add(d)
	if d <= 0 {
		tm.active = false
		c.removeTimerLocked(tm)
		tm.ch <- c.now
	} else if tm.active = true; !slices.Contains(c.timers, tm) {
		c.timers = append(c.timers, tm)
	}
	close(c.notify)
	c.notify = make(chan struct{})
}
func (c *ClockCore) fireDueLocked() {
	var due []*ClockTimer
	kept := c.timers[:0]
	for _, tm := range c.timers {
		if tm.active && !c.now.Before(tm.fireAt) {
			tm.active, due = false, append(due, tm)
		} else if tm.active {
			kept = append(kept, tm)
		}
	}
	clear(c.timers[len(kept):])
	c.timers = kept
	slices.SortFunc(due, func(a, b *ClockTimer) int {
		return cmp.Or(cmp.Compare(a.fireAt.UnixNano(), b.fireAt.UnixNano()), cmp.Compare(a.seq, b.seq))
	})
	for _, tm := range due {
		select {
		case tm.ch <- c.now:
		default:
		}
	}
}
func (c *ClockCore) removeTimerLocked(t *ClockTimer) {
	if i := slices.Index(c.timers, t); i >= 0 {
		c.timers = slices.Delete(c.timers, i, i+1)
	}
}

// ClockTimer 实现 ports.Timer，由 ClockCore 调度触发。
type ClockTimer struct {
	clk    *ClockCore
	seq    uint64
	ch     chan time.Time
	fireAt time.Time
	active bool
}

func (t *ClockTimer) C() <-chan time.Time        { return t.ch }
func (t *ClockTimer) Stop() bool                 { return t.mutate(false, 0) }
func (t *ClockTimer) Reset(d time.Duration) bool { return t.mutate(true, d) }
func (t *ClockTimer) mutate(reset bool, d time.Duration) bool {
	if t == nil || t.clk == nil {
		return false
	}
	t.clk.mu.Lock()
	defer t.clk.mu.Unlock()
	was := t.active
	if !reset {
		t.active = false
		t.clk.removeTimerLocked(t)
		return was
	}
	select {
	case <-t.ch:
	default:
	}
	t.clk.armTimerLocked(t, d)
	return was
}

// AppendCSVAsset 解析单行 CSV 资产（alias,addr,port,user）并追加至 ImportBundleSpec。
func AppendCSVAsset(spec *inventory.ImportBundleSpec, line string) error {
	p := strings.Split(line, ",")
	if len(p) != 4 {
		return ports.ErrCorruptData
	}
	alias, addr, userStr := strings.TrimSpace(p[0]), strings.TrimSpace(p[1]), strings.TrimSpace(p[3])
	portNum, pErr := strconv.ParseUint(strings.TrimSpace(p[2]), 10, 16)
	if pErr != nil || portNum == 0 {
		return ports.ErrCorruptData
	}
	ch, e0 := netaddr.ParseCanonicalHost(addr)
	ep, e1 := netaddr.NewEndpoint(ch, uint16(portNum))
	hid, e2 := inventory.ParseHostID("host-" + alias)
	iid, e3 := inventory.ParseIdentityID("ident-" + alias)
	nid, e4 := inventory.ParseNodeID(alias)
	user, e5 := option.ParseUsername(userStr)
	auth, e6 := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	h, e7 := inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: ep})
	id, e8 := inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: user, Auth: auth})
	n, e9 := inventory.NewNode(inventory.NodeSpec{ID: nid, HostRef: hid, IdentityRef: iid, Proxy: option.NewProxyUnset(), Options: option.UnsetOptionLayer(), Origin: inventory.NewOriginManaged()})
	if err := FirstErr(e0, e1, e2, e3, e4, e5, e6, e7, e8, e9); err != nil {
		return err
	}
	spec.Hosts, spec.Identities, spec.Nodes = append(spec.Hosts, h), append(spec.Identities, id), append(spec.Nodes, n)
	return nil
}

// OpenSimForwardChannel 按 ForwardSpec 方向与显式端点类型（TCP/Unix）演练 TunnelTransport，
// 同时覆盖本地 StreamLocal 拨号（DialStreamLocal）与远端 StreamLocal 监听（ListenStreamLocal）。
func OpenSimForwardChannel(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (string, io.Closer, error) {
	switch spec.Direction() {
	case ports.ForwardLocal:
		return openSimLocalForward(ctx, transport, spec)
	case ports.ForwardRemote:
		return openSimRemoteForward(ctx, transport, spec)
	case ports.ForwardDynamic:
		return spec.BindAddr(), nil, nil
	case ports.ForwardTUN:
		ts, ok := spec.TUN().Get()
		if !ok || !ts.IsValid() {
			return "", nil, ports.ErrInvalidArgument
		}
		c, err := transport.OpenTUN(ctx, ts)
		return spec.BindAddr(), c, err
	default:
		return "", nil, ports.ErrInvalidArgument
	}
}
func openSimLocalForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (string, io.Closer, error) {
	if spec.TargetKind() == ports.ForwardEndpointUnix {
		rp, err := pathalg.ParseRemotePath(spec.TargetAddr())
		if err != nil {
			return "", nil, fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
		}
		c, err := transport.DialStreamLocal(ctx, rp)
		return spec.BindAddr(), c, err
	}
	hp, err := parseHostPort(spec.TargetAddr())
	if err != nil {
		return "", nil, err
	}
	c, err := transport.DialTCP(ctx, hp)
	return spec.BindAddr(), c, err
}
func openSimRemoteForward(ctx context.Context, transport ports.TunnelTransport, spec ports.ForwardSpec) (string, io.Closer, error) {
	var ln net.Listener
	var err error
	if spec.BindKind() == ports.ForwardEndpointUnix {
		rp, pErr := pathalg.ParseRemotePath(spec.BindAddr())
		if pErr != nil {
			return "", nil, fmt.Errorf("%w: %w", ports.ErrInvalidArgument, pErr)
		}
		ln, err = transport.ListenStreamLocal(ctx, rp)
	} else {
		ln, err = transport.ListenTCP(ctx, spec.BindAddr())
	}
	if err != nil {
		return "", nil, err
	}
	return ln.Addr().String(), ln, nil
}

func parseHostPort(raw string) (netaddr.HostPort, error) {
	var zero netaddr.HostPort
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return zero, fmt.Errorf("%w: 非法转发目标地址 %q", ports.ErrInvalidArgument, raw)
	}
	portNum, pErr := strconv.ParseUint(portStr, 10, 16)
	ch, hErr := netaddr.ParseCanonicalHost(host)
	if pErr != nil || hErr != nil || portNum == 0 {
		return zero, fmt.Errorf("%w: 非法转发目标主机或端口 %q", ports.ErrInvalidArgument, raw)
	}
	return netaddr.NewHostPort(ch, uint16(portNum))
}
