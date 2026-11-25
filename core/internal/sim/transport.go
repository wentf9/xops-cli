package sim

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
)

// HopFaultProfile 定义单跳拨号与连接层的延迟、失败、保活与卡死关闭故障参数。
type HopFaultProfile struct {
	DialLatency, KeepaliveLatency   time.Duration
	DialErr, KeepaliveErr           error
	StuckClose                      bool // Close 阻塞直至父跳板关闭（INV-C3 90ms 升级）或 UnblockClose
	SessionOutput                   string
	SessionOutcome                  execution.ExecutionOutcome
	SessionStartErr, SessionWaitErr error
}

// SimDialer 实现 ports.DialerPort，支持多跳虚拟延迟、卡死关闭根升级与零泄漏连接追踪。
//
//xops:opaque
//xops:failclosed
type SimDialer struct {
	simBase
	clock       ports.Clock
	defaultProf HopFaultProfile
	byHopIdx    map[uint32]HopFaultProfile
	byDigest    map[plan.HopDigest]HopFaultProfile
	conns       []*SimTransportConn
	dialCount   atomic.Uint64
	openCount   atomic.Int64
}

// NewSimDialer 创建确定性拨号仿真器。
func NewSimDialer(clk ports.Clock, rng *SeededRand) *SimDialer {
	if clk == nil {
		clk = NewSimClock(DefaultBaseTime())
	}
	return &SimDialer{simBase: newSimBase(rng), clock: clk, byHopIdx: make(map[uint32]HopFaultProfile), byDigest: make(map[plan.HopDigest]HopFaultProfile)}
}

// SetDefaultProfile / SetHopIndexProfile / SetDigestProfile / DialCount / OpenConns / ConnsSnapshot / UnblockAll。
func (d *SimDialer) SetDefaultProfile(p HopFaultProfile) { d.withLock(func() { d.defaultProf = p }) }
func (d *SimDialer) SetHopIndexProfile(idx uint32, p HopFaultProfile) {
	d.withLock(func() { d.byHopIdx[idx] = p })
}
func (d *SimDialer) SetDigestProfile(dig plan.HopDigest, p HopFaultProfile) {
	if dig.IsValid() {
		d.withLock(func() { d.byDigest[dig] = p })
	}
}
func (d *SimDialer) DialCount() uint64 { return d.dialCount.Load() }
func (d *SimDialer) OpenConns() int64  { return d.openCount.Load() }
func (d *SimDialer) ConnsSnapshot() []*SimTransportConn {
	return withLockRet(&d.simBase, nil, func() []*SimTransportConn { return slices.Clone(d.conns) })
}
func (d *SimDialer) UnblockAll() {
	for _, c := range d.ConnsSnapshot() {
		c.UnblockClose()
	}
}

// DialHop 建立单跳或多跳仿真传输连接。
func (d *SimDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, parent ports.TransportConn) (ports.TransportConn, error) {
	if err := d.check(ctx, "", hop.IsValid(), dig.IsValid()); err != nil {
		return nil, err
	}
	d.dialCount.Add(1)
	prof := withLockRet(&d.simBase, HopFaultProfile{}, func() HopFaultProfile {
		if p, ok := d.byDigest[dig]; ok {
			return p
		}
		if p, ok := d.byHopIdx[hop.HopIndex()]; ok {
			return p
		}
		return d.defaultProf
	})
	if prof.DialLatency > 0 {
		if err := d.clock.Sleep(ctx, prof.DialLatency); err != nil {
			return nil, err
		}
	}
	if parent != nil && !parent.IsAlive() {
		return nil, fmt.Errorf("%w: 上游父跳板已断开", ports.ErrDialFailed)
	}
	if err := firstErr(prof.DialErr, d.faults.Check("dial.hop")); err != nil {
		return nil, err
	}
	simParent, _ := parent.(*SimTransportConn)
	return d.newConn(dig, hop.Endpoint(), simParent, prof), nil
}
func (d *SimDialer) newConn(dig plan.HopDigest, ep netaddr.Endpoint, parent *SimTransportConn, prof HopFaultProfile) *SimTransportConn {
	c := &SimTransportConn{
		dialer: d, digest: dig, endpoint: ep, parent: parent, prof: prof,
		closedCh: make(chan struct{}), unblockClose: make(chan struct{}), initialized: true,
	}
	c.alive.Store(true)
	if d != nil {
		d.openCount.Add(1)
		d.withLock(func() { d.conns = append(d.conns, c) })
	}
	return c
}

// SimTransportConn 实现 ports.TransportConn，支持外部断连 Drop、保活与卡死关闭升级。
//
//xops:opaque
//xops:failclosed
type SimTransportConn struct {
	dialer                 *SimDialer
	digest                 plan.HopDigest
	endpoint               netaddr.Endpoint
	parent                 *SimTransportConn
	prof                   HopFaultProfile
	initialized            bool
	alive, closed          atomic.Bool
	closeOnce, unblockOnce sync.Once
	closedCh, unblockClose chan struct{}
	keepalives             atomic.Uint64
}

func (c *SimTransportConn) HopDigest() plan.HopDigest  { return c.digest }
func (c *SimTransportConn) Endpoint() netaddr.Endpoint { return c.endpoint }
func (c *SimTransportConn) IsAlive() bool {
	return c != nil && c.initialized && c.alive.Load() && (c.parent == nil || c.parent.IsAlive())
}
func (c *SimTransportConn) IsClosed() bool         { return c == nil || !c.initialized || c.closed.Load() }
func (c *SimTransportConn) KeepaliveCount() uint64 { return c.keepalives.Load() }

// Drop 模拟底层连接静默断连（不关闭 closedCh）；UnblockClose 解除 StuckClose 阻塞。
func (c *SimTransportConn) Drop() {
	if c != nil && c.initialized {
		c.alive.Store(false)
	}
}
func (c *SimTransportConn) UnblockClose() {
	if c != nil && c.initialized {
		c.unblockOnce.Do(func() { close(c.unblockClose) })
	}
}
func (c *SimTransportConn) Close() error {
	if c == nil || !c.initialized {
		return nil
	}
	c.alive.Store(false)
	c.closeOnce.Do(func() {
		if c.prof.StuckClose {
			var pCh <-chan struct{}
			if c.parent != nil {
				pCh = c.parent.closedCh
			}
			select {
			case <-pCh:
			case <-c.unblockClose:
			}
		}
		c.closed.Store(true)
		close(c.closedCh)
		if c.dialer != nil {
			c.dialer.openCount.Add(-1)
		}
	})
	return nil
}
func (c *SimTransportConn) SendKeepalive(ctx context.Context) error {
	if err := c.checkAliveOp(ctx, ""); err != nil {
		return err
	}
	c.keepalives.Add(1)
	if c.prof.KeepaliveLatency > 0 && c.dialer != nil {
		if err := c.dialer.clock.Sleep(ctx, c.prof.KeepaliveLatency); err != nil {
			return err
		}
	}
	if c.prof.KeepaliveErr != nil || c.dialer == nil {
		return c.prof.KeepaliveErr
	}
	return c.dialer.faults.Check("conn.keepalive")
}
func (c *SimTransportConn) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	if err := c.checkAliveOp(ctx, "conn.session"); err != nil {
		return nil, err
	}
	return &SimRemoteSession{conn: c, prof: c.prof, initialized: true}, nil
}
func (c *SimTransportConn) DialTCP(ctx context.Context, target netaddr.HostPort) (net.Conn, error) {
	if err := c.checkAliveOp(ctx, ""); err != nil || !target.IsValid() {
		return nil, firstErr(err, ports.ErrInvalidArgument)
	}
	return memtree.NewEchoConn(target.String()), nil
}
func (c *SimTransportConn) ListenTCP(ctx context.Context, bindAddr string) (net.Listener, error) {
	if err := c.checkAliveOp(ctx, ""); err != nil || bindAddr == "" {
		return nil, firstErr(err, ports.ErrInvalidArgument)
	}
	return memtree.NewMemListener(bindAddr, nil), nil
}
func (c *SimTransportConn) DialStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Conn, error) {
	if err := c.checkAliveOp(ctx, "conn.streamlocal"); err != nil || !remoteSocket.IsValid() {
		return nil, firstErr(err, ports.ErrInvalidArgument)
	}
	return memtree.NewEchoConn("unix:" + remoteSocket.String()), nil
}
func (c *SimTransportConn) ListenStreamLocal(ctx context.Context, remoteSocket pathalg.RemotePath) (net.Listener, error) {
	if err := c.checkAliveOp(ctx, "conn.streamlocal"); err != nil || !remoteSocket.IsValid() {
		return nil, firstErr(err, ports.ErrInvalidArgument)
	}
	return memtree.NewMemListener("unix:"+remoteSocket.String(), nil), nil
}
func (c *SimTransportConn) OpenTUN(ctx context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, error) {
	if err := c.checkAliveOp(ctx, "conn.tun"); err != nil || !spec.IsValid() {
		return nil, firstErr(err, ports.ErrInvalidArgument)
	}
	return memtree.NewEchoConn(fmt.Sprintf("tun:%s:%d:%d", spec.Mode(), spec.LocalUnit(), spec.RemoteUnit())), nil
}
func (c *SimTransportConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	if err := c.checkAliveOp(ctx, "conn.remotefs"); err != nil {
		return nil, err
	}
	if c.dialer != nil {
		return NewSimRemoteFS(c.dialer.clock), nil
	}
	return NewSimRemoteFS(nil), nil
}
func (c *SimTransportConn) checkAliveOp(ctx context.Context, faultOp string) error {
	if err := checkCtx(ctx); err != nil {
		return err
	}
	if !c.IsAlive() {
		return ports.ErrClosed
	}
	if faultOp != "" && c.dialer != nil {
		return c.dialer.faults.Check(faultOp)
	}
	return nil
}

// SimRemoteSession 实现 ports.RemoteSession，支持前置管道获取及与 ExecStreams 互斥校验。
//
//xops:opaque
//xops:failclosed
type SimRemoteSession struct {
	mu                                sync.Mutex
	conn                              *SimTransportConn
	prof                              HopFaultProfile
	initialized                       bool
	started, closed                   atomic.Bool
	stdinPipe, stdoutPipe, stderrPipe *memtree.StreamPipe
}

func (s *SimRemoteSession) checkOpen(ctx context.Context, needConn bool) error {
	if err := checkCtx(ctx); err != nil {
		return err
	}
	if !s.initialized || s.closed.Load() || (needConn && !s.conn.IsAlive()) {
		return ports.ErrClosed
	}
	return nil
}
func (s *SimRemoteSession) allocPipe(slot **memtree.StreamPipe) (*memtree.StreamPipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized || s.closed.Load() {
		return nil, ports.ErrClosed
	}
	if s.started.Load() || *slot != nil {
		return nil, ports.ErrInvalidArgument
	}
	*slot = memtree.NewStreamPipe()
	return *slot, nil
}
func (s *SimRemoteSession) StdinPipe() (io.WriteCloser, error) { return s.allocPipe(&s.stdinPipe) }
func (s *SimRemoteSession) StdoutPipe() (io.Reader, error)     { return s.allocPipe(&s.stdoutPipe) }
func (s *SimRemoteSession) StderrPipe() (io.Reader, error)     { return s.allocPipe(&s.stderrPipe) }

func (s *SimRemoteSession) beginStartLocked(streams ports.ExecStreams) error {
	if s.started.Load() || (s.stdinPipe != nil && streams.Stdin != nil) || (s.stdoutPipe != nil && streams.Stdout != nil) || (s.stderrPipe != nil && streams.Stderr != nil) {
		return ports.ErrInvalidArgument
	}
	s.started.Store(true)
	return nil
}
func (s *SimRemoteSession) Start(ctx context.Context, cmd execution.CommandPlan, streams ports.ExecStreams) error {
	if err := firstErr(s.checkOpen(ctx, true), s.prof.SessionStartErr); err != nil || !cmd.IsValid() {
		return firstErr(err, ports.ErrInvalidArgument)
	}
	s.mu.Lock()
	err := s.beginStartLocked(streams)
	outPipe, errPipe := s.stdoutPipe, s.stderrPipe
	s.mu.Unlock()
	if err != nil {
		return err
	}
	payload := cmp.Or(s.prof.SessionOutput, "tck-ok\n")
	if outPipe != nil {
		_, _ = io.WriteString(outPipe, payload)
		_ = outPipe.Close()
	} else if streams.Stdout != nil {
		_, _ = io.WriteString(streams.Stdout, payload)
	}
	if errPipe != nil {
		_ = errPipe.Close()
	}
	return nil
}
func (s *SimRemoteSession) StartShell(ctx context.Context, streams ports.ExecStreams) error {
	if err := s.checkOpen(ctx, true); err != nil {
		return err
	}
	if ptyReq, ok := streams.PTY.Get(); ok && !ptyReq.IsValid() {
		return ports.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.beginStartLocked(streams)
}
func (s *SimRemoteSession) ResizePTY(ctx context.Context, size ports.TerminalSize) error {
	if err := s.checkOpen(ctx, false); err != nil || !size.IsValid() {
		return firstErr(err, ports.ErrInvalidTTYSize)
	}
	return nil
}
func (s *SimRemoteSession) Signal(ctx context.Context, sig string) error {
	if err := s.checkOpen(ctx, false); err != nil || sig == "" {
		return firstErr(err, ports.ErrInvalidArgument)
	}
	return nil
}
func (s *SimRemoteSession) Wait(ctx context.Context) (execution.ExecutionOutcome, error) {
	if err := firstErr(s.checkOpen(ctx, false), s.prof.SessionWaitErr); err != nil {
		return nil, err
	}
	if !s.started.Load() {
		return nil, ports.ErrInvalidArgument
	}
	if s.prof.SessionOutcome != nil && s.prof.SessionOutcome.IsValid() {
		return s.prof.SessionOutcome, nil
	}
	return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
}
func (s *SimRemoteSession) Close() error {
	s.closed.Store(true)
	s.mu.Lock()
	pipes := [3]*memtree.StreamPipe{s.stdinPipe, s.stdoutPipe, s.stderrPipe}
	s.mu.Unlock()
	for _, p := range pipes {
		if p != nil {
			_ = p.Close()
		}
	}
	return nil
}

// SimMuxSocket 实现 ports.MuxSocketPort 的零 OS 套接字纯内存仿真器。
//
//xops:opaque
//xops:failclosed
type SimMuxSocket struct {
	simBase
	dialer  *SimDialer
	masters map[string]uint32
}

// NewSimMuxSocket 创建纯内存多路复用套接字仿真器（可选绑定 dialer 以纳入连接计数与虚拟时钟）。
func NewSimMuxSocket(dialer *SimDialer) *SimMuxSocket {
	return &SimMuxSocket{simBase: newSimBase(nil), dialer: dialer, masters: make(map[string]uint32)}
}

// RegisterMaster 注册指定路径的仿真 ControlMaster 进程 PID。
func (m *SimMuxSocket) RegisterMaster(sockPath pathalg.LocalSourcePath, pid uint32) {
	if sockPath.IsValid() && pid > 0 {
		m.withLock(func() { m.masters[sockPath.String()] = pid })
	}
}
func (m *SimMuxSocket) Probe(ctx context.Context, sockPath pathalg.LocalSourcePath) (out ports.MuxControlResponse, err error) {
	if err = m.check(ctx, "mux.probe", sockPath.IsValid()); err != nil {
		return out, err
	}
	if pid := withLockRet(&m.simBase, uint32(0), func() uint32 { return m.masters[sockPath.String()] }); pid != 0 {
		return ports.NewMuxControlResponse(true, pid, "alive")
	}
	return ports.NewMuxControlResponse(false, 0, "not running")
}
func (m *SimMuxSocket) Control(ctx context.Context, req ports.MuxControlRequest) (out ports.MuxControlResponse, err error) {
	if err = m.check(ctx, "mux.control", req.IsValid()); err != nil {
		return out, err
	}
	if pid := withLockRet(&m.simBase, uint32(0), func() uint32 {
		k := req.SocketPath().String()
		p := m.masters[k]
		if p != 0 && (req.Action() == ports.MuxActionExit || req.Action() == ports.MuxActionStop) {
			delete(m.masters, k)
		}
		return p
	}); pid != 0 {
		return ports.NewMuxControlResponse(true, pid, req.Action().String())
	}
	return out, ports.ErrMuxUnavailable
}
func (m *SimMuxSocket) DialMux(ctx context.Context, sockPath pathalg.LocalSourcePath) (ports.TransportConn, error) {
	if err := m.check(ctx, "mux.dial", sockPath.IsValid()); err != nil {
		return nil, err
	}
	if withLockRet(&m.simBase, uint32(0), func() uint32 { return m.masters[sockPath.String()] }) == 0 {
		return nil, ports.ErrMuxUnavailable
	}
	ch, _ := netaddr.ParseCanonicalHost("127.0.0.1")
	ep, _ := netaddr.NewEndpoint(ch, 22)
	return m.dialer.newConn(plan.HopDigestFromSHA256([32]byte{1}), ep, nil, HopFaultProfile{}), nil
}

// WithListener 在同步闭包内借出带失效哨兵的纯内存 net.Listener，退出时自动失效并注销（兼容含 ':' 路径）。
//
//xops:syncclosure
//xops:borrowed
func (m *SimMuxSocket) WithListener(ctx context.Context, socketPath pathalg.LocalSourcePath, fn func(ln net.Listener) error) error {
	if err := m.checkFn(ctx, fn != nil, "mux.listen", socketPath.IsValid()); err != nil {
		return err
	}
	addr := socketPath.String()
	if withLockRet(&m.simBase, true, func() bool {
		if m.masters[addr] != 0 {
			return true
		}
		m.masters[addr] = 4242
		return false
	}) {
		return ports.ErrAlreadyExists
	}
	var expired atomic.Bool
	defer func() { expired.Store(true); m.withLock(func() { delete(m.masters, addr) }) }()
	return fn(memtree.NewMemListener(addr, &expired))
}
