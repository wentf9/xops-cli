package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultPTYBufferBytes = 1 << 20  // 单个持久 PTY 默认输出缓冲上限 1 MiB
	maxPTYBufferBytes     = 16 << 20 // 单个持久 PTY 最大输出缓冲上限 16 MiB
	defaultPTYReadBytes   = 64 << 10 // 单次 ReadPTY 默认最大读取 64 KiB
)

// OpenPTYRequest 描述在连接池世代 SlotMap 上创建跨请求持久 PTY 会话的强类型输入（ADR-009 / P3-T2）。
type OpenPTYRequest struct {
	Plan            plan.SealedConnectionPlan
	NodeID, Term    string
	Size            algebraic.Option[ports.TerminalSize]
	MaxBufferBytes  int
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// PTYReadRequest 描述从指定世代 PTY 句柄读取缓冲输出的请求参数。
type PTYReadRequest struct {
	Handle   plan.ManagedHandle[plan.KindPTY]
	MaxBytes int  // 0 默认 64 KiB
	Wait     bool // true 时事件驱动等待新输出、EOF 或取消/吊销
}

// PTYReadResult 封装单次 ReadPTY 的不可变输出快照；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type PTYReadResult struct {
	data         []byte
	eof, valid   bool
	droppedBytes uint64
}

func (r PTYReadResult) IsValid() bool        { return r.valid }
func (r PTYReadResult) IsZero() bool         { return !r.valid }
func (r PTYReadResult) Data() []byte         { return bytes.Clone(r.data) }
func (r PTYReadResult) EOF() bool            { return r.valid && r.eof }
func (r PTYReadResult) DroppedBytes() uint64 { return r.droppedBytes }

// PTYStatus 表示持久 PTY 句柄的不可变只读状态快照；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type PTYStatus struct {
	handleStatus     pool.HandleStatus
	term             string
	size             ports.TerminalSize
	bufferedBytes    int
	droppedBytes     uint64
	eof, active, val bool
}

func (st PTYStatus) IsValid() bool                   { return st.val && st.handleStatus.IsValid() }
func (st PTYStatus) IsZero() bool                    { return !st.IsValid() }
func (st PTYStatus) HandleStatus() pool.HandleStatus { return st.handleStatus }
func (st PTYStatus) Term() string                    { return st.term }
func (st PTYStatus) Size() ports.TerminalSize        { return st.size }
func (st PTYStatus) BufferedBytes() int              { return st.bufferedBytes }
func (st PTYStatus) DroppedBytes() uint64            { return st.droppedBytes }
func (st PTYStatus) EOF() bool                       { return st.val && st.eof }
func (st PTYStatus) Active() bool                    { return st.IsValid() && st.active }

type ptyResource interface {
	pool.ManagedResource
	read(ctx context.Context, maxBytes int, wait bool) (PTYReadResult, error)
	write(ctx context.Context, data []byte) (int, error)
	resize(ctx context.Context, sz ports.TerminalSize) error
	signal(ctx context.Context, sig string) error
}

// managedPTY 实现 ptyResource、snapshotResource[PTYStatus] 与 pool.ComparableManagedResource，
// 绑定池钉选 TransportConn、RemoteSession 与 core/conc.Nursery 输出泵（0 裸 go、两段式关闭零死锁、0 泄漏）。
//
//xops:opaque
//xops:failclosed
type managedPTY struct {
	valid, eof              bool
	revokeCtx               context.Context
	conn                    ports.TransportConn
	sess                    ports.RemoteSession
	inPipe                  io.WriteCloser
	nursery                 *conc.Nursery
	term                    string
	writeMu                 *conc.CtxMutex
	mu                      sync.Mutex
	size                    ports.TerminalSize
	buf                     []byte
	maxBuf, activePipes     int
	droppedBytes            uint64
	readNotify              chan struct{}
	closed                  atomic.Bool
	resCloseOnce, closeOnce sync.Once
	closeErr                error
}

func startManagedPTY(leaseCtx, revokeCtx context.Context, conn ports.TransportConn, ptyReq ports.PTYRequest, sendEnv map[string]string, maxBuf int) (*managedPTY, error) {
	if err := leaseCtx.Err(); err != nil {
		return nil, err
	}
	hsCtx, cleanupHS := deriveHandshakeContext(leaseCtx, revokeCtx)
	defer cleanupHS()
	sess, err := conn.OpenSession(hsCtx)
	if err != nil {
		return nil, err
	}
	inPipe, outPipe, errPipe, err := claimSessionPipes(sess)
	if err == nil {
		// StartShell 持留 revokeCtx 驱动会话生命周期，同时挂接 leaseCtx 同步中止钩子确保建链期及时响应调用方取消。
		stopStartAbort := registerSyncAbort(leaseCtx, func() { _ = sess.Close() })
		err = sess.StartShell(revokeCtx, ports.ExecStreams{PTY: algebraic.Some(ptyReq), Env: sendEnv})
		stopStartAbort()
		err = firstNonNilErr(err, leaseCtx.Err())
	}
	var n *conc.Nursery
	if err == nil {
		n, err = conc.NewNursery(revokeCtx)
	}
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	mp := &managedPTY{valid: true, revokeCtx: revokeCtx, conn: conn, sess: sess, inPipe: inPipe, nursery: n, writeMu: conc.NewCtxMutex(), term: ptyReq.Term(), size: ptyReq.Size(), maxBuf: maxBuf, activePipes: 2, readNotify: make(chan struct{})}
	for _, fn := range []func(context.Context) error{
		func(context.Context) error { mp.pumpReader(outPipe); return nil },
		func(context.Context) error { mp.pumpReader(errPipe); return nil },
		func(wCtx context.Context) error { <-wCtx.Done(); _ = mp.closeResources(); return nil },
	} {
		if err := n.Go(fn); err != nil {
			_ = mp.Close()
			return nil, err
		}
	}
	return mp, nil
}

func (p *managedPTY) pumpReader(r io.Reader) {
	defer func() {
		p.mu.Lock()
		if p.activePipes--; p.activePipes <= 0 {
			p.eof = true
			p.broadcastLocked()
		}
		p.mu.Unlock()
	}()
	if r == nil {
		return
	}
	for chunk := make([]byte, 4096); ; {
		n, err := r.Read(chunk)
		if n > 0 {
			p.mu.Lock()
			p.buf = append(p.buf, chunk[:n]...)
			if over := len(p.buf) - p.maxBuf; over > 0 {
				p.droppedBytes += uint64(over)
				p.buf = p.buf[:copy(p.buf, p.buf[over:])]
			}
			p.broadcastLocked()
			p.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}
func (p *managedPTY) broadcastLocked() { close(p.readNotify); p.readNotify = make(chan struct{}) }
func (p *managedPTY) IsValid() bool    { return p != nil && p.valid && !p.closed.Load() }
func (p *managedPTY) revokedErr(ctx context.Context) error {
	if p.closed.Load() || p.revokeCtx.Err() != nil || ctx.Err() != nil {
		return firstNonNilErr(context.Cause(p.revokeCtx), context.Cause(ctx), ctx.Err(), ErrPTYClosed)
	}
	return nil
}
func (p *managedPTY) closeResources() error {
	var err error
	p.resCloseOnce.Do(func() {
		p.closed.Store(true)
		p.mu.Lock()
		p.broadcastLocked()
		p.mu.Unlock()
		err = closeClosers(p.inPipe, p.sess, p.conn)
	})
	return err
}
func (p *managedPTY) Close() error {
	if p == nil || !p.valid {
		return nil
	}
	p.closeOnce.Do(func() {
		p.nursery.Cancel(ErrPTYClosed)
		p.closeErr = errors.Join(p.closeResources(), p.nursery.Close())
	})
	return p.closeErr
}

func (p *managedPTY) read(ctx context.Context, maxBytes int, wait bool) (PTYReadResult, error) {
	for {
		p.mu.Lock()
		if err := p.revokedErr(ctx); err != nil {
			p.mu.Unlock()
			return PTYReadResult{}, err
		}
		if len(p.buf) > 0 || p.eof || !wait {
			var out []byte
			if len(p.buf) > 0 {
				n := min(len(p.buf), maxBytes)
				out = bytes.Clone(p.buf[:n])
				p.buf = p.buf[:copy(p.buf, p.buf[n:])]
			}
			res := PTYReadResult{data: out, eof: p.eof && len(p.buf) == 0, droppedBytes: p.droppedBytes, valid: true}
			p.mu.Unlock()
			return res, nil
		}
		ch := p.readNotify
		p.mu.Unlock()
		select {
		case <-ch:
		case <-p.revokeCtx.Done():
			return PTYReadResult{}, firstNonNilErr(context.Cause(p.revokeCtx), context.Cause(ctx), ErrPTYClosed)
		case <-ctx.Done():
			return PTYReadResult{}, firstNonNilErr(context.Cause(ctx), ctx.Err(), ErrPTYClosed)
		}
	}
}

func (p *managedPTY) withWriteLock(ctx context.Context, fn func() error) error {
	return p.writeMu.WithLock(ctx, func() error {
		if err := p.revokedErr(ctx); err != nil {
			return err
		}
		if !p.conn.IsAlive() {
			return ports.ErrClosed
		}
		return fn()
	})
}

func (p *managedPTY) write(ctx context.Context, data []byte) (int, error) {
	var n int
	return n, p.withWriteLock(ctx, func() error {
		if len(data) == 0 {
			return nil
		}
		var err error
		n, err = p.inPipe.Write(data)
		return err
	})
}
func (p *managedPTY) resize(ctx context.Context, sz ports.TerminalSize) error {
	return p.withWriteLock(ctx, func() error {
		if err := p.sess.ResizePTY(ctx, sz); err != nil {
			return err
		}
		p.mu.Lock()
		p.size = sz
		p.mu.Unlock()
		return nil
	})
}
func (p *managedPTY) signal(ctx context.Context, sig string) error {
	return p.withWriteLock(ctx, func() error { return p.sess.Signal(ctx, sig) })
}
func (p *managedPTY) snapshot(hs pool.HandleStatus) PTYStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PTYStatus{handleStatus: hs, term: p.term, size: p.size, bufferedBytes: len(p.buf), droppedBytes: p.droppedBytes, eof: p.eof, active: hs.Active() && !p.closed.Load() && p.conn.IsAlive(), val: true}
}

// OpenPTY 在连接池世代 SlotMap 上创建跨请求持久 PTY 会话并返回强类型 ManagedHandle[plan.KindPTY]：
// 严格遵循 gate.WithAuthorized[security.CapExecute] 包裹 pool.WithLease 与 pool.RegisterLeaseHandleWith。
func (s *Service) OpenPTY(ctx context.Context, req OpenPTYRequest) (plan.ManagedHandle[plan.KindPTY], error) {
	defer closeStream(req.OperationStream)
	targetHop, nodeID, ptyReq, maxBuf, err := s.prepareOpenPTY(ctx, req)
	if err != nil {
		return zeroVal[plan.ManagedHandle[plan.KindPTY]](), err
	}
	gateReq, err := buildGateReq[security.CapExecute](gateReqInput{
		plan: req.Plan, targetHop: targetHop, nodeID: nodeID, action: "pty_open",
		summary:  fmt.Sprintf("open persistent PTY on %s (%s)", nodeID, ptyReq.Term()),
		risk:     req.Risk.OrElse(security.RiskModerate),
		params:   map[string]string{"user": targetHop.Username().String(), "term": ptyReq.Term(), "cols": strconv.FormatUint(uint64(ptyReq.Size().Cols()), 10), "rows": strconv.FormatUint(uint64(ptyReq.Size().Rows()), 10)},
		approval: req.Approval, stream: req.OperationStream,
	})
	if err != nil {
		return zeroVal[plan.ManagedHandle[plan.KindPTY]](), err
	}
	sendEnv := s.filterSendEnv(targetHop)
	return registerAuthorizedHandle[security.CapExecute, plan.KindPTY](ctx, s, req.Plan, nodeID, "pty_open", gateReq, req.OperationStream,
		func(leaseCtx, revokeCtx context.Context, conn ports.TransportConn) (*managedPTY, error) {
			return startManagedPTY(leaseCtx, revokeCtx, conn, ptyReq, sendEnv, maxBuf)
		})
}

func (s *Service) prepareOpenPTY(ctx context.Context, req OpenPTYRequest) (plan.HopSpec, string, ports.PTYRequest, int, error) {
	zh, zp := zeroVal[plan.HopSpec](), zeroVal[ports.PTYRequest]()
	if err := s.validateBaseCall(ctx, req.Plan, RequestTTYUnset, req.Risk); err != nil {
		return zh, "", zp, 0, err
	}
	if req.MaxBufferBytes < 0 || req.MaxBufferBytes > maxPTYBufferBytes {
		return zh, "", zp, 0, fmt.Errorf("%w: MaxBufferBytes 超出 [0, %d]", ErrInvalidRequest, maxPTYBufferBytes)
	}
	if req.MaxBufferBytes == 0 {
		req.MaxBufferBytes = defaultPTYBufferBytes
	}
	sz, hasSz := req.Size.Get()
	if hasSz && !sz.IsValid() {
		return zh, "", zp, 0, fmt.Errorf("%w: %w", ErrInvalidRequest, ports.ErrInvalidTTYSize)
	}
	ptyReq, err := buildPTYRequest(resolvePTYTerm(req.Term, s.cfg.Env), sz)
	if err != nil {
		return zh, "", zp, 0, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	targetHop, nodeID, err := resolvePlanTargetAndNode(req.Plan, req.NodeID)
	return targetHop, nodeID, ptyReq, req.MaxBufferBytes, err
}

// ReadPTY 从指定世代 PTY 句柄读取远端缓冲输出（支持非阻塞轮询与事件驱动阻塞等待，吊销立即唤醒）。
func (s *Service) ReadPTY(ctx context.Context, req PTYReadRequest) (PTYReadResult, error) {
	if err := s.validateActiveHandleOp(ctx, req.Handle.IsValid()); err != nil {
		return PTYReadResult{}, err
	}
	if req.MaxBytes < 0 {
		return PTYReadResult{}, fmt.Errorf("%w: MaxBytes 不能为负", ErrInvalidRequest)
	}
	if req.MaxBytes == 0 {
		req.MaxBytes = defaultPTYReadBytes
	}
	var res PTYReadResult
	return res, pool.WithManagedHandle[plan.KindPTY, ptyResource](ctx, s.cfg.Pool, req.Handle, func(hCtx context.Context, pty ptyResource) error {
		var rErr error
		res, rErr = pty.read(hCtx, req.MaxBytes, req.Wait)
		return rErr
	})
}

// WritePTY 向指定世代 PTY 句柄写入输入载荷；陈旧世代、已释放或熔断时严格失败关闭。
func (s *Service) WritePTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY], data []byte) (int, error) {
	if err := s.validateActiveHandleOp(ctx, handle.IsValid()); err != nil {
		return 0, err
	}
	var n int
	return n, pool.WithManagedHandle[plan.KindPTY, ptyResource](ctx, s.cfg.Pool, handle, func(hCtx context.Context, pty ptyResource) error {
		var err error
		n, err = pty.write(hCtx, data)
		return err
	})
}

// ResizePTY 向指定世代 PTY 句柄发送窗口尺寸变更请求。
func (s *Service) ResizePTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY], size ports.TerminalSize) error {
	if err := s.validateActiveHandleOp(ctx, handle.IsValid()); err != nil {
		return err
	}
	if !size.IsValid() {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, ports.ErrInvalidTTYSize)
	}
	return pool.WithManagedHandle[plan.KindPTY, ptyResource](ctx, s.cfg.Pool, handle, func(hCtx context.Context, pty ptyResource) error { return pty.resize(hCtx, size) })
}

// SignalPTY 向指定世代 PTY 句柄对应的远端进程投递 POSIX 信号。
func (s *Service) SignalPTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY], sig string) error {
	if err := s.validateActiveHandleOp(ctx, handle.IsValid()); err != nil {
		return err
	}
	if sig == "" {
		return fmt.Errorf("%w: Signal 不能为空", ErrInvalidRequest)
	}
	return pool.WithManagedHandle[plan.KindPTY, ptyResource](ctx, s.cfg.Pool, handle, func(hCtx context.Context, pty ptyResource) error { return pty.signal(hCtx, sig) })
}

// InspectPTY 返回指定世代 PTY 句柄的只读状态快照（含缓冲量、丢弃量与世代绑定信息）。
func (s *Service) InspectPTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY]) (PTYStatus, error) {
	return inspectManagedHandle[plan.KindPTY, PTYStatus](ctx, s, handle)
}

// ClosePTY 释放持久 PTY 句柄、解钉底层跳板并触发有界通道关闭与协程排空。
func (s *Service) ClosePTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY]) error {
	return releaseManagedHandle[plan.KindPTY](ctx, s, handle)
}
