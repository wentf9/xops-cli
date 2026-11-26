package mux

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux/muxstream"
	"github.com/wentf9/xops-cli/core/ports"
)

type waitDoneProvider interface {
	WaitDone() <-chan struct{}
}

// muxServerState 维护单个 ControlMaster 监听生命周期内的动态转发注册表与优雅停机信号。
type muxServerState struct {
	owner            *MuxSocket
	upstream         ports.TransportConn
	forwarder        ports.ForwarderPort
	cancelServe      context.CancelFunc
	stoppedByControl atomic.Bool

	fwdMu    sync.Mutex
	forwards map[string]ports.ForwardHandle
}

// Serve 在借用的 net.Listener（须经参数级 //xops:borrowed 确保零逃逸）上运行 OpenSSH PROTOCOL.mux v4
// ControlMaster 服务端，响应探活、动态转发、取消转发、优雅退出、停止监听、代理透传与 XOps v4 流式复用请求。
func (m *MuxSocket) Serve(
	ctx context.Context,
	//xops:borrowed
	ln net.Listener,
	upstream ports.TransportConn,
	forwarder ports.ForwarderPort,
) error {
	if err := m.checkReady(ctx); err != nil {
		return err
	}
	if ln == nil || upstream == nil {
		return fmt.Errorf("%w: Serve 需要非 nil 的 net.Listener 与 upstream", ports.ErrInvalidArgument)
	}
	if !upstream.IsAlive() {
		return ports.ErrClosed
	}
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()

	st := &muxServerState{
		owner:       m,
		upstream:    upstream,
		forwarder:   forwarder,
		cancelServe: cancelServe,
		forwards:    make(map[string]ports.ForwardHandle),
	}
	defer st.closeAllForwards()

	runErr := conc.RunWait(serveCtx, func(wCtx context.Context, n *conc.Nursery) error {
		defer n.Cancel(ports.ErrClosed)
		if err := spawnUpstreamWatcher(wCtx, n, upstream, cancelServe); err != nil {
			return err
		}
		return chanconn.RunWithAbortWatchdog(wCtx, func() { _ = ln.Close() }, func() error {
			return st.acceptLoop(wCtx, n, ln)
		})
	})
	if st.stoppedByControl.Load() && ctx.Err() == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return runErr
}

func spawnUpstreamWatcher(ctx context.Context, n *conc.Nursery, upstream ports.TransportConn, cancelServe context.CancelFunc) error {
	wp, ok := upstream.(waitDoneProvider)
	if !ok {
		return nil
	}
	done := wp.WaitDone()
	return n.Go(func(wCtx context.Context) error {
		select {
		case <-done:
			cancelServe()
		case <-wCtx.Done():
		case <-ctx.Done():
		}
		return nil
	})
}

func (st *muxServerState) acceptLoop(
	ctx context.Context,
	n *conc.Nursery,
	//xops:borrowed
	ln net.Listener,
) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || muxstream.IsBenignIOErr(err) {
				return nil
			}
			return err
		}
		if err := st.spawnClientHandler(n, conn); err != nil {
			return nil
		}
	}
}

// spawnClientHandler 在 Nursery 内监督单条客户端连接，并用 chanconn 看门狗保证
// ControlMaster 停机或 ctx 取消时即使存在空闲/停滞客户端也能 O(1) 关闭解阻。
func (st *muxServerState) spawnClientHandler(n *conc.Nursery, conn net.Conn) error {
	if err := n.Go(func(cCtx context.Context) error {
		defer func() { _ = conn.Close() }()
		return chanconn.RunWithAbortWatchdog(cCtx, func() { _ = conn.Close() }, func() error {
			st.handleClientConn(cCtx, conn)
			return nil
		})
	}); err != nil {
		_ = conn.Close()
		return err
	}
	return nil
}

func (st *muxServerState) handleClientConn(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(st.owner.handshakeDeadline(ctx))
	if err := muxstream.WriteHello(conn, true); err != nil {
		return
	}
	if _, err := muxstream.ReadHello(conn); err != nil {
		return
	}
	if st.owner.onActivity != nil {
		st.owner.onActivity()
	}
	for {
		if ctx.Err() != nil {
			return
		}
		msgType, body, err := muxstream.ReadPacket(conn)
		if err != nil {
			return
		}
		if st.owner.onActivity != nil {
			st.owner.onActivity()
		}
		if stop, _ := st.dispatchPacket(ctx, conn, msgType, body); stop {
			return
		}
	}
}

// dispatchPacket 分发单条 PROTOCOL.mux v4 或 XOps v4 请求；返回 stop=true 表示当前连接已切换至数据面或结束。
func (st *muxServerState) dispatchPacket(ctx context.Context, conn net.Conn, msgType uint32, body []byte) (bool, error) {
	switch msgType {
	case muxstream.CAliveCheck:
		st.handleAliveCheck(conn, body)
		return false, nil
	case muxstream.CTerminate, muxstream.CStopListening:
		st.handleStopControl(conn, body)
		return true, nil
	case muxstream.COpenFwd:
		st.handleOpenFwd(ctx, conn, body, false)
		return false, nil
	case muxstream.XOpsCOpenTUNFwd:
		st.handleOpenFwd(ctx, conn, body, true)
		return false, nil
	case muxstream.CCloseFwd:
		st.handleCloseFwd(conn, body, false)
		return false, nil
	case muxstream.XOpsCCloseTUNFwd:
		st.handleCloseFwd(conn, body, true)
		return false, nil
	case muxstream.CProxy:
		st.handleProxyMode(ctx, conn, body)
		return true, nil
	default:
		return st.dispatchStreamPacket(ctx, conn, msgType, body)
	}
}

func (st *muxServerState) handleAliveCheck(conn net.Conn, body []byte) {
	rd := muxstream.NewReader(body)
	reqID, err := rd.ReadUint32()
	if err != nil {
		return
	}
	if !st.upstream.IsAlive() {
		_ = muxstream.WriteStatusReply(conn, muxstream.SFailure, reqID, "upstream transport closed")
		return
	}
	resp := muxstream.AppendU32(muxstream.AppendU32(nil, reqID), st.owner.selfPID)
	_ = muxstream.WritePacket(conn, muxstream.SAlive, resp)
}

func (st *muxServerState) handleStopControl(conn net.Conn, body []byte) {
	rd := muxstream.NewReader(body)
	reqID, err := rd.ReadUint32()
	if err != nil {
		return
	}
	st.stoppedByControl.Store(true)
	st.closeAllForwards()
	_ = muxstream.WriteStatusReply(conn, muxstream.SOK, reqID, "")
	// 先优雅半关闭并排空对端 EOF，再触发 cancelServe，避免 Windows afunix.sys 抢先 RST SOK 帧。
	muxstream.GracefulHalfClose(conn, muxstream.DefaultHalfCloseDrainTimeout)
	st.cancelServe()
}

func (st *muxServerState) handleOpenFwd(ctx context.Context, conn net.Conn, body []byte, isTUN bool) {
	reqID, spec, err := decodeFwdPayload(body, isTUN)
	if err != nil {
		_ = muxstream.WriteStatusReply(conn, muxstream.SFailure, reqID, err.Error())
		return
	}
	if st.forwarder == nil {
		_ = muxstream.WriteStatusReply(conn, muxstream.SFailure, reqID, "forwarder unavailable")
		return
	}
	key := forwardSpecKey(spec)
	if st.hasForward(key) {
		_ = muxstream.WriteStatusReply(conn, muxstream.SFailure, reqID, "forward already exists")
		return
	}
	handle, fErr := st.forwarder.StartForward(ctx, st.upstream, spec)
	if fErr != nil {
		_ = muxstream.WriteStatusReply(conn, muxstream.SFailure, reqID, fErr.Error())
		return
	}
	if !st.storeForward(key, handle) {
		_ = handle.Close()
		_ = muxstream.WriteStatusReply(conn, muxstream.SFailure, reqID, "forward already exists")
		return
	}
	st.writeOpenFwdSuccess(conn, reqID, spec, handle.BoundAddr())
}

func decodeFwdPayload(body []byte, isTUN bool) (uint32, ports.ForwardSpec, error) {
	if isTUN {
		return muxstream.DecodeTUNForwardWire(body)
	}
	return muxstream.DecodeForwardWire(body)
}

func (st *muxServerState) writeOpenFwdSuccess(conn net.Conn, reqID uint32, spec ports.ForwardSpec, boundAddr string) {
	if spec.Direction() == ports.ForwardRemote && spec.BindKind() == ports.ForwardEndpointTCP {
		if _, portStr, err := net.SplitHostPort(boundAddr); err == nil {
			if p, pErr := strconv.ParseUint(portStr, 10, 32); pErr == nil && p > 0 {
				body := muxstream.AppendU32(muxstream.AppendU32(nil, reqID), uint32(p))
				_ = muxstream.WritePacket(conn, muxstream.SRemotePort, body)
				return
			}
		}
	}
	_ = muxstream.WriteStatusReply(conn, muxstream.SOK, reqID, "")
}

func (st *muxServerState) handleCloseFwd(conn net.Conn, body []byte, isTUN bool) {
	reqID, spec, err := decodeFwdPayload(body, isTUN)
	if err != nil {
		_ = muxstream.WriteStatusReply(conn, muxstream.SFailure, reqID, err.Error())
		return
	}
	h := st.takeForward(forwardSpecKey(spec))
	if h == nil {
		_ = muxstream.WriteStatusReply(conn, muxstream.SFailure, reqID, "forward not found")
		return
	}
	_ = h.Close()
	_ = muxstream.WriteStatusReply(conn, muxstream.SOK, reqID, "")
}

func (st *muxServerState) handleProxyMode(ctx context.Context, conn net.Conn, body []byte) {
	rd := muxstream.NewReader(body)
	reqID, err := rd.ReadUint32()
	if err != nil {
		return
	}
	if err := muxstream.WritePacket(conn, muxstream.SProxy, muxstream.AppendU32(nil, reqID)); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if st.owner.proxyHandler != nil {
		_ = st.owner.proxyHandler(ctx, conn, st.upstream)
		if ctx.Err() == nil {
			muxstream.GracefulHalfClose(conn, muxstream.DefaultHalfCloseDrainTimeout)
		}
		return
	}
	// 默认代理模式保持双向连接存活直至客户端半关闭/断开或 ControlMaster 停机。
	_, _ = io.Copy(io.Discard, conn)
}

func (st *muxServerState) hasForward(key string) bool {
	st.fwdMu.Lock()
	_, ok := st.forwards[key]
	st.fwdMu.Unlock()
	return ok
}

func (st *muxServerState) storeForward(key string, h ports.ForwardHandle) bool {
	st.fwdMu.Lock()
	defer st.fwdMu.Unlock()
	if st.forwards == nil || st.forwards[key] != nil {
		return false
	}
	st.forwards[key] = h
	return true
}

func (st *muxServerState) takeForward(key string) ports.ForwardHandle {
	st.fwdMu.Lock()
	defer st.fwdMu.Unlock()
	h := st.forwards[key]
	delete(st.forwards, key)
	return h
}

func (st *muxServerState) closeAllForwards() {
	st.fwdMu.Lock()
	list := make([]ports.ForwardHandle, 0, len(st.forwards))
	for k, h := range st.forwards {
		list = append(list, h)
		delete(st.forwards, k)
	}
	st.fwdMu.Unlock()
	for _, h := range list {
		if h != nil {
			_ = h.Close()
		}
	}
}

func forwardSpecKey(s ports.ForwardSpec) string {
	return s.Direction().String() + ":" + s.BindKind().String() + ":" + s.BindAddr() + "->" + s.TargetKind().String() + ":" + s.TargetAddr()
}
