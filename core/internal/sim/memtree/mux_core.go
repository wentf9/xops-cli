package memtree

import (
	"context"
	"sync"

	"github.com/wentf9/xops-cli/core/ports"
)

// MuxMasterEntry 记录纯内存 ControlMaster 仿真槽位的进程 PID、退出信号与可选服务端状态。
type MuxMasterEntry struct {
	PID       uint32
	StopCh    chan struct{}
	stopOnce  sync.Once
	Upstream  ports.TransportConn
	Forwarder ports.ForwarderPort
	Forwards  map[string]ports.ForwardHandle
}

// SignalStop 幂等关闭 StopCh 以唤醒阻塞中的 Serve 循环。
func (e *MuxMasterEntry) SignalStop() {
	if e != nil && e.StopCh != nil {
		e.stopOnce.Do(func() { close(e.StopCh) })
	}
}

// CloseForwards 关闭并清空本主进程托管的全部动态端口转发句柄。
func (e *MuxMasterEntry) CloseForwards() {
	if e == nil {
		return
	}
	for k, h := range e.Forwards {
		if h != nil {
			_ = h.Close()
		}
		delete(e.Forwards, k)
	}
}

// MuxRegistry 封装 SimMuxSocket 的纯内存主进程注册表与 PROTOCOL.mux v4 控制动作分发（无外部锁）。
type MuxRegistry struct {
	Masters map[string]*MuxMasterEntry
}

// NewMuxRegistry 创建空白多路复用注册表。
func NewMuxRegistry() *MuxRegistry {
	return &MuxRegistry{Masters: make(map[string]*MuxMasterEntry)}
}

// RegisterLocked 注册指定套接字路径的仿真主进程 PID。
func (r *MuxRegistry) RegisterLocked(addr string, pid uint32) {
	r.Masters[addr] = &MuxMasterEntry{PID: pid, StopCh: make(chan struct{}), Forwards: make(map[string]ports.ForwardHandle)}
}

// AcquireListenLocked 抢占监听槽位；已占用返回 false。
func (r *MuxRegistry) AcquireListenLocked(addr string, pid uint32) bool {
	if r.Masters[addr] != nil {
		return false
	}
	r.RegisterLocked(addr, pid)
	return true
}

// ReleaseListenLocked 释放监听槽位并唤醒可能仍在运行的 Serve。
func (r *MuxRegistry) ReleaseListenLocked(addr string) {
	if e := r.Masters[addr]; e != nil {
		e.SignalStop()
		e.CloseForwards()
		delete(r.Masters, addr)
	}
}

// AttachServerLocked 为指定地址上的主进程绑定 upstream/forwarder 并返回退出信号通道。
func (r *MuxRegistry) AttachServerLocked(addr string, upstream ports.TransportConn, forwarder ports.ForwarderPort) <-chan struct{} {
	e := r.Masters[addr]
	if e == nil {
		return nil
	}
	e.Upstream, e.Forwarder = upstream, forwarder
	return e.StopCh
}

// DetachServerLocked 清理服务端持有的转发与绑定引用。
func (r *MuxRegistry) DetachServerLocked(addr string) {
	if e := r.Masters[addr]; e != nil {
		e.CloseForwards()
		e.Upstream, e.Forwarder = nil, nil
	}
}

// ApplyControlLocked 在锁内处理 Control 请求并在必要时提取转发执行所需的非持锁回调上下文。
func (r *MuxRegistry) ApplyControlLocked(req ports.MuxControlRequest) (pid uint32, up ports.TransportConn, fwd ports.ForwarderPort, cancelHandle ports.ForwardHandle, ok bool) {
	k := req.SocketPath().String()
	e := r.Masters[k]
	if e == nil || e.PID == 0 {
		return 0, nil, nil, nil, false
	}
	pid = e.PID
	switch req.Action() {
	case ports.MuxActionExit, ports.MuxActionStop:
		e.SignalStop()
		e.CloseForwards()
		delete(r.Masters, k)
	case ports.MuxActionForward:
		up, fwd = e.Upstream, e.Forwarder
	case ports.MuxActionCancel:
		if fs, has := req.Forward().Get(); has {
			fk := forwardKey(fs)
			cancelHandle = e.Forwards[fk]
			delete(e.Forwards, fk)
		}
	}
	return pid, up, fwd, cancelHandle, true
}

// StoreForwardLocked 将成功启动的动态转发句柄登记到活跃主进程（若期间已停机则返回 false 以便立即关闭）。
func (r *MuxRegistry) StoreForwardLocked(addr string, spec ports.ForwardSpec, h ports.ForwardHandle) bool {
	e := r.Masters[addr]
	if e == nil || e.Upstream == nil {
		return false
	}
	if e.Forwards == nil {
		e.Forwards = make(map[string]ports.ForwardHandle)
	}
	e.Forwards[forwardKey(spec)] = h
	return true
}

func forwardKey(s ports.ForwardSpec) string {
	return s.Direction().String() + ":" + s.BindKind().String() + ":" + s.BindAddr() + "->" + s.TargetKind().String() + ":" + s.TargetAddr()
}

// RunServeWait 阻塞等待控制面停止信号或 ctx 取消（stopCh 为 nil 表示在 Serve 附着前已停止）。
func RunServeWait(ctx context.Context, stopCh <-chan struct{}) error {
	if stopCh == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stopCh:
		return nil
	}
}
