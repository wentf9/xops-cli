package memtree

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/ports"
)

// ForwardHandle 实现 ports.ForwardHandle 与 pool.ManagedResource，持留池钉选的 TunnelTransport 直至 Close。
//
//xops:opaque
//xops:failclosed
type ForwardHandle struct {
	initialized bool
	spec        ports.ForwardSpec
	boundAddr   string
	transport   ports.TunnelTransport
	closer      io.Closer
	doneCh      chan struct{}
	closeOnce   sync.Once
	closed      atomic.Bool
	closeErr    error
}

// NewForwardHandle 构造已启动的纯内存转发句柄并托管底层资源关闭。
func NewForwardHandle(spec ports.ForwardSpec, boundAddr string, transport ports.TunnelTransport, closer io.Closer) *ForwardHandle {
	return &ForwardHandle{
		initialized: true, spec: spec, boundAddr: boundAddr,
		transport: transport, closer: closer, doneCh: make(chan struct{}),
	}
}

func (h *ForwardHandle) IsValid() bool           { return h != nil && h.initialized && !h.closed.Load() }
func (h *ForwardHandle) Spec() ports.ForwardSpec { return h.spec }
func (h *ForwardHandle) BoundAddr() string       { return h.boundAddr }
func (h *ForwardHandle) Done() <-chan struct{}   { return h.doneCh }
func (h *ForwardHandle) Err() error              { return h.closeErr }

// OpenChannel 在 StartForward 返回后通过持留的 transport 再次打开并关闭一条数据通道，验证长生命周期非借用传输契约。
func (h *ForwardHandle) OpenChannel(ctx context.Context) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !h.IsValid() || h.transport == nil {
		return ports.ErrClosed
	}
	if h.spec.Direction() == ports.ForwardDynamic {
		hp, err := netaddr.ParseHostPort("127.0.0.1:80")
		if err != nil {
			return err
		}
		c, err := h.transport.DialTCP(ctx, hp)
		if err == nil && c != nil {
			_ = c.Close()
		}
		return err
	}
	_, c, err := OpenSimForwardChannel(ctx, h.transport, h.spec)
	if err == nil && c != nil {
		_ = c.Close()
	}
	return err
}

// Close 幂等关闭底层监听/隧道连接并广播 Done 通道。
func (h *ForwardHandle) Close() error {
	if h == nil || !h.initialized {
		return nil
	}
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		if h.closer != nil {
			h.closeErr = h.closer.Close()
		}
		close(h.doneCh)
	})
	return h.closeErr
}
