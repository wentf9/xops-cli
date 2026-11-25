package memtree

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/ports"
)

// TerminalHandle 实现 ports.TerminalHandle，封装带运行时失效哨兵的纯内存 PTY 输入/输出、缩放与双向 Relay。
type TerminalHandle struct {
	size       ports.TerminalSize
	inMu       sync.Mutex
	inR        *bytes.Reader
	blockAfter bool
	onWrite    func([]byte)
	stopMu     sync.Mutex
	stopCh     chan struct{}
	resizeCh   chan ports.TerminalSize
	valid      bool
	expired    atomic.Bool
}

// NewTerminalHandle 构造受失效哨兵保护的纯内存终端句柄并返回过期清理函数。
func NewTerminalHandle(size ports.TerminalSize, inSnap []byte, blockAfter bool, resizes []ports.TerminalSize, onWrite func([]byte)) (*TerminalHandle, func()) {
	resizeCh := make(chan ports.TerminalSize, max(4, len(resizes)))
	for _, rsz := range resizes {
		resizeCh <- rsz
	}
	h := &TerminalHandle{size: size, inR: bytes.NewReader(inSnap), blockAfter: blockAfter, onWrite: onWrite, resizeCh: resizeCh, valid: true}
	return h, func() { h.expired.Store(true); close(resizeCh) }
}

func (h *TerminalHandle) alive() bool                             { return h != nil && h.valid && !h.expired.Load() }
func (h *TerminalHandle) ResizeEvents() <-chan ports.TerminalSize { return h.resizeCh }
func (h *TerminalHandle) setStopCh(ch chan struct{}) {
	h.stopMu.Lock()
	h.stopCh = ch
	h.stopMu.Unlock()
}
func (h *TerminalHandle) currentStopCh() chan struct{} {
	h.stopMu.Lock()
	ch := h.stopCh
	h.stopMu.Unlock()
	return ch
}

// Read 从预置终端输入流读取字节；blockAfter 为 true 且耗尽后等待中继退出信号。
func (h *TerminalHandle) Read(p []byte) (int, error) {
	if !h.alive() {
		return 0, ports.ErrHandleExpired
	}
	h.inMu.Lock()
	var n int
	var err error
	if h.inR != nil {
		n, err = h.inR.Read(p)
	} else {
		err = io.EOF
	}
	h.inMu.Unlock()
	if n > 0 || err != io.EOF || !h.blockAfter {
		return n, err
	}
	if ch := h.currentStopCh(); ch != nil {
		<-ch
	}
	return 0, io.EOF
}

// Write 将输出字节递交至终端输出接收回调。
func (h *TerminalHandle) Write(p []byte) (int, error) {
	if !h.alive() {
		return 0, ports.ErrHandleExpired
	}
	if h.onWrite != nil {
		h.onWrite(p)
	}
	return len(p), nil
}

// Size 返回当前窗口尺寸。
func (h *TerminalHandle) Size() (out ports.TerminalSize, err error) {
	if !h.alive() {
		return out, ports.ErrHandleExpired
	}
	return h.size, nil
}

// Relay 在同步作用域内并发驱动终端输入、远端输出与窗口缩放回调（零裸 go、零泄漏）。
//
//xops:syncclosure
func (h *TerminalHandle) Relay(ctx context.Context, remoteIn io.Writer, remoteOut io.Reader, onResize func(ctx context.Context, size ports.TerminalSize) error) error {
	if !h.alive() {
		return ports.ErrHandleExpired
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if remoteIn == nil || remoteOut == nil {
		return ports.ErrInvalidArgument
	}
	stopCh := make(chan struct{})
	var stopOnce sync.Once
	triggerStop := func() { stopOnce.Do(func() { close(stopCh) }) }
	h.setStopCh(stopCh)
	defer func() { triggerStop(); h.setStopCh(nil) }()
	return RelayTerminalStreams(ctx, h, h, remoteIn, remoteOut, h.resizeCh, onResize, triggerStop)
}
