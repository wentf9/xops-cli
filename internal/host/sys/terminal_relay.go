package sys

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/ports"
)

type terminalHandle struct {
	owner    *Terminal
	resizeCh <-chan ports.TerminalSize
	active   atomic.Bool
}

func (t *Terminal) newHandle(resizeCh <-chan ports.TerminalSize) *terminalHandle {
	h := &terminalHandle{owner: t, resizeCh: resizeCh}
	h.active.Store(true)
	return h
}

func (h *terminalHandle) expire() {
	if h != nil {
		h.active.Store(false)
	}
}

func (h *terminalHandle) isActive() bool {
	return h != nil && h.owner != nil && h.active.Load()
}

func (h *terminalHandle) Read(p []byte) (int, error) {
	if !h.isActive() {
		return 0, ports.ErrHandleExpired
	}
	if h.owner.isFileMode {
		return h.owner.inFile.Read(p)
	}
	return h.owner.streamIn.Read(p)
}

func (h *terminalHandle) Write(p []byte) (int, error) {
	if !h.isActive() {
		return 0, ports.ErrHandleExpired
	}
	if h.owner.isFileMode {
		return h.owner.outFile.Write(p)
	}
	return h.owner.streamOut.Write(p)
}

func (h *terminalHandle) Size() (ports.TerminalSize, error) {
	if !h.isActive() {
		return zeroVal[ports.TerminalSize](), ports.ErrHandleExpired
	}
	return h.owner.Size()
}

func (h *terminalHandle) ResizeEvents() <-chan ports.TerminalSize {
	if !h.isActive() {
		return nil
	}
	return h.resizeCh
}

// Relay 在 core/conc.RunScoped 监督下同步执行本机终端与远端流之间的双向中继与窗口尺寸同步（零裸 go）：
//   - 本地输入先达 io.EOF 时，若 remoteIn 实现 io.Closer 则半关闭以传递 EOF，同时继续排空 remoteOut；
//   - 远端输出先达 io.EOF（远端命令或 Shell 退出）时，立即取消作用域并经平台取消句柄唤醒阻塞中的本地输入与缩放协程，
//     在全部子协程彻底收敛退出后返回，确保零协程泄漏（goleak.VerifyNone）。
//
//xops:syncclosure
func (h *terminalHandle) Relay(
	ctx context.Context,
	remoteIn io.Writer,
	remoteOut io.Reader,
	onResize func(ctx context.Context, size ports.TerminalSize) error,
) error {
	if err := h.checkRelayArgs(ctx, remoteIn, remoteOut); err != nil {
		return err
	}
	localIn, unblock, closeReader, err := h.openCancelableInput()
	if err != nil {
		return err
	}
	defer closeReader()

	var unblockOnce sync.Once
	triggerUnblock := func() {
		unblockOnce.Do(unblock)
	}
	stopParent := context.AfterFunc(ctx, triggerUnblock)
	defer stopParent()

	remoteDone := make(chan struct{})
	var closeRemoteDoneOnce sync.Once
	markRemoteDone := func() {
		closeRemoteDoneOnce.Do(func() { close(remoteDone) })
	}
	return conc.RunScoped(ctx, func(scopeCtx context.Context, n *conc.Nursery) error {
		stopScope := context.AfterFunc(scopeCtx, triggerUnblock)
		defer stopScope()
		defer func() {
			markRemoteDone()
			triggerUnblock()
		}()

		if err := n.Go(func(c context.Context) error {
			return pumpLocalInput(c, ctx, localIn, remoteIn, remoteDone)
		}); err != nil {
			return err
		}
		if onResize != nil {
			if err := n.Go(func(c context.Context) error {
				return pumpResizeLoop(c, ctx, h.resizeCh, remoteDone, onResize)
			}); err != nil {
				return err
			}
		}
		return copyRemoteOutput(scopeCtx, h, remoteOut)
	})
}

func (h *terminalHandle) checkRelayArgs(ctx context.Context, remoteIn io.Writer, remoteOut io.Reader) error {
	if !h.isActive() {
		return ports.ErrHandleExpired
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	if remoteIn == nil || remoteOut == nil {
		return ports.ErrInvalidArgument
	}
	return ctx.Err()
}

func (h *terminalHandle) openCancelableInput() (r io.Reader, unblock, cleanup func(), err error) {
	if h.owner.isFileMode {
		return newCancelableFileReaderOS(h.owner.inFile)
	}
	unblock = func() {}
	if h.owner.unblockFn != nil {
		unblock = h.owner.unblockFn
	}
	return h.owner.streamIn, unblock, func() {}, nil
}

func pumpLocalInput(scopeCtx, parentCtx context.Context, localIn io.Reader, remoteIn io.Writer, remoteDone <-chan struct{}) error {
	buf := make([]byte, 4096)
	for {
		if err := parentCtx.Err(); err != nil {
			return err
		}
		n, rErr := localIn.Read(buf)
		if n > 0 {
			if _, wErr := remoteIn.Write(buf[:n]); wErr != nil {
				return wErr
			}
		}
		if rErr != nil {
			return handleLocalInputEnd(scopeCtx, parentCtx, rErr, remoteIn, remoteDone)
		}
	}
}

func handleLocalInputEnd(scopeCtx, parentCtx context.Context, rErr error, remoteIn io.Writer, remoteDone <-chan struct{}) error {
	if errors.Is(rErr, errInputCanceled) {
		if err := parentCtx.Err(); err != nil {
			return err
		}
		if isClosedChan(remoteDone) {
			return nil
		}
		return scopeCtx.Err()
	}
	if errors.Is(rErr, io.EOF) {
		if parentCtx.Err() == nil && !isClosedChan(remoteDone) {
			if cl, ok := remoteIn.(io.Closer); ok {
				_ = cl.Close()
			}
		}
		return parentCtx.Err()
	}
	return rErr
}

func copyRemoteOutput(scopeCtx context.Context, dst io.Writer, remoteOut io.Reader) error {
	buf := make([]byte, 4096)
	for {
		if err := scopeCtx.Err(); err != nil {
			return err
		}
		n, rErr := remoteOut.Read(buf)
		if n > 0 {
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				return scopeCtx.Err()
			}
			return rErr
		}
	}
}

func pumpResizeLoop(scopeCtx, parentCtx context.Context, ch <-chan ports.TerminalSize, remoteDone <-chan struct{}, onResize func(context.Context, ports.TerminalSize) error) error {
	for {
		sz, ok, done, err := nextResizeOrDone(scopeCtx, parentCtx, ch, remoteDone, onResize)
		if err != nil || done || !ok {
			return err
		}
		if err := onResize(parentCtx, sz); err != nil {
			return err
		}
	}
}

func nextResizeOrDone(
	scopeCtx, parentCtx context.Context,
	ch <-chan ports.TerminalSize,
	remoteDone <-chan struct{},
	onResize func(context.Context, ports.TerminalSize) error,
) (ports.TerminalSize, bool, bool, error) {
	// 优先非阻塞消费已排队的窗口缩放事件，确保远端短命退出时也不丢弃已到达的尺寸变更。
	select {
	case sz, ok := <-ch:
		return sz, ok, !ok, nil
	default:
	}
	select {
	case sz, ok := <-ch:
		return sz, ok, !ok, nil
	case <-remoteDone:
		return finishResizeOnStop(parentCtx, parentCtx.Err(), ch, onResize)
	case <-scopeCtx.Done():
		return finishResizeOnStop(parentCtx, scopeCtx.Err(), ch, onResize)
	}
}

func finishResizeOnStop(
	parentCtx context.Context,
	stopErr error,
	ch <-chan ports.TerminalSize,
	onResize func(context.Context, ports.TerminalSize) error,
) (ports.TerminalSize, bool, bool, error) {
	var zero ports.TerminalSize
	if parentCtx.Err() == nil {
		if err := drainBufferedResizes(parentCtx, ch, onResize); err != nil {
			return zero, false, true, err
		}
	}
	return zero, false, true, stopErr
}

func drainBufferedResizes(parentCtx context.Context, ch <-chan ports.TerminalSize, onResize func(context.Context, ports.TerminalSize) error) error {
	for {
		select {
		case sz, ok := <-ch:
			if !ok {
				return nil
			}
			if err := onResize(parentCtx, sz); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

func isClosedChan(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
