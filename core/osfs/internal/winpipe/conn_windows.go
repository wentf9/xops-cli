//go:build windows

package winpipe

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

type pipeAddr string

func (pipeAddr) Network() string  { return "pipe" }
func (a pipeAddr) String() string { return string(a) }

// opSlot 隔离单方向（读/写）重叠 I/O 句柄、堆驻留 Overlapped 结构、同向串行互斥与可中断截止期，确保全双工无数据竞争。
type opSlot struct {
	mu     sync.Mutex
	dlMu   sync.Mutex
	dl     time.Time
	ioEv   windows.Handle
	wake   windows.Handle
	ov     windows.Overlapped
	closed bool
}

func (s *opSlot) setDeadline(t time.Time) error {
	s.dlMu.Lock()
	defer s.dlMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.dl = t
	return windows.SetEvent(s.wake)
}

func (s *opSlot) markClosed() {
	s.dlMu.Lock()
	s.closed = true
	_ = windows.SetEvent(s.wake)
	s.dlMu.Unlock()
}

func (s *opSlot) waitBudget(connClosed *atomic.Bool) (uint32, error) {
	s.dlMu.Lock()
	var resetErr error
	if !connClosed.Load() {
		resetErr = windows.ResetEvent(s.wake)
	}
	dl := s.dl
	s.dlMu.Unlock()
	if resetErr != nil {
		return 0, resetErr
	}
	if dl.IsZero() {
		return windows.INFINITE, nil
	}
	rem := time.Until(dl)
	if rem <= 0 {
		return 0, os.ErrDeadlineExceeded
	}
	ms := (rem + time.Millisecond - 1) / time.Millisecond
	return uint32(min(ms, time.Duration(windows.INFINITE-1))), nil
}

// Conn 直接基于每方向独立 Overlapped 事件与 closeMu 读写屏障实现全双工 Windows Named Pipe net.Conn。
// 读/写路径互不共享可变状态，Close 通过 CancelIoEx 与写锁等待全部活跃重叠 I/O 排空后再关闭句柄。
type Conn struct {
	h         windows.Handle
	addr      pipeAddr
	rSlot     opSlot
	wSlot     opSlot
	closed    atomic.Bool
	closeMu   sync.RWMutex
	closeOnce sync.Once
	closeErr  error
}

// NewConn 将已通过安全校验的 FILE_FLAG_OVERLAPPED 命名管道句柄封装为全双工 net.Conn。
// 调用失败时不关闭 h，由调用方负责回收。
func NewConn(h windows.Handle, pipePath string) (*Conn, error) {
	var evs [4]windows.Handle
	for i := range evs {
		ev, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			for j := range i {
				_ = windows.CloseHandle(evs[j])
			}
			return nil, err
		}
		evs[i] = ev
	}
	return &Conn{
		h:     h,
		addr:  pipeAddr(pipePath),
		rSlot: opSlot{ioEv: evs[0], wake: evs[1]},
		wSlot: opSlot{ioEv: evs[2], wake: evs[3]},
	}, nil
}

// LocalAddr 返回本地命名管道地址元数据（Network()=="pipe"）。
func (c *Conn) LocalAddr() net.Addr { return c.addr }

// RemoteAddr 返回对端命名管道地址元数据。
func (c *Conn) RemoteAddr() net.Addr { return c.addr }

// SetReadDeadline 设置读方向截止期并立即唤醒阻塞中的 Read。
func (c *Conn) SetReadDeadline(t time.Time) error { return c.rSlot.setDeadline(t) }

// SetWriteDeadline 设置写方向截止期并立即唤醒阻塞中的 Write。
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.wSlot.setDeadline(t) }

// SetDeadline 同时设置读/写双方向截止期。
func (c *Conn) SetDeadline(t time.Time) error {
	return errors.Join(c.rSlot.setDeadline(t), c.wSlot.setDeadline(t))
}

// Close 幂等取消全部在途重叠 I/O，待全部读/写完成 GetOverlappedResult 排空后关闭底层与事件句柄。
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.rSlot.markClosed()
		c.wSlot.markClosed()
		_ = windows.CancelIoEx(c.h, nil)
		c.closeMu.Lock()
		c.closeErr = errors.Join(
			windows.CloseHandle(c.h),
			windows.CloseHandle(c.rSlot.ioEv),
			windows.CloseHandle(c.rSlot.wake),
			windows.CloseHandle(c.wSlot.ioEv),
			windows.CloseHandle(c.wSlot.wake),
		)
		c.closeMu.Unlock()
	})
	return c.closeErr
}

// Read 以读方向独立 Overlapped 通道读取字节，支持与 Write 并发执行。
func (c *Conn) Read(p []byte) (int, error) {
	return c.doOverlapped(&c.rSlot, true, p)
}

// Write 以写方向独立 Overlapped 通道完整写出 p，支持与 Read 并发执行。
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return c.doOverlapped(&c.wSlot, false, nil)
	}
	written := 0
	for written < len(p) {
		n, err := c.doOverlapped(&c.wSlot, false, p[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func (c *Conn) doOverlapped(slot *opSlot, isRead bool, p []byte) (int, error) {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	c.closeMu.RLock()
	defer c.closeMu.RUnlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if _, err := slot.waitBudget(&c.closed); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := windows.ResetEvent(slot.ioEv); err != nil {
		return 0, err
	}
	// Overlapped 与缓冲区必须在整个内核异步 I/O 期间常驻堆并固定地址，
	// 防止 goroutine 栈扩容搬移导致内核将 IO_STATUS_BLOCK 写入旧栈而引发假 io.EOF 或内存破坏。
	slot.ov = windows.Overlapped{HEvent: slot.ioEv}
	var pinner runtime.Pinner
	pinner.Pin(&slot.ov)
	pinner.Pin(&p[0])
	defer pinner.Unpin()

	// 传入非 nil &done 避免 x/sys/windows 在 -race 模式下解引用 nil；
	// 同步完成 (err == nil) 时仍经 GetOverlappedResult 读取权威字节数，防止 done 保持 0 误报 io.EOF / io.ErrShortWrite。
	var done uint32
	err := startPipeIO(c.h, isRead, p, &done, &slot.ov)
	switch {
	case err == nil:
		err = windows.GetOverlappedResult(c.h, &slot.ov, &done, true)
	case errors.Is(err, windows.ERROR_IO_PENDING):
		done, err = c.waitOverlapped(slot, &slot.ov)
	}
	return int(done), c.mapIOErr(isRead, done, err)
}

func startPipeIO(h windows.Handle, isRead bool, p []byte, done *uint32, ov *windows.Overlapped) error {
	if isRead {
		return windows.ReadFile(h, p, done, ov)
	}
	return windows.WriteFile(h, p, done, ov)
}

func (c *Conn) waitOverlapped(slot *opSlot, ov *windows.Overlapped) (uint32, error) {
	var waitErr error
	for {
		ms, bErr := slot.waitBudget(&c.closed)
		if bErr != nil || c.closed.Load() {
			_ = windows.CancelIoEx(c.h, ov)
			break
		}
		res, wErr := windows.WaitForMultipleObjects([]windows.Handle{ov.HEvent, slot.wake}, false, ms)
		if wErr != nil || res == windows.WAIT_OBJECT_0 {
			if wErr != nil {
				waitErr = wErr
				_ = windows.CancelIoEx(c.h, ov)
			}
			break
		}
	}
	var done uint32
	// 返回前必须以 wait=true 排空内核挂起引用，避免栈上 Overlapped 与调用方切片悬空。
	err := windows.GetOverlappedResult(c.h, ov, &done, true)
	if waitErr != nil && errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		return done, waitErr
	}
	return done, err
}

func (c *Conn) mapIOErr(isRead bool, done uint32, err error) error {
	if err == nil {
		if isRead && done == 0 {
			return io.EOF
		}
		return nil
	}
	if isRead && (errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_HANDLE_EOF)) {
		if done > 0 {
			return nil
		}
		return io.EOF
	}
	if errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		if c.closed.Load() {
			return net.ErrClosed
		}
		return os.ErrDeadlineExceeded
	}
	return err
}
