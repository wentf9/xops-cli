package chanconn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/ports"
)

// WatchedConn 将不原生支持 SetDeadline 的 ssh.Channel 封装为带强制取消/截止时间看门狗的 net.Conn（ADR-015）。
//
// 生命周期与半开黑洞防挂死不变量：
//   - 所有带外排空、O(1) 截止看门狗与脱离的 Read/Write 均受上游 lifeNursery 统一托管，零裸 go；
//   - 仅当具体方向存在活跃 I/O 且该方向当前截止时间确已到期时才中止通道，清除/延长截止或空闲态永不误杀；
//   - 脱离的 Read 读入内部独立缓冲、Write 拷贝内部切片，通道中止返回后绝不触碰调用方切片（-race 安全）；
//   - 对端进入半开黑洞（不回传 SSH_MSG_CHANNEL_CLOSE）时，abortCh 立即唤醒 Read/Write 与上层握手，
//     Close() 经有界宽限返回且不伤健康父连接，父连接 Close() 关底层 TCP 时 100% 回收全部协程（零泄漏）。
//
//xops:opaque
//xops:failclosed
type WatchedConn struct {
	lifeNursery *conc.Nursery
	ch          ssh.Channel
	localAddr   net.Addr
	remoteAddr  net.Addr
	clock       ports.Clock

	abortCh      chan struct{}
	abortOnce    sync.Once
	wakeCh       chan struct{}
	drainersDone chan struct{}
	watcherDone  chan struct{}

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	activeReads   int
	activeWrites  int
	deadlineHit   atomic.Bool
	closed        atomic.Bool
	closeOnce     sync.Once
	closeErr      error
	valid         bool
}

// WrapChannel 创建受 lifeNursery 监督的 ssh.Channel 包装器并启动带外排空与 O(1) 截止看门狗。
func WrapChannel(
	lifeNursery *conc.Nursery,
	ch ssh.Channel,
	reqs <-chan *ssh.Request,
	localAddr, remoteAddr net.Addr,
	clk ports.Clock,
) (*WatchedConn, error) {
	if lifeNursery == nil || ch == nil {
		if ch != nil {
			_ = ch.Close()
		}
		return nil, ports.ErrClosed
	}
	wc := &WatchedConn{
		lifeNursery:  lifeNursery,
		ch:           ch,
		localAddr:    localAddr,
		remoteAddr:   remoteAddr,
		clock:        clk,
		abortCh:      make(chan struct{}),
		wakeCh:       make(chan struct{}, 1),
		drainersDone: make(chan struct{}),
		watcherDone:  make(chan struct{}),
		valid:        true,
	}
	if err := wc.startBackgroundWorkers(reqs); err != nil {
		wc.signalAbort(false)
		_ = ch.Close()
		return nil, err
	}
	return wc, nil
}

func (c *WatchedConn) startBackgroundWorkers(reqs <-chan *ssh.Request) error {
	if err := c.lifeNursery.Go(func(nCtx context.Context) error {
		defer close(c.watcherDone)
		return c.runDeadlineWatcher(nCtx)
	}); err != nil {
		close(c.watcherDone)
		close(c.drainersDone)
		return ports.ErrClosed
	}
	var rem atomic.Int32
	rem.Store(1)
	if reqs != nil {
		rem.Store(2)
	}
	doneOne := func() {
		if rem.Add(-1) == 0 {
			close(c.drainersDone)
		}
	}
	if reqs != nil {
		if err := c.lifeNursery.Go(func(context.Context) error {
			defer doneOne()
			ssh.DiscardRequests(reqs)
			return nil
		}); err != nil {
			doneOne()
			doneOne()
			return ports.ErrClosed
		}
	}
	if err := c.lifeNursery.Go(func(context.Context) error {
		defer doneOne()
		if stderr := c.ch.Stderr(); stderr != nil {
			_, _ = io.Copy(io.Discard, stderr)
		}
		return nil
	}); err != nil {
		doneOne()
		return ports.ErrClosed
	}
	return nil
}

func (c *WatchedConn) now() time.Time {
	if c.clock != nil {
		return c.clock.Now()
	}
	return time.Now()
}

func (c *WatchedConn) signalAbort(dueToDeadline bool) {
	if dueToDeadline {
		c.deadlineHit.Store(true)
	}
	c.abortOnce.Do(func() { close(c.abortCh) })
}

func (c *WatchedConn) abortForDeadline() {
	c.signalAbort(true)
	_ = c.lifeNursery.Go(func(context.Context) error {
		_ = c.ch.Close()
		return nil
	})
}

func (c *WatchedConn) notifyDeadlineWatcher() {
	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}

func (c *WatchedConn) runDeadlineWatcher(nurseryCtx context.Context) error {
	for {
		waitDur, expired := c.nextActiveDeadlineWait()
		if expired {
			c.abortForDeadline()
			return nil
		}
		if waitDur < 0 {
			select {
			case <-c.abortCh:
				return nil
			case <-nurseryCtx.Done():
				return nil
			case <-c.wakeCh:
				continue
			}
		}
		if c.waitDeadlineOrWake(nurseryCtx, waitDur) {
			return nil
		}
	}
}

func (c *WatchedConn) nextActiveDeadlineWait() (time.Duration, bool) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var earliest time.Time
	if c.activeReads > 0 && !c.readDeadline.IsZero() {
		if !now.Before(c.readDeadline) {
			return 0, true
		}
		earliest = c.readDeadline
	}
	if c.activeWrites > 0 && !c.writeDeadline.IsZero() {
		if !now.Before(c.writeDeadline) {
			return 0, true
		}
		if earliest.IsZero() || c.writeDeadline.Before(earliest) {
			earliest = c.writeDeadline
		}
	}
	if earliest.IsZero() {
		return -1, false
	}
	return earliest.Sub(now), false
}

func (c *WatchedConn) waitDeadlineOrWake(nurseryCtx context.Context, d time.Duration) bool {
	if c.clock != nil {
		tm := c.clock.NewTimer(d)
		defer tm.Stop()
		select {
		case <-c.abortCh:
			return true
		case <-nurseryCtx.Done():
			return true
		case <-c.wakeCh:
			return false
		case <-tm.C():
			return false
		}
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-c.abortCh:
		return true
	case <-nurseryCtx.Done():
		return true
	case <-c.wakeCh:
		return false
	case <-tm.C:
		return false
	}
}

type channelIOResult struct {
	n   int
	err error
}

// Read 从底层 ssh.Channel 读取字节；受 O(1) 读截止看门狗与半开黑洞即时解阻保护。
func (c *WatchedConn) Read(p []byte) (int, error) {
	if err := c.checkReadyForIO(true); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.enterIO(true)
	defer c.leaveIO(true)
	return c.runDetachedRead(p)
}

// Write 向底层 ssh.Channel 分块写入字节；受 O(1) 写截止看门狗与半开黑洞即时解阻保护。
func (c *WatchedConn) Write(p []byte) (int, error) {
	if err := c.checkReadyForIO(false); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.enterIO(false)
	defer c.leaveIO(false)
	total := 0
	for total < len(p) {
		end := min(total+MaxCopyChunk, len(p))
		n, err := c.runDetachedWrite(bytes.Clone(p[total:end]))
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (c *WatchedConn) checkReadyForIO(isRead bool) error {
	if c == nil || !c.valid {
		return ports.ErrClosed
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	if c.deadlineHit.Load() {
		return os.ErrDeadlineExceeded
	}
	now := c.now()
	c.mu.Lock()
	dl := c.writeDeadline
	if isRead {
		dl = c.readDeadline
	}
	c.mu.Unlock()
	if !dl.IsZero() && !now.Before(dl) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (c *WatchedConn) enterIO(isRead bool) {
	c.mu.Lock()
	if isRead {
		c.activeReads++
	} else {
		c.activeWrites++
	}
	c.mu.Unlock()
	c.notifyDeadlineWatcher()
}

func (c *WatchedConn) leaveIO(isRead bool) {
	c.mu.Lock()
	if isRead {
		c.activeReads--
	} else {
		c.activeWrites--
	}
	c.mu.Unlock()
	c.notifyDeadlineWatcher()
}

func (c *WatchedConn) runDetachedRead(p []byte) (int, error) {
	buf := make([]byte, min(len(p), MaxCopyChunk))
	resCh := make(chan channelIOResult, 1)
	var opMu sync.Mutex
	abandoned := false
	if err := c.lifeNursery.Go(func(context.Context) error {
		n, err := c.ch.Read(buf)
		opMu.Lock()
		if !abandoned {
			resCh <- channelIOResult{n: n, err: err}
		}
		opMu.Unlock()
		return nil
	}); err != nil {
		return 0, c.abortedErr()
	}
	select {
	case res := <-resCh:
		if res.n > 0 {
			copy(p, buf[:res.n])
		}
		return res.n, c.mapIOErr(res.err)
	case <-c.abortCh:
		opMu.Lock()
		abandoned = true
		opMu.Unlock()
		return 0, c.abortedErr()
	}
}

func (c *WatchedConn) runDetachedWrite(chunk []byte) (int, error) {
	resCh := make(chan channelIOResult, 1)
	var opMu sync.Mutex
	abandoned := false
	if err := c.lifeNursery.Go(func(context.Context) error {
		n, err := c.ch.Write(chunk)
		opMu.Lock()
		if !abandoned {
			resCh <- channelIOResult{n: n, err: err}
		}
		opMu.Unlock()
		return nil
	}); err != nil {
		return 0, c.abortedErr()
	}
	select {
	case res := <-resCh:
		return res.n, c.mapIOErr(res.err)
	case <-c.abortCh:
		opMu.Lock()
		abandoned = true
		opMu.Unlock()
		return 0, c.abortedErr()
	}
}

func (c *WatchedConn) abortedErr() error {
	if c.deadlineHit.Load() {
		return os.ErrDeadlineExceeded
	}
	return net.ErrClosed
}

func (c *WatchedConn) mapIOErr(ioErr error) error {
	if ioErr == nil {
		return nil
	}
	if c.deadlineHit.Load() {
		return os.ErrDeadlineExceeded
	}
	return ioErr
}

// Close 幂等关闭底层 ssh.Channel、立即唤醒阻塞读写与 O(1) 看门狗，并在有界宽限内收敛带外排空。
func (c *WatchedConn) Close() error {
	if c == nil || !c.valid {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.signalAbort(false)
		chErr := c.ch.Close()
		if errors.Is(chErr, io.EOF) || errors.Is(chErr, net.ErrClosed) {
			chErr = nil
		}
		<-c.watcherDone
		WaitBounded(c.drainersDone, CloseGraceTimeout)
		c.closeErr = chErr
	})
	return c.closeErr
}

// CloseWrite 半关闭底层 ssh.Channel 的写方向（发送 SSH_MSG_CHANNEL_EOF），供 SFTP/透传子系统使用。
func (c *WatchedConn) CloseWrite() error {
	if c == nil || !c.valid || c.closed.Load() {
		return net.ErrClosed
	}
	return c.ch.CloseWrite()
}

// LocalAddr 返回虚拟通道本端地址。
func (c *WatchedConn) LocalAddr() net.Addr { return c.localAddr }

// RemoteAddr 返回虚拟通道远端地址。
func (c *WatchedConn) RemoteAddr() net.Addr { return c.remoteAddr }

// SetDeadline 原子更新读写截止时间并通知 O(1) 看门狗；无活跃 I/O 时绝不提前销毁通道。
func (c *WatchedConn) SetDeadline(t time.Time) error {
	if c == nil || !c.valid || c.closed.Load() {
		return errors.Join(net.ErrClosed, ports.ErrClosed)
	}
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	c.notifyDeadlineWatcher()
	return nil
}

// SetReadDeadline 原子更新读截止时间并通知 O(1) 看门狗；清除或延长截止时立即取消旧到期判断。
func (c *WatchedConn) SetReadDeadline(t time.Time) error {
	if c == nil || !c.valid || c.closed.Load() {
		return errors.Join(net.ErrClosed, ports.ErrClosed)
	}
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	c.notifyDeadlineWatcher()
	return nil
}

// SetWriteDeadline 原子更新写截止时间并通知 O(1) 看门狗；清除或延长截止时立即取消旧到期判断。
func (c *WatchedConn) SetWriteDeadline(t time.Time) error {
	if c == nil || !c.valid || c.closed.Load() {
		return errors.Join(net.ErrClosed, ports.ErrClosed)
	}
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	c.notifyDeadlineWatcher()
	return nil
}
