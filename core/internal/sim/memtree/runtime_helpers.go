package memtree

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/ports"
)

// Addr 表示纯内存虚拟网络地址。
type Addr string

func (a Addr) Network() string { return "sim" }
func (a Addr) String() string  { return string(a) }

// MemListener 实现带可选失效哨兵的纯内存 net.Listener。
type MemListener struct {
	addr    Addr
	expired *atomic.Bool
}

// NewMemListener 构造纯内存 net.Listener（expired 非 nil 时作为借用作用域失效哨兵）。
func NewMemListener(addr string, expired *atomic.Bool) *MemListener {
	return &MemListener{addr: Addr(addr), expired: expired}
}
func (l *MemListener) Addr() net.Addr { return l.addr }
func (l *MemListener) Close() error {
	if l != nil && l.expired != nil && l.expired.Load() {
		return ports.ErrHandleExpired
	}
	return nil
}
func (l *MemListener) Accept() (net.Conn, error) { return nil, FirstErr(l.Close(), ports.ErrClosed) }

// EchoConn 实现纯内存双向回显 net.Conn 与 io.ReadWriteCloser。
type EchoConn struct {
	mu     sync.Mutex
	addr   Addr
	buf    bytes.Buffer
	closed bool
}

// NewEchoConn 构造绑定虚拟地址的纯内存回显连接。
func NewEchoConn(addr string) *EchoConn { return &EchoConn{addr: Addr(addr)} }
func (c *EchoConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.EOF
	}
	return c.buf.Read(p)
}
func (c *EchoConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, ports.ErrClosed
	}
	return c.buf.Write(p)
}
func (c *EchoConn) Close() error                     { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *EchoConn) LocalAddr() net.Addr              { return c.addr }
func (c *EchoConn) RemoteAddr() net.Addr             { return c.addr }
func (c *EchoConn) SetDeadline(time.Time) error      { return nil }
func (c *EchoConn) SetReadDeadline(time.Time) error  { return nil }
func (c *EchoConn) SetWriteDeadline(time.Time) error { return nil }

// StreamPipe 是零协程、并发安全、非阻塞写入且支持半关闭 EOF 唤醒的纯内存流管道（供 SimRemoteSession 复用）。
type StreamPipe struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
	notify chan struct{}
}

// NewStreamPipe 构造打开状态的纯内存流管道。
func NewStreamPipe() *StreamPipe { return &StreamPipe{notify: make(chan struct{})} }

func (p *StreamPipe) broadcastLocked() {
	close(p.notify)
	p.notify = make(chan struct{})
}

// Write 非阻塞写入缓冲并唤醒等待读者；已关闭时返回 io.ErrClosedPipe。
func (p *StreamPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	n, _ := p.buf.Write(b)
	p.broadcastLocked()
	return n, nil
}

// Read 从缓冲读取字节；缓冲为空且未关闭时阻塞直至新数据到达或 Close 返回 io.EOF。
func (p *StreamPipe) Read(b []byte) (int, error) {
	for {
		p.mu.Lock()
		if p.buf.Len() > 0 {
			n, err := p.buf.Read(b)
			p.mu.Unlock()
			return n, err
		}
		if p.closed {
			p.mu.Unlock()
			return 0, io.EOF
		}
		ch := p.notify
		p.mu.Unlock()
		<-ch
	}
}

// Close 幂等关闭写入端并广播唤醒全部阻塞读者返回 io.EOF。
func (p *StreamPipe) Close() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.broadcastLocked()
	}
	p.mu.Unlock()
	return nil
}

// SeedXoshiro256 使用 SplitMix64 从 64 位种子展开跨平台一致的非零 xoshiro256++ 状态向量。
func SeedXoshiro256(seed uint64) (st [4]uint64) {
	sm := seed
	for i := range st {
		sm += 0x9e3779b97f4a7c15
		z := (sm ^ (sm >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		st[i] = z ^ (z >> 31)
	}
	if st == ([4]uint64{}) {
		st[0] = 0x9e3779b97f4a7c15
	}
	return st
}

// NextXoshiro256 推进一次 xoshiro256++ 状态并返回下一个 64 位伪随机数。
func NextXoshiro256(s *[4]uint64) uint64 {
	res, t := bits.RotateLeft64(s[0]+s[3], 23)+s[0], s[1]<<17
	s[2] ^= s[0]
	s[3] ^= s[1]
	s[1] ^= s[2]
	s[0] ^= s[3]
	s[2] ^= t
	s[3] = bits.RotateLeft64(s[3], 45)
	return res
}

// FillXoshiro256Bytes 使用 xoshiro256++ 确定性填充字节切片（长度 >= 16 时保证非全零）。
func FillXoshiro256Bytes(s *[4]uint64, p []byte) {
	var buf [8]byte
	for off := 0; off < len(p); off += 8 {
		binary.LittleEndian.PutUint64(buf[:], NextXoshiro256(s))
		copy(p[off:], buf[:])
	}
	if len(p) >= 16 && !slices.ContainsFunc(p, func(b byte) bool { return b != 0 }) {
		p[0] = 1
	}
}

// RelayTerminalStreams 在 core/conc.RunWait 监督下并发执行终端输入、远端输出与窗口缩放中继（零裸 go、零泄漏）：
//   - localIn 遇 io.EOF 时若 remoteIn 实现 io.Closer 则半关闭以传递通道 EOF，同时继续排空 remoteOut；
//   - remoteOut 遇 io.EOF（远端退出）时关闭 remoteDone 并调用 onRemoteDone 立即唤醒阻塞的 localIn 与缩放泵。
//
//xops:syncclosure
func RelayTerminalStreams(
	ctx context.Context,
	localIn io.Reader,
	localOut io.Writer,
	remoteIn io.Writer,
	remoteOut io.Reader,
	resizeCh <-chan ports.TerminalSize,
	onResize func(ctx context.Context, size ports.TerminalSize) error,
	onRemoteDone func(),
) error {
	remoteDone := make(chan struct{})
	if onRemoteDone != nil {
		stopCancel := context.AfterFunc(ctx, onRemoteDone)
		defer stopCancel()
	}
	return conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(c context.Context) error { return relayInputWorker(c, remoteIn, localIn, remoteDone) }); err != nil {
			return err
		}
		if err := n.Go(func(c context.Context) error {
			return relayOutputWorker(c, localOut, remoteOut, remoteDone, onRemoteDone)
		}); err != nil {
			return err
		}
		if onResize == nil {
			return nil
		}
		return n.Go(func(c context.Context) error {
			return relayResizeWorker(c, resizeCh, remoteDone, onResize, onRemoteDone)
		})
	})
}

func relayInputWorker(ctx context.Context, remoteIn io.Writer, localIn io.Reader, remoteDone <-chan struct{}) error {
	err := copyStreamWithCtx(ctx, remoteIn, localIn)
	if err == nil {
		closeRemoteInIfOpen(remoteIn, remoteDone)
	}
	return err
}

func relayOutputWorker(ctx context.Context, localOut io.Writer, remoteOut io.Reader, remoteDone chan struct{}, onRemoteDone func()) error {
	defer func() {
		close(remoteDone)
		if onRemoteDone != nil {
			onRemoteDone()
		}
	}()
	return copyStreamWithCtx(ctx, localOut, remoteOut)
}

func relayResizeWorker(ctx context.Context, resizeCh <-chan ports.TerminalSize, remoteDone <-chan struct{}, onResize func(context.Context, ports.TerminalSize) error, onRemoteDone func()) error {
	err := pumpResizes(ctx, resizeCh, remoteDone, onResize)
	if err != nil && onRemoteDone != nil {
		onRemoteDone()
	}
	return err
}

func closeRemoteInIfOpen(remoteIn io.Writer, remoteDone <-chan struct{}) {
	select {
	case <-remoteDone:
		return
	default:
	}
	if cl, ok := remoteIn.(io.Closer); ok {
		_ = cl.Close()
	}
}

func copyStreamWithCtx(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rErr := src.Read(buf)
		if n > 0 {
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				return ctx.Err()
			}
			return rErr
		}
	}
}

func pumpResizes(ctx context.Context, ch <-chan ports.TerminalSize, remoteDone <-chan struct{}, onResize func(context.Context, ports.TerminalSize) error) error {
	for {
		sz, ok, done, err := nextResizeEvent(ctx, ch, remoteDone)
		if err != nil || done || !ok {
			return err
		}
		if err := onResize(ctx, sz); err != nil {
			return err
		}
	}
}

func nextResizeEvent(ctx context.Context, ch <-chan ports.TerminalSize, remoteDone <-chan struct{}) (ports.TerminalSize, bool, bool, error) {
	var zero ports.TerminalSize
	select {
	case sz, ok := <-ch:
		return sz, ok, false, nil
	default:
	}
	select {
	case sz, ok := <-ch:
		return sz, ok, false, nil
	case <-remoteDone:
		return zero, false, true, nil
	case <-ctx.Done():
		return zero, false, true, ctx.Err()
	}
}
