// Package muxstream 提供 OpenSSH PROTOCOL.mux v4 线缆编解码与跨平台 XOps 流式复用桥接原语
// （零 core/osfs 与 SCM_RIGHTS 依赖，Linux/macOS/FreeBSD/Windows 字节级一致）。
//
// 本包仅面向同域上层包 core/internal/sshnet/mux 使用，统一承载：
//   - PROTOCOL.mux v4 控制报文与 xops-stream-mux@xops.dev 扩展帧编解码（wire_codec.go）；
//   - 远端会话（ports.RemoteSession）双向帧桥接客户端与服务端实现；
//   - 远端监听器（ListenTCP / ListenStreamLocal）多流复用客户端与服务端实现；
//   - 基于 core/conc.Nursery 的零泄漏双向字节流拼接（SpliceStreams，支持半关闭）。
package muxstream

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"sync"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	// MaxPacketBytes 限制单个 PROTOCOL.mux / 流式复用帧体上限（1 MiB），防止恶意对端 OOM。
	MaxPacketBytes = 1 << 20
	// CopyChunkBytes 限制单次流拷贝与帧分片大小（32 KiB），保持低内存占用与良好响应性。
	CopyChunkBytes = 32 * 1024
)

// HalfWriteCloser 表达支持 TCP/Unix/SSH 半关闭（写方向 EOF）的底层流接口。
type HalfWriteCloser interface {
	CloseWrite() error
}

// SyncFrameWriter 对底层 io.Writer 串行化写入完整 PROTOCOL.mux 帧，防止并发写交错破坏帧边界。
type SyncFrameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewSyncFrameWriter 构造绑定目标写入器的并发安全帧写入器。
func NewSyncFrameWriter(w io.Writer) *SyncFrameWriter {
	return &SyncFrameWriter{w: w}
}

// Write 持锁原子写入单条完整帧。
func (fw *SyncFrameWriter) Write(msgType uint32, body []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return WritePacket(fw.w, msgType, body)
}

// SpliceStreams 在 core/conc.Nursery 监督下执行双向原始流透传，任一侧 EOF 尽力传播半关闭，
// 上下文取消或异常错误时同步关闭两端以保证零协程泄漏。
func SpliceStreams(ctx context.Context, left, right io.ReadWriteCloser) error {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}
	defer closeBoth()
	return conc.RunScoped(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		if err := n.Go(func(c context.Context) error {
			<-c.Done()
			closeBoth()
			return nil
		}); err != nil {
			return err
		}
		return conc.RunWait(wCtx, func(_ context.Context, cn *conc.Nursery) error {
			if err := cn.Go(func(context.Context) error {
				copyDirection(right, left, closeBoth)
				return nil
			}); err != nil {
				return err
			}
			copyDirection(left, right, closeBoth)
			return nil
		})
	})
}

func copyDirection(dst io.Writer, src io.Reader, closeBoth func()) {
	buf := make([]byte, CopyChunkBytes)
	if _, err := io.CopyBuffer(dst, src, buf); err != nil && !IsBenignIOErr(err) {
		closeBoth()
		return
	}
	if hc, ok := dst.(HalfWriteCloser); ok {
		_ = hc.CloseWrite()
	}
}

// IsBenignIOErr 判断错误是否属于正常断连、管道关闭或上下文取消。
func IsBenignIOErr(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, ports.ErrClosed) ||
		errors.Is(err, context.Canceled)
}

// FirstErr 返回参数序列中首个非 nil 错误。
func FirstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// ZeroVal 返回任意类型 T 的零值（规避对跨包 opaque 值类型书写复合字面量）。
func ZeroVal[T any]() (z T) { return z }
