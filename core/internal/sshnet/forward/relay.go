package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"sync"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

type (
	connDialFunc    func(ctx context.Context) (net.Conn, error)
	connHandlerFunc func(ctx context.Context, conn net.Conn) error
	halfWriteCloser interface{ CloseWrite() error }
)

func buildRemoteTargetDialer(transport ports.TunnelTransport, spec ports.ForwardSpec) (connDialFunc, error) {
	if spec.TargetKind() == ports.ForwardEndpointUnix {
		rp, err := pathalg.ParseRemotePath(spec.TargetAddr())
		if err != nil {
			return nil, fmt.Errorf("%w: 远端 Unix 目标路径非法: %w", ports.ErrInvalidArgument, err)
		}
		return func(ctx context.Context) (net.Conn, error) {
			return transport.DialStreamLocal(ctx, rp)
		}, nil
	}
	hp, err := netaddr.ParseHostPort(spec.TargetAddr())
	if err != nil {
		return nil, fmt.Errorf("%w: 远端 TCP 目标地址非法: %w", ports.ErrInvalidArgument, err)
	}
	return func(ctx context.Context) (net.Conn, error) {
		return transport.DialTCP(ctx, hp)
	}, nil
}

func (f *Forwarder) buildLocalTargetDialer(spec ports.ForwardSpec) (connDialFunc, error) {
	if spec.TargetKind() == ports.ForwardEndpointUnix {
		sockPath, err := osfs.ValidateControlSocketPath(spec.TargetAddr())
		if err != nil {
			return nil, fmt.Errorf("%w: 本机 Unix 目标路径非法: %w", ports.ErrInvalidArgument, err)
		}
		if !f.hasCustomLocalDialer {
			// 默认本机 Unix 反向转发强制走 core/osfs.DialUnixVerified（核验对端用户凭证与安全属性）。
			return func(ctx context.Context) (net.Conn, error) {
				conn, _, dErr := osfs.DialUnixVerified(ctx, sockPath)
				return conn, dErr
			}, nil
		}
		native := sockPath.NativePath()
		return func(ctx context.Context) (net.Conn, error) {
			return f.localDialer(ctx, "unix", native)
		}, nil
	}
	hp, err := netaddr.ParseHostPort(spec.TargetAddr())
	if err != nil {
		return nil, fmt.Errorf("%w: 本机 TCP 目标地址非法: %w", ports.ErrInvalidArgument, err)
	}
	target := hp.String()
	return func(ctx context.Context) (net.Conn, error) {
		return f.localDialer(ctx, "tcp", target)
	}, nil
}

func relayAcceptedToDial(ctx context.Context, inbound net.Conn, dialTarget connDialFunc) error {
	outbound, err := dialTarget(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = outbound.Close() }()
	return bridgeStreams(ctx, inbound, outbound)
}

// bridgeStreams 在 conc.RunScoped 监督下执行双工零泄漏数据中继：
//   - 任一方向自然到达 io.EOF 且对端支持并成功 CloseWrite() 时保留反方向排空；
//   - 若对端不支持 CloseWrite()、半关闭失败、源流异常关闭或 ctx 取消，立即同步关闭双端流杜绝僵尸隧道。
func bridgeStreams(ctx context.Context, left, right io.ReadWriteCloser) error {
	return bridgeStreamsCore(ctx, left, right, true)
}

// bridgeStreamsStrict 用于无半关闭语义的双向帧设备（如 TUN）：任一侧 EOF 或故障即刻关闭双端。
func bridgeStreamsStrict(ctx context.Context, left, right io.ReadWriteCloser) error {
	return bridgeStreamsCore(ctx, left, right, false)
}

func bridgeStreamsCore(ctx context.Context, left, right io.ReadWriteCloser, allowHalfClose bool) error {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
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
		return runBidirectionalCopy(wCtx, left, right, allowHalfClose, closeBoth)
	})
}

func runBidirectionalCopy(ctx context.Context, left, right io.ReadWriteCloser, allowHalfClose bool, closeBoth func()) error {
	var errMu sync.Mutex
	var firstErr error
	record := func(e error) {
		if e == nil || isBenignCloseErr(e) {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = e
		}
		errMu.Unlock()
		closeBoth()
	}
	copyErr := conc.RunWait(ctx, func(_ context.Context, cn *conc.Nursery) error {
		if err := cn.Go(func(context.Context) error {
			record(copyHalfDuplex(right, left, allowHalfClose, closeBoth))
			return nil
		}); err != nil {
			return err
		}
		record(copyHalfDuplex(left, right, allowHalfClose, closeBoth))
		return nil
	})
	if firstErr != nil {
		return firstErr
	}
	return copyErr
}

func copyHalfDuplex(dst io.Writer, src io.Reader, allowHalfClose bool, closeBoth func()) error {
	buf := make([]byte, relayCopyBufferBytes)
	_, err := io.CopyBuffer(dst, src, buf)
	if err == nil {
		if allowHalfClose {
			if hc, ok := dst.(halfWriteCloser); ok {
				if cwErr := hc.CloseWrite(); cwErr == nil {
					return nil
				}
			}
		}
		closeBoth()
		return nil
	}
	closeBoth()
	if isBenignCloseErr(err) {
		return nil
	}
	return err
}

func isBenignCloseErr(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, ports.ErrClosed) ||
		errors.Is(err, context.Canceled)
}
