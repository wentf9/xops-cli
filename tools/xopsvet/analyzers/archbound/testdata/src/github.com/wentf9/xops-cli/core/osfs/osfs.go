package osfs

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/ports"
)

// SocketSlot 合法持有 *net.UnixListener 与 net.Listener 字段（验证防线 3 仅禁同构克隆，绝不误杀）。
type SocketSlot struct {
	listener net.Listener
	ln       *net.UnixListener
}

type LocalFS struct {
	Root   *os.Root
	dialer net.Dialer
	lc     net.ListenConfig
	slot   SocketSlot
}

func (LocalFS) WithRoot(_ algebraic.Duration) error { return nil }
func (LocalFS) WithOperatorRead(_ string) error     { return nil }

var _ ports.ScopedRootFS = LocalFS{}
var _ ports.OperatorReadFS = LocalFS{}

// ProbeStaleUnixSocket 演示 core/osfs 在 v2.3.3 18 符号 + 3 含 ctx 方法 + 3 包级直接绑定下的全部合法用法。
func (fs *LocalFS) ProbeStaleUnixSocket(ctx context.Context, sockPath string) error {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return err
	}
	_ = addr.Name
	_ = addr.Net
	_ = addr.Network()
	_ = addr.String()

	lc := net.ListenConfig{
		Control: func(_, _ string, _ syscall.RawConn) error { return nil },
	}
	ln, err := lc.Listen(ctx, "unix", sockPath)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	_ = ln.Addr()

	if ul, ok := ln.(*net.UnixListener); ok {
		fs.slot = SocketSlot{listener: ln, ln: ul}
		ul.SetUnlinkOnClose(false)
		_, _ = ul.SyscallConn()
		_ = ul.SetDeadline(time.Time{})
	}
	if pc, err := lc.ListenPacket(ctx, "unixgram", sockPath); err == nil {
		_ = pc.Close()
	}

	d := net.Dialer{
		Timeout:   time.Second,
		Deadline:  time.Time{},
		LocalAddr: addr,
		Control:   func(_, _ string, _ syscall.RawConn) error { return nil },
		ControlContext: func(_ context.Context, _, _ string, _ syscall.RawConn) error {
			return nil
		},
	}
	_ = fs.dialer.Timeout
	_ = fs.lc.Control

	if uc, err := d.DialUnix(ctx, "unix", nil, addr); err == nil {
		_, _ = uc.SyscallConn()
		_, _ = uc.Read(nil)
		_, _ = uc.Write(nil)
		_ = uc.LocalAddr()
		_ = uc.RemoteAddr()
		_ = uc.SetDeadline(time.Time{})
		_ = uc.Close()
	}
	if ul2, err := net.ListenUnix("unix", addr); err == nil {
		_ = ul2.Close()
	}
	if uc2, err := net.ListenUnixgram("unixgram", addr); err == nil {
		_ = uc2.Close()
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		_ = opErr.Op
		_ = opErr.Net
		_ = opErr.Timeout()
		_ = opErr.Unwrap()
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		_ = netErr.Timeout()
	}
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return nil
}
