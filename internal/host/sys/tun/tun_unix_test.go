//go:build linux || darwin

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"
)

// TestUnixTUNConn_NonBlockRetryAndStripRuntFrame 验证非阻塞 fd 在 EAGAIN/EWOULDBLOCK 下自动重轮询
// 以及 Darwin 4 字节 AF 头剥离模式下自动跳过残缺帧而不返回 (0, nil)。
func TestUnixTUNConn_NonBlockRetryAndStripRuntFrame(t *testing.T) {
	defer goleak.VerifyNone(t)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("Socketpair 失败: %v", err)
	}
	if err := unix.SetNonblock(fds[0], true); err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		t.Fatalf("SetNonblock 失败: %v", err)
	}
	defer func() { _ = unix.Close(fds[1]) }()

	conn, err := newUnixTUNConn(fds[0], true)
	if err != nil {
		t.Fatalf("newUnixTUNConn 失败: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// 先发 4 字节残缺帧（仅有 AF 头），再发合法 IPv4 帧，Read 必须跳过残缺帧并直接返回后续合法帧。
	runt := make([]byte, 4)
	binary.BigEndian.PutUint32(runt, uint32(unix.AF_INET))
	validPayload := []byte{0x45, 0x00, 0x00, 0x14, 0xaa, 0xbb}
	validFrame := append(bytes.Clone(runt), validPayload...)

	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			if _, wErr := unix.Write(fds[1], runt); wErr != nil {
				return wErr
			}
			_, wErr := unix.Write(fds[1], validFrame)
			return wErr
		}); gErr != nil {
			return gErr
		}
		buf := make([]byte, 64)
		gotN, rErr := conn.Read(buf)
		if rErr != nil {
			return rErr
		}
		if !bytes.Equal(buf[:gotN], validPayload) {
			t.Errorf("Read = %x, 期望 %x", buf[:gotN], validPayload)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unixTUNConn 非阻塞读取/残缺帧跳过测试失败: %v", err)
	}
}
