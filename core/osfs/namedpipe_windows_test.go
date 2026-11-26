//go:build windows

package osfs_test

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"go.uber.org/goleak"
	"golang.org/x/sys/windows"
)

func TestDialWindowsNamedPipeVerified_Validation(t *testing.T) {
	defer goleak.VerifyNone(t)
	var nilCtx context.Context
	if _, err := osfs.DialWindowsNamedPipeVerified(nilCtx, `\\.\pipe\xops-test`); !errors.Is(err, ports.ErrNilContext) {
		t.Fatalf("nil ctx = %v, 期望 ErrNilContext", err)
	}
	for _, bad := range []string{"", `C:\tmp\not-a-pipe`, `\\remote\pipe\x`, `\\.\pipe\`, `\\.\pipe\..\escape`, `\\.\pipe\bad:name`} {
		if _, err := osfs.DialWindowsNamedPipeVerified(context.Background(), bad); !errors.Is(err, ports.ErrInvalidArgument) {
			t.Fatalf("bad pipe path %q = %v, 期望 ErrInvalidArgument", bad, err)
		}
	}
	if _, err := osfs.DialWindowsNamedPipeVerified(context.Background(), `\\.\pipe\xops-nonexistent-pipe-9f8e7d`); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("missing pipe = %v, 期望 ErrNotFound", err)
	}
}

func TestDialWindowsNamedPipeVerified_RoundTrip(t *testing.T) {
	defer goleak.VerifyNone(t)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("rand.Read 失败: %v", err)
	}
	pipePath := `\\.\pipe\xops-osfs-tck-` + hex.EncodeToString(rnd[:])
	serverH := createOwnerOnlyTestPipe(t, pipePath)
	defer func() { _ = windows.CloseHandle(serverH) }()

	err := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		stop := context.AfterFunc(ctx, func() { _ = windows.CancelIoEx(serverH, nil) })
		defer stop()
		if gErr := n.Go(func(context.Context) error { return serveSingleEchoPipe(serverH) }); gErr != nil {
			return gErr
		}
		return verifyNamedPipeEcho(ctx, pipePath)
	})
	if err != nil {
		t.Fatalf("Windows 命名管道往返测试失败: %v", err)
	}
}

func verifyNamedPipeEcho(ctx context.Context, pipePath string) error {
	conn, err := osfs.DialWindowsNamedPipeVerified(ctx, pipePath)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if conn.LocalAddr().Network() != "pipe" || conn.RemoteAddr().String() != pipePath {
		return errors.New("命名管道地址元数据不匹配")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		return errors.New("管道回显内容不匹配")
	}
	return nil
}

func createOwnerOnlyTestPipe(t *testing.T, pipePath string) windows.Handle {
	t.Helper()
	currSID, err := osfs.CurrentProcessUserSID()
	if err != nil {
		t.Fatalf("CurrentProcessUserSID 失败: %v", err)
	}
	sd, err := osfs.NewOwnerOnlySecurityDescriptor(currSID, windows.NO_INHERITANCE)
	if err != nil {
		t.Fatalf("NewOwnerOnlySecurityDescriptor 失败: %v", err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	namePtr, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		t.Fatalf("UTF16PtrFromString 失败: %v", err)
	}
	const (
		pipeAccessDuplex       = 0x00000003
		fileFlagFirstPipeInst  = 0x00080000
		pipeRejectRemoteClient = 0x00000008
	)
	h, err := windows.CreateNamedPipe(namePtr, pipeAccessDuplex|fileFlagFirstPipeInst, pipeRejectRemoteClient, 1, 65536, 65536, 0, sa)
	runtime.KeepAlive(sd)
	runtime.KeepAlive(sa)
	if err != nil {
		t.Fatalf("CreateNamedPipe 失败: %v", err)
	}
	return h
}

func serveSingleEchoPipe(h windows.Handle) error {
	if err := windows.ConnectNamedPipe(h, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return err
	}
	buf := make([]byte, 64)
	var n, written uint32
	if err := windows.ReadFile(h, buf, &n, nil); err != nil {
		return err
	}
	return windows.WriteFile(h, buf[:n], &written, nil)
}

// TestDialWindowsNamedPipeVerified_ConcurrentFullDuplex 验证全双工并发 Read/Write 零数据竞争（复现 ssh/agent pipeline 模式）。
func TestDialWindowsNamedPipeVerified_ConcurrentFullDuplex(t *testing.T) {
	defer goleak.VerifyNone(t)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("rand.Read 失败: %v", err)
	}
	pipePath := `\\.\pipe\xops-osfs-duplex-` + hex.EncodeToString(rnd[:])
	serverH := createOwnerOnlyTestPipe(t, pipePath)
	defer func() { _ = windows.CloseHandle(serverH) }()

	const frames = 32
	err := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		stop := context.AfterFunc(ctx, func() { _ = windows.CancelIoEx(serverH, nil) })
		defer stop()
		if gErr := n.Go(func(context.Context) error { return serveLoopEchoPipe(serverH) }); gErr != nil {
			return gErr
		}
		return verifyFullDuplexFrames(ctx, pipePath, frames)
	})
	if err != nil {
		t.Fatalf("Windows 命名管道全双工并发测试失败: %v", err)
	}
}

func serveLoopEchoPipe(h windows.Handle) error {
	if err := windows.ConnectNamedPipe(h, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return err
	}
	buf := make([]byte, 1024)
	for {
		var n, written uint32
		if err := windows.ReadFile(h, buf, &n, nil); err != nil {
			if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_HANDLE_EOF) {
				return nil
			}
			return err
		}
		if err := windows.WriteFile(h, buf[:n], &written, nil); err != nil {
			return err
		}
	}
}

func verifyFullDuplexFrames(ctx context.Context, pipePath string, frames int) error {
	conn, err := osfs.DialWindowsNamedPipeVerified(ctx, pipePath)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error { return writeDuplexFrames(conn, frames) }); gErr != nil {
			return gErr
		}
		return n.Go(func(context.Context) error { return readDuplexFrames(conn, frames) })
	})
}

func writeDuplexFrames(w io.Writer, frames int) error {
	var frame [8]byte
	for i := range frames {
		binary.BigEndian.PutUint64(frame[:], uint64(i+1))
		if _, err := w.Write(frame[:]); err != nil {
			return err
		}
	}
	return nil
}

func readDuplexFrames(r io.Reader, frames int) error {
	var got [8]byte
	for i := range frames {
		if _, err := io.ReadFull(r, got[:]); err != nil {
			return err
		}
		if binary.BigEndian.Uint64(got[:]) != uint64(i+1) {
			return errors.New("全双工管道帧序号不匹配")
		}
	}
	return nil
}

// TestDialWindowsNamedPipeVerified_DeadlineAndClose 验证 SetReadDeadline 超时唤醒与 Close 立即解除挂起 Read。
func TestDialWindowsNamedPipeVerified_DeadlineAndClose(t *testing.T) {
	defer goleak.VerifyNone(t)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("rand.Read 失败: %v", err)
	}
	pipePath := `\\.\pipe\xops-osfs-dl-` + hex.EncodeToString(rnd[:])
	serverH := createOwnerOnlyTestPipe(t, pipePath)
	defer func() { _ = windows.CloseHandle(serverH) }()

	connected := make(chan struct{})
	doneSrv := make(chan struct{})
	err := conc.RunWait(context.Background(), func(ctx context.Context, n *conc.Nursery) error {
		stop := context.AfterFunc(ctx, func() { _ = windows.CancelIoEx(serverH, nil) })
		defer stop()
		if gErr := n.Go(func(context.Context) error {
			if cErr := windows.ConnectNamedPipe(serverH, nil); cErr != nil && !errors.Is(cErr, windows.ERROR_PIPE_CONNECTED) {
				return cErr
			}
			close(connected)
			<-doneSrv
			return nil
		}); gErr != nil {
			return gErr
		}
		defer close(doneSrv)
		return verifyPipeDeadlineAndClose(ctx, pipePath, connected)
	})
	if err != nil {
		t.Fatalf("Windows 命名管道截止期与关闭唤醒测试失败: %v", err)
	}
}

func verifyPipeDeadlineAndClose(ctx context.Context, pipePath string, connected <-chan struct{}) error {
	conn, err := osfs.DialWindowsNamedPipeVerified(ctx, pipePath)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	<-connected

	if err := conn.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		return err
	}
	var buf [16]byte
	if _, rErr := conn.Read(buf[:]); !errors.Is(rErr, os.ErrDeadlineExceeded) {
		return errors.New("SetReadDeadline 期望返回 os.ErrDeadlineExceeded")
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	readErrCh := make(chan error, 1)
	return conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			_, rErr := conn.Read(buf[:])
			readErrCh <- rErr
			return nil
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(context.Context) error {
			tm := time.NewTimer(30 * time.Millisecond)
			defer tm.Stop()
			select {
			case rErr := <-readErrCh:
				return errors.New("Close 前 Read 提前返回: " + rErr.Error())
			case <-tm.C:
			}
			if cErr := conn.Close(); cErr != nil {
				return cErr
			}
			if rErr := <-readErrCh; !errors.Is(rErr, net.ErrClosed) {
				return errors.New("Close 后挂起 Read 期望返回 net.ErrClosed")
			}
			return nil
		})
	})
}
