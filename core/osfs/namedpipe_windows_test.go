//go:build windows

package osfs_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"runtime"
	"testing"
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
	h, err := windows.CreateNamedPipe(namePtr, pipeAccessDuplex|fileFlagFirstPipeInst, pipeRejectRemoteClient, 1, 4096, 4096, 0, sa)
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
