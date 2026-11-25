package osfs_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"go.uber.org/goleak"
)

func shortSocketTempDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("", "xops-s-")
	if err != nil {
		t.Fatalf("创建短套接字临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	sub := filepath.Join(base, "s")
	ensureTestSocketDir(t, sub)
	return sub
}

func verifyWindowsControlSocketRules(t *testing.T, percentC string) {
	t.Helper()
	winOK, err := osfs.ValidateWindowsControlSocketPath(`C:\xops\cm-`+percentC+`.sock`, 107)
	if err != nil || !winOK.IsValid() || winOK.Dir() != `C:\xops` {
		t.Fatalf("Windows %%C 套接字路径校验失败: (%v, %v)", winOK, err)
	}
	for _, badWin := range []string{
		`C:\xops\cm-alice@prod:22`, `C:\xops\sock:ads`, `C:\xops\CON.sock`, `\\server\share\cm.sock`,
		`C:relative.sock`, `/tmp/a.sock`, `C:\xops\dir\`, `C:\xops\dir/`, `C:\xops\dir\.`, `C:\xops\dir\..`,
	} {
		if _, err := osfs.ValidateWindowsControlSocketPath(badWin, 107); !errors.Is(err, osfs.ErrInvalidControlPath) {
			t.Fatalf("Windows 必须拒绝非法控制套接字路径 %q, 实际 %v", badWin, err)
		}
	}
	if _, err := osfs.ValidateWindowsControlSocketPath(`C:\ok.sock`, 0); !errors.Is(err, osfs.ErrInvalidControlPath) {
		t.Fatalf("Windows maxBytes<=0 必须返回 ErrInvalidControlPath: %v", err)
	}
	if _, err := osfs.ValidateWindowsControlSocketPath(`C:\`+strings.Repeat("a", 110), 107); !errors.Is(err, osfs.ErrControlPathTooLong) {
		t.Fatalf("Windows 未拒绝超长 sun_path: %v", err)
	}
}

func TestControlSocketPathCrossPlatformRules(t *testing.T) {
	percentC, err := option.ComputePercentC("workstation", "prod.example.com", 22, "deploy")
	if err != nil {
		t.Fatalf("ComputePercentC 失败: %v", err)
	}
	pColon, err := osfs.ValidateUnixControlSocketPath("/tmp/cm-alice@prod:22", 107)
	if err != nil || !pColon.IsValid() || pColon.Name() != "cm-alice@prod:22" || pColon.Dir() != "/tmp" {
		t.Fatalf("Unix 允许含冒号 ControlPath 失败: (%v, %v)", pColon, err)
	}
	for _, badUnix := range []string{"/tmp/../escape.sock", "/tmp/dir/", "/tmp/dir/.", "/tmp/dir/..", "."} {
		if _, err := osfs.ValidateUnixControlSocketPath(badUnix, 107); !errors.Is(err, osfs.ErrInvalidControlPath) {
			t.Fatalf("Unix 必须拒绝非法路径 %q, 实际 %v", badUnix, err)
		}
	}
	if _, err := osfs.ValidateUnixControlSocketPath("/tmp/ok.sock", 0); !errors.Is(err, osfs.ErrInvalidControlPath) {
		t.Fatalf("maxBytes<=0 必须返回 ErrInvalidControlPath: %v", err)
	}
	if _, err := osfs.ValidateUnixControlSocketPath("/tmp/"+strings.Repeat("a", 120), 107); !errors.Is(err, osfs.ErrControlPathTooLong) {
		t.Fatalf("Unix 未拒绝超长 sun_path: %v", err)
	}
	verifyWindowsControlSocketRules(t, percentC)

	shortDir := mustLocalDir(t, shortSocketTempDir(t))
	managed, err := osfs.BuildManagedMuxSocketPath(shortDir, percentC)
	if err != nil || !managed.IsValid() || !strings.HasSuffix(managed.Name(), percentC+".sock") {
		t.Fatalf("BuildManagedMuxSocketPath = (%v, %v)", managed, err)
	}
	if _, err := osfs.BuildManagedMuxSocketPath(shortDir, "NOT-HEX"); !errors.Is(err, osfs.ErrInvalidControlPath) {
		t.Fatalf("BuildManagedMuxSocketPath 必须拒绝非法 %%C: %v", err)
	}
	srcSock := mustLocalSource(t, managed.NativePath())
	fromSrc, err := osfs.ControlSocketPathFromSource(srcSock)
	if err != nil || !fromSrc.Equal(managed) {
		t.Fatalf("ControlSocketPathFromSource = (%v, %v), 期望 %v", fromSrc, err, managed)
	}
}

func TestSocketSlotLifecyclePeerCredAndStaleRecovery(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := shortSocketTempDir(t)
	sockRaw := filepath.Join(dir, "ctrl.sock")
	sockPath, err := osfs.ValidateControlSocketPath(sockRaw)
	if err != nil {
		t.Fatalf("ValidateControlSocketPath(%q) 失败: %v", sockRaw, err)
	}
	ctx := context.Background()

	// 1. 不存在时探测必须返回 SocketProbeMissing。
	if st, pErr := osfs.ProbeStaleUnixSocket(ctx, sockPath); pErr != nil || st != osfs.SocketProbeMissing {
		t.Fatalf("缺失套接字探测 = (%v, %v), 期望 missing", st, pErr)
	}

	// 2. 绑定活跃槽位：验证对端凭据、活跃冲突拒绝、ReplaceStale 绝不抢占活槽位以及 Prune 绝不删活套接字。
	verifyActiveSocketSlot(t, ctx, sockPath)

	// 3. 退出 WithSocketSlot 后套接字文件已按 INV-A3 清理。
	if st, pErr := osfs.ProbeStaleUnixSocket(ctx, sockPath); pErr != nil || st != osfs.SocketProbeMissing {
		t.Fatalf("释放后探测 = (%v, %v), 期望 missing", st, pErr)
	}

	// 4. 构造遗留陈旧套接字：验证 ProbeStale -> PruneStale 与 ReplaceStale 接管。
	verifyStaleSocketRecovery(t, ctx, sockPath)
}

func acceptAndEchoOnce(slot *osfs.SocketSlot) error {
	srvConn, srvCred, err := slot.AcceptVerified()
	if err != nil {
		return err
	}
	defer func() { _ = srvConn.Close() }()
	if !srvCred.IsValid() {
		return errors.New("服务端对端凭据无效")
	}
	if pid, ok := srvCred.PID(); ok && pid != uint32(os.Getpid()) {
		return errors.New("服务端对端 PID 与当前进程不一致")
	}
	var buf [4]byte
	if _, err := srvConn.Read(buf[:]); err != nil {
		return err
	}
	_, err = srvConn.Write(bytes.ToUpper(buf[:]))
	return err
}

func verifyActiveSocketSlot(t *testing.T, ctx context.Context, sockPath osfs.ControlSocketPath) {
	t.Helper()
	err := osfs.WithSocketSlot(ctx, sockPath, osfs.SocketSlotOptions{}, func(slot *osfs.SocketSlot) error {
		if !slot.IsActive() || !slot.Path().Equal(sockPath) {
			t.Fatal("SocketSlot 在作用域内必须活跃且路径一致")
		}
		if err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
			if err := n.Go(func(c context.Context) error { return dialEchoAndCheckPeer(c, sockPath) }); err != nil {
				return err
			}
			// 借用句柄 slot 严格保留在同步回调协程内消费（零跨协程逃逸，满足 linearlease）。
			return acceptAndEchoOnce(slot)
		}); err != nil {
			return err
		}
		// 同时验证 Listener().Accept() 走对端凭据核验通道并正常完成双向通信。
		if err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
			if err := n.Go(func(c context.Context) error { return dialEchoAndCheckPeer(c, sockPath) }); err != nil {
				return err
			}
			return acceptListenerAndEchoOnce(slot)
		}); err != nil {
			return err
		}
		return verifyLiveSlotProtections(ctx, sockPath)
	})
	if err != nil {
		t.Fatalf("活跃 SocketSlot 测试失败: %v", err)
	}
}

func acceptListenerAndEchoOnce(slot *osfs.SocketSlot) error {
	srvConn, err := slot.Listener().Accept()
	if err != nil {
		return err
	}
	defer func() { _ = srvConn.Close() }()
	var buf [4]byte
	if _, err := srvConn.Read(buf[:]); err != nil {
		return err
	}
	_, err = srvConn.Write(bytes.ToUpper(buf[:]))
	return err
}

func dialEchoAndCheckPeer(ctx context.Context, sockPath osfs.ControlSocketPath) error {
	cliConn, cliCred, err := osfs.DialUnixVerified(ctx, sockPath)
	if err != nil {
		return err
	}
	defer func() { _ = cliConn.Close() }()
	if !cliCred.IsValid() {
		return errors.New("客户端对端凭据无效")
	}
	if pid, ok := cliCred.PID(); ok && pid != uint32(os.Getpid()) {
		return errors.New("客户端对端 PID 与当前进程不一致")
	}
	if _, err := cliConn.Write([]byte("ping")); err != nil {
		return err
	}
	var reply [4]byte
	if _, err := cliConn.Read(reply[:]); err != nil {
		return err
	}
	if string(reply[:]) != "PING" {
		return errors.New("AF_UNIX 回显内容不匹配")
	}
	return nil
}

func verifyLiveSlotProtections(ctx context.Context, sockPath osfs.ControlSocketPath) error {
	if st, err := osfs.ProbeStaleUnixSocket(ctx, sockPath); err != nil || st != osfs.SocketProbeLive {
		return errors.New("活套接字探测期望 live")
	}
	if occErr := osfs.WithSocketSlot(ctx, sockPath, osfs.SocketSlotOptions{ReplaceStale: true}, func(*osfs.SocketSlot) error {
		return nil
	}); !errors.Is(occErr, osfs.ErrSlotOccupied) {
		return errors.New("活套接字 ReplaceStale 必须返回 ErrSlotOccupied")
	}
	if prSt, prErr := osfs.PruneStaleUnixSocket(ctx, sockPath); prErr != nil || prSt != osfs.SocketProbeLive {
		return errors.New("活套接字 Prune 必须返回 live 且保留")
	}
	return nil
}

func verifyStaleSocketRecovery(t *testing.T, ctx context.Context, sockPath osfs.ControlSocketPath) {
	t.Helper()
	createStaleSocketFile(t, sockPath.NativePath())
	if st, pErr := osfs.ProbeStaleUnixSocket(ctx, sockPath); pErr != nil || st != osfs.SocketProbeStale {
		t.Fatalf("陈旧套接字探测 = (%v, %v), 期望 stale", st, pErr)
	}
	if occErr := osfs.WithSocketSlot(ctx, sockPath, osfs.SocketSlotOptions{ReplaceStale: false}, func(*osfs.SocketSlot) error {
		return nil
	}); !errors.Is(occErr, osfs.ErrSlotOccupied) {
		t.Fatalf("ReplaceStale=false 遇到陈旧套接字必须返回 ErrSlotOccupied, 实际 %v", occErr)
	}
	if err := osfs.WithSocketSlot(ctx, sockPath, osfs.SocketSlotOptions{ReplaceStale: true}, func(slot *osfs.SocketSlot) error {
		if !slot.IsActive() {
			return errors.New("接管后槽位未激活")
		}
		return nil
	}); err != nil {
		t.Fatalf("ReplaceStale=true 接管陈旧套接字失败: %v", err)
	}

	createStaleSocketFile(t, sockPath.NativePath())
	if st, pErr := osfs.PruneStaleUnixSocket(ctx, sockPath); pErr != nil || st != osfs.SocketProbeStale {
		t.Fatalf("PruneStaleUnixSocket = (%v, %v), 期望 stale", st, pErr)
	}
	if st, pErr := osfs.ProbeStaleUnixSocket(ctx, sockPath); pErr != nil || st != osfs.SocketProbeMissing {
		t.Fatalf("清理陈旧套接字后探测 = (%v, %v), 期望 missing", st, pErr)
	}
}

func TestSocketSlotNeverDeletesRegularFile(t *testing.T) {
	dir := shortSocketTempDir(t)
	regRaw := filepath.Join(dir, "not-a-socket.txt")
	if err := os.WriteFile(regRaw, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	sockPath, err := osfs.ValidateControlSocketPath(regRaw)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if st, pErr := osfs.ProbeStaleUnixSocket(ctx, sockPath); pErr != nil || st != osfs.SocketProbeNotSocket {
		t.Fatalf("常规文件探测 = (%v, %v), 期望 not_socket", st, pErr)
	}
	if st, pErr := osfs.PruneStaleUnixSocket(ctx, sockPath); pErr != nil || st != osfs.SocketProbeNotSocket {
		t.Fatalf("常规文件 Prune = (%v, %v), 期望 not_socket", st, pErr)
	}
	if err := osfs.WithSocketSlot(ctx, sockPath, osfs.SocketSlotOptions{ReplaceStale: true}, func(*osfs.SocketSlot) error {
		return nil
	}); !errors.Is(err, osfs.ErrNotSocket) {
		t.Fatalf("常规文件 WithSocketSlot(ReplaceStale) = %v, 期望 ErrNotSocket", err)
	}
	data, err := os.ReadFile(regRaw)
	if err != nil || string(data) != "precious" {
		t.Fatalf("常规文件被误删或篡改: (%q, %v)", string(data), err)
	}
	if _, _, err := osfs.DialUnixVerified(ctx, sockPath); !errors.Is(err, osfs.ErrNotSocket) {
		t.Fatalf("DialUnixVerified(regular) = %v, 期望 ErrNotSocket", err)
	}
	var nilCtx context.Context
	if err := osfs.WithSocketSlot(nilCtx, sockPath, osfs.SocketSlotOptions{}, func(*osfs.SocketSlot) error { return nil }); !errors.Is(err, ports.ErrNilContext) {
		t.Fatalf("WithSocketSlot(nil ctx) = %v, 期望 ErrNilContext", err)
	}
	if err := osfs.WithSocketSlot(ctx, sockPath, osfs.SocketSlotOptions{}, nil); !errors.Is(err, ports.ErrNilCallback) {
		t.Fatalf("WithSocketSlot(nil fn) = %v, 期望 ErrNilCallback", err)
	}
}

func TestPruneMissingDirHasNoSideEffectsAndReleaseClosesOnDirRemoval(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	base := shortSocketTempDir(t)
	missingDir := filepath.Join(base, "never-created")
	missingSock, err := osfs.ValidateControlSocketPath(filepath.Join(missingDir, "dead.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if st, pErr := osfs.PruneStaleUnixSocket(ctx, missingSock); pErr != nil || st != osfs.SocketProbeMissing {
		t.Fatalf("缺失目录 PruneStaleUnixSocket = (%v, %v), 期望 (missing, nil)", st, pErr)
	}
	if _, stErr := os.Stat(missingDir); !errors.Is(stErr, os.ErrNotExist) {
		t.Fatalf("PruneStaleUnixSocket 严禁创建缺失父目录: %v", stErr)
	}

	// 验证 WithSocketSlot 作用域内目录被删除时，退出仍无条件关闭监听器且不重建已删目录。
	ephemeralDir := filepath.Join(base, "ephem")
	ensureTestSocketDir(t, ephemeralDir)
	ephemSock, err := osfs.ValidateControlSocketPath(filepath.Join(ephemeralDir, "c.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := osfs.WithSocketSlot(ctx, ephemSock, osfs.SocketSlotOptions{}, func(slot *osfs.SocketSlot) error {
		if !slot.IsActive() {
			return errors.New("槽位未激活")
		}
		_ = os.RemoveAll(ephemeralDir)
		return nil
	}); err != nil {
		t.Fatalf("删除父目录后释放槽位失败: %v", err)
	}
}

func createStaleSocketFile(t *testing.T, addr string) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", addr)
	if err != nil {
		t.Fatalf("构造测试陈旧套接字失败: %v", err)
	}
	uln, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		t.Fatal("监听器不是 *net.UnixListener")
	}
	uln.SetUnlinkOnClose(false)
	if err := uln.Close(); err != nil {
		t.Fatalf("关闭陈旧测试监听器失败: %v", err)
	}
}
