package sim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// TestInterfaceCompliance 在编译期断言本包实现 core/ports 全部 19 个出站端口及借用句柄接口。
func TestInterfaceCompliance(t *testing.T) {
	defer goleak.VerifyNone(t)
	_ = ports.InventoryStore((*SimInventoryStore)(nil))
	_ = ports.JournalStore((*SimJournalStore)(nil))
	_ = ports.FormatImporter((*SimFormatImporter)(nil))
	_ = ports.OpenSSHConfigSource((*SimOpenSSHConfigSource)(nil))
	_ = ports.ScopedRootFS((*SimScopedRootFS)(nil))
	_ = ports.RootHandle((*simRootHandle)(nil))
	_ = ports.LockedFile((*simLockedFile)(nil))
	_ = ports.OperatorReadFS((*SimOperatorReadFS)(nil))
	_ = ports.SecretVault((*SimVault)(nil))
	_ = ports.KeySignerPort((*SimKeySigner)(nil))
	_ = ports.HostTrustPort((*SimHostTrust)(nil))
	_ = ports.DialerPort((*SimDialer)(nil))
	_ = ports.TransportConn((*SimTransportConn)(nil))
	_ = ports.RemoteSession((*SimRemoteSession)(nil))
	_ = ports.MuxSocketPort((*SimMuxSocket)(nil))
	_ = ports.RemoteFSPort((*SimRemoteFS)(nil))
	_ = ports.AuditSink((*SimAuditSink)(nil))
	_ = ports.AuditReconciler((*SimAuditCluster)(nil))
	_ = ports.Clock((*SimClock)(nil))
	_ = ports.Timer((*simTimer)(nil))
	_ = ports.Entropy((*SeededRand)(nil))
	_ = ports.ProcessPort((*SimProcessPort)(nil))
	_ = ports.TerminalPort((*SimTerminalPort)(nil))
	_ = ports.TerminalHandle((*simTerminalHandle)(nil))
	_ = ports.InteractionPort((*SimInteractionPort)(nil))
}

// TestFaultInjectorModes 验证故障注入器的单次、常驻、概率、清除与计数契约。
func TestFaultInjectorModes(t *testing.T) {
	defer goleak.VerifyNone(t)
	rng := NewSeededRand(99)
	fi := NewFaultInjector(rng)

	fi.InjectOnce("op.once", ErrFaultInjected)
	if !errors.Is(fi.Check("op.once"), ErrFaultInjected) || fi.Check("op.once") != nil || fi.Count("op.once") != 2 {
		t.Fatalf("InjectOnce contract broken")
	}
	fi.SetSticky("op.sticky", ErrSimulatedENOSPC)
	if !errors.Is(fi.Check("op.sticky"), ErrSimulatedENOSPC) {
		t.Fatalf("SetSticky must return injected error")
	}
	fi.Clear("op.sticky")
	if fi.Check("op.sticky") != nil {
		t.Fatalf("Clear must disable sticky rule")
	}
	fi.SetRate("op.rate", 1, 1, ErrFaultInjected)
	if !errors.Is(fi.Check("op.rate"), ErrFaultInjected) {
		t.Fatalf("SetRate(1/1) must trigger")
	}
	fi.ClearAll()
	if fi.Check("op.rate") != nil {
		t.Fatalf("ClearAll must remove rules")
	}
}

// TestDialerStuckCloseUnblocksOnParentClose 验证子跳卡死关闭在父跳板关闭后自动解阻并使 OpenConns 归零。
func TestDialerStuckCloseUnblocksOnParentClose(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	clk := NewSimClock(DefaultBaseTime())
	dialer := NewSimDialer(clk, NewSeededRand(77))
	_, twoHop := tck.MustHopAndPlan(t)
	hops := twoHop.Hops().Slice()
	dialer.SetHopIndexProfile(1, HopFaultProfile{StuckClose: true})

	p0, err := dialer.DialHop(ctx, hops[0], twoHop.HopDigests()[0], nil)
	if err != nil {
		t.Fatalf("DialHop(0) failed: %v", err)
	}
	p1, err := dialer.DialHop(ctx, hops[1], twoHop.HopDigests()[1], p0)
	if err != nil {
		t.Fatalf("DialHop(1) failed: %v", err)
	}
	if dialer.OpenConns() != 2 {
		t.Fatalf("OpenConns=%d, want 2", dialer.OpenConns())
	}

	closeStarted := make(chan struct{})
	err = conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			close(closeStarted)
			return p1.Close()
		}); gErr != nil {
			return gErr
		}
		return n.Go(func(context.Context) error {
			<-closeStarted
			return p0.Close()
		})
	})
	if err != nil || dialer.OpenConns() != 0 {
		t.Fatalf("parent close unblock failed: err=%v open=%d", err, dialer.OpenConns())
	}
}

// TestScopedRootFSENOSPCAndRandFault 验证 ScopedRootFS 的 ENOSPC 注入、失效哨兵拦截与 SeededRand 错误注入。
func TestScopedRootFSENOSPCAndRandFault(t *testing.T) {
	defer goleak.VerifyNone(t)
	clk := NewSimClock(DefaultBaseTime())
	sfs := NewSimScopedRootFS(clk)
	dir, _ := pathalg.ParseLocalDir("/sim/enospc")
	dest, _ := pathalg.ParseLocalRootedDest("file.txt")
	lim, _ := ports.NewReadLimits(1024)

	sfs.SetENOSPC(true)
	if wErr := sfs.WithRoot(dir, func(root ports.RootHandle) error {
		return root.AtomicReplace(dest, 0o600, func(w io.Writer) error {
			_, e := w.Write([]byte("x"))
			return e
		})
	}); !errors.Is(wErr, ErrSimulatedENOSPC) {
		t.Fatalf("expected ErrSimulatedENOSPC, got %v", wErr)
	}

	expiredHandle := &simRootHandle{fs: sfs, tree: newSimMemTree(clk, true, 0o700), valid: true}
	expiredHandle.expired.Store(true)
	if _, rErr := expiredHandle.ReadAllBounded(dest, lim); !errors.Is(rErr, ports.ErrHandleExpired) {
		t.Fatalf("expired RootHandle must fail closed with ErrHandleExpired, got %v", rErr)
	}

	sfs.SetENOSPC(false)
	if wErr := sfs.WithRoot(dir, func(root ports.RootHandle) error {
		return root.AtomicReplace(dest, 0o600, func(w io.Writer) error {
			_, e := w.Write([]byte("ok"))
			return e
		})
	}); wErr != nil {
		t.Fatalf("AtomicReplace after ENOSPC clear failed: %v", wErr)
	}

	rng := NewSeededRand(100)
	if rng.Faults() == nil {
		t.Fatalf("NewSeededRand.Faults() must not be nil")
	}
	rng.SetReadFault(ErrFaultInjected)
	if _, rErr := rng.Read(make([]byte, 16)); !errors.Is(rErr, ErrFaultInjected) {
		t.Fatalf("SetReadFault got %v, want ErrFaultInjected", rErr)
	}
	rng.SetReadFault(nil)
	var buf [32]byte
	if n, rErr := rng.Read(buf[:]); rErr != nil || n != 32 || bytes.Equal(buf[:], make([]byte, 32)) {
		t.Fatalf("SeededRand.Read after clear failed: n=%d err=%v", n, rErr)
	}
}

// TestSim_ScopedFSAndLockedFileBoundaries 验证预校验、借用 Writer 失效哨兵、软链 Stat/O_NOFOLLOW 与锁模式写保护。
func TestSim_ScopedFSAndLockedFileBoundaries(t *testing.T) {
	defer goleak.VerifyNone(t)
	sfs := NewSimScopedRootFS(NewSimClock(DefaultBaseTime()))
	dir, _ := pathalg.ParseLocalDir("/sim/bounds")
	fDest, _ := pathalg.ParseLocalRootedDest("a.txt")
	linkDest, _ := pathalg.ParseLocalRootedDest("sub/a.link")
	subDir, _ := pathalg.ParseLocalRootedDest("sub")
	lim, _ := ports.NewReadLimits(1024)

	if err := sfs.WithRoot(dir, func(root ports.RootHandle) error {
		return verifyScopedWriteAndSymlink(t, sfs, root, subDir, fDest, linkDest, lim)
	}); err != nil {
		t.Fatalf("WithRoot write/symlink checks failed: %v", err)
	}
	if err := sfs.WithRoot(dir, func(root ports.RootHandle) error {
		return verifyLockedFileModes(t, sfs, root, fDest)
	}); err != nil {
		t.Fatalf("WithRoot lock mode checks failed: %v", err)
	}
}

func verifyScopedWriteAndSymlink(t *testing.T, sfs *SimScopedRootFS, root ports.RootHandle, subDir, fDest, linkDest pathalg.LocalRootedDest, lim ports.ReadLimits) error {
	t.Helper()
	if err := root.AtomicReplace(fDest, 0o600, func(w io.Writer) error {
		if _, ok := w.(*simScopedWriter); !ok {
			t.Fatalf("AtomicReplace writer must be sentinel-guarded *simScopedWriter")
		}
		_, e := w.Write([]byte("hello"))
		return e
	}); err != nil {
		return err
	}
	var exp atomic.Bool
	exp.Store(true)
	expiredW := &simScopedWriter{buf: &bytes.Buffer{}, expired: &exp}
	if _, err := expiredW.Write([]byte("late")); !errors.Is(err, ports.ErrHandleExpired) {
		t.Fatalf("expired simScopedWriter must fail with ErrHandleExpired, got %v", err)
	}
	called := false
	if err := root.CreateExclusive(fDest, 0o600, func(io.Writer) error { called = true; return nil }); !errors.Is(err, ports.ErrAlreadyExists) || called {
		t.Fatalf("CreateExclusive must reject existing target before callback: err=%v called=%v", err, called)
	}
	if err := root.AtomicReplace(fDest, 0o600, func(w io.Writer) error {
		sfs.SetENOSPC(true)
		defer sfs.SetENOSPC(false)
		_, e := w.Write([]byte("boom"))
		return e
	}); !errors.Is(err, ErrSimulatedENOSPC) {
		t.Fatalf("mid-callback ENOSPC write got %v, want ErrSimulatedENOSPC", err)
	}
	if raw, err := root.ReadAllBounded(fDest, lim); err != nil || string(raw) != "hello" {
		t.Fatalf("failed AtomicReplace must preserve prior content: %q err=%v", raw, err)
	}
	if err := root.MkdirAll(subDir, 0o700); err != nil {
		return err
	}
	if err := root.CreateSymlink(linkDest, "../a.txt"); err != nil {
		return err
	}
	if err := root.AtomicReplace(linkDest, 0o600, func(io.Writer) error { called = true; return nil }); !errors.Is(err, ports.ErrSymlinkRejected) || called {
		t.Fatalf("AtomicReplace on symlink must fail with ErrSymlinkRejected before callback: err=%v called=%v", err, called)
	}
	info, err := root.Stat(linkDest)
	if err != nil || info.Name() != linkDest.Base() || info.Size() != 5 || info.Mode().IsDir() {
		t.Fatalf("Stat(symlink) must follow intra-root target with Name=Base(): info=%+v err=%v", info, err)
	}
	return nil
}

func verifyLockedFileModes(t *testing.T, sfs *SimScopedRootFS, root ports.RootHandle, fDest pathalg.LocalRootedDest) error {
	t.Helper()
	ctx := context.Background()
	if err := root.WithLockedFile(ctx, fDest, ports.LockShared, false, 0o600, func(f ports.LockedFile) error {
		if _, wErr := f.Write([]byte("nope")); !errors.Is(wErr, ports.ErrPermissionDenied) {
			t.Fatalf("LockShared Write got %v, want ErrPermissionDenied", wErr)
		}
		if tErr := f.Truncate(0); !errors.Is(tErr, ports.ErrPermissionDenied) {
			t.Fatalf("LockShared Truncate got %v, want ErrPermissionDenied", tErr)
		}
		return nil
	}); err != nil {
		return err
	}
	return root.WithLockedFile(ctx, fDest, ports.LockExclusive, false, 0o600, func(f ports.LockedFile) error {
		sfs.SetENOSPC(true)
		defer sfs.SetENOSPC(false)
		if _, wErr := f.Write([]byte("x")); !errors.Is(wErr, ErrSimulatedENOSPC) {
			t.Fatalf("LockExclusive Write under ENOSPC got %v, want ErrSimulatedENOSPC", wErr)
		}
		if tErr := f.Truncate(1); !errors.Is(tErr, ErrSimulatedENOSPC) {
			t.Fatalf("LockExclusive Truncate under ENOSPC got %v, want ErrSimulatedENOSPC", tErr)
		}
		if sErr := f.Sync(); !errors.Is(sErr, ErrSimulatedENOSPC) {
			t.Fatalf("LockExclusive Sync under ENOSPC got %v, want ErrSimulatedENOSPC", sErr)
		}
		return nil
	})
}

// TestSim_RemoteFSAndOperatorReadSymlinks 验证远端中间目录软链解析、子树原子重命名与操作员只读中间软链策略。
func TestSim_RemoteFSAndOperatorReadSymlinks(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rfs := NewSimRemoteFS(NewSimClock(DefaultBaseTime()))
	lim, _ := ports.NewReadLimits(1024)
	ws, _ := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: 0o600})

	etcDir, _ := pathalg.ParseRemotePath("/etc")
	etcFile, _ := pathalg.ParseRemotePath("/etc/app.conf")
	linkDir, _ := pathalg.ParseRemotePath("/unprotected/dir_link")
	viaLink, _ := pathalg.ParseRemotePath("/unprotected/dir_link/app.conf")
	_ = rfs.MkdirAll(ctx, etcDir, 0o755)
	if _, err := rfs.WriteFileAtomic(ctx, etcFile, ws, strings.NewReader("secret")); err != nil {
		t.Fatalf("WriteFileAtomic(/etc/app.conf): %v", err)
	}
	if err := rfs.PutSymlink(linkDir, "/etc"); err != nil {
		t.Fatalf("PutSymlink: %v", err)
	}
	if rp, err := rfs.RealPath(ctx, viaLink); err != nil || rp.String() != "/etc/app.conf" {
		t.Fatalf("RealPath through dir symlink got (%q, %v), want /etc/app.conf", rp.String(), err)
	}
	if err := rfs.WithReadFile(ctx, viaLink, lim, func(rd io.Reader, _ int64) error {
		b, e := io.ReadAll(rd)
		if e != nil || string(b) != "secret" {
			t.Fatalf("WithReadFile via dir symlink got %q (%v)", b, e)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithReadFile via dir symlink failed: %v", err)
	}
	verifyRemoteFSMkdirAndRename(t, ctx, rfs, ws, etcFile)
	verifyOperatorIntermediateSymlink(t, ctx)
}

func verifyRemoteFSMkdirAndRename(t *testing.T, ctx context.Context, rfs *SimRemoteFS, ws ports.RemoteWriteSpec, regFile pathalg.RemotePath) {
	t.Helper()
	underFile, _ := pathalg.ParseRemotePath(regFile.String() + "/child")
	if err := rfs.MkdirAll(ctx, underFile, 0o755); !errors.Is(err, ports.ErrAlreadyExists) {
		t.Fatalf("MkdirAll under regular file got %v, want ErrAlreadyExists", err)
	}
	srcDir, _ := pathalg.ParseRemotePath("/move/src")
	dstDir, _ := pathalg.ParseRemotePath("/move/dst")
	srcChild, _ := pathalg.ParseRemotePath("/move/src/item.txt")
	dstChild, _ := pathalg.ParseRemotePath("/move/dst/item.txt")
	selfDesc, _ := pathalg.ParseRemotePath("/move/src/sub")
	_ = rfs.MkdirAll(ctx, srcDir, 0o755)
	_, _ = rfs.WriteFileAtomic(ctx, srcChild, ws, strings.NewReader("payload"))

	if err := rfs.RenameAtomic(ctx, regFile, srcDir, algebraic.None[ports.RemoteFileAnchor]()); !errors.Is(err, ports.ErrRemoteIsDir) {
		t.Fatalf("file-over-dir rename got %v, want ErrRemoteIsDir", err)
	}
	if err := rfs.RenameAtomic(ctx, srcDir, selfDesc, algebraic.None[ports.RemoteFileAnchor]()); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("self-descendant dir rename got %v, want ErrInvalidArgument", err)
	}
	if err := rfs.RenameAtomic(ctx, srcDir, dstDir, algebraic.None[ports.RemoteFileAnchor]()); err != nil {
		t.Fatalf("directory subtree RenameAtomic failed: %v", err)
	}
	if _, err := rfs.Stat(ctx, srcChild); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("old subtree child must not exist after rename: %v", err)
	}
	if _, err := rfs.Stat(ctx, dstChild); err != nil {
		t.Fatalf("relocated subtree child missing after rename: %v", err)
	}
}

func verifyOperatorIntermediateSymlink(t *testing.T, ctx context.Context) {
	t.Helper()
	opFS := NewSimOperatorReadFS()
	realFile, _ := pathalg.ParseLocalSourcePath("/op/real/cfg")
	realDir, _ := pathalg.ParseLocalSourcePath("/op/real")
	linkDir, _ := pathalg.ParseLocalSourcePath("/op/linkdir")
	viaLink, _ := pathalg.ParseLocalSourcePath("/op/linkdir/cfg")
	_ = opFS.PutFile(realFile, []byte("op-data"))
	_ = opFS.PutSymlink(linkDir, realDir)

	if err := opFS.WithOperatorRead(ctx, viaLink, pathalg.SymlinkReject, func(io.Reader, int64) error { return nil }); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("SymlinkReject must reject intermediate dir symlink, got %v", err)
	}
	if err := opFS.WithOperatorRead(ctx, viaLink, pathalg.SymlinkFollowOperatorSource, func(r io.Reader, _ int64) error {
		raw, e := io.ReadAll(r)
		if e != nil || string(raw) != "op-data" {
			t.Fatalf("SymlinkFollowOperatorSource read %q (%v)", raw, e)
		}
		return nil
	}); err != nil {
		t.Fatalf("SymlinkFollowOperatorSource failed: %v", err)
	}
}

// TestSim_AuditMuxSignerAndSessionMinors 验证审计关闭优先与截断计数、签名未注册路径、OpenSSH 端点匹配、会话未启动 Wait 与 Mux 借用哨兵。
func TestSim_AuditMuxSignerAndSessionMinors(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rng := NewSeededRand(555)
	cluster := NewSimAuditCluster()
	sink, err := cluster.NewSinkFromEntropy(rng)
	if err != nil {
		t.Fatalf("NewSinkFromEntropy: %v", err)
	}
	absentOp, _ := security.NewOperationIDFrom(rng)
	if err := sink.UnstageOperation(ctx, absentOp); err != nil || cluster.LockTruncations() != 0 {
		t.Fatalf("unstaging absent op must not increment truncations: err=%v trunc=%d", err, cluster.LockTruncations())
	}
	_ = sink.Close()
	cluster.SetENOSPC(true)
	if err := sink.StageOperation(ctx, absentOp); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("closed audit sink must return ErrClosed even under ENOSPC, got %v", err)
	}

	ks := NewSimKeySigner(tck.MustPublicKey(t, tck.TestFingerprintA, 1))
	missingPath, _ := inventory.ParseKeyPathSpec("/sim/keys/unregistered")
	if _, err := ks.InspectPrivateKeyFingerprint(ctx, missingPath, algebraic.None[secret.Ref]()); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("unregistered key path must return ErrNotFound, got %v", err)
	}

	verifyOpenSSHAndTransportMinors(t, ctx, rng)
}

func verifyOpenSSHAndTransportMinors(t *testing.T, ctx context.Context, rng *SeededRand) {
	t.Helper()
	epA, epB := tck.MustEndpoint(t, "10.0.0.1", 22), tck.MustEndpoint(t, "10.0.0.2", 22)
	target, _ := option.ParseOriginalHost("web")
	layerA := option.UnsetOptionLayer().WithForwardAgent(true)
	layerB := option.UnsetOptionLayer().WithBatchMode(true)
	vhA, _ := ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
		Alias: "web", SourceFile: "/sim/cfg", Endpoint: algebraic.Some(epA), Proxy: option.NewProxyUnset(), Layer: layerA,
	})
	vhWild, _ := ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
		Alias: "web", SourceFile: "/sim/cfg", Endpoint: algebraic.None[netaddr.Endpoint](), Proxy: option.NewProxyUnset(), Layer: layerB,
	})
	src := NewSimOpenSSHConfigSource(vhA, vhWild)
	if got, err := src.ResolveTier4(ctx, target, epA); err != nil || !got.ForwardAgent().IsSome() || !got.BatchMode().IsSome() {
		t.Fatalf("matching endpoint ResolveTier4 must compose both layers: layer=%+v err=%v", got, err)
	}
	if got, err := src.ResolveTier4(ctx, target, epB); err != nil || got.ForwardAgent().IsSome() || !got.BatchMode().IsSome() {
		t.Fatalf("non-matching endpoint must only apply endpoint-agnostic layer: layer=%+v err=%v", got, err)
	}

	clk := NewSimClock(DefaultBaseTime())
	dialer := NewSimDialer(clk, rng)
	mux := NewSimMuxSocket(dialer)
	sockPath, _ := pathalg.ParseLocalSourcePath("/sim/mux/m.sock")
	mux.RegisterMaster(sockPath, 1234)
	conn, err := mux.DialMux(ctx, sockPath)
	if err != nil || dialer.OpenConns() != 1 {
		t.Fatalf("DialMux must track connection in SimDialer: err=%v open=%d", err, dialer.OpenConns())
	}
	sess, err := conn.OpenSession(ctx)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if _, err := sess.Wait(ctx); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("Wait before Start must fail with ErrInvalidArgument, got %v", err)
	}
	_ = sess.Close()
	if _, err := sess.Wait(ctx); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("Wait after Close must fail with ErrClosed, got %v", err)
	}
	_ = conn.Close()
	if dialer.OpenConns() != 0 {
		t.Fatalf("Close must release DialMux connection count, got %d", dialer.OpenConns())
	}
	dir, _ := pathalg.ParseLocalDir("/sim/mux")
	name, _ := pathalg.ParseLocalRootedDest("s.sock")
	if err := mux.WithListener(ctx, dir, name, func(ln net.Listener) error {
		if _, ok := ln.(*simMemListener); !ok {
			t.Fatalf("WithListener must pass sentinel-guarded *simMemListener")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithListener: %v", err)
	}
	var expLn atomic.Bool
	expLn.Store(true)
	expiredLn := &simMemListener{addr: "sim", expired: &expLn}
	if _, err := expiredLn.Accept(); !errors.Is(err, ports.ErrHandleExpired) {
		t.Fatalf("expired simMemListener Accept must fail with ErrHandleExpired, got %v", err)
	}
	if err := expiredLn.Close(); !errors.Is(err, ports.ErrHandleExpired) {
		t.Fatalf("expired simMemListener Close must fail with ErrHandleExpired, got %v", err)
	}
}
