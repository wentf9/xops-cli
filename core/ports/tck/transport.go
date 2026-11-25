package tck

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"net"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/ports"
)

// DialerFixture 描述 DialerPort / TransportConn / RemoteSession 契约测试夹具。
type DialerFixture struct {
	// NewDialer 返回待测拨号器；可与已连接的仿真/回环服务端交互。
	NewDialer func(t *testing.T) ports.DialerPort
	// TestCommand 指定用于验证 RemoteSession.Start + Wait 的只读命令（为空时默认 "echo tck-ok"）。
	TestCommand string
	// CheckMultiHop 为 true 时额外验证基于首跳 parent TransportConn 的二跳拨号契约。
	CheckMultiHop bool
	// CheckRemoteFS 为 true 时验证 TransportConn.OpenRemoteFS 可打开可用 RemoteFSPort。
	CheckRemoteFS bool
	// CheckTunnelExtensions 为 true 时验证 DialStreamLocal、ListenStreamLocal 与 OpenTUN 成功返回并可关闭。
	CheckTunnelExtensions bool
}

// MuxSocketFixture 描述 MuxSocketPort 契约测试夹具。
type MuxSocketFixture struct {
	// NewMux 返回待测多路复用套接字端口与用于 WithListener 的合法本机套接字路径（可含 OpenSSH ':'）。
	NewMux func(t *testing.T) (ports.MuxSocketPort, pathalg.LocalSourcePath)
	// ExistingSocket 指向活跃 ControlMaster 套接字路径（可选；提供时验证 Probe/Control/DialMux）。
	ExistingSocket algebraic.Option[pathalg.LocalSourcePath]
}

// RemoteFSFixture 描述 RemoteFSPort（SFTP v3 协议无关安全文件端口）契约测试夹具。
type RemoteFSFixture struct {
	// NewRemoteFS 返回隔离的 RemoteFSPort 与测试工作目录路径（如 "/tmp/tck"）。
	NewRemoteFS func(t *testing.T) (ports.RemoteFSPort, pathalg.RemotePath)
	// CheckDevInoAnchor 为 true 时使用携带 (dev, ino) 的失配锚点验证 FSTAT 锚定拦截（ADR-016）。
	CheckDevInoAnchor bool
}

// RunDialerSuite 验证 DialerPort、TransportConn 与 RemoteSession 的单跳/多跳拨号、命令执行、保活与关闭幂等契约。
func RunDialerSuite(t *testing.T, fx DialerFixture) {
	t.Helper()
	requireTrue(t, fx.NewDialer != nil, "DialerFixture.NewDialer 不能为 nil")
	cmdText := fx.TestCommand
	if cmdText == "" {
		cmdText = "echo tck-ok"
	}

	t.Run("ValidationAndSingleHopLifecycle", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		dialer := fx.NewDialer(t)
		singlePlan, multiPlan := MustHopAndPlan(t)
		hop0, ok := singlePlan.HopAt(0)
		requireTrue(t, ok, "HopAt(0)")
		dig0, ok := singlePlan.HopDigestAt(0)
		requireTrue(t, ok, "HopDigestAt(0)")

		var nilCtx context.Context
		var zeroHop plan.HopSpec
		var zeroDig plan.HopDigest
		_, err := dialer.DialHop(nilCtx, hop0, dig0, nil)
		requireErrIs(t, err, ports.ErrNilContext, "DialHop(nil ctx)")
		_, err = dialer.DialHop(ctx, zeroHop, dig0, nil)
		requireErr(t, err, "DialHop(zero hop)")
		_, err = dialer.DialHop(ctx, hop0, zeroDig, nil)
		requireErr(t, err, "DialHop(zero digest)")

		conn, err := dialer.DialHop(ctx, hop0, dig0, nil)
		requireNoErr(t, err, "DialHop(hop0)")
		requireTrue(t, conn.IsAlive() && conn.HopDigest().Equal(dig0) && conn.Endpoint().Equal(hop0.Endpoint()), "TransportConn 元信息须与 HopSpec/HopDigest 一致")
		requireNoErr(t, conn.SendKeepalive(ctx), "SendKeepalive")

		verifyRemoteSessionLifecycle(t, ctx, conn, cmdText)
		verifyTransportTunnelExtensions(t, ctx, conn, fx.CheckTunnelExtensions)

		if fx.CheckRemoteFS {
			rfs, rErr := conn.OpenRemoteFS(ctx)
			requireNoErr(t, rErr, "OpenRemoteFS")
			requireNoErr(t, rfs.Close(), "RemoteFS.Close")
		}
		if fx.CheckMultiHop {
			hop1, okH := multiPlan.HopAt(1)
			dig1, okD := multiPlan.HopDigestAt(1)
			requireTrue(t, okH && okD, "multiPlan hop1")
			conn2, dErr := dialer.DialHop(ctx, hop1, dig1, conn)
			requireNoErr(t, dErr, "DialHop(hop1 via parent)")
			requireTrue(t, conn2.IsAlive() && conn2.HopDigest().Equal(dig1), "二跳连接摘要须匹配")
			requireNoErr(t, conn2.Close(), "conn2.Close")
		}

		requireNoErr(t, conn.Close(), "conn.Close(1)")
		requireNoErr(t, conn.Close(), "conn.Close(2, idempotent)")
		requireTrue(t, !conn.IsAlive(), "关闭后 IsAlive 须为 false")
		requireErrIs(t, conn.SendKeepalive(ctx), ports.ErrClosed, "关闭后 SendKeepalive 须返回 ErrClosed")
	})
}

func verifyRemoteSessionLifecycle(t *testing.T, ctx context.Context, conn ports.TransportConn, cmdText string) {
	t.Helper()
	sess, err := conn.OpenSession(ctx)
	requireNoErr(t, err, "OpenSession")

	var stdout, stderr bytes.Buffer
	err = sess.Start(ctx, MustCommandPlan(t, cmdText), ports.ExecStreams{Stdout: &stdout, Stderr: &stderr})
	requireNoErr(t, err, "RemoteSession.Start")
	out, err := sess.Wait(ctx)
	requireNoErr(t, err, "RemoteSession.Wait")
	requireTrue(t, out != nil && out.IsValid(), "ExecutionOutcome 必须有效")
	completed, ok := out.(*execution.OutcomeCompleted)
	requireTrue(t, ok && completed.Succeeded(), "测试命令须以成功 ExitStatus 完成")
	requireNoErr(t, sess.Close(), "RemoteSession.Close(1)")
	requireNoErr(t, sess.Close(), "RemoteSession.Close(2, idempotent)")

	// 验证统一 ExecStreams.PTY + Env 驱动的 StartShell 契约。
	shellSess, err := conn.OpenSession(ctx)
	requireNoErr(t, err, "OpenSession(shell)")
	sz, err := ports.NewTerminalSize(80, 24)
	requireNoErr(t, err, "NewTerminalSize")
	ptyReq, err := ports.NewPTYRequest("xterm-256color", sz)
	requireNoErr(t, err, "NewPTYRequest")
	err = shellSess.StartShell(ctx, ports.ExecStreams{PTY: algebraic.Some(ptyReq), Env: map[string]string{"LANG": "C.UTF-8"}})
	requireNoErr(t, err, "RemoteSession.StartShell")
	_, pErr := shellSess.StdinPipe()
	requireErr(t, pErr, "StartShell 后获取 StdinPipe 必须拒绝")
	requireNoErr(t, shellSess.Close(), "RemoteSession(shell).Close")

	verifyRemoteSessionPipes(t, ctx, conn, cmdText)
}

func verifyRemoteSessionPipes(t *testing.T, ctx context.Context, conn ports.TransportConn, cmdText string) {
	t.Helper()
	sess, err := conn.OpenSession(ctx)
	requireNoErr(t, err, "OpenSession(pipes)")
	stdinW, err := sess.StdinPipe()
	requireNoErr(t, err, "StdinPipe")
	stdoutR, err := sess.StdoutPipe()
	requireNoErr(t, err, "StdoutPipe")
	stderrR, err := sess.StderrPipe()
	requireNoErr(t, err, "StderrPipe")

	// 重复获取与非空 ExecStreams 混用均须严格拒绝。
	_, err = sess.StdinPipe()
	requireErr(t, err, "重复 StdinPipe 必须拒绝")
	_, err = sess.StdoutPipe()
	requireErr(t, err, "重复 StdoutPipe 必须拒绝")
	_, err = sess.StderrPipe()
	requireErr(t, err, "重复 StderrPipe 必须拒绝")

	cmd := MustCommandPlan(t, cmdText)
	var clash bytes.Buffer
	requireErr(t, sess.Start(ctx, cmd, ports.ExecStreams{Stdin: strings.NewReader("x")}), "StdinPipe 与 ExecStreams.Stdin 互斥")
	requireErr(t, sess.Start(ctx, cmd, ports.ExecStreams{Stdout: &clash}), "StdoutPipe 与 ExecStreams.Stdout 互斥")
	requireErr(t, sess.Start(ctx, cmd, ports.ExecStreams{Stderr: &clash}), "StderrPipe 与 ExecStreams.Stderr 互斥")

	requireNoErr(t, sess.Start(ctx, cmd, ports.ExecStreams{}), "Start(pipes)")
	_, err = sess.StdoutPipe()
	requireErr(t, err, "Start 后 StdoutPipe 必须拒绝")
	requireNoErr(t, stdinW.Close(), "StdinPipe.Close")
	outBytes, err := io.ReadAll(stdoutR)
	requireNoErr(t, err, "ReadAll(StdoutPipe)")
	_, err = io.ReadAll(stderrR)
	requireNoErr(t, err, "ReadAll(StderrPipe)")
	requireTrue(t, len(outBytes) > 0, "StdoutPipe 应读到命令输出")
	out, err := sess.Wait(ctx)
	requireNoErr(t, err, "Wait(pipes)")
	requireTrue(t, out != nil && out.IsValid(), "Wait(pipes) Outcome 必须有效")
	requireNoErr(t, sess.Close(), "Close(pipes)")
	_, err = sess.StdinPipe()
	requireErr(t, err, "Close 后 StdinPipe 必须拒绝")
}

func verifyTransportTunnelExtensions(t *testing.T, ctx context.Context, conn ports.TransportConn, requireOK bool) {
	t.Helper()
	var zeroRP pathalg.RemotePath
	var zeroTUN ports.TUNSpec
	_, err := conn.DialStreamLocal(ctx, zeroRP)
	requireErr(t, err, "DialStreamLocal(zero path)")
	_, err = conn.ListenStreamLocal(ctx, zeroRP)
	requireErr(t, err, "ListenStreamLocal(zero path)")
	_, err = conn.OpenTUN(ctx, zeroTUN)
	requireErr(t, err, "OpenTUN(zero spec)")
	if !requireOK {
		return
	}
	rp, err := pathalg.ParseRemotePath("/run/tck.sock")
	requireNoErr(t, err, "ParseRemotePath")
	c, err := conn.DialStreamLocal(ctx, rp)
	requireNoErr(t, err, "DialStreamLocal")
	requireNoErr(t, c.Close(), "DialStreamLocal.Close")
	ln, err := conn.ListenStreamLocal(ctx, rp)
	requireNoErr(t, err, "ListenStreamLocal")
	requireNoErr(t, ln.Close(), "ListenStreamLocal.Close")
	ts, err := ports.NewTUNSpec(ports.TUNModePointToPoint, 0, 0)
	requireNoErr(t, err, "NewTUNSpec")
	tun, err := conn.OpenTUN(ctx, ts)
	requireNoErr(t, err, "OpenTUN")
	requireNoErr(t, tun.Close(), "OpenTUN.Close")
}

// RunMuxSocketSuite 验证 MuxSocketPort 的参数校验、统一 socketPath 作用域监听生命周期与控制面契约（INV-A3 / INV-C4）。
func RunMuxSocketSuite(t *testing.T, fx MuxSocketFixture) {
	t.Helper()
	requireTrue(t, fx.NewMux != nil, "MuxSocketFixture.NewMux 不能为 nil")

	t.Run("ValidationAndScopedListener", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		mux, listenPath := fx.NewMux(t)
		var nilCtx context.Context
		var zeroSrc pathalg.LocalSourcePath
		var zeroReq ports.MuxControlRequest

		_, err := mux.Probe(nilCtx, zeroSrc)
		requireErrIs(t, err, ports.ErrNilContext, "Probe(nil ctx)")
		_, err = mux.Probe(ctx, zeroSrc)
		requireErr(t, err, "Probe(zero path)")
		_, err = mux.Control(nilCtx, zeroReq)
		requireErrIs(t, err, ports.ErrNilContext, "Control(nil ctx)")
		_, err = mux.Control(ctx, zeroReq)
		requireErr(t, err, "Control(zero req)")
		_, err = mux.DialMux(nilCtx, zeroSrc)
		requireErrIs(t, err, ports.ErrNilContext, "DialMux(nil ctx)")
		_, err = mux.DialMux(ctx, zeroSrc)
		requireErr(t, err, "DialMux(zero path)")

		requireErrIs(t, mux.WithListener(nilCtx, listenPath, func(net.Listener) error { return nil }), ports.ErrNilContext, "WithListener(nil ctx)")
		requireErrIs(t, mux.WithListener(ctx, listenPath, nil), ports.ErrNilCallback, "WithListener(nil fn)")
		requireErr(t, mux.WithListener(ctx, zeroSrc, func(net.Listener) error { return nil }), "WithListener(zero path)")

		var observedAddr string
		err = mux.WithListener(ctx, listenPath, func(ln net.Listener) error {
			requireTrue(t, ln != nil && ln.Addr() != nil, "WithListener 借出的 net.Listener 必须非 nil")
			observedAddr = ln.Addr().String()
			return nil
		})
		requireNoErr(t, err, "WithListener")
		requireTrue(t, observedAddr != "", "监听地址不能为空")

		if sockPath, ok := fx.ExistingSocket.Get(); ok {
			verifyExistingMuxControl(t, ctx, mux, sockPath)
		}
	})
}

func verifyExistingMuxControl(t *testing.T, ctx context.Context, mux ports.MuxSocketPort, sockPath pathalg.LocalSourcePath) {
	t.Helper()
	resp, err := mux.Probe(ctx, sockPath)
	requireNoErr(t, err, "Probe(existing)")
	requireTrue(t, resp.IsValid(), "Probe 响应必须有效")

	req, err := ports.NewMuxControlRequest(ports.MuxActionCheck, sockPath, algebraic.None[ports.ForwardSpec]())
	requireNoErr(t, err, "NewMuxControlRequest(check)")
	cResp, err := mux.Control(ctx, req)
	requireNoErr(t, err, "Control(check)")
	requireTrue(t, cResp.IsValid(), "Control(check) 响应必须有效")
}

// RunRemoteFSSuite 验证 RemoteFSPort 的全部安全读写、有界读取、NoClobber、FSTAT 锚点校验与原子重命名契约（ADR-016）。
func RunRemoteFSSuite(t *testing.T, fx RemoteFSFixture) {
	t.Helper()
	requireTrue(t, fx.NewRemoteFS != nil, "RemoteFSFixture.NewRemoteFS 不能为 nil")

	t.Run("ValidationAndCRUD", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		rfs, workDir := fx.NewRemoteFS(t)
		requireTrue(t, workDir.IsValid(), "workDir 必须为有效 RemotePath")
		verifyRemoteFSGuards(t, ctx, rfs)
		verifyRemoteFSWriteReadAnchor(t, ctx, rfs, workDir, fx.CheckDevInoAnchor)
		verifyRemoteFSChunkAndRename(t, ctx, rfs, workDir)

		requireNoErr(t, rfs.Close(), "RemoteFSPort.Close(1)")
		requireNoErr(t, rfs.Close(), "RemoteFSPort.Close(2, idempotent)")
	})
}

func verifyRemoteFSGuards(t *testing.T, ctx context.Context, rfs ports.RemoteFSPort) {
	t.Helper()
	var nilCtx context.Context
	var zeroPath pathalg.RemotePath
	var zeroSpec ports.RemoteWriteSpec
	lim, err := ports.NewReadLimits(1024)
	requireNoErr(t, err, "NewReadLimits")

	_, err = rfs.Stat(nilCtx, zeroPath)
	requireErrIs(t, err, ports.ErrNilContext, "Stat(nil ctx)")
	_, err = rfs.Stat(ctx, zeroPath)
	requireErr(t, err, "Stat(zero path)")
	requireErrIs(t, rfs.WithReadFile(ctx, zeroPath, lim, nil), ports.ErrNilCallback, "WithReadFile(nil fn)")
	_, err = rfs.WriteFileAtomic(ctx, zeroPath, zeroSpec, strings.NewReader("x"))
	requireErr(t, err, "WriteFileAtomic(zero path/spec)")
}

func verifyRemoteFSWriteReadAnchor(t *testing.T, ctx context.Context, rfs ports.RemoteFSPort, workDir pathalg.RemotePath, checkDevIno bool) {
	t.Helper()
	requireNoErr(t, rfs.MkdirAll(ctx, workDir, 0o755), "MkdirAll(workDir)")
	realDir, err := rfs.RealPath(ctx, workDir)
	requireNoErr(t, err, "RealPath(workDir)")
	requireTrue(t, realDir.IsValid(), "RealPath 须返回有效路径")

	filePath, err := pathalg.ParseRemotePath(strings.TrimRight(realDir.String(), "/") + "/hello.txt")
	requireNoErr(t, err, "ParseRemotePath(hello.txt)")
	createSpec, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: 0o644, NoClobber: true, AtomicRename: true})
	requireNoErr(t, err, "NewRemoteWriteSpec(noClobber)")

	stat1, err := rfs.WriteFileAtomic(ctx, filePath, createSpec, strings.NewReader("remote-v1"))
	requireNoErr(t, err, "WriteFileAtomic(v1)")
	requireTrue(t, stat1.IsValid() && stat1.IsRegular() && stat1.Size() == 9, "WriteFileAtomic 返回元信息不匹配")

	// NoClobber 再次写入必须失败。
	_, err = rfs.WriteFileAtomic(ctx, filePath, createSpec, strings.NewReader("overwrite-blocked"))
	requireErrIs(t, err, ports.ErrAlreadyExists, "NoClobber 必须阻止覆盖已有文件")

	// 携带匹配锚点允许覆写；携带冲突锚点必须返回 ErrRemoteAnchorMismatch（ADR-016）。
	matchSpec, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{
		Perm: 0o644, ExpectedAnchor: algebraic.Some(stat1.Anchor()), AtomicRename: true,
	})
	requireNoErr(t, err, "NewRemoteWriteSpec(matchAnchor)")
	stat2, err := rfs.WriteFileAtomic(ctx, filePath, matchSpec, strings.NewReader("remote-v2-ok"))
	requireNoErr(t, err, "WriteFileAtomic(matching anchor)")
	requireTrue(t, stat2.Size() == 12, "匹配锚点覆写后大小不符")

	badAnchor, err := ports.NewRemoteFileAnchor(ports.RemoteFileDir, false, 0, 0)
	if checkDevIno && stat2.Anchor().HasDevIno() {
		badAnchor, err = ports.NewRemoteFileAnchor(ports.RemoteFileRegular, true, stat2.Anchor().Dev()+1, stat2.Anchor().Ino()+1)
	}
	requireNoErr(t, err, "NewRemoteFileAnchor(mismatch)")
	badSpec, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{
		Perm: 0o644, ExpectedAnchor: algebraic.Some(badAnchor),
	})
	requireNoErr(t, err, "NewRemoteWriteSpec(badAnchor)")
	_, err = rfs.WriteFileAtomic(ctx, filePath, badSpec, strings.NewReader("must-fail"))
	requireErrIs(t, err, ports.ErrRemoteAnchorMismatch, "失配锚点必须返回 ErrRemoteAnchorMismatch")

	// 验证有界读取与超限拒绝。
	lim, err := ports.NewReadLimits(64)
	requireNoErr(t, err, "NewReadLimits")
	var got []byte
	err = rfs.WithReadFile(ctx, filePath, lim, func(r io.Reader, size int64) error {
		requireTrue(t, size == 12, "WithReadFile size 不符")
		var rErr error
		got, rErr = io.ReadAll(r)
		return rErr
	})
	requireNoErr(t, err, "WithReadFile")
	requireTrue(t, bytes.Equal(got, []byte("remote-v2-ok")), "WithReadFile 内容不匹配")

	tinyLim, err := ports.NewReadLimits(4)
	requireNoErr(t, err, "NewReadLimits(4)")
	err = rfs.WithReadFile(ctx, filePath, tinyLim, func(r io.Reader, _ int64) error {
		_, rErr := io.ReadAll(r)
		return rErr
	})
	requireErrIs(t, err, ports.ErrLimitExceeded, "超出 ReadLimits 须拒绝")

	entries, err := rfs.ReadDir(ctx, realDir)
	requireNoErr(t, err, "ReadDir")
	requireTrue(t, len(entries) >= 1 && entries[0].IsValid(), "ReadDir 须返回有效 RemoteDirEntry")
}

func verifyRemoteFSChunkAndRename(t *testing.T, ctx context.Context, rfs ports.RemoteFSPort, workDir pathalg.RemotePath) {
	t.Helper()
	base := strings.TrimRight(workDir.String(), "/")
	stagePath, err := pathalg.ParseRemotePath(base + "/upload.part")
	requireNoErr(t, err, "ParseRemotePath(stage)")
	finalPath, err := pathalg.ParseRemotePath(base + "/upload.bin")
	requireNoErr(t, err, "ParseRemotePath(final)")

	requireNoErr(t, rfs.WriteChunk(ctx, stagePath, 0, strings.NewReader("chunk-1-"), 8), "WriteChunk(0)")
	requireNoErr(t, rfs.WriteChunk(ctx, stagePath, 8, strings.NewReader("chunk-2"), 7), "WriteChunk(8)")
	requireNoErr(t, rfs.RenameAtomic(ctx, stagePath, finalPath, algebraic.None[ports.RemoteFileAnchor]()), "RenameAtomic")

	st, err := rfs.Lstat(ctx, finalPath)
	requireNoErr(t, err, "Lstat(final)")
	requireTrue(t, st.IsValid() && st.IsRegular() && st.Size() == 15, "分片合并重命名后大小应为 15")

	verifyRemoteFSReadChunkAndChmod(t, ctx, rfs, finalPath)

	// RenameAtomic 携带失配锚点覆盖既有目标时必须拒绝并返回 ErrRemoteAnchorMismatch（ADR-016）。
	stage2Path, err := pathalg.ParseRemotePath(base + "/upload2.part")
	requireNoErr(t, err, "ParseRemotePath(stage2)")
	requireNoErr(t, rfs.WriteChunk(ctx, stage2Path, 0, strings.NewReader("bad"), 3), "WriteChunk(stage2)")
	wrongAnc, err := ports.NewRemoteFileAnchor(ports.RemoteFileDir, false, 0, 0)
	requireNoErr(t, err, "NewRemoteFileAnchor(wrong)")
	requireErrIs(t, rfs.RenameAtomic(ctx, stage2Path, finalPath, algebraic.Some(wrongAnc)), ports.ErrRemoteAnchorMismatch, "RenameAtomic 锚点失配须返回 ErrRemoteAnchorMismatch")
	stAfter, err := rfs.Lstat(ctx, finalPath)
	requireNoErr(t, err, "Lstat(final after rejected rename)")
	requireTrue(t, stAfter.Size() == 15, "被拒 RenameAtomic 不得覆盖既有目标文件")
	requireNoErr(t, rfs.Remove(ctx, stage2Path), "Remove(stage2)")

	requireNoErr(t, rfs.Remove(ctx, finalPath), "Remove(final)")
	requireErrIs(t, rfs.Remove(ctx, finalPath), ports.ErrNotFound, "重复 Remove 须返回 ErrNotFound")
}

func verifyRemoteFSReadChunkAndChmod(t *testing.T, ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) {
	t.Helper()
	var buf bytes.Buffer
	_, err := rfs.ReadChunk(ctx, p, -1, &buf, 4)
	requireErr(t, err, "ReadChunk(负偏移)")
	_, err = rfs.ReadChunk(ctx, p, 0, nil, 4)
	requireErr(t, err, "ReadChunk(nil dst)")

	n1, err := rfs.ReadChunk(ctx, p, 0, &buf, 8)
	requireNoErr(t, err, "ReadChunk(0..8)")
	requireTrue(t, n1 == 8 && buf.String() == "chunk-1-", "ReadChunk 首片内容不匹配")
	buf.Reset()
	n2, err := rfs.ReadChunk(ctx, p, 8, &buf, 16)
	requireErrIs(t, err, io.EOF, "ReadChunk 越尾读取须返回 io.EOF")
	requireTrue(t, n2 == 7 && buf.String() == "chunk-2", "ReadChunk 尾片内容不匹配")
	buf.Reset()
	n3, err := rfs.ReadChunk(ctx, p, 15, &buf, 4)
	requireErrIs(t, err, io.EOF, "ReadChunk 精确在 EOF 处须返回 io.EOF")
	requireTrue(t, n3 == 0, "EOF 处 ReadChunk 须返回 0 字节")

	requireErr(t, rfs.Chmod(ctx, p, 0), "Chmod(0)")
	requireErr(t, rfs.Chmod(ctx, p, fs.ModeSetuid|0o755), "Chmod(特殊权限位)")
	requireNoErr(t, rfs.Chmod(ctx, p, 0o640), "Chmod(0640)")
	st, err := rfs.Stat(ctx, p)
	requireNoErr(t, err, "Stat(after Chmod)")
	requireTrue(t, st.Perm() == 0o640, "Chmod 后 Stat.Perm 须为 0640")
}
