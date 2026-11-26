package engine_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports"
)

// TestEngine_AllRealSSHNetLoopbackEndToEnd 验证核心 Engine 全默认真实 sshnet/* 生产装配闭环：
// Dialer / HostTrust / KeySigner / PrivilegeEscalation / ShellProbe / Forwarder / MuxSocket / RemoteFS
// 全部留空（nil），通过进程内真实 x/crypto/ssh 回环服务端端到端实测：
//  1. Exec + 真实 KnownHostsDB（accept-new 落盘 + yes 复核）+ 真实 KeySigner；
//  2. ProbeShell 两阶段 POSIX 探测（sshnet/probe）；
//  3. ExecPrivileged 随机 -p/就绪帧提权握手 + Vault WithSecret 口令投递（sshnet/priv）；
//  4. SCPUpload / WriteRemoteFile / ReadRemoteFile / StatRemoteFile / SCPDownload（sshnet/sftp）；
//  5. StartForward / InspectForward / StopForward 本地 -L TCP 转发（sshnet/forward）；
//  6. StartControlMaster / ProbeMux / 透明客户端 Exec+SFTP 零新拨号复用 / ControlMux / StopControlMaster（sshnet/mux）。
func TestEngine_AllRealSSHNetLoopbackEndToEnd(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rig := newLoopbackRigBase(t, false)
	clientPub, keyPath := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_allreal")
	vault := sim.NewSimVault(rig.rng.Fork())
	sudoPassRef, err := secret.NewRef("vault", "sudo-e2e-pass")
	if err != nil {
		t.Fatalf("secret.NewRef: %v", err)
	}
	if err := secret.WithBytes([]byte("top-secret-sudo"), func(box *secret.SecretBox) error {
		return vault.PutAndVerify(ctx, sudoPassRef, box)
	}); err != nil {
		t.Fatalf("PutAndVerify(sudo): %v", err)
	}
	srv := newRealSSHNetStub(t, "top-secret-sudo", clientPub)

	eng := mustNewAllDefaultRealEngine(t, rig, vault, srv)
	defer closeEngineChecked(t, eng)

	baseCLI := option.UnsetOptionLayer().
		WithIdentityFiles(mustIdentityPathList(t, keyPath)).
		WithIdentitiesOnly(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew)

	assertAllRealExecAndKnownHosts(t, ctx, eng, baseCLI, keyPath)
	assertAllRealDefaultKeySignerDoctor(t, ctx, eng, keyPath)
	assertAllRealProbeAndPrivilege(t, ctx, eng, baseCLI, sudoPassRef, srv)
	assertAllRealSFTPAndSCP(t, ctx, eng, rig, baseCLI, srv)
	assertAllRealLocalForward(t, ctx, eng, baseCLI, srv)
	assertAllRealControlMasterAndReuse(t, ctx, eng, rig, vault, keyPath, srv)
	assertRemoteFSOverridePreservesMuxSubsystems(t, ctx, rig, vault, keyPath, srv)
}

func mustNewAllDefaultRealEngine(t *testing.T, rig *loopbackEngineRig, vault *sim.SimVault, srv *realSSHNetStub) *engine.Engine {
	t.Helper()
	var emptyGraph inventory.Graph
	invStore, err := sim.NewSimInventoryStore(emptyGraph)
	if err != nil {
		t.Fatalf("NewSimInventoryStore: %v", err)
	}
	// 故意将全部 8 个真实 sshnet 槽位保持 nil，强制验证 Engine 默认生产装配路径。
	eng, err := engine.New(engine.Config{
		Profile:        engine.PolicyProfileDirectOperator,
		Guardrail:      engine.DefaultGuardrailConfig(),
		Clock:          rig.clk,
		Entropy:        rig.rng.Fork(),
		AuditSink:      rig.auditSink,
		Reconciler:     rig.cluster,
		ScopedFS:       rig.rootFS,
		OperatorReadFS: rig.readFS,
		Env:            rig.env,
		Vault:          vault,
		VaultControl:   vault,
		InventoryStore: invStore,
		KnownStores:    []string{"vault"},
		DialContext:    srv.dialFunc(),
	})
	if err != nil {
		t.Fatalf("engine.New(all-real defaults): %v", err)
	}
	return eng
}

func assertAllRealDefaultKeySignerDoctor(t *testing.T, ctx context.Context, eng *engine.Engine, keyPath string) {
	t.Helper()
	idID, _ := inventory.ParseIdentityID("id-real-key")
	user, _ := option.ParseUsername("deploy")
	kp, err := inventory.ParseKeyPathSpec(keyPath)
	if err != nil {
		t.Fatalf("ParseKeyPathSpec: %v", err)
	}
	kps := algebraic.NewNonEmpty(kp)
	authKey, err := inventory.NewAuthPrivateKey(kps, algebraic.None[inventory.KeyPassphraseBinding](), nil)
	if err != nil {
		t.Fatalf("NewAuthPrivateKey: %v", err)
	}
	ident, err := inventory.NewIdentity(inventory.IdentitySpec{ID: idID, User: user, Auth: authKey})
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	if _, err := eng.CreateIdentity(ctx, engine.IdentityMutationRequest{Identity: ident}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	rep, err := eng.InventoryDoctor(ctx, engine.InventoryDoctorRequest{CheckVaultSecrets: true})
	if err != nil {
		t.Fatalf("InventoryDoctor: %v", err)
	}
	for _, f := range rep.Findings {
		if f.Code == "key_signer_unavailable" || f.Severity == engine.DoctorSeverityError {
			t.Fatalf("默认真实 KeySigner 装配下 InventoryDoctor 不应报告缺失或错误: %+v", rep.Findings)
		}
	}
}

func assertAllRealExecAndKnownHosts(t *testing.T, ctx context.Context, eng *engine.Engine, baseCLI option.OptionLayer, keyPath string) {
	t.Helper()
	var stdout bytes.Buffer
	out, err := eng.Exec(ctx, engine.ExecRequest{
		TargetSpec: "deploy@127.0.0.1:22100",
		CLIOptions: baseCLI,
		Command:    "uname -a",
		Stdout:     &stdout,
	})
	if err != nil {
		t.Fatalf("Engine.Exec(accept-new): %v", err)
	}
	comp, ok := out.(*execution.OutcomeCompleted)
	if !ok || !comp.Succeeded() || stdout.String() != "real-exec:uname -a\n" {
		t.Fatalf("首次真实 Exec 输出失配: out=%#v stdout=%q", out, stdout.String())
	}

	// 第二次以 StrictHostKeyChecking=yes 连接同一端点，验证真实 KnownHostsDB 已落盘并放行。
	strictCLI := option.UnsetOptionLayer().
		WithIdentityFiles(mustIdentityPathList(t, keyPath)).
		WithIdentitiesOnly(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingYes)
	stdout.Reset()
	out2, err := eng.Exec(ctx, engine.ExecRequest{
		TargetSpec: "deploy@127.0.0.1:22100",
		CLIOptions: strictCLI,
		Command:    "echo known-ok",
		Stdout:     &stdout,
	})
	if err != nil {
		t.Fatalf("Engine.Exec(strict yes): %v", err)
	}
	comp2, ok := out2.(*execution.OutcomeCompleted)
	if !ok || !comp2.Succeeded() || stdout.String() != "real-exec:echo known-ok\n" {
		t.Fatalf("StrictHostKeyChecking=yes 复核失配: out=%#v stdout=%q", out2, stdout.String())
	}
}

func assertAllRealProbeAndPrivilege(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	baseCLI option.OptionLayer,
	sudoPassRef secret.Ref,
	srv *realSSHNetStub,
) {
	t.Helper()
	rc := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:22100", CLIOptions: baseCLI}}
	probeRes, err := eng.ProbeShell(ctx, engine.ProbeShellRequest{RemoteCall: rc})
	if err != nil {
		t.Fatalf("Engine.ProbeShell: %v", err)
	}
	if probeRes.Dialect() != execution.DialectPOSIX || probeRes.Interpreter() != execution.InterpreterBash || probeRes.ProbeStage() != 2 {
		t.Fatalf("真实两阶段 ShellProbe 结果失配: dialect=%s interp=%s stage=%d", probeRes.Dialect(), probeRes.Interpreter(), probeRes.ProbeStage())
	}
	if srv.probeCount.Load() != 2 {
		t.Fatalf("期望触发 2 次探针命令（阶段 1 + 阶段 2），实际=%d", srv.probeCount.Load())
	}

	cmdPlan, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindCommand,
		Profile: execution.DefaultServerLaunchProfile(),
		Command: "id",
	})
	if err != nil {
		t.Fatalf("NewCommandPlan: %v", err)
	}
	privReq, err := engine.NewPrivilegeRequest(engine.PrivilegeRequestSpec{
		Method:  engine.PrivilegeMethodSudo,
		Command: cmdPlan,
	})
	if err != nil {
		t.Fatalf("NewPrivilegeRequest: %v", err)
	}
	var privOut bytes.Buffer
	pOut, err := eng.ExecPrivileged(ctx, engine.PrivilegeExecRequest{
		RemoteCall:  rc,
		Privilege:   privReq,
		PasswordRef: algebraic.Some(sudoPassRef),
		Stdout:      &privOut,
	})
	if err != nil {
		t.Fatalf("Engine.ExecPrivileged: %v", err)
	}
	pComp, ok := pOut.(*execution.OutcomeCompleted)
	if !ok || !pComp.Succeeded() || privOut.String() != "uid=0(root)\n" || srv.privCount.Load() != 1 {
		t.Fatalf("真实 sshnet/priv 提权结果失配: out=%#v stdout=%q privCount=%d", pOut, privOut.String(), srv.privCount.Load())
	}
}

func assertAllRealSFTPAndSCP(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	rig *loopbackEngineRig,
	baseCLI option.OptionLayer,
	srv *realSSHNetStub,
) {
	t.Helper()
	rc := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:22100", CLIOptions: baseCLI}}
	assertAllRealSFTPWriteReadStat(t, ctx, eng, rc)
	assertAllRealSCPRoundTrip(t, ctx, eng, rig, rc, srv)
}

func assertAllRealSFTPWriteReadStat(t *testing.T, ctx context.Context, eng *engine.Engine, rc engine.RemoteCall) {
	t.Helper()
	// 1. 经真实 sshnet/sftp 原子写入并回读、Stat 校验。
	writtenPath, err := pathalg.ParseRemotePath("/srv/e2e/written.txt")
	if err != nil {
		t.Fatalf("ParseRemotePath: %v", err)
	}
	wantWritten := []byte("real-sftp-atomic-payload")
	if _, err := eng.WriteRemoteFile(ctx, engine.RemoteFileWriteRequest{
		RemoteCall:    rc,
		Path:          writtenPath,
		Content:       wantWritten,
		CreateParents: true,
	}); err != nil {
		t.Fatalf("Engine.WriteRemoteFile: %v", err)
	}
	rdRes, err := eng.ReadRemoteFile(ctx, engine.RemoteFileReadRequest{RemoteCall: rc, Path: writtenPath})
	if err != nil || !bytes.Equal(rdRes.Content, wantWritten) {
		t.Fatalf("Engine.ReadRemoteFile 失配: got=%q err=%v", string(rdRes.Content), err)
	}
	st, err := eng.StatRemoteFile(ctx, engine.RemoteStatRequest{RemoteCall: rc, Path: writtenPath})
	if err != nil || !st.IsRegular() || st.Size() != int64(len(wantWritten)) {
		t.Fatalf("Engine.StatRemoteFile 失配: st=%+v err=%v", st, err)
	}
}

func assertAllRealSCPRoundTrip(t *testing.T, ctx context.Context, eng *engine.Engine, rig *loopbackEngineRig, rc engine.RemoteCall, srv *realSSHNetStub) {
	t.Helper()
	// 2. 经真实 OperatorReadFS + sshnet/sftp SCPUpload 上传本地文件，再经 ScopedRootFS SCPDownload 下载校验。
	localDir := mustPrepareLocalTransferFile(t, rig, "src.txt", []byte("real-scp-roundtrip-content-0123456789"))
	srcFull, err := pathalg.ParseLocalSourcePath(filepath.Join(localDir.String(), "src.txt"))
	if err != nil {
		t.Fatalf("ParseLocalSourcePath: %v", err)
	}
	upSrc, err := engine.NewOperatorUploadSource(srcFull, pathalg.SymlinkFollowOperatorSource)
	if err != nil {
		t.Fatalf("NewOperatorUploadSource: %v", err)
	}
	remSCP, _ := pathalg.ParseRemotePath("/srv/e2e/uploaded.txt")
	if _, err := eng.SCPUpload(ctx, engine.SCPUploadRequest{RemoteCall: rc, Source: upSrc, RemoteDest: remSCP}); err != nil {
		t.Fatalf("Engine.SCPUpload: %v", err)
	}
	dlRel, _ := pathalg.ParseLocalRootedDest("dl/downloaded.txt")
	if _, err := eng.SCPDownload(ctx, engine.SCPDownloadRequest{
		RemoteCall:   rc,
		RemoteSource: remSCP,
		LocalRoot:    localDir,
		LocalDest:    dlRel,
	}); err != nil {
		t.Fatalf("Engine.SCPDownload: %v", err)
	}
	gotDL := mustReadLocalRootFile(t, rig.rootFS, localDir, dlRel)
	if string(gotDL) != "real-scp-roundtrip-content-0123456789" || srv.sftpCount.Load() < 1 {
		t.Fatalf("真实 SFTP/SCP 往返校验失败: got=%q sftpCount=%d", string(gotDL), srv.sftpCount.Load())
	}
}

func mustPrepareLocalTransferFile(t *testing.T, rig *loopbackEngineRig, name string, data []byte) pathalg.LocalDir {
	t.Helper()
	localDir, err := rig.homeDir.JoinComponent("xfer")
	if err != nil {
		t.Fatalf("JoinComponent(xfer): %v", err)
	}
	if err := rig.rootFS.EnsureRoot(localDir, 0o700); err != nil {
		t.Fatalf("EnsureRoot(xfer): %v", err)
	}
	srcRel, _ := pathalg.ParseLocalRootedDest(name)
	if err := rig.rootFS.WithRoot(localDir, func(r ports.RootHandle) error {
		return r.AtomicReplace(srcRel, 0o600, func(w io.Writer) error {
			_, wErr := w.Write(data)
			return wErr
		})
	}); err != nil {
		t.Fatalf("写入本地 SCP 源文件失败: %v", err)
	}
	return localDir
}

func mustReadLocalRootFile(t *testing.T, rootFS ports.ScopedRootFS, dir pathalg.LocalDir, rel pathalg.LocalRootedDest) []byte {
	t.Helper()
	var got []byte
	readLim, _ := ports.NewReadLimits(1 << 20)
	if err := rootFS.WithRoot(dir, func(r ports.RootHandle) error {
		return r.WithReadRegular(rel, readLim, func(rd ports.BoundedReadHandle, _ int64) error {
			var rErr error
			got, rErr = io.ReadAll(rd)
			return rErr
		})
	}); err != nil {
		t.Fatalf("读取下载文件失败: %v", err)
	}
	return got
}

func assertAllRealLocalForward(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	baseCLI option.OptionLayer,
	srv *realSSHNetStub,
) {
	t.Helper()
	rc := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:22100", CLIOptions: baseCLI}}
	// 默认 ForwardAllowGatewayPorts=false 必须拒绝非回环 0.0.0.0 绑定（OpenSSH GatewayPorts=no）。
	nonLoopSpec, err := engine.NewForwardSpec(engine.ForwardLocal, "0.0.0.0:0", "10.88.0.1:8080")
	if err != nil {
		t.Fatalf("NewForwardSpec(0.0.0.0): %v", err)
	}
	if _, err := eng.StartForward(ctx, engine.StartForwardRequest{RemoteCall: rc, Spec: nonLoopSpec}); err == nil {
		t.Fatal("默认 ForwardAllowGatewayPorts=false 必须拒绝 0.0.0.0 非回环绑定")
	}

	fwdSpec, err := engine.NewForwardSpec(engine.ForwardLocal, "127.0.0.1:0", "10.88.0.1:8080")
	if err != nil {
		t.Fatalf("NewForwardSpec: %v", err)
	}
	fwdInfo, err := eng.StartForward(ctx, engine.StartForwardRequest{RemoteCall: rc, Spec: fwdSpec})
	if err != nil {
		t.Fatalf("Engine.StartForward(-L): %v", err)
	}
	if st, err := eng.InspectForward(ctx, fwdInfo.Handle()); err != nil || !st.Active() {
		_ = eng.StopForward(ctx, fwdInfo.Handle())
		t.Fatalf("Engine.InspectForward 失配: st=%+v err=%v", st, err)
	}
	roundTripLoopbackForward(t, ctx, fwdInfo.BoundAddr(), "ping-fwd\n", "fwd[10.88.0.1:8080]:ping-fwd\n")
	if srv.fwdCount.Load() != 1 {
		_ = eng.StopForward(ctx, fwdInfo.Handle())
		t.Fatalf("期望 1 次 -L direct-tcpip，实际=%d", srv.fwdCount.Load())
	}
	if err := eng.StopForward(ctx, fwdInfo.Handle()); err != nil {
		t.Fatalf("Engine.StopForward: %v", err)
	}
	<-fwdInfo.Done()
	if err := fwdInfo.Wait(ctx); err != nil {
		t.Fatalf("StopForward 后 ForwardInfo.Wait(ctx) 期望 nil，实际=%v", err)
	}
}

func roundTripLoopbackForward(t *testing.T, ctx context.Context, addr, send, want string) {
	t.Helper()
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("Dial -L BoundAddr(%s): %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, send); err != nil {
		t.Fatalf("写入 -L 转发连接失败: %v", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || reply != want {
		t.Fatalf("真实 sshnet/forward -L 回显失配: reply=%q err=%v", reply, err)
	}
}

func assertAllRealControlMasterAndReuse(
	t *testing.T,
	ctx context.Context,
	masterEng *engine.Engine,
	rig *loopbackEngineRig,
	vault *sim.SimVault,
	keyPath string,
	srv *realSSHNetStub,
) {
	t.Helper()
	sockDir := shortEngineMuxDir(t)
	sockRaw := filepath.Join(sockDir, "cm.sock")
	cpSpec, err := option.ParseControlPath(sockRaw)
	if err != nil {
		t.Fatalf("ParseControlPath(%q): %v", sockRaw, err)
	}
	mkCLI := func(mode option.ControlMasterMode) option.OptionLayer {
		return option.UnsetOptionLayer().
			WithIdentityFiles(mustIdentityPathList(t, keyPath)).
			WithIdentitiesOnly(true).
			WithStrictHostKeyChecking(option.StrictHostKeyCheckingYes).
			WithControlPolicy(option.UnsetControlPolicy().WithPath(cpSpec).WithMaster(mode))
	}

	masterRC := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:22100", CLIOptions: mkCLI(option.ControlMasterYes)}}
	cmInfo, err := masterEng.StartControlMaster(ctx, engine.ControlMasterRequest{RemoteCall: masterRC})
	if err != nil {
		t.Fatalf("Engine.StartControlMaster: %v", err)
	}
	cmHandle, hasHandle := cmInfo.Handle().Get()
	if !hasHandle {
		t.Fatalf("StartControlMaster 期望返回有效托管句柄，实际=%+v", cmInfo)
	}

	probeResp, err := masterEng.ProbeMux(ctx, engine.MuxControlRequest{RemoteCall: masterRC})
	if err != nil || !probeResp.Alive() || probeResp.MasterPID() == 0 {
		_ = masterEng.StopControlMaster(ctx, cmHandle)
		t.Fatalf("Engine.ProbeMux 期望 Alive && MasterPID>0，实际=%+v err=%v", probeResp, err)
	}

	// 启动第二个同样全默认装配（连接池全空）的独立 Engine，实证透明客户端 ControlMaster 复用对 Exec 与 SFTP 均零新拨号。
	clientEng := mustNewAllDefaultRealEngine(t, rig, vault, srv)
	defer closeEngineChecked(t, clientEng)

	dialsBefore := srv.dialCount.Load()
	autoCLI := mkCLI(option.ControlMasterAuto)
	var muxOut bytes.Buffer
	out, err := clientEng.Exec(ctx, engine.ExecRequest{
		TargetSpec: "deploy@127.0.0.1:22100",
		CLIOptions: autoCLI,
		Command:    "via-real-mux",
		Stdout:     &muxOut,
	})
	if err != nil {
		_ = masterEng.StopControlMaster(ctx, cmHandle)
		t.Fatalf("clientEng.Exec(real mux): %v", err)
	}
	if comp, ok := out.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() || muxOut.String() != "real-exec:via-real-mux\n" {
		_ = masterEng.StopControlMaster(ctx, cmHandle)
		t.Fatalf("复用 Exec 输出失配: out=%#v stdout=%q", out, muxOut.String())
	}
	remPath, _ := pathalg.ParseRemotePath("/srv/e2e/written.txt")
	autoRC := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:22100", CLIOptions: autoCLI}}
	rdRes, err := clientEng.ReadRemoteFile(ctx, engine.RemoteFileReadRequest{RemoteCall: autoRC, Path: remPath})
	if err != nil || string(rdRes.Content) != "real-sftp-atomic-payload" {
		_ = masterEng.StopControlMaster(ctx, cmHandle)
		t.Fatalf("复用 SFTP ReadRemoteFile 失配: got=%q err=%v", string(rdRes.Content), err)
	}
	if srv.dialCount.Load() != dialsBefore {
		_ = masterEng.StopControlMaster(ctx, cmHandle)
		t.Fatalf("透明 ControlMaster 复用期间不得触发底层新 SSH 拨号: before=%d after=%d", dialsBefore, srv.dialCount.Load())
	}

	chkResp, err := clientEng.ControlMux(ctx, engine.MuxControlRequest{RemoteCall: autoRC, Action: engine.MuxActionCheck})
	if err != nil || !chkResp.Alive() {
		_ = masterEng.StopControlMaster(ctx, cmHandle)
		t.Fatalf("Engine.ControlMux(check) 失配: resp=%+v err=%v", chkResp, err)
	}
	// 发送 -O exit 正常退出主进程并验证 ControlMasterInfo.Done()/Wait(ctx) 零轮询收敛返回 nil。
	if _, err := clientEng.ControlMux(ctx, engine.MuxControlRequest{RemoteCall: autoRC, Action: engine.MuxActionExit}); err != nil {
		_ = masterEng.StopControlMaster(ctx, cmHandle)
		t.Fatalf("Engine.ControlMux(exit): %v", err)
	}
	<-cmInfo.Done()
	if err := cmInfo.Wait(ctx); err != nil {
		t.Fatalf("-O exit 后 ControlMasterInfo.Wait(ctx) 期望 nil，实际=%v", err)
	}
}

// assertRemoteFSOverridePreservesMuxSubsystems 验证 #159 Minor 2：
// 即使调用方设置 engine.Config.RemoteFS != nil，外层 remoteFSConn 仍透明透传 WaitDone 与 OpenSubsystemStream，
// 保证通过 ControlMaster 复用 SFTP 子系统不受破坏。
func assertRemoteFSOverridePreservesMuxSubsystems(
	t *testing.T,
	ctx context.Context,
	rig *loopbackEngineRig,
	vault *sim.SimVault,
	keyPath string,
	srv *realSSHNetStub,
) {
	t.Helper()
	overrideEng, err := engine.New(engine.Config{
		Profile:        engine.PolicyProfileDirectOperator,
		Guardrail:      engine.DefaultGuardrailConfig(),
		Clock:          rig.clk,
		Entropy:        rig.rng.Fork(),
		AuditSink:      rig.auditSink,
		ScopedFS:       rig.rootFS,
		OperatorReadFS: rig.readFS,
		Env:            rig.env,
		Vault:          vault,
		DialContext:    srv.dialFunc(),
		RemoteFS: func(c context.Context, conn ports.TransportConn) (ports.RemoteFSPort, error) {
			return conn.OpenRemoteFS(c)
		},
	})
	if err != nil {
		t.Fatalf("engine.New(RemoteFS override): %v", err)
	}
	defer closeEngineChecked(t, overrideEng)

	sockRaw := filepath.Join(shortEngineMuxDir(t), "rfs.sock")
	cpSpec, _ := option.ParseControlPath(sockRaw)
	mkCLI := func(mode option.ControlMasterMode) option.OptionLayer {
		return option.UnsetOptionLayer().
			WithIdentityFiles(mustIdentityPathList(t, keyPath)).
			WithIdentitiesOnly(true).
			WithStrictHostKeyChecking(option.StrictHostKeyCheckingYes).
			WithControlPolicy(option.UnsetControlPolicy().WithPath(cpSpec).WithMaster(mode))
	}
	masterRC := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:22100", CLIOptions: mkCLI(option.ControlMasterYes)}}
	cmInfo, err := overrideEng.StartControlMaster(ctx, engine.ControlMasterRequest{RemoteCall: masterRC})
	if err != nil {
		t.Fatalf("overrideEng.StartControlMaster: %v", err)
	}
	defer func() {
		if h, ok := cmInfo.Handle().Get(); ok {
			if sErr := overrideEng.StopControlMaster(ctx, h); sErr != nil && !errors.Is(sErr, engine.ErrHandleNotFound) {
				t.Errorf("StopControlMaster(override): %v", sErr)
			}
		}
	}()
	clientEng := mustNewAllDefaultRealEngine(t, rig, vault, srv)
	defer closeEngineChecked(t, clientEng)
	remPath, _ := pathalg.ParseRemotePath("/srv/e2e/written.txt")
	autoRC := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:22100", CLIOptions: mkCLI(option.ControlMasterAuto)}}
	rdRes, err := clientEng.ReadRemoteFile(ctx, engine.RemoteFileReadRequest{RemoteCall: autoRC, Path: remPath})
	if err != nil || string(rdRes.Content) != "real-sftp-atomic-payload" {
		t.Fatalf("RemoteFS 覆写模式下复用 SFTP 必须透传 OpenSubsystemStream: got=%q err=%v", string(rdRes.Content), err)
	}
}

func shortEngineMuxDir(t *testing.T) string {
	t.Helper()
	parent := os.TempDir()
	if runtime.GOOS != "windows" && len(parent) >= 40 {
		parent = "/tmp"
	}
	dir, err := os.MkdirTemp(parent, "xe-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sub := filepath.Join(dir, "m")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	return sub
}
