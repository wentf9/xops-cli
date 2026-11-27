package engine_test

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/internal/sim"
)

// TestEngine_ControlPersistActivityRenewalAndIdleExit 验证默认真实 sshnet/mux 装配下的有限时长 ControlPersist 语义：
//  1. 启动 ControlMaster（ControlPersist=10s）后推进虚拟时钟 6s，主进程仍存活；
//  2. 客户端经真实 AF_UNIX 控制套接字发起 ProbeMux 与透明复用 Exec，自动经 muxActivityHub 刷新空闲计时器；
//  3. 累计经过时间超过初始 10s（达 12s / 18s）仍保持存活（证明客户端活动有效续期，而非静态超时）；
//  4. 停止全部客户端活动并推进虚拟时钟超过 10s 后，主进程自动回收退出且 Done()/Wait(ctx) 返回 nil，无 goroutine 泄漏。
func TestEngine_ControlPersistActivityRenewalAndIdleExit(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rig := newLoopbackRigBase(t, false)
	clientPub, keyPath := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_mux_persist")
	vault := sim.NewSimVault(rig.rng.Fork())
	srv := newRealSSHNetStub(t, "unused-sudo", clientPub)

	masterEng := mustNewAllDefaultRealEngine(t, rig, vault, srv)
	defer closeEngineChecked(t, masterEng)
	clientEng := mustNewAllDefaultRealEngine(t, rig, vault, srv)
	defer closeEngineChecked(t, clientEng)

	sockDir := shortEngineMuxDir(t)
	sockRaw := filepath.Join(sockDir, "cm-persist.sock")
	cpSpec, err := option.ParseControlPath(sockRaw)
	if err != nil {
		t.Fatalf("ParseControlPath: %v", err)
	}
	persistSpec, err := option.ParseControlPersist("10s")
	if err != nil {
		t.Fatalf("ParseControlPersist(10s): %v", err)
	}
	mkCLI := func(mode option.ControlMasterMode) option.OptionLayer {
		return option.UnsetOptionLayer().
			WithIdentityFiles(mustIdentityPathList(t, keyPath)).
			WithIdentitiesOnly(true).
			WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew).
			WithControlPolicy(option.UnsetControlPolicy().WithPath(cpSpec).WithMaster(mode).WithPersist(persistSpec))
	}

	masterRC := engine.RemoteCall{
		TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:22100", CLIOptions: mkCLI(option.ControlMasterYes)},
	}
	cmInfo, err := masterEng.StartControlMaster(ctx, engine.ControlMasterRequest{RemoteCall: masterRC})
	if err != nil {
		t.Fatalf("StartControlMaster: %v", err)
	}
	if cmInfo.ReusedExisting() {
		t.Fatal("首次 StartControlMaster 不应标记 ReusedExisting")
	}
	if err := rig.clk.WaitPending(ctx, 1); err != nil {
		t.Fatalf("WaitPending(persist timer): %v", err)
	}

	// 推进 6s（小于 10s），经 ProbeMux 触发活跃续期并等待服务端观察到连接离开重装 10s 计时器。
	rig.clk.Advance(6 * time.Second)
	assertMuxMasterStillAlive(t, ctx, masterEng, masterRC, cmInfo)
	waitPersistTimerRearmed(t, ctx, rig.clk)

	// 再推进 6s（总计 12s > 初始 10s），证明 ProbeMux 活动成功续期而非静默忽略。
	rig.clk.Advance(6 * time.Second)
	assertMuxMasterStillAlive(t, ctx, masterEng, masterRC, cmInfo)
	waitPersistTimerRearmed(t, ctx, rig.clk)

	// 经独立客户端透明复用执行 Exec，继续触发续期（t=12s -> 截止 t=22s），且零新增底层 SSH 拨号。
	dialsBefore := srv.dialCount.Load()
	var outBuf bytes.Buffer
	out, err := clientEng.Exec(ctx, engine.ExecRequest{
		TargetSpec: "deploy@127.0.0.1:22100",
		CLIOptions: mkCLI(option.ControlMasterAuto),
		Command:    "persist-renew",
		Stdout:     &outBuf,
	})
	if err != nil {
		t.Fatalf("clientEng.Exec(mux): %v", err)
	}
	if comp, ok := out.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() || outBuf.String() != "real-exec:persist-renew\n" {
		t.Fatalf("复用 Exec 输出失配: out=%#v stdout=%q", out, outBuf.String())
	}
	if srv.dialCount.Load() != dialsBefore {
		t.Fatalf("透明复用 Exec 不应触发新拨号: before=%d after=%d", dialsBefore, srv.dialCount.Load())
	}
	waitPersistTimerRearmed(t, ctx, rig.clk)

	// 再推进 6s（总计 18s），仍应保持存活。
	rig.clk.Advance(6 * time.Second)
	assertMuxMasterStillAlive(t, ctx, masterEng, masterRC, cmInfo)
	waitPersistTimerRearmed(t, ctx, rig.clk)

	// 停止一切客户端活动并推进超过 10s 空闲阈值，验证自动回收且 Wait 返回 nil。
	rig.clk.Advance(11 * time.Second)
	assertControlMasterExpired(t, ctx, masterEng, masterRC, cmInfo)
}

// TestEngine_ControlPersistHoldsActiveSessionAndExpiresAfterClose 验证有限 ControlPersist 遵守 OpenSSH 语义：
//  1. 当存在活跃多路复用长连接（RunMuxProxy）时，推进虚拟时钟远超 ControlPersist（30s > 10s）绝不中途终止；
//  2. 期间叠加并发 ProbeMux 探活（activeClients: 1 -> 2 -> 1）仍保持空闲计时器暂停；
//  3. 仅在最后一个活跃客户端关闭离开后才重新起算完整 10s 空闲倒计时，到期后自动回收退出且 Wait 返回 nil。
func TestEngine_ControlPersistHoldsActiveSessionAndExpiresAfterClose(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rig := newLoopbackRigBase(t, false)
	clientPub, keyPath := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_mux_hold")
	vault := sim.NewSimVault(rig.rng.Fork())
	srv := newRealSSHNetStub(t, "unused-sudo", clientPub)

	masterEng := mustNewAllDefaultRealEngine(t, rig, vault, srv)
	defer closeEngineChecked(t, masterEng)
	clientEng := mustNewAllDefaultRealEngine(t, rig, vault, srv)
	defer closeEngineChecked(t, clientEng)

	sockRaw := filepath.Join(shortEngineMuxDir(t), "cm-hold.sock")
	cpSpec, err := option.ParseControlPath(sockRaw)
	if err != nil {
		t.Fatalf("ParseControlPath: %v", err)
	}
	persistSpec, err := option.ParseControlPersist("10s")
	if err != nil {
		t.Fatalf("ParseControlPersist: %v", err)
	}
	mkCLI := func(mode option.ControlMasterMode) option.OptionLayer {
		return option.UnsetOptionLayer().
			WithIdentityFiles(mustIdentityPathList(t, keyPath)).
			WithIdentitiesOnly(true).
			WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew).
			WithControlPolicy(option.UnsetControlPolicy().WithPath(cpSpec).WithMaster(mode).WithPersist(persistSpec))
	}

	masterRC := engine.RemoteCall{
		TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:22101", CLIOptions: mkCLI(option.ControlMasterYes)},
	}
	cmInfo, err := masterEng.StartControlMaster(ctx, engine.ControlMasterRequest{RemoteCall: masterRC})
	if err != nil {
		t.Fatalf("StartControlMaster: %v", err)
	}
	waitPersistTimerRearmed(t, ctx, rig.clk)

	pr, pw := io.Pipe()
	proxyRC := engine.RemoteCall{
		TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:22101", CLIOptions: mkCLI(option.ControlMasterAuto)},
	}
	var proxyErr error
	runErr := conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			proxyErr = clientEng.RunMuxProxy(c, engine.MuxControlRequest{RemoteCall: proxyRC}, pr, io.Discard)
			return nil
		}); gErr != nil {
			return gErr
		}
		// io.Pipe 同步写入返回即证明客户端已完成 HELLO + CProxy + SProxy 握手，服务端已处于活跃占用态。
		if _, wErr := io.WriteString(pw, "hold-active-session\n"); wErr != nil {
			_ = pw.Close()
			return wErr
		}
		if pending := rig.clk.PendingTimers(); pending != 0 {
			_ = pw.Close()
			t.Errorf("存在活跃多路复用会话时 ControlPersist 空闲计时器必须暂停，实际 pending=%d", pending)
		}
		// 推进 3 倍 ControlPersist（30s > 10s），活跃会话与主控绝不可被中途击杀。
		rig.clk.Advance(30 * time.Second)
		assertMuxMasterStillAlive(t, wCtx, masterEng, masterRC, cmInfo)
		// 叠加第二条探活连接（1 -> 2 -> 1）后再推进 15s，仍须保持存活。
		rig.clk.Advance(15 * time.Second)
		assertMuxMasterStillAlive(t, wCtx, masterEng, masterRC, cmInfo)
		return pw.Close()
	})
	if runErr != nil || proxyErr != nil {
		t.Fatalf("长连接 RunMuxProxy 异常退出: runErr=%v proxyErr=%v", runErr, proxyErr)
	}

	// 最后一个客户端断开后，等待服务端重新装填完整 10s 空闲计时器。
	waitPersistTimerRearmed(t, ctx, rig.clk)
	rig.clk.Advance(6 * time.Second)
	assertMuxMasterStillAlive(t, ctx, masterEng, masterRC, cmInfo)
	waitPersistTimerRearmed(t, ctx, rig.clk)

	// 空闲超过 10s 后确定性回收退出。
	rig.clk.Advance(11 * time.Second)
	assertControlMasterExpired(t, ctx, masterEng, masterRC, cmInfo)
}

func waitPersistTimerRearmed(t *testing.T, ctx context.Context, clk *sim.SimClock) {
	t.Helper()
	if err := clk.WaitPending(ctx, 1); err != nil {
		t.Fatalf("WaitPending(persist timer): %v", err)
	}
}

func assertControlMasterExpired(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	rc engine.RemoteCall,
	cmInfo engine.ControlMasterInfo,
) {
	t.Helper()
	select {
	case <-cmInfo.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("有限 ControlPersist 空闲到期后 ControlMaster.Done() 未关闭")
	}
	if err := cmInfo.Wait(ctx); err != nil {
		t.Fatalf("ControlPersist 空闲回收期望 Wait 返回 nil，实际=%v", err)
	}
	probeAfter, err := eng.ProbeMux(ctx, engine.MuxControlRequest{RemoteCall: rc})
	if err != nil {
		t.Fatalf("回收后 ProbeMux 返回意外错误: %v", err)
	}
	if probeAfter.Alive() {
		t.Fatalf("ControlPersist 空闲回收后 ProbeMux 不应仍报告 Alive: %+v", probeAfter)
	}
}

func assertMuxMasterStillAlive(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	rc engine.RemoteCall,
	cmInfo engine.ControlMasterInfo,
) {
	t.Helper()
	select {
	case <-cmInfo.Done():
		t.Fatalf("ControlMaster 在活动续期内意外提前退出: wait=%v", cmInfo.Wait(ctx))
	default:
	}
	resp, err := eng.ProbeMux(ctx, engine.MuxControlRequest{RemoteCall: rc})
	if err != nil || !resp.Alive() {
		t.Fatalf("ControlMaster 续期内 ProbeMux 期望存活，实际 resp=%+v err=%v", resp, err)
	}
}
