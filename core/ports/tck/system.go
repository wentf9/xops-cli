package tck

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// ClockFixture 描述 Clock 契约测试夹具（同时兼容真实系统时钟与确定性仿真时钟 SimClock）。
type ClockFixture struct {
	// NewClock 返回待测 Clock 实例。
	NewClock func(t *testing.T) ports.Clock
	// Advance 若非 nil，用于推进确定性虚拟时钟（真实时钟留空即可，自动等待 SleepDuration）。
	Advance func(d time.Duration)
	// SleepDuration 指定测试用短延时（为空时默认 15ms）。
	SleepDuration time.Duration
}

// ProcessFixture 描述 ProcessPort 契约测试夹具。
type ProcessFixture struct {
	// NewProcess 返回待测 ProcessPort 实例。
	NewProcess func(t *testing.T) ports.ProcessPort
	// EchoSpec 指定可读取 stdin 并向 stdout 回显的成功子进程规格。
	EchoSpec ports.ProcessSpec
	// FailSpec 指定以非零退出状态结束的子进程规格（可选）。
	FailSpec ports.ProcessSpec
	// DialStdioSpec 指定支持双向 stdio 管道通信的子进程规格（可选）。
	DialStdioSpec ports.ProcessSpec
}

// TerminalFixture 描述 TerminalPort 契约测试夹具。
type TerminalFixture struct {
	// NewTerminal 返回待测 TerminalPort 实例。
	NewTerminal func(t *testing.T) ports.TerminalPort
	// ExpectInteractive 指示待测终端是否处于交互式 TTY 状态。
	ExpectInteractive bool
}

// InteractionFixture 描述 InteractionPort 契约测试夹具。
type InteractionFixture struct {
	// NewInteraction 返回预设确定性回答的 InteractionPort 实例。
	NewInteraction func(t *testing.T) ports.InteractionPort
	// ExpectedSecret 指定 PromptSecret 预期送入回调的测试机密串（默认 TestSecretTokenA）。
	ExpectedSecret string
	// ExpectedText 指定 PromptText 预期返回的非空文本（留空则仅断言返回非空或无错）。
	ExpectedText string
}

// RunClockSuite 验证 Clock 的当前时刻、耗时计算、Timer 触发/取消/重置与可取消 Sleep 契约。
func RunClockSuite(t *testing.T, fx ClockFixture) {
	t.Helper()
	requireTrue(t, fx.NewClock != nil, "ClockFixture.NewClock 不能为 nil")
	step := fx.SleepDuration
	if step <= 0 {
		step = 15 * time.Millisecond
	}

	t.Run("NowSinceTimerAndSleep", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		clk := fx.NewClock(t)
		t0 := clk.Now()
		requireTrue(t, !t0.IsZero(), "Clock.Now() 不能返回零时刻")
		requireTrue(t, clk.Since(t0) >= 0, "Clock.Since(t0) 不能为负")

		var nilCtx context.Context
		requireErrIs(t, clk.Sleep(nilCtx, step), ports.ErrNilContext, "Sleep(nil ctx)")

		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		requireErrIs(t, clk.Sleep(canceled, time.Hour), context.Canceled, "已取消 ctx 的 Sleep 必须立即返回 context.Canceled")

		// 验证 Sleep 正常推进与 Timer 到期触发（虚拟时钟以完成信号驱动迭代推进，杜绝抢跑死锁）。
		sleepDone := make(chan struct{})
		err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
			if gErr := n.Go(func(c context.Context) error {
				defer close(sleepDone)
				return clk.Sleep(c, step)
			}); gErr != nil {
				return gErr
			}
			if fx.Advance != nil {
				return n.Go(func(c context.Context) error {
					return driveVirtualClockUntilDone(c, fx.Advance, step, sleepDone)
				})
			}
			return nil
		})
		requireNoErr(t, err, "Sleep 正常等待")

		verifyClockTimerReset(t, clk, fx.Advance, step)
	})
}

func driveVirtualClockUntilDone(ctx context.Context, advance func(time.Duration), step time.Duration, done <-chan struct{}) error {
	tk := time.NewTicker(time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-tk.C:
			advance(step)
		}
	}
}

func verifyClockTimerReset(t *testing.T, clk ports.Clock, advance func(time.Duration), step time.Duration) {
	t.Helper()
	tm := clk.NewTimer(time.Hour)
	requireTrue(t, tm != nil, "NewTimer 不能返回 nil")
	_ = tm.Stop()
	tm.Reset(step)

	timerDone := make(chan struct{})
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			defer close(timerDone)
			select {
			case fired := <-tm.C():
				if fired.IsZero() {
					return fmt.Errorf("timer 到期时间不能为零")
				}
				return nil
			case <-time.After(2 * time.Second):
				return fmt.Errorf("timer 重置后未在预期时间内触发")
			case <-c.Done():
				return c.Err()
			}
		}); gErr != nil {
			return gErr
		}
		if advance != nil {
			return n.Go(func(c context.Context) error {
				return driveVirtualClockUntilDone(c, advance, step, timerDone)
			})
		}
		return nil
	})
	requireNoErr(t, err, "Timer 重置与到期验证")
}

// RunEntropySuite 验证 Entropy 直接作为 io.Reader 驱动全部安全标识构造器的零摩擦兼容、不重复性与并发安全契约。
func RunEntropySuite(t *testing.T, newEntropy func(t *testing.T) ports.Entropy) {
	t.Helper()
	requireTrue(t, newEntropy != nil, "newEntropy 工厂不能为 nil")

	t.Run("DirectReaderCompatibility", func(t *testing.T) {
		ent := newEntropy(t)
		buf := make([]byte, 32)
		n, err := io.ReadFull(ent, buf)
		requireNoErr(t, err, "io.ReadFull(Entropy)")
		requireTrue(t, n == 32, "Entropy 必须完整填满请求切片")

		t1, err := security.NewTraceIDFrom(ent)
		requireNoErr(t, err, "NewTraceIDFrom(1)")
		t2, err := security.NewTraceIDFrom(ent)
		requireNoErr(t, err, "NewTraceIDFrom(2)")
		requireTrue(t, t1.IsValid() && t2.IsValid() && !t1.Equal(t2), "连续生成的 TraceID 必须有效且互不相同")

		op1, err := security.NewOperationIDFrom(ent)
		requireNoErr(t, err, "NewOperationIDFrom")
		nonce, err := security.NewApprovalNonceFrom(ent)
		requireNoErr(t, err, "NewApprovalNonceFrom")
		hid, err := plan.NewHandleIDFrom(ent)
		requireNoErr(t, err, "NewHandleIDFrom")
		pid, err := ports.NewProcessInstanceIDFrom(ent)
		requireNoErr(t, err, "NewProcessInstanceIDFrom")

		requireTrue(t, op1.IsValid() && nonce != ([16]byte{}) && hid.IsValid() && pid.IsValid(), "全部领域/端口 ID 构造均须成功")
	})

	t.Run("ConcurrentIDGeneration", func(t *testing.T) {
		verifyConcurrentEntropy(t, newEntropy)
	})
}

func verifyConcurrentEntropy(t *testing.T, newEntropy func(t *testing.T) ports.Entropy) {
	t.Helper()
	defer VerifyNoLeaks(t)
	ent := newEntropy(t)
	var mu sync.Mutex
	seenTrace := make(map[string]bool, 32)
	seenProc := make(map[string]bool, 32)

	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for range 8 {
			if gErr := n.Go(func(context.Context) error {
				return drawConcurrentIDs(ent, &mu, seenTrace, seenProc)
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	requireNoErr(t, err, "并发 Entropy ID 生成")
	requireTrue(t, len(seenTrace) == 32 && len(seenProc) == 32, "并发生成 32 组标识须全部互异")
}

func drawConcurrentIDs(ent ports.Entropy, mu *sync.Mutex, seenTrace, seenProc map[string]bool) error {
	for range 4 {
		tid, err := security.NewTraceIDFrom(ent)
		if err != nil {
			return err
		}
		pid, err := ports.NewProcessInstanceIDFrom(ent)
		if err != nil {
			return err
		}
		mu.Lock()
		dup := seenTrace[tid.String()] || seenProc[pid.String()]
		seenTrace[tid.String()], seenProc[pid.String()] = true, true
		mu.Unlock()
		if dup {
			return fmt.Errorf("并发熵源产出重复标识")
		}
	}
	return nil
}

// RunProcessSuite 验证 ProcessPort 的一次性受控执行、失败退出与可选 DialStdio 管道契约。
func RunProcessSuite(t *testing.T, fx ProcessFixture) {
	t.Helper()
	requireTrue(t, fx.NewProcess != nil && fx.EchoSpec.IsValid(), "ProcessFixture 必须提供 NewProcess 与有效 EchoSpec")

	t.Run("ValidationRunAndStdio", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		proc := fx.NewProcess(t)
		var nilCtx context.Context
		var zeroSpec ports.ProcessSpec

		_, err := proc.Run(nilCtx, fx.EchoSpec, nil)
		requireErrIs(t, err, ports.ErrNilContext, "Run(nil ctx)")
		_, err = proc.Run(ctx, zeroSpec, nil)
		requireErr(t, err, "Run(zero spec)")

		res, err := proc.Run(ctx, fx.EchoSpec, strings.NewReader("tck-process-stdin"))
		requireNoErr(t, err, "Run(EchoSpec)")
		requireTrue(t, res.IsValid() && res.Succeeded() && bytes.Contains(res.Stdout(), []byte("tck-process-stdin")), "回显子进程须成功并包含预期输出")

		if fx.FailSpec.IsValid() {
			fRes, fErr := proc.Run(ctx, fx.FailSpec, nil)
			requireNoErr(t, fErr, "Run(FailSpec)")
			requireTrue(t, fRes.IsValid() && !fRes.Succeeded(), "非零退出子进程 Succeeded 须为 false")
		}
		if fx.DialStdioSpec.IsValid() {
			conn, dErr := proc.DialStdio(ctx, fx.DialStdioSpec)
			requireNoErr(t, dErr, "DialStdio")
			_, wErr := conn.Write([]byte("ping"))
			requireNoErr(t, wErr, "DialStdio.Write")
			reply := make([]byte, 4)
			_, rErr := io.ReadFull(conn, reply)
			requireNoErr(t, rErr, "DialStdio.Read")
			requireTrue(t, bytes.Equal(reply, []byte("ping")), "DialStdio 回显数据不匹配")
			requireNoErr(t, conn.Close(), "DialStdio.Close")
		}
	})
}

// RunTerminalSuite 验证 TerminalPort 的孤儿进程组安全判定（INV-E1）、尺寸查询与原始终端作用域契约。
func RunTerminalSuite(t *testing.T, fx TerminalFixture) {
	t.Helper()
	requireTrue(t, fx.NewTerminal != nil, "TerminalFixture.NewTerminal 不能为 nil")

	t.Run("SuspendCheckSizeAndRawScope", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		term := fx.NewTerminal(t)
		requireTrue(t, term.IsInteractive() == fx.ExpectInteractive, "IsInteractive 与夹具预期不符")

		verdict, err := term.CanSuspendProcessGroup()
		if err != nil {
			requireTrue(t, verdict == security.VerdictDeny, "INV-E1: 判定出错时必须失败关闭返回 VerdictDeny")
		} else {
			requireTrue(t, verdict.IsValid(), "CanSuspendProcessGroup 须返回有效 Verdict")
		}

		var nilCtx context.Context
		requireErrIs(t, term.WithRawTerminal(nilCtx, func(ports.TerminalHandle) error { return nil }), ports.ErrNilContext, "WithRawTerminal(nil ctx)")
		requireErrIs(t, term.WithRawTerminal(context.Background(), nil), ports.ErrNilCallback, "WithRawTerminal(nil fn)")

		if fx.ExpectInteractive {
			sz, sErr := term.Size()
			requireNoErr(t, sErr, "Terminal.Size")
			requireTrue(t, sz.IsValid(), "交互终端 Size 必须有效")

			err = term.WithRawTerminal(context.Background(), func(h ports.TerminalHandle) error {
				requireTrue(t, h != nil, "TerminalHandle 不能为 nil")
				hSize, hsErr := h.Size()
				requireNoErr(t, hsErr, "TerminalHandle.Size")
				requireTrue(t, hSize.IsValid(), "句柄 Size 必须有效")
				_, wErr := h.Write([]byte("raw-ok"))
				return wErr
			})
			requireNoErr(t, err, "WithRawTerminal")
		}
	})
}

// RunInteractionSuite 验证 InteractionPort 的确认、审批摘要绑定、文本输入与受管 SecretBox 机密采集契约。
// 严格遵循 ADR-011 / Plan §4.6：PromptSecret 的 secret.WithBytes 内嵌于 t.Run，零 box.Use 明文消费。
func RunInteractionSuite(t *testing.T, fx InteractionFixture) {
	t.Helper()
	requireTrue(t, fx.NewInteraction != nil, "InteractionFixture.NewInteraction 不能为 nil")
	expectedSecret := fx.ExpectedSecret
	if expectedSecret == "" {
		expectedSecret = TestSecretTokenA
	}

	t.Run("ConfirmApprovalAndText", func(t *testing.T) {
		ctx := context.Background()
		ui := fx.NewInteraction(t)
		requireTrue(t, ui.CanInteract(), "可交互夹具 CanInteract() 必须为 true")
		var nilCtx context.Context
		var zeroConfirm ports.ConfirmRequest
		var zeroEnv security.ApprovalEnvelope
		var zeroText ports.TextPromptRequest

		_, err := ui.Confirm(nilCtx, zeroConfirm)
		requireErrIs(t, err, ports.ErrNilContext, "Confirm(nil ctx)")
		_, err = ui.Confirm(ctx, zeroConfirm)
		requireErr(t, err, "Confirm(zero req)")

		cReq, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{Message: "Proceed?", Risk: security.RiskModerate})
		requireNoErr(t, err, "NewConfirmRequest")
		verdict, err := ui.Confirm(ctx, cReq)
		requireNoErr(t, err, "Confirm")
		requireTrue(t, verdict.IsValid(), "Confirm 必须返回有效 Verdict")

		_, err = ui.PromptApproval(ctx, zeroEnv)
		requireErr(t, err, "PromptApproval(zero env)")
		env := MustApprovalEnvelope(t, NewDeterministicEntropy(77))
		wantDig, err := env.Digest()
		requireNoErr(t, err, "ApprovalEnvelope.Digest")
		resp, err := ui.PromptApproval(ctx, env)
		requireNoErr(t, err, "PromptApproval")
		requireTrue(t, resp.IsValid() && resp.EnvelopeDigest().Equal(wantDig), "审批响应必须回传匹配的 ApprovalEnvelope 规范摘要")

		_, err = ui.PromptText(ctx, zeroText)
		requireErr(t, err, "PromptText(zero req)")
		tReq, err := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{Prompt: "Enter tag"})
		requireNoErr(t, err, "NewTextPromptRequest")
		txt, err := ui.PromptText(ctx, tReq)
		requireNoErr(t, err, "PromptText")
		if fx.ExpectedText != "" {
			requireTrue(t, txt == fx.ExpectedText, "PromptText 返回内容不匹配")
		}
	})

	t.Run("PromptSecretScopedZeroPlaintext", func(t *testing.T) {
		ctx := context.Background()
		ui := fx.NewInteraction(t)
		var nilCtx context.Context
		var zeroSec ports.SecretPromptRequest

		sReq, err := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Prompt: "Password:"})
		requireNoErr(t, err, "NewSecretPromptRequest")
		requireErrIs(t, ui.PromptSecret(nilCtx, sReq, func(*secret.SecretBox) error { return nil }), ports.ErrNilContext, "PromptSecret(nil ctx)")
		requireErrIs(t, ui.PromptSecret(ctx, sReq, nil), ports.ErrNilCallback, "PromptSecret(nil fn)")
		requireErr(t, ui.PromptSecret(ctx, zeroSec, func(*secret.SecretBox) error { return nil }), "PromptSecret(zero req)")

		var matched bool
		err = secret.WithBytes([]byte(expectedSecret), func(expected *secret.SecretBox) error {
			return ui.PromptSecret(ctx, sReq, func(got *secret.SecretBox) error {
				matched = got.IsValid() && got.Len() == expected.Len() && got.Equal(expected)
				return nil
			})
		})
		requireNoErr(t, err, "PromptSecret")
		requireTrue(t, matched, "PromptSecret 借出的 SecretBox 须与预期常量时间相等")
	})
}
