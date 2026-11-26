package priv_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sshnet/priv"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// TestEscalator_AbortSecurityAndProtocolRegressions 覆盖评审 #25 / #31 全部高危与协议边界回归：
//   - 就绪后调用方取消 / PrivilegeRequest.Timeout 到期无死锁且返回不可重试 *execution.OutcomeUnknown；
//   - 半开 TCP 黑洞下握手超时与就绪后取消均 O(1) 返回；
//   - 非 PTY 模式 stdout 出现 "Password: " 严禁触发混淆代理口令泄露、误中止或字节篡改；
//   - promptCh 溢出返回 ports.ErrAuthFailed 而非被 nCtx context.Canceled 掩盖；
//   - 显式非 POSIX 方言（cmd/powershell/raw）失败关闭，NonInteractive sudo 省略 -S -p。
func TestEscalator_AbortSecurityAndProtocolRegressions(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("PostReadyCancelAndTimeout_NoDeadlockAndOutcomeUnknown", testPostReadyCancelAndTimeout)
	t.Run("BlackholeHandshakeTimeout_O1Return", testBlackholeHandshakeTimeout)
	t.Run("NonPTYStdoutPassword_NoConfusedDeputyLeakOrCorruption", testNonPTYStdoutNoConfusedDeputy)
	t.Run("PromptOverflowPreservesErrAuthFailed", testPromptOverflowPreservesAuthErr)
	t.Run("RejectNonPOSIXDialectAndNonInteractiveSudoFlags", testNonPOSIXAndNonInteractiveSudo)
}

func testPostReadyCancelAndTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1. 就绪后运行中由调用方取消 ctx：模拟远端黑洞不响应 Close，须 O(1) 返回 OutcomeUnknown(CanRetry==false) + Canceled。
	runCtx, cancel := context.WithCancel(context.Background())
	neverEnd := make(chan struct{})
	sessCancel := newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		out := &gatedStepReader{
			closedCh: closedCh,
			steps:    []readStep{{waitCh: neverEnd, err: io.EOF}},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte(readyTok)},
				{waitCh: neverEnd, err: io.EOF},
			},
		}
		return out, errR
	})
	sessCancel.blackhole = true
	defer sessCancel.releaseBlackhole()

	// 利用 post-ready stdin 写入钩子在 readyFlag 置位后确定性取消 ctx（零 time.Sleep）。
	sessCancel.stdin.onWriteHook = func(string) { cancel() }
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(81)})
	reqCancel, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "sleep 3600"),
	})
	out, err := esc.RunPrivileged(runCtx, &scriptedOpener{session: sessCancel}, reqCancel, nil, ports.ExecStreams{
		Stdin: strings.NewReader("trigger-cancel"),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("就绪后取消须返回 context.Canceled，实际 %v", err)
	}
	assertOutcomeUnknownNoRetry(t, out)

	// 2. PrivilegeRequest.Timeout 在就绪后到期：须 O(1) 返回 OutcomeUnknown(CanRetry==false) + DeadlineExceeded。
	sessTimeout := newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		outR := &gatedStepReader{closedCh: closedCh, steps: []readStep{{waitCh: neverEnd, err: io.EOF}}}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte(readyTok)},
				{waitCh: neverEnd, err: io.EOF},
			},
		}
		return outR, errR
	})
	sessTimeout.blackhole = true
	defer sessTimeout.releaseBlackhole()
	reqTO, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "sleep 3600"),
		Timeout: algebraic.Some(algebraic.FromStdDuration(30 * time.Millisecond)),
	})
	outTO, errTO := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sessTimeout}, reqTO, nil, ports.ExecStreams{})
	if !errors.Is(errTO, context.DeadlineExceeded) {
		t.Fatalf("就绪后 req.Timeout 到期须返回 DeadlineExceeded，实际 %v", errTO)
	}
	assertOutcomeUnknownNoRetry(t, outTO)
}

func assertOutcomeUnknownNoRetry(t *testing.T, out execution.ExecutionOutcome) {
	t.Helper()
	unk, ok := out.(*execution.OutcomeUnknown)
	if !ok || !unk.IsValid() || unk.CanRetry() {
		t.Fatalf("就绪后中止必须返回有效不可重试 *OutcomeUnknown，实际 %#v", out)
	}
}

func testBlackholeHandshakeTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)
	neverEnd := make(chan struct{})
	sess := newScriptedSession(1, func(_ string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		out := &gatedStepReader{closedCh: closedCh, steps: []readStep{{waitCh: neverEnd, err: io.EOF}}}
		errR := &gatedStepReader{closedCh: closedCh, steps: []readStep{{waitCh: neverEnd, err: io.EOF}}}
		return out, errR
	})
	sess.blackhole = true
	defer sess.releaseBlackhole()

	esc, _ := priv.NewEscalator(priv.Config{
		Entropy:          tck.NewDeterministicEntropy(82),
		HandshakeTimeout: 30 * time.Millisecond,
	})
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "id"),
	})
	out, err := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sess}, req, nil, ports.ExecStreams{})
	if !errors.Is(err, context.DeadlineExceeded) || out != nil {
		t.Fatalf("黑洞对端握手超时须 O(1) 返回 (nil, DeadlineExceeded)，实际 out=%#v err=%v", out, err)
	}
}

func testNonPTYStdoutNoConfusedDeputy(t *testing.T) {
	defer goleak.VerifyNone(t)
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(83)})

	// 场景 A：免密 doas 且调用方仍传入 SecretBox；stdout 抢先输出 "Password: root\n" 并 EOF，
	// 严禁向 stdin 泄露提权口令，且 stdout 字节完整无篡改。
	stdoutEOFA := make(chan struct{})
	sessA := newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte("Password: root\n")},
				{err: io.EOF, onReturned: func() { close(stdoutEOFA) }},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps:    []readStep{{waitCh: stdoutEOFA, data: []byte(readyTok)}, {err: io.EOF}},
		}
		return out, errR
	})
	reqDoas, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodDoas,
		Command: tck.MustCommandPlan(t, "grep Password /etc/ssh/sshd_config"),
	})
	var stdoutA bytes.Buffer
	err := secret.WithBytes([]byte("TOP-SECRET-ROOT-PW"), func(box *secret.SecretBox) error {
		_, rErr := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sessA}, reqDoas, box, ports.ExecStreams{Stdout: &stdoutA})
		return rErr
	})
	if err != nil {
		t.Fatalf("免密 doas stdout 含 Password: 不应失败: %v", err)
	}
	if gotIn := sessA.stdin.snapshot(); gotIn != "" {
		t.Fatalf("混淆代理漏洞：stdout 含 Password: 严禁触发口令写入 stdin，实际写入 %q", gotIn)
	}
	if stdoutA.String() != "Password: root\n" {
		t.Fatalf("stdout 含 Password: 须原样保留，实际 %q", stdoutA.String())
	}

	// 场景 B：需口令 su 在合法密码通过后 stdout 抢先输出 "Password: ok\n" 并 EOF，
	// 不得误判为二次质询返回 ErrAuthFailed 或吞掉 stdout。
	stdoutEOFB := make(chan struct{})
	var sessB *scriptedSession
	sessB = newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{waitCh: sessB.stdin.firstWrote, data: []byte("Password: ok\n")},
				{err: io.EOF, onReturned: func() { close(stdoutEOFB) }},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte("Password: ")},
				{waitCh: stdoutEOFB, data: []byte(readyTok)},
				{err: io.EOF},
			},
		}
		return out, errR
	})
	reqSu, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSu,
		Command: tck.MustCommandPlan(t, "grep Password /etc/ssh/sshd_config"),
	})
	var stdoutB bytes.Buffer
	err = secret.WithBytes([]byte("su-secret"), func(box *secret.SecretBox) error {
		_, rErr := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sessB}, reqSu, box, ports.ExecStreams{Stdout: &stdoutB})
		return rErr
	})
	if err != nil || stdoutB.String() != "Password: ok\n" || sessB.stdin.snapshot() != "su-secret\n" {
		t.Fatalf("需口令 su stdout 含 Password: 异常: stdout=%q stdin=%q err=%v", stdoutB.String(), sessB.stdin.snapshot(), err)
	}
}

func testPromptOverflowPreservesAuthErr(t *testing.T) {
	defer goleak.VerifyNone(t)
	neverEnd := make(chan struct{})
	sess := newScriptedSession(1, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		promptTok := extractBracketToken(cmd, `[xops-priv-prompt-`)
		// 单次写入连续 12 个提示帧触发 promptCh(cap=4) 溢出，校验返回 ErrAuthFailed 而非 context.Canceled。
		flood := strings.Repeat(promptTok, 12)
		out := &gatedStepReader{closedCh: closedCh, steps: []readStep{{waitCh: neverEnd, err: io.EOF}}}
		errR := &gatedStepReader{closedCh: closedCh, steps: []readStep{{data: []byte(flood)}, {waitCh: neverEnd, err: io.EOF}}}
		return out, errR
	})
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(84)})
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "id"),
	})
	_, err := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sess}, req, nil, ports.ExecStreams{})
	if !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("promptCh 溢出须保留 ErrAuthFailed 而非 context.Canceled，实际 %v", err)
	}
}

func testNonPOSIXAndNonInteractiveSudo(t *testing.T) {
	defer goleak.VerifyNone(t)
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(85)})

	// 1. 拒绝显式非 POSIX 启动方言（cmd / powershell / raw）。
	for _, dialect := range []execution.LaunchDialect{execution.DialectCmd, execution.DialectPowerShell, execution.DialectRaw} {
		prof, err := execution.NewLaunchProfile(execution.LaunchProfileSpec{
			Dialect:     algebraic.Some(dialect),
			Interpreter: execution.InterpreterServer,
			Login:       execution.LoginModeInherit,
		})
		if err != nil {
			t.Fatalf("NewLaunchProfile(%s): %v", dialect, err)
		}
		plan, err := execution.NewCommandPlan(execution.CommandPlanSpec{
			Kind:    execution.PlanKindCommand,
			Profile: prof,
			Command: "whoami",
		})
		if err != nil {
			t.Fatalf("NewCommandPlan(%s): %v", dialect, err)
		}
		req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
			Method:  ports.PrivilegeMethodSudo,
			Command: plan,
		})
		dummy := newScriptedSession(0, func(_ string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
			return &gatedStepReader{closedCh: closedCh}, &gatedStepReader{closedCh: closedCh}
		})
		if _, err := esc.RunPrivileged(context.Background(), &scriptedOpener{session: dummy}, req, nil, ports.ExecStreams{}); !errors.Is(err, ports.ErrUnsupported) {
			t.Fatalf("非 POSIX 方言 %s 须返回 ErrUnsupported，实际 %v", dialect, err)
		}
	}

	// 2. NonInteractive sudo 渲染为 "LC_ALL=C sudo -n -- ..."（省略 -S -p）。
	sessNI := newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		return &gatedStepReader{closedCh: closedCh, steps: []readStep{{data: []byte("ok\n")}, {err: io.EOF}}},
			&gatedStepReader{closedCh: closedCh, steps: []readStep{{data: []byte(readyTok)}, {err: io.EOF}}}
	})
	reqNI, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:         ports.PrivilegeMethodSudo,
		Command:        tck.MustCommandPlan(t, "id"),
		NonInteractive: true,
	})
	if _, err := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sessNI}, reqNI, nil, ports.ExecStreams{}); err != nil {
		t.Fatalf("NonInteractive sudo 失败: %v", err)
	}
	if !strings.HasPrefix(sessNI.seenRendered, "LC_ALL=C sudo -n -- ") || strings.Contains(sessNI.seenRendered, " -S ") || strings.Contains(sessNI.seenRendered, " -p ") {
		t.Fatalf("NonInteractive sudo 应省略 -S -p，实际命令: %q", sessNI.seenRendered)
	}
}
