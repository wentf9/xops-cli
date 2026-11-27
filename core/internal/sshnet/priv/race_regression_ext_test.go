package priv_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sshnet/priv"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

type readStep struct {
	onEnter    func()
	waitCh     <-chan struct{}
	data       []byte
	err        error
	onReturned func()
}

// gatedStepReader 按预设确定性步骤交付字节（零 time.Sleep、零裸 go），
// 用于在单元测试中 100% 复现跨流 EOF、大输出与混淆代理并发交错时序。
type gatedStepReader struct {
	steps    []readStep
	idx      int
	offset   int
	closedCh <-chan struct{}
}

func (r *gatedStepReader) Read(p []byte) (int, error) {
	for r.idx < len(r.steps) {
		step := &r.steps[r.idx]
		if step.onEnter != nil {
			cb := step.onEnter
			step.onEnter = nil
			cb()
		}
		if step.waitCh != nil {
			select {
			case <-step.waitCh:
				step.waitCh = nil
			case <-r.closedCh:
				return 0, io.EOF
			}
		}
		if r.offset < len(step.data) {
			n := copy(p, step.data[r.offset:])
			r.offset += n
			if r.offset == len(step.data) {
				r.advanceStep(step.onReturned)
			}
			return n, nil
		}
		err := step.err
		r.advanceStep(step.onReturned)
		if err != nil {
			return 0, err
		}
	}
	return 0, io.EOF
}

func (r *gatedStepReader) advanceStep(cb func()) {
	r.idx++
	r.offset = 0
	if cb != nil {
		cb()
	}
}

type recordStdinPipe struct {
	mu          sync.Mutex
	buf         bytes.Buffer
	closed      bool
	closedCh    chan struct{}
	firstWrite  sync.Once
	firstWrote  chan struct{}
	closeOnce   sync.Once
	onWriteHook func(snapshot string)
}

func newRecordStdinPipe() *recordStdinPipe {
	return &recordStdinPipe{
		closedCh:   make(chan struct{}),
		firstWrote: make(chan struct{}),
	}
}

func (p *recordStdinPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	n, _ := p.buf.Write(b)
	snap := p.buf.String()
	hook := p.onWriteHook
	p.mu.Unlock()
	p.firstWrite.Do(func() { close(p.firstWrote) })
	if hook != nil {
		hook(snap)
	}
	return n, nil
}

func (p *recordStdinPipe) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.closeOnce.Do(func() { close(p.closedCh) })
	return nil
}

func (p *recordStdinPipe) snapshot() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}

type scriptedSession struct {
	stdin        *recordStdinPipe
	outPR        *io.PipeReader
	outPW        *io.PipeWriter
	errPR        *io.PipeReader
	errPW        *io.PipeWriter
	buildFn      func(renderedCmd string, closedCh <-chan struct{}) (stdout, stderr io.Reader)
	exitCode     int32
	blackhole    bool
	seenRendered string

	nursery     *conc.Nursery
	pumpsDone   chan struct{}
	closeOnce   sync.Once
	releaseOnce sync.Once
	closedCh    chan struct{}
}

type scriptedOpener struct {
	session *scriptedSession
}

func (o *scriptedOpener) OpenSession(context.Context) (ports.RemoteSession, error) {
	return o.session, nil
}

func newScriptedSession(exitCode int32, buildFn func(renderedCmd string, closedCh <-chan struct{}) (io.Reader, io.Reader)) *scriptedSession {
	outPR, outPW := io.Pipe()
	errPR, errPW := io.Pipe()
	return &scriptedSession{
		stdin:     newRecordStdinPipe(),
		outPR:     outPR,
		outPW:     outPW,
		errPR:     errPR,
		errPW:     errPW,
		buildFn:   buildFn,
		exitCode:  exitCode,
		pumpsDone: make(chan struct{}),
		closedCh:  make(chan struct{}),
	}
}

func (s *scriptedSession) StdinPipe() (io.WriteCloser, error) { return s.stdin, nil }
func (s *scriptedSession) StdoutPipe() (io.Reader, error)     { return s.outPR, nil }
func (s *scriptedSession) StderrPipe() (io.Reader, error)     { return s.errPR, nil }

func (s *scriptedSession) Start(_ context.Context, cmd execution.CommandPlan, _ ports.ExecStreams) error {
	rendered, err := cmd.RenderCommand()
	if err != nil {
		return err
	}
	s.seenRendered = rendered
	outR, errR := s.buildFn(rendered, s.closedCh)
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		return err
	}
	s.nursery = n
	var rem atomic.Int32
	rem.Store(2)
	doneOne := func() {
		if rem.Add(-1) == 0 {
			close(s.pumpsDone)
		}
	}
	// 忠实模拟 remotesess 独立桥接语义：每条流到达自身 EOF 时立即独立关闭对应 PipeWriter。
	_ = n.Go(func(context.Context) error {
		defer doneOne()
		defer func() { _ = s.outPW.Close() }()
		if outR != nil {
			_, _ = io.Copy(s.outPW, outR)
		}
		return nil
	})
	_ = n.Go(func(context.Context) error {
		defer doneOne()
		defer func() { _ = s.errPW.Close() }()
		if errR != nil {
			_, _ = io.Copy(s.errPW, errR)
		}
		return nil
	})
	return nil
}

func (*scriptedSession) StartShell(context.Context, ports.ExecStreams) error {
	return ports.ErrUnsupported
}
func (*scriptedSession) ResizePTY(context.Context, ports.TerminalSize) error { return nil }
func (*scriptedSession) Signal(context.Context, string) error                { return nil }

func (s *scriptedSession) Wait(ctx context.Context) (execution.ExecutionOutcome, error) {
	select {
	case <-s.pumpsDone:
		return execution.NewOutcomeCompleted(execution.NewExitCode(s.exitCode), false)
	case <-ctx.Done():
		phase := execution.ExecPhaseCanceled
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			phase = execution.ExecPhaseTimedOut
		}
		out, _ := execution.NewOutcomeUnknown(phase, "scripted_wait_canceled", ctx.Err().Error())
		return out, ctx.Err()
	}
}

func (s *scriptedSession) Close() error {
	s.closeOnce.Do(func() {
		_ = s.stdin.Close()
		_ = s.outPW.Close()
		_ = s.errPW.Close()
		if !s.blackhole {
			s.releaseOnce.Do(func() { close(s.closedCh) })
			if s.nursery != nil {
				_ = s.nursery.Close()
			}
		}
	})
	return nil
}

func (s *scriptedSession) releaseBlackhole() {
	s.releaseOnce.Do(func() { close(s.closedCh) })
	if s.nursery != nil {
		_ = s.nursery.Close()
	}
}

func TestEscalator_CrossStreamEOFOrdering_Deterministic(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("StdoutEOFArrivesBeforeStderrReady", testStdoutEOFBeforeStderrReady)
	t.Run("LargeStdoutOverHoldThresholdBeforeStderrReady", testLargeStdoutBeforeStderrReady)
	t.Run("StdoutAndStderrEOFWithoutReady_FailsClosed", testBothEOFWithoutReadyFailClosed)
	t.Run("StdoutPausedAtHoldThreshold_HandshakeTimeoutUnblocks", testPausedStdoutTimeoutUnblocks)
	t.Run("PlanKindScript_StdinAfterReadyAndStdoutRace", testScriptStdinOrderAndStdoutRace)
	t.Run("PTYMode_CombinedStdoutPromptReadyAndLargeOutput", testPTYModeCombinedStream)
	t.Run("SecondaryPreReadyFlushedImmediatelyOnReadyWhileBlocked", testSecondaryPreReadyFlushedImmediatelyWhileBlocked)
	t.Run("SecondaryPreReadyFlushedBeforePostReadyCancel", testSecondaryPreReadyFlushedBeforePostReadyCancel)
	t.Run("SecondaryConcurrentReadyAndCancel_NoFIFOGap", testSecondaryConcurrentReadyAndCancelNoFIFOGap)
}

func testStdoutEOFBeforeStderrReady(t *testing.T) {
	defer goleak.VerifyNone(t)
	stdoutEOF := make(chan struct{})
	sess := newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte("uid=0(root)\n")},
				{err: io.EOF, onReturned: func() { close(stdoutEOF) }},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{waitCh: stdoutEOF, data: []byte(readyTok + "post-err\n")},
				{err: io.EOF},
			},
		}
		return out, errR
	})
	esc, err := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(71)})
	if err != nil {
		t.Fatalf("NewEscalator: %v", err)
	}
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodDoas,
		Command: tck.MustCommandPlan(t, "id"),
	})
	var stdout, stderr bytes.Buffer
	out, err := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sess}, req, nil, ports.ExecStreams{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("stdout 先于 stderr ready 到达 EOF 时不应失败: %v", err)
	}
	if comp, ok := out.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() {
		t.Fatalf("期望成功 OutcomeCompleted，实际 %#v", out)
	}
	if stdout.String() != "uid=0(root)\n" || stderr.String() != "post-err\n" {
		t.Fatalf("跨流 EOF 时序下输出发生丢失或串扰: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func testLargeStdoutBeforeStderrReady(t *testing.T) {
	defer goleak.VerifyNone(t)
	chunk := bytes.Repeat([]byte("A"), 32*1024)
	want := bytes.Repeat(chunk, 5) // 160 KiB > 64 KiB 暂存上限
	hitThreshold := make(chan struct{})
	sess := newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		mid := len(readyTok) / 2
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: chunk},
				{data: chunk, onReturned: func() { close(hitThreshold) }},
				{data: chunk},
				{data: chunk},
				{data: chunk},
				{err: io.EOF},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{waitCh: hitThreshold, data: []byte(readyTok[:mid])},
				{data: []byte(readyTok[mid:])},
				{err: io.EOF},
			},
		}
		return out, errR
	})
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(72)})
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "cat"),
	})
	var stdout bytes.Buffer
	if _, err := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sess}, req, nil, ports.ExecStreams{Stdout: &stdout}); err != nil {
		t.Fatalf("超过暂存上限的大 stdout 竞态失败: %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Fatalf("大 stdout 字节不完整: got=%d want=%d", stdout.Len(), len(want))
	}
}

func testBothEOFWithoutReadyFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	stdoutEOF := make(chan struct{})
	sess := newScriptedSession(1, func(_ string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte("untrusted-pre-ready-stdout\n")},
				{err: io.EOF, onReturned: func() { close(stdoutEOF) }},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{waitCh: stdoutEOF, data: []byte("sudo: a password is required\n")},
				{err: io.EOF},
			},
		}
		return out, errR
	})
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(73)})
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:         ports.PrivilegeMethodSudo,
		Command:        tck.MustCommandPlan(t, "id"),
		NonInteractive: true,
	})
	var stdout bytes.Buffer
	if _, err := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sess}, req, nil, ports.ExecStreams{Stdout: &stdout}); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("未就绪双流结束须返回 ErrAuthFailed，实际 %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("未就绪认证失败时严禁向 stdout 泄露预暂存字节，实际 %q", stdout.String())
	}
}

func testPausedStdoutTimeoutUnblocks(t *testing.T) {
	defer goleak.VerifyNone(t)
	chunk := bytes.Repeat([]byte("Z"), 32*1024)
	neverReady := make(chan struct{})
	sess := newScriptedSession(1, func(_ string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: chunk},
				{data: chunk},
				{data: chunk},
				{data: chunk},
				{waitCh: neverReady, err: io.EOF},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps:    []readStep{{waitCh: neverReady, err: io.EOF}},
		}
		return out, errR
	})
	esc, _ := priv.NewEscalator(priv.Config{
		Entropy:          tck.NewDeterministicEntropy(74),
		HandshakeTimeout: 30 * time.Millisecond,
	})
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "id"),
	})
	if _, err := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sess}, req, nil, ports.ExecStreams{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("次流暂存暂停期间握手超时须返回 DeadlineExceeded，实际 %v", err)
	}
}

func testScriptStdinOrderAndStdoutRace(t *testing.T) {
	defer goleak.VerifyNone(t)
	stdoutEOF := make(chan struct{})
	var preReadyStdin string
	var sess *scriptedSession
	sess = newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		promptTok := extractBracketToken(cmd, `[xops-priv-prompt-`)
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{waitCh: sess.stdin.closedCh, data: []byte("script-done\n")},
				{err: io.EOF, onReturned: func() { close(stdoutEOF) }},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte(promptTok)},
				{
					waitCh: sess.stdin.firstWrote,
					data:   []byte(readyTok),
					onReturned: func() {
						preReadyStdin = sess.stdin.snapshot()
					},
				},
				{waitCh: stdoutEOF, err: io.EOF},
			},
		}
		return out, errR
	})
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(75)})
	prof, _ := execution.POSIXLaunchProfile(execution.InterpreterSH, execution.LoginModeDisabled)
	scriptPlan, _ := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindScript,
		Profile: prof,
		Command: "SCRIPT_BODY;",
	})
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: scriptPlan,
	})
	var stdout bytes.Buffer
	err := secret.WithBytes([]byte("pw-script"), func(box *secret.SecretBox) error {
		_, rErr := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sess}, req, box, ports.ExecStreams{
			Stdin:  strings.NewReader("USER_DATA"),
			Stdout: &stdout,
		})
		return rErr
	})
	if err != nil {
		t.Fatalf("脚本提权跨流时序失败: %v", err)
	}
	if preReadyStdin != "pw-script\n" {
		t.Fatalf("就绪前 stdin 须仅包含提权口令，实际 %q", preReadyStdin)
	}
	if gotStdin := sess.stdin.snapshot(); gotStdin != "pw-script\nSCRIPT_BODY;USER_DATA" {
		t.Fatalf("stdin 投递顺序异常: got=%q", gotStdin)
	}
	if stdout.String() != "script-done\n" {
		t.Fatalf("stdout 结果异常: got=%q", stdout.String())
	}
}

func testPTYModeCombinedStream(t *testing.T) {
	defer goleak.VerifyNone(t)
	large := bytes.Repeat([]byte("P"), 96*1024)
	neverErr := make(chan struct{})
	var sess *scriptedSession
	sess = newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		promptTok := extractBracketToken(cmd, `[xops-priv-prompt-`)
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte(promptTok)},
				{waitCh: sess.stdin.firstWrote, data: []byte(readyTok)},
				{data: large},
				{err: io.EOF, onReturned: func() { close(neverErr) }},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps:    []readStep{{waitCh: neverErr, err: io.EOF}},
		}
		return out, errR
	})
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(76)})
	sz, _ := ports.NewTerminalSize(24, 80)
	ptyReq, _ := ports.NewPTYRequest("xterm-256color", sz)
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "id"),
	})
	var stdout bytes.Buffer
	err := secret.WithBytes([]byte("pty-pass"), func(box *secret.SecretBox) error {
		_, rErr := esc.RunPrivileged(context.Background(), &scriptedOpener{session: sess}, req, box, ports.ExecStreams{
			PTY:    algebraic.Some(ptyReq),
			Stdout: &stdout,
		})
		return rErr
	})
	if err != nil {
		t.Fatalf("PTY 合并流提权失败: %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), large) {
		t.Fatalf("PTY 模式合并流大输出不完整: got=%d want=%d", stdout.Len(), len(large))
	}
}

type signalMatchWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	substr string
	once   sync.Once
	hitCh  chan struct{}
}

func newSignalMatchWriter(substr string) *signalMatchWriter {
	return &signalMatchWriter{substr: substr, hitCh: make(chan struct{})}
}

func (w *signalMatchWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	if w.substr != "" && strings.Contains(w.buf.String(), w.substr) {
		w.once.Do(func() { close(w.hitCh) })
	}
	w.mu.Unlock()
	return n, err
}

func (w *signalMatchWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// testSecondaryPreReadyFlushedImmediatelyWhileBlocked 确定性复现次流（stdout）先于主控流（stderr）readyTok
// 抵达少量字节（< maxPreReadyHoldBytes）随后管道阻塞的场景：验证 markReady() 立即刷出暂存字节、
// 零永久滞留，且与后续 stdout 字节维持严格 FIFO 顺序与零重复写入。
func testSecondaryPreReadyFlushedImmediatelyWhileBlocked(t *testing.T) {
	defer goleak.VerifyNone(t)
	firstChunkRead := make(chan struct{})
	releaseTail := make(chan struct{})
	sess := newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte("post-ready-started\n")},
				{onEnter: func() { close(firstChunkRead) }, waitCh: releaseTail, data: []byte("tail-after-flush\n")},
				{err: io.EOF},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{waitCh: firstChunkRead, data: []byte(readyTok)},
				{waitCh: releaseTail, data: []byte("err-after-flush\n")},
				{err: io.EOF},
			},
		}
		return out, errR
	})
	esc, err := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(77)})
	if err != nil {
		t.Fatalf("NewEscalator: %v", err)
	}
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "long-op"),
	})
	outW := newSignalMatchWriter("post-ready-started\n")
	var errBuf bytes.Buffer
	var runOut execution.ExecutionOutcome
	var runErr error

	waitErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			runOut, runErr = esc.RunPrivileged(context.Background(), &scriptedOpener{session: sess}, req, nil, ports.ExecStreams{
				Stdout: outW,
				Stderr: &errBuf,
			})
			return nil
		}); gErr != nil {
			return gErr
		}
		tm := time.NewTimer(5 * time.Second)
		defer tm.Stop()
		select {
		case <-outW.hitCh:
			close(releaseTail)
			return nil
		case <-tm.C:
			_ = sess.Close()
			return context.DeadlineExceeded
		}
	})
	if waitErr != nil || runErr != nil {
		t.Fatalf("markReady 须立即刷出次流暂存首包: waitErr=%v runErr=%v stdout=%q", waitErr, runErr, outW.String())
	}
	if comp, ok := runOut.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() {
		t.Fatalf("期望成功 OutcomeCompleted，实际 %#v", runOut)
	}
	if outW.String() != "post-ready-started\ntail-after-flush\n" || errBuf.String() != "err-after-flush\n" {
		t.Fatalf("即时刷出后 FIFO 顺序或内容失配: stdout=%q stderr=%q", outW.String(), errBuf.String())
	}
}

// testSecondaryPreReadyFlushedBeforePostReadyCancel 确定性验证次流首包在 markReady() 后立即刷出并触发
// 外部 ctx 取消时，RunPrivileged 返回不可重试的 *execution.OutcomeUnknown 且零协程泄漏。
func testSecondaryPreReadyFlushedBeforePostReadyCancel(t *testing.T) {
	defer goleak.VerifyNone(t)
	firstChunkRead := make(chan struct{})
	neverRelease := make(chan struct{})
	sess := newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte("post-ready-started\n")},
				{onEnter: func() { close(firstChunkRead) }, waitCh: neverRelease, err: io.EOF},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{waitCh: firstChunkRead, data: []byte(readyTok)},
				{waitCh: neverRelease, err: io.EOF},
			},
		}
		return out, errR
	})
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(78)})
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "hang-op"),
	})
	outW := newSignalMatchWriter("post-ready-started\n")
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runOut execution.ExecutionOutcome
	var runErr error

	waitErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			runOut, runErr = esc.RunPrivileged(runCtx, &scriptedOpener{session: sess}, req, nil, ports.ExecStreams{
				Stdout: outW,
			})
			return nil
		}); gErr != nil {
			return gErr
		}
		tm := time.NewTimer(5 * time.Second)
		defer tm.Stop()
		select {
		case <-outW.hitCh:
			cancel()
			return nil
		case <-tm.C:
			cancel()
			return context.DeadlineExceeded
		}
	})
	if waitErr != nil || !errors.Is(runErr, context.Canceled) {
		t.Fatalf("期望首包刷出后取消返回 context.Canceled: waitErr=%v runErr=%v", waitErr, runErr)
	}
	unk, ok := runOut.(*execution.OutcomeUnknown)
	if !ok || unk.CanRetry() {
		t.Fatalf("就绪后取消必须返回不可重试 OutcomeUnknown，实际 %#v", runOut)
	}
	if outW.String() != "post-ready-started\n" {
		t.Fatalf("首包内容失配: stdout=%q", outW.String())
	}
}

// testSecondaryConcurrentReadyAndCancelNoFIFOGap 在端到端 RunPrivileged 中并发触发 readyTok、
// 多分片次流 stdout 与外部 ctx 取消，验证任何调度序下 dst 恒为完整输出的前缀（零中段 FIFO 断层、零数据竞争）。
func testSecondaryConcurrentReadyAndCancelNoFIFOGap(t *testing.T) {
	defer goleak.VerifyNone(t)
	const fullStream = "chunk-1\nchunk-2\n"
	firstHandedOff := make(chan struct{})
	readyHandedOff := make(chan struct{})
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess := newScriptedSession(0, func(cmd string, closedCh <-chan struct{}) (io.Reader, io.Reader) {
		readyTok := extractBracketToken(cmd, `[xops-priv-ready-`)
		out := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{data: []byte("chunk-1\n")},
				{onEnter: func() { close(firstHandedOff) }, waitCh: readyHandedOff, data: []byte("chunk-2\n")},
				{err: io.EOF},
			},
		}
		errR := &gatedStepReader{
			closedCh: closedCh,
			steps: []readStep{
				{waitCh: firstHandedOff, data: []byte(readyTok)},
				{onEnter: func() {
					close(readyHandedOff)
					cancel()
				}, err: io.EOF},
			},
		}
		return out, errR
	})
	esc, _ := priv.NewEscalator(priv.Config{Entropy: tck.NewDeterministicEntropy(79)})
	req, _ := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method:  ports.PrivilegeMethodSudo,
		Command: tck.MustCommandPlan(t, "race-cancel"),
	})
	outW := newSignalMatchWriter("")
	_, _ = esc.RunPrivileged(runCtx, &scriptedOpener{session: sess}, req, nil, ports.ExecStreams{Stdout: outW})
	got := outW.String()
	if !strings.HasPrefix(fullStream, got) {
		t.Fatalf("并发就绪与取消下出现中段 FIFO 断层: got=%q must be prefix of %q", got, fullStream)
	}
}
