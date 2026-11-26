package priv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
)

var errHandshakeEndedBeforeReady = errors.New("sshnet/priv: 远端在提权就绪帧到达前结束输出")

// RunPrivileged 通过借用的 opener 打开远端会话并按 req 执行随机化 -p / 就绪帧提权握手，
// 实现 ports.PrivilegeEscalationPort；口令仅在调用方同步协程内写入经验证的 (ports.RemoteSession).StdinPipe。
func (e *Escalator) RunPrivileged(
	ctx context.Context,
	//xops:borrowed
	opener ports.SessionOpener,
	req ports.PrivilegeRequest,
	//xops:borrowed
	password *secret.SecretBox,
	streams ports.ExecStreams,
) (execution.ExecutionOutcome, error) {
	if err := e.validateCall(ctx, opener, req, password, streams); err != nil {
		return nil, err
	}
	return e.executeEscalation(ctx, opener, req, password, nil, streams)
}

// RunPrivilegedWithCombinedSecret 支持双因素提权（如口令 + 第二因子 PIN/OTP 拼接场景），
// 在同步调用方协程内以嵌套 primary.Use -> secondary.Use 方式将拼接明文写入经验证的 StdinPipe 并立即清零（0 nolint）。
func (e *Escalator) RunPrivilegedWithCombinedSecret(
	ctx context.Context,
	//xops:borrowed
	opener ports.SessionOpener,
	req ports.PrivilegeRequest,
	//xops:borrowed
	primary *secret.SecretBox,
	//xops:borrowed
	secondary *secret.SecretBox,
	streams ports.ExecStreams,
) (execution.ExecutionOutcome, error) {
	if err := e.validateCall(ctx, opener, req, primary, streams); err != nil {
		return nil, err
	}
	if primary == nil || secondary == nil || !secondary.IsValid() {
		return nil, fmt.Errorf("%w: 双因素提权需要两个有效的 SecretBox", ports.ErrInvalidArgument)
	}
	return e.executeEscalation(ctx, opener, req, primary, secondary, streams)
}

func (e *Escalator) validateCall(
	ctx context.Context,
	//xops:borrowed
	opener ports.SessionOpener,
	req ports.PrivilegeRequest,
	//xops:borrowed
	password *secret.SecretBox,
	streams ports.ExecStreams,
) error {
	if e == nil || !e.valid {
		return fmt.Errorf("%w: Escalator 未初始化", ports.ErrInvalidArgument)
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if opener == nil || !req.IsValid() {
		return fmt.Errorf("%w: SessionOpener 与 PrivilegeRequest 均须有效", ports.ErrInvalidArgument)
	}
	if password != nil && !password.IsValid() {
		return fmt.Errorf("%w: 提权口令 SecretBox 无效或已失效", ports.ErrInvalidArgument)
	}
	if ptyReq, ok := streams.PTY.Get(); ok && !ptyReq.IsValid() {
		return fmt.Errorf("%w: PTYRequest 无效", ports.ErrInvalidArgument)
	}
	return nil
}

func (e *Escalator) executeEscalation(
	ctx context.Context,
	//xops:borrowed
	opener ports.SessionOpener,
	req ports.PrivilegeRequest,
	//xops:borrowed
	primary *secret.SecretBox,
	//xops:borrowed
	secondary *secret.SecretBox,
	streams ports.ExecStreams,
) (execution.ExecutionOutcome, error) {
	runCtx, cancel := applyOptionalRequestTimeout(ctx, req)
	defer cancel()

	tokens, err := generateHandshakeTokens(e.entropy)
	if err != nil {
		return nil, err
	}
	wrappedPlan, scriptBody, hasScript, err := buildEscalationPlan(req, tokens)
	if err != nil {
		return nil, err
	}

	sess, err := opener.OpenSession(runCtx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sess.Close() }()

	// 直接在本地获取 (ports.RemoteSession).StdinPipe，确保 secrettaint 正向白名单精准溯源（0 nolint）。
	stdinPipe, err := sess.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, stderrPipe, err := claimOutputPipes(sess)
	if err != nil {
		return nil, err
	}
	startStreams := ports.ExecStreams{PTY: streams.PTY, Env: streams.Env}
	if err := sess.Start(runCtx, wrappedPlan, startStreams); err != nil {
		return nil, err
	}

	state := newSharedHandshakeState(req.Method(), tokens, req.Command().MaxOutputBytes())
	postStdin := buildPostReadyStdin(scriptBody, hasScript, streams.Stdin)
	writeSecret := func() error {
		if secondary == nil {
			return primary.Use(func(plain []byte) error {
				line := make([]byte, len(plain)+1)
				defer clear(line)
				copy(line, plain)
				line[len(plain)] = '\n'
				_, wErr := stdinPipe.Write(line)
				return wErr
			})
		}
		return primary.Use(func(p1 []byte) error {
			return secondary.Use(func(p2 []byte) error {
				line := make([]byte, len(p1)+len(p2)+1)
				defer clear(line)
				copy(line, p1)
				copy(line[len(p1):], p2)
				line[len(p1)+len(p2)] = '\n'
				_, wErr := stdinPipe.Write(line)
				return wErr
			})
		})
	}

	sentAttempts, runErr := e.driveSessionIOAndHandshake(
		runCtx, sess, stdinPipe, stdoutPipe, stderrPipe, postStdin,
		req, primary != nil, state, streams, writeSecret,
	)
	if runErr != nil {
		return nil, classifyEscalationErr(runCtx, req, state, sentAttempts, runErr)
	}
	out, waitErr := sess.Wait(runCtx)
	if waitErr != nil {
		return out, waitErr
	}
	return applyTruncationOutcome(out, state.truncated.Load()), nil
}

// driveSessionIOAndHandshake 在 core/conc.RunWait 下并发泵送输出流与就绪后输入流，
// 同时在调用方同步协程内执行提权握手回调 writeSecret（严禁跨协程传递 SecretBox）。
//
//xops:syncclosure
func (e *Escalator) driveSessionIOAndHandshake(
	runCtx context.Context,
	sess ports.RemoteSession,
	stdinPipe io.WriteCloser,
	stdoutPipe, stderrPipe io.Reader,
	postStdin io.Reader,
	req ports.PrivilegeRequest,
	hasSecret bool,
	state *sharedHandshakeState,
	streams ports.ExecStreams,
	writeSecret func() error,
) (int, error) {
	readersDone := make(chan struct{})
	stdinCtx, cancelStdin := context.WithCancel(runCtx)
	defer cancelStdin()

	var sentAttempts int
	var hsErr error
	nurseryErr := conc.RunWait(runCtx, func(nCtx context.Context, n *conc.Nursery) error {
		if err := spawnOutputScanners(n, stdoutPipe, stderrPipe, state, streams, readersDone); err != nil {
			return err
		}
		if err := spawnPostReadyStdinPump(n, stdinCtx, state.readyCh, stdinPipe, postStdin); err != nil {
			return err
		}
		sentAttempts, hsErr = e.awaitHandshakeOnCaller(nCtx, req, hasSecret, state, readersDone, writeSecret)
		if hsErr != nil {
			cancelStdin()
			_ = sess.Close()
			waitReadersOrCancel(nCtx, readersDone)
			return nil
		}
		waitReadersOrCancel(nCtx, readersDone)
		cancelStdin()
		return nil
	})
	if hsErr != nil {
		return sentAttempts, hsErr
	}
	return sentAttempts, nurseryErr
}

// awaitHandshakeOnCaller 在调用方同步协程内驱动提权握手，按需触发同步回调 writeSecret。
//
//xops:syncclosure
func (e *Escalator) awaitHandshakeOnCaller(
	ctx context.Context,
	req ports.PrivilegeRequest,
	hasSecret bool,
	state *sharedHandshakeState,
	readersDone <-chan struct{},
	writeSecret func() error,
) (int, error) {
	timerCh, stopTimer := e.startHandshakeTimer()
	defer stopTimer()

	attempts := 0
	for {
		select {
		case <-state.readyCh:
			return attempts, nil
		case <-readersDone:
			if state.readyFlag.Load() {
				return attempts, nil
			}
			return attempts, errHandshakeEndedBeforeReady
		case <-state.promptCh:
			if err := checkCanSendPassword(req, hasSecret, attempts); err != nil {
				return attempts, err
			}
			if err := writeSecret(); err != nil {
				return attempts, fmt.Errorf("%w: 写入提权口令失败: %w", ports.ErrAuthFailed, err)
			}
			attempts++
		case <-timerCh:
			return attempts, fmt.Errorf("%w: 等待远端提权握手超时", context.DeadlineExceeded)
		case <-ctx.Done():
			return attempts, ctx.Err()
		}
	}
}

func checkCanSendPassword(req ports.PrivilegeRequest, hasSecret bool, attempts int) error {
	if req.NonInteractive() || !hasSecret {
		return fmt.Errorf("%w: 远端提权需要口令但未提供或处于非交互模式", ports.ErrAuthFailed)
	}
	if attempts >= 1 {
		return fmt.Errorf("%w: 提权口令被远端拒绝（重复质询）", ports.ErrAuthFailed)
	}
	return nil
}

func spawnOutputScanners(
	n *conc.Nursery,
	stdoutPipe, stderrPipe io.Reader,
	state *sharedHandshakeState,
	streams ports.ExecStreams,
	readersDone chan struct{},
) error {
	var rem atomic.Int32
	rem.Store(2)
	doneOne := func() {
		if rem.Add(-1) == 0 {
			close(readersDone)
		}
	}
	if err := n.Go(func(context.Context) error {
		defer doneOne()
		return newStreamScanner(state, streams.Stdout).pump(stdoutPipe)
	}); err != nil {
		close(readersDone)
		return err
	}
	if err := n.Go(func(context.Context) error {
		defer doneOne()
		return newStreamScanner(state, streams.Stderr).pump(stderrPipe)
	}); err != nil {
		doneOne()
		return err
	}
	return nil
}

func spawnPostReadyStdinPump(
	n *conc.Nursery,
	stdinCtx context.Context,
	readyCh <-chan struct{},
	stdinPipe io.WriteCloser,
	postStdin io.Reader,
) error {
	return n.Go(func(context.Context) error {
		select {
		case <-readyCh:
		case <-stdinCtx.Done():
			return nil
		}
		defer func() { _ = stdinPipe.Close() }()
		if postStdin == nil {
			return nil
		}
		return copyPostReadyStdin(stdinCtx, stdinPipe, postStdin)
	})
}

func copyPostReadyStdin(ctx context.Context, dst io.WriteCloser, src io.Reader) error {
	buf := make([]byte, copyChunkBytes)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, rErr := src.Read(buf)
		if n > 0 {
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return nil
			}
		}
		if rErr != nil {
			return nil
		}
	}
}

func claimOutputPipes(sess ports.RemoteSession) (io.Reader, io.Reader, error) {
	outPipe, err := sess.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	errPipe, err := sess.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	return outPipe, errPipe, nil
}

func buildPostReadyStdin(scriptBody string, hasScript bool, userStdin io.Reader) io.Reader {
	if !hasScript {
		return userStdin
	}
	if userStdin == nil {
		return strings.NewReader(scriptBody)
	}
	return io.MultiReader(strings.NewReader(scriptBody), userStdin)
}

func (e *Escalator) startHandshakeTimer() (<-chan time.Time, func()) {
	if e.clock != nil {
		tm := e.clock.NewTimer(e.handshakeTimeout)
		return tm.C(), func() { tm.Stop() }
	}
	tm := time.NewTimer(e.handshakeTimeout)
	return tm.C, func() { tm.Stop() }
}

func waitReadersOrCancel(ctx context.Context, readersDone <-chan struct{}) {
	select {
	case <-readersDone:
	case <-ctx.Done():
	}
}

func applyOptionalRequestTimeout(ctx context.Context, req ports.PrivilegeRequest) (context.Context, context.CancelFunc) {
	if d, ok := req.Timeout().Get(); ok && d.IsPositive() {
		return context.WithTimeout(ctx, d.Std())
	}
	return context.WithCancel(ctx)
}

func classifyEscalationErr(
	ctx context.Context,
	req ports.PrivilegeRequest,
	state *sharedHandshakeState,
	sentAttempts int,
	err error,
) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, ports.ErrAuthFailed) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, errHandshakeEndedBeforeReady) {
		diag := state.diagText()
		if sentAttempts > 0 || req.NonInteractive() || isAuthRejectionDiagnostic(diag) {
			return fmt.Errorf("%w: 提权认证在命令启动前被拒绝", ports.ErrAuthFailed)
		}
		return fmt.Errorf("%w: %w", ports.ErrAuthFailed, err)
	}
	return err
}

func applyTruncationOutcome(out execution.ExecutionOutcome, truncated bool) execution.ExecutionOutcome {
	if !truncated || out == nil {
		return out
	}
	comp, ok := out.(*execution.OutcomeCompleted)
	if !ok || comp.Truncated() {
		return out
	}
	rebuilt, err := execution.NewOutcomeCompleted(comp.Status(), true)
	if err != nil {
		return out
	}
	return rebuilt
}
