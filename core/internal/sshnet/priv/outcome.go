package priv

import (
	"context"
	"errors"
	"time"

	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/ports"
)

type driveResult struct {
	sentAttempts int
	waitOut      execution.ExecutionOutcome
	waitErr      error
	runErr       error
}

func buildDriveResult(
	runCtx context.Context,
	sentAttempts int,
	waitOut execution.ExecutionOutcome,
	waitErr, hsErr, nurseryErr error,
) driveResult {
	res := driveResult{
		sentAttempts: sentAttempts,
		waitOut:      waitOut,
		waitErr:      waitErr,
	}
	if hsErr != nil {
		// 若扫描器在握手前先报错（如 promptCh 溢出返回 ErrAuthFailed）导致 nCtx 取消，
		// 保留原始 nurseryErr 而非被 nCtx 的 context.Canceled 掩盖。
		if runCtx.Err() == nil && errors.Is(hsErr, context.Canceled) && nurseryErr != nil {
			res.runErr = nurseryErr
		} else {
			res.runErr = hsErr
		}
		return res
	}
	if nurseryErr != nil {
		res.runErr = nurseryErr
		return res
	}
	if err := runCtx.Err(); err != nil {
		res.runErr = err
	}
	return res
}

// finalizeEscalationResult 严格遵守 ADR-016 不变式：
//   - 若在 readyTok 之前失败（目标命令尚未启动），返回 (nil, classifiedErr)；
//   - 一旦已观测到 readyTok（远端提权命令已开始执行），任何取消、超时或传输中止都必须返回有效的
//     *execution.OutcomeUnknown（CanRetry() == false），绝不返回 (nil, err)。
func finalizeEscalationResult(
	runCtx context.Context,
	req ports.PrivilegeRequest,
	state *sharedHandshakeState,
	res driveResult,
) (execution.ExecutionOutcome, error) {
	if !state.readyFlag.Load() {
		err := firstNonNilErr(res.runErr, res.waitErr, errHandshakeEndedBeforeReady)
		return nil, classifyEscalationErr(runCtx, req, state, res.sentAttempts, err)
	}
	if ctxErr := runCtx.Err(); ctxErr != nil {
		return synthesizePostReadyUnknown(ctxErr), ctxErr
	}
	if err := firstNonNilErr(res.runErr, res.waitErr, nil); err != nil {
		if res.waitOut != nil && res.waitOut.IsValid() {
			return applyTruncationOutcome(res.waitOut, state.truncated.Load()), err
		}
		return synthesizePostReadyUnknown(err), err
	}
	if res.waitOut == nil || !res.waitOut.IsValid() {
		return synthesizePostReadyUnknown(ports.ErrClosed), ports.ErrClosed
	}
	return applyTruncationOutcome(res.waitOut, state.truncated.Load()), nil
}

func firstNonNilErr(a, b, fallback error) error {
	if a != nil {
		return a
	}
	if b != nil {
		return b
	}
	return fallback
}

func synthesizePostReadyUnknown(err error) execution.ExecutionOutcome {
	phase := execution.ExecPhaseTransportLost
	code := "priv_aborted_post_ready"
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		phase = execution.ExecPhaseTimedOut
		code = "priv_timeout_post_ready"
	case errors.Is(err, context.Canceled):
		phase = execution.ExecPhaseCanceled
		code = "priv_canceled_post_ready"
	}
	detail := "elevated command aborted after ready"
	if err != nil {
		detail = err.Error()
	}
	out, _ := execution.NewOutcomeUnknown(phase, code, detail)
	return out
}

func applyOptionalRequestTimeout(ctx context.Context, req ports.PrivilegeRequest) (context.Context, context.CancelFunc) {
	var chosen time.Duration
	if d, ok := req.Timeout().Get(); ok && d.IsPositive() {
		chosen = d.Std()
	}
	if d, ok := req.Command().Timeout().Get(); ok && d.IsPositive() {
		if chosen == 0 || d.Std() < chosen {
			chosen = d.Std()
		}
	}
	if chosen > 0 {
		return context.WithTimeout(ctx, chosen)
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
			return domi18n.EF(ports.ErrAuthFailed, domi18n.KeyPrivAuthRejected)
		}
		return domi18n.WrapSentinel(ports.ErrAuthFailed, err)
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
