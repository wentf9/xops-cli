package probe

import (
	"bytes"
	"context"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/ports"
)

// ProbeShell 通过借用的 opener 执行规范化两阶段远端 Shell 探测，实现 ports.ShellProbePort：
//   - 阶段 1 按序探测合法启动方言（posix / cmd / powershell），遇传输/取消/截断立即失败关闭；
//   - 阶段 2 在阶段 1 确认的方言上枚举并校验可用解释器，产出一律经 execution.LaunchProfile 校验的不可变快照。
func (p *Prober) ProbeShell(
	ctx context.Context,
	//xops:borrowed
	opener ports.SessionOpener,
) (ports.ShellProbeResult, error) {
	var zero ports.ShellProbeResult
	if p == nil || !p.valid {
		return zero, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonComponentClosed, domi18n.Str("component", "Prober"))
	}
	if ctx == nil {
		return zero, ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if opener == nil {
		return zero, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldNil, domi18n.Str("field", "SessionOpener"))
	}

	hit, err := p.runStage1(ctx, opener)
	if err != nil {
		return zero, err
	}
	if p.stage1Only {
		return ports.NewShellProbeResult(ports.ShellProbeResultSpec{
			Dialect:     hit.dialect,
			Interpreter: execution.InterpreterServer,
			OSFamily:    hit.osFamily,
			ProbeStage:  1,
			RawBanner:   hit.rawBanner,
		})
	}
	return p.runStage2(ctx, opener, hit)
}

func (p *Prober) runStage1(
	ctx context.Context,
	//xops:borrowed
	opener ports.SessionOpener,
) (stage1Hit, error) {
	for _, spec := range stage1ProbeSequence(p.preferWindows) {
		output, succeeded, err := p.execProbeCommand(ctx, opener, spec.command)
		if err != nil {
			return stage1Hit{}, err
		}
		if !succeeded {
			continue
		}
		if hit, ok := parseStage1Output(spec.dialect, output); ok {
			return hit, nil
		}
	}
	return stage1Hit{}, domi18n.EF(ErrProbeFailed, domi18n.KeyProbeNoDialect)
}

func (p *Prober) runStage2(
	ctx context.Context,
	//xops:borrowed
	opener ports.SessionOpener,
	hit stage1Hit,
) (ports.ShellProbeResult, error) {
	var zero ports.ShellProbeResult
	enumCmd, err := stage2EnumCommand(hit.dialect)
	if err != nil {
		return zero, err
	}
	output, succeeded, err := p.execProbeCommand(ctx, opener, enumCmd)
	if err != nil {
		return zero, err
	}
	if !succeeded {
		return zero, domi18n.EF(ErrProbeFailed, domi18n.KeyCommonOpTargetFailed, domi18n.Str("op", "stage 2 interpreter enumeration"), domi18n.Str("target", hit.dialect.String()))
	}
	interpreters, err := parseStage2Interpreters(output)
	if err != nil {
		return zero, err
	}
	selected, ok := selectRecommendedInterpreter(hit, interpreters)
	if !ok {
		return zero, domi18n.EF(ErrProbeFailed, domi18n.KeyProbeNoInterpreter, domi18n.Str("dialect", hit.dialect.String()))
	}
	return ports.NewShellProbeResult(ports.ShellProbeResultSpec{
		Dialect:     hit.dialect,
		Interpreter: selected,
		OSFamily:    hit.osFamily,
		ProbeStage:  2,
		RawBanner:   hit.rawBanner,
	})
}

// execProbeCommand 在隔离远端会话上执行单条有界只读探针命令：
//   - 传输错误、上下文取消/超时、OutcomeUnknown 与输出截断一律返回非空 error（Fail-Closed）；
//   - 仅常规 OutcomeCompleted 返回 (stdout, succeeded, nil)，由上层区分非匹配的语法退出码。
func (p *Prober) execProbeCommand(
	ctx context.Context,
	//xops:borrowed
	opener ports.SessionOpener,
	command string,
) (string, bool, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, p.commandTimeout)
	defer cancel()

	plan, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:           execution.PlanKindCommand,
		Profile:        execution.DefaultServerLaunchProfile(),
		Command:        command,
		MaxOutputBytes: algebraic.Some(p.maxOutputBytes),
	})
	if err != nil {
		return "", false, domi18n.WrapSentinel(ErrProbeFailed, err)
	}
	sess, err := opener.OpenSession(cmdCtx)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = sess.Close() }()

	var stdout, stderr bytes.Buffer
	if err := sess.Start(cmdCtx, plan, ports.ExecStreams{Stdout: &stdout, Stderr: &stderr}); err != nil {
		return "", false, err
	}
	out, err := sess.Wait(cmdCtx)
	if err != nil {
		return "", false, err
	}
	return inspectProbeOutcome(out, stdout.String(), p.maxOutputBytes)
}

func inspectProbeOutcome(out execution.ExecutionOutcome, stdout string, maxBytes uint64) (string, bool, error) {
	if out == nil || !out.IsValid() {
		return "", false, domi18n.EF(ErrProbeFailed, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ExecutionOutcome"))
	}
	switch v := out.(type) {
	case *execution.OutcomeCompleted:
		if v.Truncated() || uint64(len(stdout)) > maxBytes {
			return "", false, domi18n.EF(ErrProbeFailed, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "probe output"), domi18n.Uint64("size", uint64(len(stdout))), domi18n.Uint64("limit", maxBytes))
		}
		return stdout, v.Succeeded(), nil
	case *execution.OutcomeNotStarted:
		return "", false, domi18n.EF(ErrProbeFailed, domi18n.KeyCommonOpTargetFailed, domi18n.Str("op", "start probe session"), domi18n.BoundStr("target", v.Code()))
	case *execution.OutcomeUnknown:
		return "", false, domi18n.EF(ErrProbeFailed, domi18n.KeyCommonOpTargetFailed, domi18n.Str("op", "probe session execution"), domi18n.BoundStr("target", v.Code()))
	default:
		return "", false, domi18n.EF(ErrProbeFailed, domi18n.KeyCommonNotSupported, domi18n.Str("feature", "execution outcome variant"))
	}
}
