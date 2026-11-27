package clikit

import (
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// ExecOutcomeView 描述单节点 SSH/Exec 在 `--json` 模式下的规范输出载荷（零裸 time.Duration）。
type ExecOutcomeView struct {
	OK          bool   `json:"ok"`
	ExitCode    int    `json:"exit_code"`
	OutcomeKind string `json:"outcome_kind"`
	Stdout      string `json:"stdout,omitzero"`
	Stderr      string `json:"stderr,omitzero"`
	Truncated   bool   `json:"truncated,omitzero"`
	Signal      string `json:"signal,omitzero"`
	Phase       string `json:"phase,omitzero"`
	Diagnostic  string `json:"diagnostic,omitzero"`
	ErrorCode   string `json:"error_code,omitzero"`
	DoNotRetry  bool   `json:"do_not_retry,omitzero"`
}

// BuildExecOutcomeView 以规范英文穷尽投影 execution.ExecutionOutcome 与 runErr 为机器可读视图，保证零 fail-open。
func BuildExecOutcomeView(outcome execution.ExecutionOutcome, runErr error, stdoutText, stderrText string) (ExecOutcomeView, int, string) {
	return BuildExecOutcomeViewLocalized(nil, outcome, runErr, stdoutText, stderrText)
}

// BuildExecOutcomeViewLocalized 使用指定 Localizer 本地化 Diagnostic 字段并穷尽投影 execution.ExecutionOutcome，
// 保持 ExitCode、OutcomeKind、ErrorCode 与 DoNotRetry 机器契约完全不变。
func BuildExecOutcomeViewLocalized(loc *i18n.Localizer, outcome execution.ExecutionOutcome, runErr error, stdoutText, stderrText string) (ExecOutcomeView, int, string) {
	code, diag, _ := MapOutcomeToExitLocalized(loc, outcome, runErr)
	view := ExecOutcomeView{
		OK:         code == ExitOK && runErr == nil,
		ExitCode:   code,
		Stdout:     stdoutText,
		Stderr:     stderrText,
		Diagnostic: diag,
	}
	if runErr != nil {
		view.ErrorCode = ClassifyErrorCode(runErr)
	}
	if err := populateOutcomeFields(&view, outcome); err != nil {
		view.OK = false
		view.OutcomeKind = "invalid"
	}
	return view, code, diag
}

func populateOutcomeFields(view *ExecOutcomeView, outcome execution.ExecutionOutcome) error {
	if outcome == nil || !outcome.IsValid() {
		view.OutcomeKind = "invalid"
		return i18n.E(i18n.KeyCLIExitInvalidOutcome)
	}
	view.OutcomeKind = outcome.Kind().String()
	switch v := outcome.(type) {
	case *execution.OutcomeCompleted:
		view.Truncated = v.Truncated()
		if sig, ok := v.Status().(*execution.ExitSignal); ok && sig.IsValid() {
			view.Signal = sig.Signal()
		}
		return nil
	case *execution.OutcomeNotStarted:
		view.Phase = v.Phase().String()
		return nil
	case *execution.OutcomeUnknown:
		view.Phase = v.Phase().String()
		view.DoNotRetry = true
		return nil
	default:
		view.OutcomeKind = "invalid"
		return i18n.E(i18n.KeyCLIExitUnexpectedOutcome, i18n.Str("type", fmt.Sprintf("%T", outcome)))
	}
}

// MapOutcomeToExit 穷尽映射封闭和类型 execution.ExecutionOutcome 与可选运行期错误，
// 返回确定性进程退出码与面向 stderr 的规范英文诊断信息（零 fail-open 路径）。
func MapOutcomeToExit(outcome execution.ExecutionOutcome, runErr error) (exitCode int, diagMsg string, mapErr error) {
	return MapOutcomeToExitLocalized(nil, outcome, runErr)
}

// MapOutcomeToExitLocalized 使用指定 Localizer 穷尽映射 execution.ExecutionOutcome 与可选运行期错误，
// 返回确定性进程退出码与本地化诊断文本（零 fail-open 路径）。
//
// 核心安全不变量：
//   - 即使远端进程退出码为 0，若 runErr != nil（例如终态审计写入失败触发 Halted 熔断），
//     也绝不返回 0 退出码，必须强制失败关闭返回非零退出码并输出错误诊断；
//   - OutcomeNotStarted、OutcomeUnknown、ExitUnknown 或任何无效结果一律返回非零退出码。
func MapOutcomeToExitLocalized(loc *i18n.Localizer, outcome execution.ExecutionOutcome, runErr error) (exitCode int, diagMsg string, mapErr error) {
	effLoc := EnsureLocalizer(loc)
	if outcome == nil || !outcome.IsValid() {
		err := pickOrFallbackErr(runErr, i18n.E(i18n.KeyCLIExitInvalidOutcome))
		return ExitSSHError, effLoc.RenderError(err), err
	}
	switch v := outcome.(type) {
	case *execution.OutcomeCompleted:
		code, statusDiag, err := mapExitStatusToExit(effLoc, v.Status())
		if runErr != nil {
			diag := joinDiagnostics(effLoc, statusDiag, effLoc.RenderError(runErr))
			if code == ExitOK {
				code = ExitSSHError
			}
			return code, diag, runErr
		}
		return code, statusDiag, err
	case *execution.OutcomeNotStarted:
		err := buildNotStartedErr(v, runErr)
		return ExitSSHError, effLoc.RenderError(err), err
	case *execution.OutcomeUnknown:
		err := buildUnknownOutcomeErr(v, runErr)
		return ExitSSHError, effLoc.RenderError(err), err
	default:
		err := pickOrFallbackErr(runErr, i18n.E(i18n.KeyCLIExitUnexpectedOutcome, i18n.Str("type", fmt.Sprintf("%T", outcome))))
		return ExitSSHError, effLoc.RenderError(err), err
	}
}

func mapExitStatusToExit(loc *i18n.Localizer, status execution.ExitStatus) (exitCode int, diagMsg string, mapErr error) {
	if status == nil || !status.IsValid() {
		err := i18n.E(i18n.KeyCLIExitInvalidStatus)
		return ExitSSHError, loc.RenderError(err), err
	}
	switch s := status.(type) {
	case *execution.ExitCode:
		code, ok := s.Code()
		if !ok {
			err := i18n.E(i18n.KeyCLIExitUnreadableCode)
			return ExitSSHError, loc.RenderError(err), err
		}
		return NormalizeProcessExitCode(code), "", nil
	case *execution.ExitSignal:
		return mapSignalExit(s), formatSignalDiag(loc, s), nil
	case *execution.ExitUnknown:
		err := buildExitUnknownErr(s)
		return ExitSSHError, loc.RenderError(err), err
	default:
		err := i18n.E(i18n.KeyCLIExitUnexpectedStatus, i18n.Str("type", fmt.Sprintf("%T", status)))
		return ExitSSHError, loc.RenderError(err), err
	}
}

// NormalizeProcessExitCode 将远端退出码跨平台统一规整至 [0, 255]：
//   - 0 保持为 0；
//   - 超出 [1, 255] 的非零退出码统一取低 8 位（int(code) & 0xff），避免 Unix 与 Windows 退出码行为分叉；
//   - 若非零退出码的低 8 位为 0（如 256 或 -256），归约为 1，防止失败被静默截断为成功 0。
func NormalizeProcessExitCode(code int32) int {
	if code == 0 {
		return ExitOK
	}
	if code > 0 && code <= 255 {
		return int(code)
	}
	low := int(code) & 0xff
	if low == 0 {
		return ExitGeneral
	}
	return low
}

func mapSignalExit(sig *execution.ExitSignal) int {
	if num, ok := posixSignalNumber(sig.Signal()); ok {
		return ExitSignalBase + num
	}
	return ExitSSHError
}

func posixSignalNumber(raw string) (int, bool) {
	name := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(raw)), "SIG")
	nums := map[string]int{
		"HUP": 1, "INT": 2, "QUIT": 3, "ILL": 4, "TRAP": 5,
		"ABRT": 6, "IOT": 6, "BUS": 7, "FPE": 8, "KILL": 9,
		"USR1": 10, "SEGV": 11, "USR2": 12, "PIPE": 13, "ALRM": 14, "TERM": 15,
	}
	n, ok := nums[name]
	return n, ok
}

func formatSignalDiag(loc *i18n.Localizer, sig *execution.ExitSignal) string {
	msg := strings.TrimSpace(sig.Message())
	sigParam := i18n.BoundStr("signal", sig.Signal())
	switch {
	case sig.CoreDumped() && msg != "":
		return loc.T(i18n.KeyCLIExitSignalCoreMsg, sigParam, i18n.BoundStr("message", msg))
	case sig.CoreDumped():
		return loc.T(i18n.KeyCLIExitSignalCore, sigParam)
	case msg != "":
		return loc.T(i18n.KeyCLIExitSignalMsg, sigParam, i18n.BoundStr("message", msg))
	default:
		return loc.T(i18n.KeyCLIExitSignal, sigParam)
	}
}

func buildExitUnknownErr(u *execution.ExitUnknown) error {
	if reason := strings.TrimSpace(u.Reason()); reason != "" {
		return i18n.E(i18n.KeyCLIExitUnknownReason, i18n.BoundStr("reason", reason))
	}
	return i18n.E(i18n.KeyCLIExitUnknown)
}

func buildNotStartedErr(ns *execution.OutcomeNotStarted, runErr error) error {
	if runErr != nil && strings.TrimSpace(runErr.Error()) != "" {
		return runErr
	}
	if reason := strings.TrimSpace(ns.Reason()); reason != "" {
		return i18n.E(i18n.KeyCLIExitNotStartedReason, i18n.Str("phase", ns.Phase().String()), i18n.BoundStr("reason", reason))
	}
	return i18n.E(i18n.KeyCLIExitNotStarted, i18n.Str("phase", ns.Phase().String()))
}

func buildUnknownOutcomeErr(u *execution.OutcomeUnknown, runErr error) error {
	phaseParam := i18n.Str("phase", u.Phase().String())
	if runErr != nil && strings.TrimSpace(runErr.Error()) != "" {
		return i18n.Wrap(runErr, i18n.KeyCLIExitOutcomeUnknown, phaseParam)
	}
	if reason := strings.TrimSpace(u.Reason()); reason != "" {
		return i18n.E(i18n.KeyCLIExitOutcomeUnknownReason, phaseParam, i18n.BoundStr("reason", reason))
	}
	return i18n.E(i18n.KeyCLIExitOutcomeUnknown, phaseParam)
}

func pickOrFallbackErr(err, fallback error) error {
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		return err
	}
	return fallback
}

func joinDiagnostics(loc *i18n.Localizer, a, b string) string {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	switch {
	case a == "":
		return b
	case b == "" || a == b:
		return a
	default:
		return loc.T(i18n.KeyCLIExitJoinDiag, i18n.BoundStr("a", a), i18n.BoundStr("b", b))
	}
}
