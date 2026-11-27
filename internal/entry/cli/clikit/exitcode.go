package clikit

import (
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/execution"
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

// BuildExecOutcomeView 穷尽投影 execution.ExecutionOutcome 与 runErr 为机器可读视图，保证零 fail-open。
func BuildExecOutcomeView(outcome execution.ExecutionOutcome, runErr error, stdoutText, stderrText string) (ExecOutcomeView, int, string) {
	code, diag, _ := MapOutcomeToExit(outcome, runErr)
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
		return fmt.Errorf("invalid execution outcome")
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
		return fmt.Errorf("unexpected execution outcome type %T", outcome)
	}
}

// MapOutcomeToExit 穷尽映射封闭和类型 execution.ExecutionOutcome 与可选运行期错误，
// 返回确定性进程退出码与面向 stderr 的简洁诊断信息（零 fail-open 路径）。
//
// 核心安全不变量：
//   - 即使远端进程退出码为 0，若 runErr != nil（例如终态审计写入失败触发 Halted 熔断），
//     也绝不返回 0 退出码，必须强制失败关闭返回非零退出码并输出错误诊断；
//   - OutcomeNotStarted、OutcomeUnknown、ExitUnknown 或任何无效结果一律返回非零退出码。
func MapOutcomeToExit(outcome execution.ExecutionOutcome, runErr error) (exitCode int, diagMsg string, mapErr error) {
	if outcome == nil || !outcome.IsValid() {
		msg := formatFallbackError("ssh execution failed: invalid execution outcome", runErr)
		return ExitSSHError, msg, fmt.Errorf("%s", msg)
	}
	switch v := outcome.(type) {
	case *execution.OutcomeCompleted:
		code, statusDiag, err := mapExitStatusToExit(v.Status())
		if runErr != nil {
			diag := joinDiagnostics(statusDiag, runErr.Error())
			if code == ExitOK {
				code = ExitSSHError
			}
			return code, diag, runErr
		}
		return code, statusDiag, err
	case *execution.OutcomeNotStarted:
		msg := formatNotStartedDiag(v, runErr)
		return ExitSSHError, msg, fmt.Errorf("%s", msg)
	case *execution.OutcomeUnknown:
		msg := formatUnknownOutcomeDiag(v, runErr)
		return ExitSSHError, msg, fmt.Errorf("%s", msg)
	default:
		msg := formatFallbackError(fmt.Sprintf("unexpected execution outcome type %T", outcome), runErr)
		return ExitSSHError, msg, fmt.Errorf("%s", msg)
	}
}

func mapExitStatusToExit(status execution.ExitStatus) (exitCode int, diagMsg string, mapErr error) {
	if status == nil || !status.IsValid() {
		msg := "ssh execution finished with invalid exit status"
		return ExitSSHError, msg, fmt.Errorf("%s", msg)
	}
	switch s := status.(type) {
	case *execution.ExitCode:
		code, ok := s.Code()
		if !ok {
			msg := "ssh execution finished with unreadable exit code"
			return ExitSSHError, msg, fmt.Errorf("%s", msg)
		}
		return NormalizeProcessExitCode(code), "", nil
	case *execution.ExitSignal:
		return mapSignalExit(s), formatSignalDiag(s), nil
	case *execution.ExitUnknown:
		msg := formatExitUnknownDiag(s)
		return ExitSSHError, msg, fmt.Errorf("%s", msg)
	default:
		msg := fmt.Sprintf("unexpected exit status type %T", status)
		return ExitSSHError, msg, fmt.Errorf("%s", msg)
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

func formatSignalDiag(sig *execution.ExitSignal) string {
	base := fmt.Sprintf("remote process terminated by signal %s", sig.Signal())
	if sig.CoreDumped() {
		base += " (core dumped)"
	}
	if msg := strings.TrimSpace(sig.Message()); msg != "" {
		base += ": " + msg
	}
	return base
}

func formatExitUnknownDiag(u *execution.ExitUnknown) string {
	if reason := strings.TrimSpace(u.Reason()); reason != "" {
		return "remote process exited without exit status: " + reason
	}
	return "remote process exited without exit status"
}

func formatNotStartedDiag(ns *execution.OutcomeNotStarted, runErr error) string {
	if runErr != nil && strings.TrimSpace(runErr.Error()) != "" {
		return runErr.Error()
	}
	if reason := strings.TrimSpace(ns.Reason()); reason != "" {
		return fmt.Sprintf("ssh failed before start (%s): %s", ns.Phase(), reason)
	}
	return fmt.Sprintf("ssh failed before start (%s)", ns.Phase())
}

func formatUnknownOutcomeDiag(u *execution.OutcomeUnknown, runErr error) string {
	if runErr != nil && strings.TrimSpace(runErr.Error()) != "" {
		return fmt.Sprintf("ssh outcome unknown (%s; do not blindly retry): %s", u.Phase(), runErr.Error())
	}
	if reason := strings.TrimSpace(u.Reason()); reason != "" {
		return fmt.Sprintf("ssh outcome unknown (%s; do not blindly retry): %s", u.Phase(), reason)
	}
	return fmt.Sprintf("ssh outcome unknown (%s; do not blindly retry)", u.Phase())
}

func formatFallbackError(fallback string, err error) string {
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		return err.Error()
	}
	return fallback
}

func joinDiagnostics(a, b string) string {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	switch {
	case a == "":
		return b
	case b == "" || a == b:
		return a
	default:
		return a + "; " + b
	}
}
