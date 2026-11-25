package cli

import (
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/execution"
)

// mapOutcomeToExit 穷尽映射封闭和类型 execution.ExecutionOutcome 与可选运行期错误，
// 返回确定性的进程退出码与面向 stderr 的简洁诊断信息（零 fail-open 路径）。
//
// 核心安全不变量：
//   - 即使远端进程退出码为 0，若 runErr != nil（例如终态审计写入失败触发 Halted 熔断），
//     也绝不返回 0 退出码，必须强制失败关闭返回非零退出码并输出错误诊断；
//   - OutcomeNotStarted、OutcomeUnknown、ExitUnknown 或任何无效结果一律返回非零退出码。
func mapOutcomeToExit(outcome execution.ExecutionOutcome, runErr error) (exitCode int, diagMsg string, mapErr error) {
	if outcome == nil || !outcome.IsValid() {
		msg := formatFallbackError("ssh execution failed: invalid execution outcome", runErr)
		return exitCodeSSHError, msg, fmt.Errorf("%s", msg)
	}
	switch v := outcome.(type) {
	case *execution.OutcomeCompleted:
		code, statusDiag, err := mapExitStatusToExit(v.Status())
		if runErr != nil {
			diag := joinDiagnostics(statusDiag, runErr.Error())
			if code == exitCodeOK {
				code = exitCodeSSHError
			}
			return code, diag, runErr
		}
		return code, statusDiag, err
	case *execution.OutcomeNotStarted:
		msg := formatNotStartedDiag(v, runErr)
		return exitCodeSSHError, msg, fmt.Errorf("%s", msg)
	case *execution.OutcomeUnknown:
		msg := formatUnknownOutcomeDiag(v, runErr)
		return exitCodeSSHError, msg, fmt.Errorf("%s", msg)
	default:
		msg := formatFallbackError(fmt.Sprintf("unexpected execution outcome type %T", outcome), runErr)
		return exitCodeSSHError, msg, fmt.Errorf("%s", msg)
	}
}

func mapExitStatusToExit(status execution.ExitStatus) (exitCode int, diagMsg string, mapErr error) {
	if status == nil || !status.IsValid() {
		msg := "ssh execution finished with invalid exit status"
		return exitCodeSSHError, msg, fmt.Errorf("%s", msg)
	}
	switch s := status.(type) {
	case *execution.ExitCode:
		code, ok := s.Code()
		if !ok {
			msg := "ssh execution finished with unreadable exit code"
			return exitCodeSSHError, msg, fmt.Errorf("%s", msg)
		}
		return normalizeProcessExitCode(code), "", nil
	case *execution.ExitSignal:
		return mapSignalExit(s), formatSignalDiag(s), nil
	case *execution.ExitUnknown:
		msg := formatExitUnknownDiag(s)
		return exitCodeSSHError, msg, fmt.Errorf("%s", msg)
	default:
		msg := fmt.Sprintf("unexpected exit status type %T", status)
		return exitCodeSSHError, msg, fmt.Errorf("%s", msg)
	}
}

// normalizeProcessExitCode 将远端退出码跨平台统一规整至 [0, 255]：
//   - 0 保持为 0；
//   - 超出 [1, 255] 的非零退出码统一取低 8 位（int(code) & 0xff），避免 Unix 与 Windows 退出码行为分叉；
//   - 若非零退出码的低 8 位为 0（如 256 或 -256），归约为 1，防止失败被静默截断为成功 0。
func normalizeProcessExitCode(code int32) int {
	if code == 0 {
		return exitCodeOK
	}
	if code > 0 && code <= 255 {
		return int(code)
	}
	low := int(code) & 0xff
	if low == 0 {
		return exitCodeGeneralError
	}
	return low
}

func mapSignalExit(sig *execution.ExitSignal) int {
	if num, ok := posixSignalNumber(sig.Signal()); ok {
		return exitCodeSignalBase + num
	}
	return exitCodeSSHError
}

func posixSignalNumber(raw string) (int, bool) {
	name := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(raw)), "SIG")
	switch name {
	case "HUP":
		return 1, true
	case "INT":
		return 2, true
	case "QUIT":
		return 3, true
	case "ILL":
		return 4, true
	case "TRAP":
		return 5, true
	case "ABRT", "IOT":
		return 6, true
	case "BUS":
		return 7, true
	case "FPE":
		return 8, true
	case "KILL":
		return 9, true
	case "USR1":
		return 10, true
	case "SEGV":
		return 11, true
	case "USR2":
		return 12, true
	case "PIPE":
		return 13, true
	case "ALRM":
		return 14, true
	case "TERM":
		return 15, true
	default:
		return 0, false
	}
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
