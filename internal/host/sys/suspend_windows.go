//go:build windows

package sys

import "github.com/wentf9/xops-cli/core/domain/security"

// checkSuspendProcessGroupOS 在 Windows 上严格失败关闭返回 VerdictDeny（Windows 无 POSIX SIGTSTP 作业挂起语义）。
func checkSuspendProcessGroupOS() (security.Verdict, error) {
	return security.VerdictDeny, nil
}
