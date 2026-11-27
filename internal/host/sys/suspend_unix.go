//go:build unix

package sys

import (
	"os"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/internal/i18n"
	"golang.org/x/sys/unix"
)

type suspendProcessSnapshot struct {
	pid           int
	ppid          int
	pgrp          int
	sid           int
	sidErr        error
	parentSID     int
	parentSIDErr  error
	parentPGRP    int
	parentPGRPErr error
}

// checkSuspendProcessGroupOS 采集当前进程及其父进程的 POSIX 会话与进程组快照并执行完整孤儿进程组判定（INV-E1）。
func checkSuspendProcessGroupOS() (security.Verdict, error) {
	pid := os.Getpid()
	ppid := os.Getppid()
	pgrp := unix.Getpgrp()
	sid, sidErr := unix.Getsid(0)
	var (
		parentSID     int
		parentSIDErr  error
		parentPGRP    int
		parentPGRPErr error
	)
	if ppid > 1 {
		parentSID, parentSIDErr = unix.Getsid(ppid)
		parentPGRP, parentPGRPErr = unix.Getpgid(ppid)
	}
	return evaluateSuspendProcessGroup(suspendProcessSnapshot{
		pid:           pid,
		ppid:          ppid,
		pgrp:          pgrp,
		sid:           sid,
		sidErr:        sidErr,
		parentSID:     parentSID,
		parentSIDErr:  parentSIDErr,
		parentPGRP:    parentPGRP,
		parentPGRPErr: parentPGRPErr,
	})
}

// evaluateSuspendProcessGroup 实现纯函数 POSIX 孤儿进程组判定：
// 进程组非孤儿当且仅当当前进程非会话首进程、非会话首进程所在组、存在有效父进程，
// 且父进程与当前进程同属一个会话但位于不同进程组；任何错误或条件不满足一律失败关闭返回 VerdictDeny。
func evaluateSuspendProcessGroup(s suspendProcessSnapshot) (security.Verdict, error) {
	if s.pid <= 0 || s.ppid <= 1 || s.pgrp <= 0 {
		return security.VerdictDeny, ErrOrphanedProcessGroup
	}
	if s.sidErr != nil {
		return security.VerdictDeny, domi18n.WrapSentinel(ErrOrphanedProcessGroup, i18n.Wrap(s.sidErr, i18n.KeyHostSysSyscallFailed, i18n.Str("call", "getsid(0)")))
	}
	if s.sid <= 0 || s.pid == s.sid || s.pgrp == s.sid {
		return security.VerdictDeny, ErrOrphanedProcessGroup
	}
	if s.parentSIDErr != nil {
		return security.VerdictDeny, domi18n.WrapSentinel(ErrOrphanedProcessGroup, i18n.Wrap(s.parentSIDErr, i18n.KeyHostSysSyscallFailed, i18n.Str("call", "getsid(ppid)")))
	}
	if s.parentSID <= 0 || s.parentSID != s.sid {
		return security.VerdictDeny, ErrOrphanedProcessGroup
	}
	if s.parentPGRPErr != nil {
		return security.VerdictDeny, domi18n.WrapSentinel(ErrOrphanedProcessGroup, i18n.Wrap(s.parentPGRPErr, i18n.KeyHostSysSyscallFailed, i18n.Str("call", "getpgid(ppid)")))
	}
	if s.parentPGRP <= 0 || s.parentPGRP == s.pgrp {
		return security.VerdictDeny, ErrOrphanedProcessGroup
	}
	return security.VerdictAllow, nil
}
