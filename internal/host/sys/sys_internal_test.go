//go:build unix

package sys

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/security"
)

// TestEvaluateSuspendProcessGroupFailClosed 验证 POSIX 孤儿进程组纯函数判定（INV-E1）全部放行与失败关闭边界。
func TestEvaluateSuspendProcessGroupFailClosed(t *testing.T) {
	cases := []struct {
		name      string
		snap      suspendProcessSnapshot
		want      security.Verdict
		expectErr bool
	}{
		{
			name:      "non_orphaned_job_control_child",
			snap:      suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 100, parentSID: 100, parentPGRP: 100},
			want:      security.VerdictAllow,
			expectErr: false,
		},
		{
			name:      "session_leader_denied",
			snap:      suspendProcessSnapshot{pid: 100, ppid: 50, pgrp: 100, sid: 100, parentSID: 100, parentPGRP: 50},
			want:      security.VerdictDeny,
			expectErr: true,
		},
		{
			name:      "init_reparented_denied",
			snap:      suspendProcessSnapshot{pid: 200, ppid: 1, pgrp: 200, sid: 100, parentSID: 100, parentPGRP: 100},
			want:      security.VerdictDeny,
			expectErr: true,
		},
		{
			name:      "parent_different_session_denied",
			snap:      suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 150, parentSID: 100, parentPGRP: 100},
			want:      security.VerdictDeny,
			expectErr: true,
		},
		{
			name:      "parent_same_process_group_denied",
			snap:      suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 100, parentSID: 100, parentPGRP: 200},
			want:      security.VerdictDeny,
			expectErr: true,
		},
		{
			name:      "getsid_error_fail_closed",
			snap:      suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sidErr: errors.New("eperm")},
			want:      security.VerdictDeny,
			expectErr: true,
		},
		{
			name:      "parent_getpgid_error_fail_closed",
			snap:      suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 100, parentSID: 100, parentPGRPErr: errors.New("esrch")},
			want:      security.VerdictDeny,
			expectErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evaluateSuspendProcessGroup(tc.snap)
			if got != tc.want {
				t.Fatalf("evaluateSuspendProcessGroup = %v, 期望 %v", got, tc.want)
			}
			if tc.expectErr && err == nil {
				t.Fatal("期望返回错误，但得到 nil")
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("非预期错误: %v", err)
			}
		})
	}
}
