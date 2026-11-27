//go:build unix

package sys

import (
	"errors"
	"strings"
	"testing"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// TestEvaluateSuspendProcessGroupFailClosed 验证 POSIX 孤儿进程组纯函数判定（INV-E1）全部放行与失败关闭边界，
// 并锁定系统调用失败分支完整保留 ErrOrphanedProcessGroup 双语语义（零哨兵吞噬）。
func TestEvaluateSuspendProcessGroupFailClosed(t *testing.T) {
	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	enLoc := cat.For(domi18n.LocaleEn)
	zhLoc := cat.For(domi18n.LocaleZh)
	errEperm := errors.New("eperm")
	errEsrch := errors.New("esrch")

	cases := []struct {
		name      string
		snap      suspendProcessSnapshot
		want      security.Verdict
		expectErr bool
		cause     error
		wantCall  string
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
			snap:      suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sidErr: errEperm},
			want:      security.VerdictDeny,
			expectErr: true,
			cause:     errEperm,
			wantCall:  "getsid(0)",
		},
		{
			name:      "parent_getsid_error_fail_closed",
			snap:      suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 100, parentSIDErr: errEperm},
			want:      security.VerdictDeny,
			expectErr: true,
			cause:     errEperm,
			wantCall:  "getsid(ppid)",
		},
		{
			name:      "parent_getpgid_error_fail_closed",
			snap:      suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 100, parentSID: 100, parentPGRPErr: errEsrch},
			want:      security.VerdictDeny,
			expectErr: true,
			cause:     errEsrch,
			wantCall:  "getpgid(ppid)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, evalErr := evaluateSuspendProcessGroup(tc.snap)
			if got != tc.want {
				t.Fatalf("evaluateSuspendProcessGroup = %v, 期望 %v", got, tc.want)
			}
			assertSuspendEvalErr(t, enLoc, zhLoc, evalErr, tc.expectErr, tc.cause, tc.wantCall)
		})
	}
}

func assertSuspendEvalErr(t *testing.T, enLoc, zhLoc *i18n.Localizer, err error, expectErr bool, cause error, wantCall string) {
	t.Helper()
	if !expectErr {
		if err != nil {
			t.Fatalf("非预期错误: %v", err)
		}
		return
	}
	if err == nil || !errors.Is(err, ErrOrphanedProcessGroup) {
		t.Fatalf("期望返回包装 ErrOrphanedProcessGroup 的错误，实际=%v", err)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("错误链缺失底层 syscall 错误: %v", err)
	}
	gotEn := enLoc.RenderError(err)
	if gotEn != err.Error() || !strings.Contains(gotEn, "orphaned process group") {
		t.Fatalf("EN 渲染必须保留孤儿进程组哨兵语义且与 err.Error() 等值: en=%q raw=%q", gotEn, err.Error())
	}
	gotZh := zhLoc.RenderError(err)
	if !strings.Contains(gotZh, "孤儿进程组") || !strings.Contains(gotZh, "禁止执行挂起") || strings.ContainsAny(gotZh, "{}") {
		t.Fatalf("ZH 渲染必须完整保留孤儿进程组与禁止挂起语义: %q", gotZh)
	}
	if wantCall != "" && (!strings.Contains(gotEn, wantCall+" failed") || !strings.Contains(gotZh, "系统调用 "+wantCall+" 失败")) {
		t.Fatalf("双语渲染缺失系统调用 %s 明细: en=%q zh=%q", wantCall, gotEn, gotZh)
	}
}
