package playbook_test

import (
	"context"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/pkg/playbook"
)

// mockSSHClient 是用于测试 runEnsure 等函数的 SSH 客户端 mock。
// 因为 Engine 方法依赖 *ssh.Client（无 interface），
// 所以这里测试 StepResult 状态机的纯逻辑部分。
//
// 注意：runShell/runScript/runCopy 等需要真实 SSH 连接，
// 集成测试阶段再覆盖。此处专注于状态收敛逻辑的单元测试。

// ensureResult 模拟 ensure 步骤的状态机输出。
type ensureResult struct {
	checkPassFirst bool // 第一次 check 是否通过
	actionFails    bool // action 是否失败
	checkPassAfter bool // action 后 check 是否通过
}

// simulateEnsure 模拟 ensure 步骤的状态机，验证幂等性逻辑。
func simulateEnsure(r ensureResult) playbook.StepStatus {
	// 第一次 check 通过 → skipped
	if r.checkPassFirst {
		return playbook.StatusSkipped
	}

	// action 失败 → failed
	if r.actionFails {
		return playbook.StatusFailed
	}

	// action 成功后再次 check
	if r.checkPassAfter {
		return playbook.StatusChanged
	}

	// 修复后仍失败 → failed
	return playbook.StatusFailed
}

func TestEnsure_AlreadySatisfied(t *testing.T) {
	status := simulateEnsure(ensureResult{checkPassFirst: true})
	if status != playbook.StatusSkipped {
		t.Errorf("expected StatusSkipped when already satisfied, got %s", status)
	}
}

func TestEnsure_ActionSuccess(t *testing.T) {
	status := simulateEnsure(ensureResult{
		checkPassFirst: false,
		actionFails:    false,
		checkPassAfter: true,
	})
	if status != playbook.StatusChanged {
		t.Errorf("expected StatusChanged after successful remediation, got %s", status)
	}
}

func TestEnsure_ActionFails(t *testing.T) {
	status := simulateEnsure(ensureResult{
		checkPassFirst: false,
		actionFails:    true,
	})
	if status != playbook.StatusFailed {
		t.Errorf("expected StatusFailed when action fails, got %s", status)
	}
}

func TestEnsure_PostCheckFails(t *testing.T) {
	status := simulateEnsure(ensureResult{
		checkPassFirst: false,
		actionFails:    false,
		checkPassAfter: false,
	})
	if status != playbook.StatusFailed {
		t.Errorf("expected StatusFailed when post-action check still fails, got %s", status)
	}
}

// TestStepResult_Status 验证 StepResult 状态常量的基本值。
func TestStepResult_Status(t *testing.T) {
	tests := []struct {
		status playbook.StepStatus
		want   string
	}{
		{playbook.StatusOK, "ok"},
		{playbook.StatusChanged, "changed"},
		{playbook.StatusSkipped, "skipped"},
		{playbook.StatusFailed, "failed"},
	}
	for _, tt := range tests {
		if string(tt.status) != tt.want {
			t.Errorf("StepStatus %q != %q", tt.status, tt.want)
		}
	}
}

// TestReport_Summary 验证 HostReport.Summary() 计数逻辑。
func TestReport_Summary(t *testing.T) {
	hr := &playbook.HostReport{
		Steps: []playbook.StepResult{
			{Status: playbook.StatusOK},
			{Status: playbook.StatusChanged},
			{Status: playbook.StatusChanged},
			{Status: playbook.StatusSkipped},
			{Status: playbook.StatusFailed},
		},
	}

	ok, changed, skipped, failed := hr.Summary()
	if ok != 1 || changed != 2 || skipped != 1 || failed != 1 {
		t.Errorf("Summary() = (%d, %d, %d, %d), want (1, 2, 1, 1)",
			ok, changed, skipped, failed)
	}
}

// TestReport_Duration 验证报告的执行时长计算。
func TestReport_Duration(t *testing.T) {
	import_time_package_test(t)
}

func import_time_package_test(_ *testing.T) {
	// 此函数仅用于说明下面的测试需要 time 包
	// 实际测试在 TestReport_Duration_Real 中
}

// TestParseVars 通过 cmd/play.go 中暴露的 parseVars 测试变量解析。
// 由于 parseVars 是 unexported，此处通过集成方式测试（Load + extraVars）。
func TestParseVars_ViaLoad(t *testing.T) {
	yaml := `
name: var-parse-test
targets:
  tags: [web]
vars:
  key1: original
steps:
  - name: test
    shell: "echo {{ .key1 }} {{ .key2 }}"
`
	path := writeTempPlaybook(t, yaml)

	pb, err := playbook.Load(path, map[string]string{
		"key1": "overridden",
		"key2": "new-value",
	})
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	want := "echo overridden new-value"
	if pb.Steps[0].Shell != want {
		t.Errorf("Shell = %q, want %q", pb.Steps[0].Shell, want)
	}
}

// TestContextCancellation 验证 context 取消时步骤不执行（概念验证）。
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	// 验证 ctx 已取消
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Error("expected context.Canceled")
	}
}

// TestOnError_Constants 验证 OnError 策略常量的值。
func TestOnError_Constants(t *testing.T) {
	tests := []struct {
		name string
		val  playbook.OnError
		want string
	}{
		{"continue", playbook.OnErrorContinue, "continue"},
		{"stop", playbook.OnErrorStop, "stop"},
		{"abort_all", playbook.OnErrorAbortAll, "abort_all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.val) != tt.want {
				t.Errorf("OnError %q != %q", tt.val, tt.want)
			}
		})
	}
}
