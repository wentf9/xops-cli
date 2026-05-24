package playbook

import (
	"fmt"
	"strings"
	"time"
)

// StepStatus 表示单个步骤的执行状态
type StepStatus string

const (
	// StatusOK 步骤成功且无变更（ensure: check 通过直接返回）
	StatusOK StepStatus = "ok"
	// StatusChanged 步骤成功并产生了实际变更
	StatusChanged StepStatus = "changed"
	// StatusSkipped ensure 步骤中 check 通过，跳过 action
	StatusSkipped StepStatus = "skipped"
	// StatusFailed 步骤执行失败
	StatusFailed StepStatus = "failed"
)

// HostStatus 表示单台主机的整体执行状态
type HostStatus string

const (
	HostStatusSuccess HostStatus = "success"
	HostStatusFailed  HostStatus = "failed"
	HostStatusAborted HostStatus = "aborted"
)

// StepResult 表示单个步骤在单台主机上的执行结果
type StepResult struct {
	StepName string
	Status   StepStatus
	Output   string
	Err      error
	Duration time.Duration
}

// HostReport 是单台主机的完整执行报告
type HostReport struct {
	NodeID   string
	Host     string
	Steps    []StepResult
	Status   HostStatus
	Duration time.Duration
}

// Summary 返回该主机各状态的计数摘要
func (h *HostReport) Summary() (ok, changed, skipped, failed int) {
	for _, s := range h.Steps {
		switch s.Status {
		case StatusOK:
			ok++
		case StatusChanged:
			changed++
		case StatusSkipped:
			skipped++
		case StatusFailed:
			failed++
		}
	}
	return
}

// Report 是整个 Playbook 执行的汇总报告
type Report struct {
	PlaybookName string
	StartTime    time.Time
	EndTime      time.Time
	Hosts        []HostReport
}

// Duration 返回整个 Playbook 的执行耗时
func (r *Report) Duration() time.Duration {
	return r.EndTime.Sub(r.StartTime)
}

// Print 将格式化的执行报告输出到 stdout。
func (r *Report) Print() {
	separator := strings.Repeat("═", 60)
	fmt.Println()
	fmt.Println(separator)
	fmt.Printf("PLAYBOOK RECAP — %s\n", r.PlaybookName)
	fmt.Println(separator)
	fmt.Println()

	var successCount, failedCount int
	for _, h := range r.Hosts {
		ok, changed, skipped, failed := h.Summary()
		statusIcon := "✅"
		if h.Status != HostStatusSuccess {
			statusIcon = "❌"
			failedCount++
		} else {
			successCount++
		}
		fmt.Printf("  %-30s ok=%-3d changed=%-3d skipped=%-3d failed=%-3d %s\n",
			h.Host, ok, changed, skipped, failed, statusIcon)
	}

	fmt.Println()
	total := len(r.Hosts)
	fmt.Printf("Duration: %-10s | Hosts: %-4d | Success: %-4d | Failed: %d\n",
		r.Duration().Round(time.Millisecond),
		total, successCount, failedCount,
	)
	fmt.Println(separator)
}
