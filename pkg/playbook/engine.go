package playbook

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/ssh"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

const defaultConcurrency = uint(1)

// Engine 是 Playbook 的执行引擎
type Engine struct {
	pb        *Playbook
	provider  config.ConfigProvider
	connector *ssh.Connector
}

// NewEngine 创建一个执行引擎实例。
func NewEngine(pb *Playbook, provider config.ConfigProvider, connector *ssh.Connector) *Engine {
	return &Engine{
		pb:        pb,
		provider:  provider,
		connector: connector,
	}
}

// Run 执行 Playbook，返回完整的执行报告。
func (e *Engine) Run(ctx context.Context) (*Report, error) {
	nodeIDs, err := e.resolveTargets()
	if err != nil {
		return nil, err
	}
	if len(nodeIDs) == 0 {
		return nil, fmt.Errorf("%s", i18n.T("play_err_no_targets"))
	}

	logger.Info(i18n.Tf("play_target_resolved", map[string]any{"Count": len(nodeIDs)}))

	report := &Report{
		PlaybookName: e.pb.Name,
		StartTime:    time.Now(),
	}

	concurrency := e.pb.Settings.Concurrency
	if concurrency == 0 {
		concurrency = defaultConcurrency
	}

	onError := e.pb.Settings.OnError
	if onError == "" {
		onError = OnErrorStop
	}

	// abort_all 模式使用可取消的 context
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if e.pb.Settings.Timeout.Duration > 0 {
		var timeoutCancel context.CancelFunc
		runCtx, timeoutCancel = context.WithTimeout(runCtx, e.pb.Settings.Timeout.Duration)
		defer timeoutCancel()
	}

	// 收集各主机结果（需保证线程安全）
	var (
		mu      sync.Mutex
		reports = make([]HostReport, 0, len(nodeIDs))
	)

	wp := pkgutils.NewWorkerPool(concurrency)
	for _, nodeID := range nodeIDs {
		id := nodeID // capture
		wp.Execute(func() {
			hr := e.runOnHost(runCtx, id, cancel, onError)
			mu.Lock()
			reports = append(reports, hr)
			mu.Unlock()
		})
	}
	wp.Wait()

	report.Hosts = reports
	report.EndTime = time.Now()
	return report, nil
}

// resolveTargets 根据 Playbook 的 Targets 配置解析出目标节点 ID 列表。
func (e *Engine) resolveTargets() ([]string, error) {
	seen := make(map[string]struct{})
	var nodeIDs []string

	addNode := func(id string) {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			nodeIDs = append(nodeIDs, id)
		}
	}

	// 按标签筛选
	for _, tag := range e.pb.Targets.Tags {
		nodes := e.provider.GetNodesByTag(tag)
		if len(nodes) == 0 {
			logger.Warn(i18n.Tf("play_warn_tag_empty", map[string]any{"Tag": tag}))
			continue
		}
		for id := range nodes {
			addNode(id)
		}
	}

	// 按节点名精确匹配
	for _, name := range e.pb.Targets.Nodes {
		id := e.provider.Find(name)
		if id == "" {
			return nil, fmt.Errorf("%s", i18n.Tf("play_err_node_not_found", map[string]any{"Node": name}))
		}
		addNode(id)
	}

	// 按主机地址/IP 匹配（临时即席主机，不要求在配置中存在）
	for _, h := range e.pb.Targets.Hosts {
		id := e.provider.Find(h)
		if id == "" {
			return nil, fmt.Errorf("%s", i18n.Tf("play_err_node_not_found", map[string]any{"Node": h}))
		}
		addNode(id)
	}

	return nodeIDs, nil
}

// runOnHost 在单台主机上顺序执行所有步骤。
// cancel 用于 abort_all 策略时通知其他 goroutine。
func (e *Engine) runOnHost(ctx context.Context, nodeID string, cancel context.CancelFunc, onError OnError) HostReport {
	hostObj, _ := e.provider.GetHost(nodeID)
	hostAddr := hostObj.Address

	hr := HostReport{
		NodeID: nodeID,
		Host:   hostAddr,
	}
	start := time.Now()

	client, err := e.connector.Connect(ctx, nodeID)
	if err != nil {
		logger.Error(i18n.Tf("play_connect_failed", map[string]any{"Host": hostAddr, "Error": err}))
		hr.Status = HostStatusFailed
		hr.Steps = append(hr.Steps, StepResult{
			StepName: "<connect>",
			Status:   StatusFailed,
			Err:      err,
		})
		hr.Duration = time.Since(start)
		return hr
	}

	globalSudo := e.pb.Settings.Sudo
	hr.Status = HostStatusSuccess

	for _, step := range e.pb.Steps {
		// 检查 context 是否已被取消（abort_all 触发）
		if ctx.Err() != nil {
			hr.Status = HostStatusAborted
			break
		}

		logger.Info(i18n.Tf("play_step_running", map[string]any{
			"Host": hostAddr,
			"Step": step.Name,
		}))

		result := e.runStep(ctx, client, step, globalSudo)
		hr.Steps = append(hr.Steps, result)

		// 打印步骤结果
		e.printStepResult(hostAddr, step.Name, result)

		// 处理失败
		if result.Status == StatusFailed {
			if step.IgnoreError {
				// 步骤级别忽略，继续
				continue
			}

			switch onError {
			case OnErrorContinue:
				// 继续下一步
			case OnErrorAbortAll:
				hr.Status = HostStatusFailed
				cancel() // 通知所有其他 goroutine 停止
				return hr
			default: // OnErrorStop
				hr.Status = HostStatusFailed
				hr.Duration = time.Since(start)
				return hr
			}
		}
	}

	hr.Duration = time.Since(start)
	return hr
}

// printStepResult 根据步骤状态打印格式化日志。
func (e *Engine) printStepResult(host, stepName string, r StepResult) {
	switch r.Status {
	case StatusOK, StatusChanged:
		logger.PrintSuccess(i18n.Tf("play_step_ok", map[string]any{
			"Host": host, "Step": stepName,
		}))
	case StatusSkipped:
		logger.Info(i18n.Tf("play_step_skipped", map[string]any{
			"Host": host, "Step": stepName,
		}))
	case StatusFailed:
		logger.PrintError(i18n.Tf("play_step_failed", map[string]any{
			"Host": host, "Step": stepName, "Error": r.Err,
		}))
	}
}
