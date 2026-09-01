package playbook

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/ssh"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

const defaultConcurrency = uint(1)

// Engine 是 Playbook 的执行引擎
type Engine struct {
	pb        *Playbook
	provider  config.ConfigProvider
	listener  EventListener
	connect   func(context.Context, string) (*ssh.Client, error)
	runStepFn func(context.Context, *ssh.Client, Step, bool) StepResult
}

// NewEngine 创建一个执行引擎实例，支持通过 EngineOption 注入不可变组件。
func NewEngine(pb *Playbook, provider config.ConfigProvider, connector *ssh.Connector, opts ...EngineOption) *Engine {
	e := &Engine{
		pb:       pb,
		provider: provider,
		listener: NopEventListener,
	}
	if connector == nil {
		e.connect = func(context.Context, string) (*ssh.Client, error) {
			return nil, errors.New("playbook connector is nil")
		}
	} else {
		e.connect = connector.Connect
	}
	e.runStepFn = e.runStep
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	return e
}

func (e *Engine) getListener() EventListener {
	if e != nil && e.listener != nil {
		return e.listener
	}
	return NopEventListener
}

// Run 执行 Playbook，返回完整的执行报告。
func (e *Engine) Run(ctx context.Context) (*Report, error) {
	nodeIDs, err := e.resolveTargets()
	if err != nil {
		return nil, err
	}
	if len(nodeIDs) == 0 {
		return nil, ErrNoTargets
	}

	e.getListener().OnTargetsResolved(len(nodeIDs))

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
	if err := ctx.Err(); err != nil {
		return report, fmt.Errorf("playbook execution canceled: %w", err)
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return report, fmt.Errorf("playbook execution timed out: %w", runCtx.Err())
	}
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
			e.getListener().OnTagEmpty(tag)
			continue
		}
		for id := range nodes {
			addNode(id)
		}
	}

	// 按节点名精确匹配
	for _, name := range e.pb.Targets.Nodes {
		id, err := e.provider.ResolveSelector(name)
		if err != nil {
			return nil, fmt.Errorf("resolve playbook node target %q failed: %w", name, err)
		}
		if id == "" {
			return nil, &TargetNotFoundError{Target: name}
		}
		addNode(id)
	}

	// 按主机地址/IP 匹配（临时即席主机，不要求在配置中存在）
	for _, h := range e.pb.Targets.Hosts {
		id, err := e.provider.ResolveSelector(h)
		if err != nil {
			return nil, fmt.Errorf("resolve playbook host target %q failed: %w", h, err)
		}
		if id == "" {
			return nil, &TargetNotFoundError{Target: h}
		}
		addNode(id)
	}

	return nodeIDs, nil
}

// runOnHost 在单台主机上顺序执行所有步骤。
// cancel 用于 abort_all 策略时通知其他 goroutine。
func (e *Engine) runOnHost(ctx context.Context, nodeID string, cancel context.CancelFunc, onError OnError) HostReport {
	hr := HostReport{
		NodeID: nodeID,
	}
	start := time.Now()
	_, hostObj, _, resolveErr := e.provider.Resolve(nodeID)
	if resolveErr != nil {
		hr.Status = HostStatusFailed
		resolveStep := StepResult{
			StepName: "<resolve>",
			Status:   StatusFailed,
			Err:      fmt.Errorf("resolve playbook target %q failed: %w", nodeID, resolveErr),
		}
		hr.Steps = append(hr.Steps, resolveStep)
		hr.Duration = time.Since(start)
		e.getListener().OnStepResult(nodeID, "<resolve>", resolveStep)
		if onError == OnErrorAbortAll {
			cancel()
		}
		return hr
	}
	hostAddr := hostObj.Address
	hr.Host = hostAddr

	client, err := e.connect(ctx, nodeID)
	if err != nil {
		if ctx.Err() != nil {
			hr.Status = HostStatusAborted
		} else {
			hr.Status = HostStatusFailed
			if onError == OnErrorAbortAll {
				cancel()
			}
		}
		connectStep := StepResult{
			StepName: "<connect>",
			Status:   StatusFailed,
			Err:      err,
		}
		hr.Steps = append(hr.Steps, connectStep)
		hr.Duration = time.Since(start)
		e.getListener().OnStepResult(hostAddr, "<connect>", connectStep)
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

		e.getListener().OnStepRunning(hostAddr, step.Name)

		result := e.runStepFn(ctx, client, step, globalSudo)
		hr.Steps = append(hr.Steps, result)

		// 触发步骤结果回调
		e.getListener().OnStepResult(hostAddr, step.Name, result)

		// 处理失败
		if result.Status == StatusFailed {
			if step.IgnoreError {
				// 步骤级别显式忽略，继续且不污染主机成功状态
				continue
			}

			// 任何非 IgnoreError 的失败步骤都必须将主机标记为 HostStatusFailed
			hr.Status = HostStatusFailed

			switch onError {
			case OnErrorContinue:
				// 继续执行后续步骤
				continue
			case OnErrorAbortAll:
				cancel() // 通知所有其他 goroutine 停止
				return hr
			default: // OnErrorStop
				hr.Duration = time.Since(start)
				return hr
			}
		}
	}

	hr.Duration = time.Since(start)
	return hr
}
