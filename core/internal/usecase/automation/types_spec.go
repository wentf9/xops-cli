// Package automation 实现 XOps v2 自动化编排用例服务（ADR-007 / ADR-008 / ADR-009 / ADR-010 / Plan P3-T4）。
//
// 核心交付范围与安全不变量：
//   - 并行批量 exec（BatchExec）：受 core/conc.Nursery（RunWait）有界并发监督（0 裸 go），支持节点与标签排除过滤、
//     单节点独立隔离 OperationStream（确定性 EOF + panic defer 终态事件）、ScopedRootFS 沙箱输出目录（--out-dir）
//     及确定性排序聚合报告；严格遵循 gate.WithAuthorized 包裹 pool.WithLease、严分 OutcomeNotStarted 与 OutcomeUnknown
//     （绝不重试并忠实上报 AuditOutcomeUnknown）并在 Gate Halted 熔断态立即拒绝执行；
//   - Playbook vNext 判别式 AST 执行器（RunPlaybook）：穷尽分派 shell / script / copy / template / ensure 五类封闭动作，
//     严格驱动纯函数 EnsureFSM 状态机与 FoldPlaybookReport 确定性折叠；两步审批绑定 100% 由显式入参确定、零门控前抽熵漂移；
//     copy / template / script 严守双模态本地 FS 隔离（MCP 路径缺席 OperatorReadFS 即 Fail-Closed，沙箱源与输出经 ScopedRootFS），
//     远端路径全程 0 path/filepath 并在非 DirectOperator 配置档下执行 Round-2 软链规范化与受保护路径复核。
package automation

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	toolAutomation               = "automation"
	defaultConcurrency           = 8
	maxConcurrency               = 64
	defaultMaxScriptBytes  int64 = 4 << 20
	maxAllowedScriptBytes  int64 = 16 << 20
	defaultMaxTemplateSize int64 = 4 << 20
	maxAllowedTemplateSize int64 = 16 << 20
	defaultMaxCopyBytes    int64 = 64 << 20
	maxAllowedCopyBytes    int64 = 64 << 20
	outputChunkMaxSize           = 32 << 10
	maxRemoteCanonicalHops       = 128
	defaultRemoteFilePerm        = 0o644
	defaultOutDirPerm            = 0o700
	defaultOutFilePerm           = 0o600
	terminalEventTimeout         = 50 * time.Millisecond
)

// 本包导出的不可变哨兵错误，供 core/engine、CLI/MCP 与测试经 errors.Is 精确区分故障类别。
var (
	ErrNilContext              = errors.New("usecase/automation: context 不能为 nil")
	ErrInvalidConfig           = errors.New("usecase/automation: 无效的 ServiceConfig 配置")
	ErrServiceNotInitialized   = errors.New("usecase/automation: Service 未初始化")
	ErrInvalidRequest          = errors.New("usecase/automation: 无效的自动化执行请求")
	ErrNoTargets               = errors.New("usecase/automation: 筛选后不存在可执行目标节点")
	ErrOperatorReadUnavailable = errors.New("usecase/automation: 未配置 OperatorReadFS，拒绝读取操作员本地源路径")
	ErrScopedFSUnavailable     = errors.New("usecase/automation: 未配置 ScopedRootFS")
	ErrInventoryUnavailable    = errors.New("usecase/automation: 未配置 InventoryService，无法按选择器解析目标节点")
	ErrTemplateRender          = errors.New("usecase/automation: 模板解析或渲染失败")
	ErrBatchFailed             = errors.New("usecase/automation: 批量命令执行存在失败节点")
	ErrPlaybookFailed          = errors.New("usecase/automation: Playbook 执行存在失败步骤")
	ErrPlaybookAborted         = errors.New("usecase/automation: Playbook 执行被策略中止")
	ErrUncertainOutcome        = errors.New("usecase/automation: 存在执行结果未知（OutcomeUnknown），严禁重试")
	ErrUncertainDurability     = errors.New("usecase/automation: 远端变更已应用但持久性不确定，严禁重试")
	ErrUnsupportedAction       = errors.New("usecase/automation: 不支持的 Playbook 步骤动作类型")
	ErrSymlinkPolicyDenied     = errors.New("usecase/automation: 符号链接策略不允许当前读取或远端展开超限")
)

// ServiceConfig 定义自动化用例服务 Service 的显式出站依赖配置；
// MCP 路径物理不注入 OperatorReadFS，使需读取操作员任意路径的 Playbook 步骤自动 Fail-Closed。
type ServiceConfig struct {
	Gate               gate.Authorizer      // 必填：能力门控授权器（ADR-008）
	Pool               *pool.Pool           // 必填：双通道纯内存 Actor 连接池（ADR-009）
	Clock              ports.Clock          // 必填：确定性时钟端口
	Entropy            ports.Entropy        // 必填：显式熵源端口
	Env                ports.EnvPort        // 可选：SendEnv 环境变量过滤端口
	ScopedFS           ports.ScopedRootFS   // 可选：沙箱本地文件系统端口（--out-dir 与沙箱源文件）
	OperatorReadFS     ports.OperatorReadFS // 可选：操作员只读本地源端口（MCP 路径留 nil）
	Inventory          *ucinv.Service       // 可选：资产与目标解析服务（按 TargetSelector 动态解析节点）
	SystemBus          *events.SystemBus    // 可选：非阻塞诊断总线
	DefaultConcurrency int                  // 可选：默认并发度（0 默认 8，上限 64）
	MaxScriptBytes     int64                // 可选：脚本文件字节上限（0 默认 4 MiB，上限 16 MiB）
	MaxTemplateBytes   int64                // 可选：模板文件字节上限（0 默认 4 MiB，上限 16 MiB）
	MaxCopyBytes       int64                // 可选：copy 文件字节上限（0 默认 64 MiB，上限 64 MiB）
}

// NodeStreamFactory 按需为动态解析的单个节点构造独立隔离的 OperationStream；
// 回调在门控授权之后、派发节点工作协程之前同步执行，流由 automation.Service 在节点结束或 panic 时确定性闭合。
type NodeStreamFactory func(nodeID inventory.NodeID, traceID security.TraceID, opID security.OperationID) (*events.OperationStream, error)

// TargetNodeSpec 是构造不可变目标节点快照 TargetNode 的显式入参规格。
type TargetNodeSpec struct {
	NodeID         inventory.NodeID
	Plan           plan.SealedConnectionPlan
	Tags           []inventory.Tag
	DefaultProfile algebraic.Option[execution.LaunchProfile]
}

// TargetNode 表示经校验的不可变目标节点执行快照（含 Merkle 连接计划、标签与可选节点默认启动配置）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type TargetNode struct {
	nodeID         inventory.NodeID
	plan           plan.SealedConnectionPlan
	tags           []inventory.Tag
	defaultProfile algebraic.Option[execution.LaunchProfile]
	valid          bool
}

// NewTargetNode 校验节点标识、Merkle 连接计划、标签与可选启动配置并构造不可变 TargetNode。
func NewTargetNode(spec TargetNodeSpec) (TargetNode, error) {
	if !spec.NodeID.IsValid() || !spec.Plan.IsValid() {
		return TargetNode{}, fmt.Errorf("%w: TargetNode 的 NodeID 与 SealedConnectionPlan 均须有效", ErrInvalidRequest)
	}
	if prof, ok := spec.DefaultProfile.Get(); ok && !prof.IsValid() {
		return TargetNode{}, fmt.Errorf("%w: TargetNode.DefaultProfile 无效", ErrInvalidRequest)
	}
	tags, err := canonicalizeTags(spec.Tags)
	if err != nil {
		return TargetNode{}, err
	}
	return TargetNode{nodeID: spec.NodeID, plan: spec.Plan, tags: tags, defaultProfile: spec.DefaultProfile, valid: true}, nil
}

// IsValid / IsZero / 只读访问器（零值恒无效并失败关闭）。
func (t TargetNode) IsValid() bool                   { return t.valid && t.nodeID.IsValid() && t.plan.IsValid() }
func (t TargetNode) IsZero() bool                    { return !t.IsValid() }
func (t TargetNode) NodeID() inventory.NodeID        { return t.nodeID }
func (t TargetNode) Plan() plan.SealedConnectionPlan { return t.plan }
func (t TargetNode) Tags() []inventory.Tag           { return slices.Clone(t.tags) }
func (t TargetNode) DefaultProfile() algebraic.Option[execution.LaunchProfile] {
	return t.defaultProfile
}

// BatchExecRequest 描述并发批量 exec 用例的强类型输入（P3-T4）。
// Targets 与 Selector 可组合使用：两者并存时先按 Selector 筛选 Targets；仅提供 Selector 时经 Inventory 解析。
type BatchExecRequest struct {
	Targets           []TargetNode
	Selector          algebraic.Option[playbook.TargetSelector]
	CLIOptions        option.OptionLayer
	ExcludeNodes      []inventory.NodeID
	ExcludeTags       []inventory.Tag
	Command           execution.CommandPlan
	Concurrency       int
	MaxOutputBytes    uint64
	OutputDir         algebraic.Option[pathalg.LocalDir]
	FailFast          bool
	Risk              algebraic.Option[security.RiskLevel]
	Approval          algebraic.Option[gate.ApprovalSubmission]
	OperationStream   *events.OperationStream
	NodeStreams       map[inventory.NodeID]*events.OperationStream
	NodeStreamFactory NodeStreamFactory
}

// BatchNodeResult 表示批量 exec 单个节点的不可变执行结果快照；零值恒无效。
//
//xops:opaque
//xops:failclosed
type BatchNodeResult struct {
	nodeID     inventory.NodeID
	outcome    execution.ExecutionOutcome
	stdout     []byte
	stderr     []byte
	truncated  bool
	duration   algebraic.Duration
	stdoutFile algebraic.Option[pathalg.LocalRootedDest]
	stderrFile algebraic.Option[pathalg.LocalRootedDest]
	errMsg     string
	err        error
	valid      bool
}

// BatchNodeResult 只读访问器与语义判定（严分 OutcomeNotStarted / OutcomeCompleted / OutcomeUnknown）。
func (r BatchNodeResult) IsValid() bool {
	return r.valid && r.nodeID.IsValid() && r.outcome != nil && r.outcome.IsValid() && !r.duration.IsNegative()
}
func (r BatchNodeResult) IsZero() bool                        { return !r.IsValid() }
func (r BatchNodeResult) NodeID() inventory.NodeID            { return r.nodeID }
func (r BatchNodeResult) Outcome() execution.ExecutionOutcome { return r.outcome }
func (r BatchNodeResult) Stdout() []byte                      { return bytes.Clone(r.stdout) }
func (r BatchNodeResult) Stderr() []byte                      { return bytes.Clone(r.stderr) }
func (r BatchNodeResult) Truncated() bool                     { return r.IsValid() && r.truncated }
func (r BatchNodeResult) Duration() algebraic.Duration        { return r.duration }
func (r BatchNodeResult) StdoutFile() algebraic.Option[pathalg.LocalRootedDest] {
	return r.stdoutFile
}
func (r BatchNodeResult) StderrFile() algebraic.Option[pathalg.LocalRootedDest] {
	return r.stderrFile
}
func (r BatchNodeResult) Err() error           { return r.err }
func (r BatchNodeResult) ErrorMessage() string { return r.errMsg }
func (r BatchNodeResult) IsOutcomeUnknown() bool {
	return r.IsValid() && r.outcome.Kind() == execution.OutcomeKindUnknown
}
func (r BatchNodeResult) IsNotStarted() bool {
	return r.IsValid() && r.outcome.Kind() == execution.OutcomeKindNotStarted
}
func (r BatchNodeResult) Succeeded() bool {
	if !r.IsValid() || r.err != nil {
		return false
	}
	c, ok := r.outcome.(*execution.OutcomeCompleted)
	return ok && c.Succeeded()
}

type batchNodeResultWire struct {
	NodeID       inventory.NodeID                          `json:"node_id"`
	OutcomeKind  execution.OutcomeKind                     `json:"outcome_kind"`
	Succeeded    bool                                      `json:"succeeded"`
	Truncated    bool                                      `json:"truncated,omitzero"`
	Duration     algebraic.Duration                        `json:"duration"`
	StdoutBytes  int                                       `json:"stdout_bytes"`
	StderrBytes  int                                       `json:"stderr_bytes"`
	StdoutFile   algebraic.Option[pathalg.LocalRootedDest] `json:"stdout_file,omitzero"`
	StderrFile   algebraic.Option[pathalg.LocalRootedDest] `json:"stderr_file,omitzero"`
	ErrorMessage string                                    `json:"error_message,omitzero"`
}

// MarshalJSONTo 实现 BatchNodeResult 的 Go 1.27 encoding/json/v2 确定性编码（零裸 time.Duration）；零值失败关闭。
func (r BatchNodeResult) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !r.IsValid() {
		return ErrInvalidRequest
	}
	return jsonv2.MarshalEncode(enc, batchNodeResultWire{
		NodeID: r.nodeID, OutcomeKind: r.outcome.Kind(), Succeeded: r.Succeeded(),
		Truncated: r.truncated, Duration: r.duration, StdoutBytes: len(r.stdout), StderrBytes: len(r.stderr),
		StdoutFile: r.stdoutFile, StderrFile: r.stderrFile, ErrorMessage: r.errMsg,
	})
}

// BatchExecReport 表示跨节点批量 exec 按 NodeID 确定性排序折叠的不可变汇总报告；零值恒无效。
//
//xops:opaque
//xops:failclosed
type BatchExecReport struct {
	results                                                    []BatchNodeResult
	succeededCount, failedCount, unknownCount, notStartedCount int
	hasUnknownOutcome, valid                                   bool
	duration                                                   algebraic.Duration
}

// BatchExecReport 只读访问器与确定性 JSON 编码。
func (r BatchExecReport) IsValid() bool {
	return r.valid && len(r.results) > 0 && !r.duration.IsNegative()
}
func (r BatchExecReport) IsZero() bool { return !r.IsValid() }
func (r BatchExecReport) Results() []BatchNodeResult {
	if !r.IsValid() {
		return nil
	}
	out := make([]BatchNodeResult, len(r.results))
	for i, item := range r.results {
		item.stdout, item.stderr = bytes.Clone(item.stdout), bytes.Clone(item.stderr)
		out[i] = item
	}
	return out
}
func (r BatchExecReport) SucceededCount() int          { return r.succeededCount }
func (r BatchExecReport) FailedCount() int             { return r.failedCount }
func (r BatchExecReport) UnknownCount() int            { return r.unknownCount }
func (r BatchExecReport) NotStartedCount() int         { return r.notStartedCount }
func (r BatchExecReport) HasUnknownOutcome() bool      { return r.IsValid() && r.hasUnknownOutcome }
func (r BatchExecReport) Duration() algebraic.Duration { return r.duration }

type batchExecReportWire struct {
	Results           []BatchNodeResult  `json:"results"`
	SucceededCount    int                `json:"succeeded_count"`
	FailedCount       int                `json:"failed_count"`
	UnknownCount      int                `json:"unknown_count"`
	NotStartedCount   int                `json:"not_started_count"`
	HasUnknownOutcome bool               `json:"has_unknown_outcome"`
	Duration          algebraic.Duration `json:"duration"`
}

// MarshalJSONTo 实现 BatchExecReport 的 Go 1.27 encoding/json/v2 确定性编码；零值失败关闭。
func (r BatchExecReport) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !r.IsValid() {
		return ErrInvalidRequest
	}
	return jsonv2.MarshalEncode(enc, batchExecReportWire{
		Results: r.results, SucceededCount: r.succeededCount, FailedCount: r.failedCount,
		UnknownCount: r.unknownCount, NotStartedCount: r.notStartedCount,
		HasUnknownOutcome: r.hasUnknownOutcome, Duration: r.duration,
	})
}

// CanonicalJSON 使用 Go 1.27 encoding/json/v2 Deterministic(true) 序列化规范报告。
func (r BatchExecReport) CanonicalJSON() ([]byte, error) {
	if !r.IsValid() {
		return nil, ErrInvalidRequest
	}
	return jsonv2.Marshal(r, jsonv2.Deterministic(true))
}

// PlaybookRequest 描述 Playbook vNext 判别式 AST 执行用例的强类型输入（P3-T4）。
type PlaybookRequest struct {
	Playbook          playbook.Playbook
	Targets           []TargetNode
	CLIOptions        option.OptionLayer
	DefaultProfile    algebraic.Option[execution.LaunchProfile]
	ScopedSourceRoot  algebraic.Option[pathalg.LocalDir]
	Concurrency       int
	Timeout           algebraic.Option[algebraic.Duration]
	ExtraVars         map[string]string
	Risk              algebraic.Option[security.RiskLevel]
	Approval          algebraic.Option[gate.ApprovalSubmission]
	OperationStream   *events.OperationStream
	NodeStreams       map[inventory.NodeID]*events.OperationStream
	NodeStreamFactory NodeStreamFactory
}

// PlaybookRunResult 封装 Playbook 执行的不可变折叠报表与元状态；零值恒无效。
//
//xops:opaque
//xops:failclosed
type PlaybookRunResult struct {
	report            playbook.PlaybookReport
	aborted           bool
	hasUnknownOutcome bool
	duration          algebraic.Duration
	valid             bool
}

// PlaybookRunResult 只读访问器（零值恒无效并失败关闭）。
func (r PlaybookRunResult) IsValid() bool {
	return r.valid && r.report.IsValid() && !r.duration.IsNegative()
}
func (r PlaybookRunResult) IsZero() bool                    { return !r.IsValid() }
func (r PlaybookRunResult) Report() playbook.PlaybookReport { return r.report }
func (r PlaybookRunResult) Aborted() bool                   { return r.IsValid() && r.aborted }
func (r PlaybookRunResult) HasUnknownOutcome() bool         { return r.IsValid() && r.hasUnknownOutcome }
func (r PlaybookRunResult) Duration() algebraic.Duration    { return r.duration }

type playbookRunResultWire struct {
	Report            playbook.PlaybookReport `json:"report"`
	Aborted           bool                    `json:"aborted"`
	HasUnknownOutcome bool                    `json:"has_unknown_outcome"`
	Duration          algebraic.Duration      `json:"duration"`
}

// MarshalJSONTo 实现 PlaybookRunResult 的 Go 1.27 encoding/json/v2 确定性编码；零值失败关闭。
func (r PlaybookRunResult) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !r.IsValid() {
		return ErrInvalidRequest
	}
	return jsonv2.MarshalEncode(enc, playbookRunResultWire{
		Report:            r.report,
		Aborted:           r.aborted,
		HasUnknownOutcome: r.hasUnknownOutcome,
		Duration:          r.duration,
	})
}
