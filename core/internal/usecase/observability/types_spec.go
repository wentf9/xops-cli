// Package observability 实现 XOps v2 实时可观测性投影、远端指标/日志流与 POSIX 强校验 GUI 自动化/会话用例服务
// （ADR-007 / ADR-008 / ADR-009 / ADR-010 / Plan P3-T4）。
//
// 核心交付范围与安全不变量：
//   - TUI 指标 / 日志流聚合投影（Projection）：受 core/conc.Nursery 监督消费 events.SystemBus 与多条隔离
//     OperationStream（0 裸 go、0 time.Sleep），穷尽覆盖全部 12 类封闭 Event 变体，提供有界无锁竞态快照、
//     单调锁存 GateHalted/OutcomeUnknown 标志、DropAndCount 丢弃计数与事件驱动 WaitUpdate；
//   - 远端指标与日志流（StreamMetrics / StreamLogs）：强制 POSIX Bourne 启动方言（INV-E4），日志文件路径在非
//     DirectOperator 配置档下经 Round-2 规范化防软链逃逸，Docker 容器名严格白名单正则防注入；
//   - POSIX 强校验 GUI 自动化与受管隧道会话（ExecuteGUI / OpenGUISession / InspectGUISession / CloseGUISession）：
//     严格校验 X11/Wayland Display、键位和弦、归一化坐标与端口范围；纯 Go 零 CGO 截图防解压炸弹与等比压缩；
//     全程 0 OperatorReadFS 依赖（仅经可选 ScopedRootFS 落盘产物），供 P3-T5 MCP gui 工具直接安全复用。
package observability

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	toolObservability        = "observability"
	maxProjectionBufferCap   = 16384
	defaultLogTailLines      = 100
	maxLogTailLines          = 10000
	defaultLogMaxBytes       = 4 << 20
	maxAllowedLogBytes       = 32 << 20
	defaultMetricsInterval   = 2 * time.Second
	minMetricsInterval       = 200 * time.Millisecond
	maxMetricsInterval       = 60 * time.Second
	defaultMetricsTopProcs   = 10
	maxMetricsTopProcs       = 50
	maxMetricsSamples        = 10000
	maxMetricsLineBytes      = 256 << 10
	maxUptimeSeconds         = 100 * 365 * 24 * 3600
	maxGUIScriptCaptureBytes = 48 << 20
	maxGUITypeTextBytes      = 4096
	maxGUIClicks             = 100
	maxGUIDisplayNum         = 99
	maxRemoteCanonicalHops   = 128
	outputChunkMaxSize       = 32 << 10
	terminalEventTimeout     = 50 * time.Millisecond
	screenshotStartMarker    = "XOPS_GUI_SHOT_BEGIN_V2"
	screenshotEndMarker      = "XOPS_GUI_SHOT_END_V2"
	maxScreenshotRawBytes    = 32 << 20
	maxScreenshotDim         = 16384
	maxScreenshotPixels      = 64_000_000
	screenshotTargetMaxEdge  = 1280
	screenshotJPEGQuality    = 75
)

// 本包导出的不可变哨兵错误，供 core/engine、entry/tui、mcpruntime 与测试经 errors.Is 精确区分故障类别。
var (
	ErrNilContext            = errors.New("usecase/observability: context 不能为 nil")
	ErrInvalidConfig         = errors.New("usecase/observability: 无效的 ServiceConfig 或 ProjectionConfig 配置")
	ErrServiceNotInitialized = errors.New("usecase/observability: Service 未初始化")
	ErrInvalidRequest        = errors.New("usecase/observability: 无效的可观测性或 GUI 请求")
	ErrPOSIXShellRequired    = errors.New("usecase/observability: 目标节点必须使用 POSIX Bourne 兼容 Shell（sh/bash/zsh）")
	ErrInvalidLogTarget      = errors.New("usecase/observability: 无效的远端日志目标或非法容器名称")
	ErrInvalidGUIInput       = errors.New("usecase/observability: 无效或包含注入风险的 GUI 输入参数")
	ErrScreenshotInvalid     = errors.New("usecase/observability: 远端截图载荷缺失、格式不受支持或触发解压炸弹防护")
	ErrScopedFSUnavailable   = errors.New("usecase/observability: 未配置 ScopedRootFS，无法落盘沙箱产物")
	ErrForwarderUnavailable  = errors.New("usecase/observability: 未配置 ForwarderPort，无法建立受管 GUI 隧道会话")
	ErrProjectionClosed      = errors.New("usecase/observability: Projection 未初始化或已关闭")
	ErrUncertainOutcome      = errors.New("usecase/observability: 远端操作结果未知（OutcomeUnknown），严禁重试")
	ErrSymlinkPolicyDenied   = errors.New("usecase/observability: 远端软链展开超限或被策略拒绝")
	errLogLimitReached       = errors.New("usecase/observability: 远端跟随日志已达到 max_bytes 字节上限")
)

// ServiceConfig 定义可观测性与 GUI 用例服务 Service 的显式出站依赖配置；
// 物理不接受 OperatorReadFS，确保 MCP 运行时（P3-T5）复用本服务时 100% 满足沙箱边界隔离。
type ServiceConfig struct {
	Gate       gate.Authorizer      // 必填：能力门控授权器（ADR-008）
	Pool       *pool.Pool           // 必填：双通道纯内存 Actor 连接池（ADR-009）
	Clock      ports.Clock          // 必填：确定性时钟端口
	Entropy    ports.Entropy        // 必填：显式熵源端口
	Env        ports.EnvPort        // 可选：SendEnv 环境变量过滤端口
	ScopedFS   ports.ScopedRootFS   // 可选：沙箱本地文件系统（仅用于 GUI 截图产物原子落盘）
	Forwarder  ports.ForwarderPort  // 可选：SSH 端口/Unix 隧道转发端口（GUI X11/VNC 会话）
	ShellProbe ports.ShellProbePort // 可选：两阶段远端 Shell 方言探测端口
	SystemBus  *events.SystemBus    // 可选：非阻塞诊断总线
}

func appendEnumText(b []byte, valid bool, s string, err error) ([]byte, error) {
	if !valid {
		return nil, err
	}
	return append(b, s...), nil
}
func unmarshalEnum[T any](dst *T, zero T, text []byte, parse func(string) (T, error)) error {
	if dst == nil {
		return ports.ErrNilReceiver
	}
	v, err := parse(string(text))
	*dst = pickIf(err == nil, v, zero)
	return err
}
func parseEnumTable[T ~uint8](raw string, names []string, baseErr error) (T, error) {
	if idx := slices.Index(names[1:], raw); idx >= 0 {
		return T(idx + 1), nil
	}
	return 0, fmt.Errorf("%w: 非法枚举值 %q", baseErr, raw)
}
func enumTableName(idx uint8, names []string) string {
	return pickIf(int(idx) > 0 && int(idx) < len(names), names[idx], "invalid")
}

// 5 个失败关闭领域枚举类型（零值恒 *Invalid）。
type (
	//xops:opaque
	//xops:failclosed
	LogTargetKind uint8
	//xops:opaque
	//xops:failclosed
	ProcessSortBy uint8
	//xops:opaque
	//xops:failclosed
	GUIActionKind uint8
	//xops:opaque
	//xops:failclosed
	ScrollDirection uint8
	//xops:opaque
	//xops:failclosed
	GUISessionKind uint8
)

const (
	LogTargetInvalid LogTargetKind = iota
	LogTargetFile
	LogTargetDocker
	ProcessSortInvalid     ProcessSortBy   = 0
	ProcessSortCPU         ProcessSortBy   = 1
	ProcessSortMem         ProcessSortBy   = 2
	GUIActionInvalid       GUIActionKind   = 0
	GUIActionScreenshot    GUIActionKind   = 1
	GUIActionClick         GUIActionKind   = 2
	GUIActionDoubleClick   GUIActionKind   = 3
	GUIActionRightClick    GUIActionKind   = 4
	GUIActionMove          GUIActionKind   = 5
	GUIActionDrag          GUIActionKind   = 6
	GUIActionScroll        GUIActionKind   = 7
	GUIActionType          GUIActionKind   = 8
	GUIActionKey           GUIActionKind   = 9
	ScrollDirectionInvalid ScrollDirection = 0
	ScrollUp               ScrollDirection = 1
	ScrollDown             ScrollDirection = 2
	ScrollLeft             ScrollDirection = 3
	ScrollRight            ScrollDirection = 4
	GUISessionInvalid      GUISessionKind  = 0
	GUISessionX11          GUISessionKind  = 1
	GUISessionVNC          GUISessionKind  = 2
)

func logTargetNames() []string   { return []string{"invalid", "file", "docker"} }
func processSortNames() []string { return []string{"invalid", "cpu", "mem"} }
func guiActionNames() []string {
	return []string{"invalid", "screenshot", "click", "double_click", "right_click", "move", "drag", "scroll", "type", "key"}
}
func scrollDirNames() []string  { return []string{"invalid", "up", "down", "left", "right"} }
func guiSessionNames() []string { return []string{"invalid", "x11", "vnc"} }

// ParseLogTargetKind / ParseProcessSortBy / ParseGUIActionKind / ParseScrollDirection / ParseGUISessionKind。
func ParseLogTargetKind(raw string) (LogTargetKind, error) {
	return parseEnumTable[LogTargetKind](raw, logTargetNames(), ErrInvalidLogTarget)
}
func ParseProcessSortBy(raw string) (ProcessSortBy, error) {
	return parseEnumTable[ProcessSortBy](raw, processSortNames(), ErrInvalidRequest)
}
func ParseGUIActionKind(raw string) (GUIActionKind, error) {
	return parseEnumTable[GUIActionKind](raw, guiActionNames(), ErrInvalidGUIInput)
}
func ParseScrollDirection(raw string) (ScrollDirection, error) {
	return parseEnumTable[ScrollDirection](raw, scrollDirNames(), ErrInvalidGUIInput)
}
func ParseGUISessionKind(raw string) (GUISessionKind, error) {
	return parseEnumTable[GUISessionKind](raw, guiSessionNames(), ErrInvalidGUIInput)
}
func (k LogTargetKind) IsValid() bool  { return k == LogTargetFile || k == LogTargetDocker }
func (k LogTargetKind) IsZero() bool   { return !k.IsValid() }
func (k LogTargetKind) String() string { return enumTableName(uint8(k), logTargetNames()) }
func (k LogTargetKind) AppendText(b []byte) ([]byte, error) {
	return appendEnumText(b, k.IsValid(), k.String(), ErrInvalidLogTarget)
}
func (k LogTargetKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *LogTargetKind) UnmarshalText(t []byte) error {
	return unmarshalEnum(k, 0, t, ParseLogTargetKind)
}
func (s ProcessSortBy) IsValid() bool  { return s == ProcessSortCPU || s == ProcessSortMem }
func (s ProcessSortBy) IsZero() bool   { return !s.IsValid() }
func (s ProcessSortBy) String() string { return enumTableName(uint8(s), processSortNames()) }
func (s ProcessSortBy) AppendText(b []byte) ([]byte, error) {
	return appendEnumText(b, s.IsValid(), s.String(), ErrInvalidRequest)
}
func (s ProcessSortBy) MarshalText() ([]byte, error) { return s.AppendText(nil) }
func (s *ProcessSortBy) UnmarshalText(t []byte) error {
	return unmarshalEnum(s, 0, t, ParseProcessSortBy)
}
func (k GUIActionKind) IsValid() bool  { return k >= GUIActionScreenshot && k <= GUIActionKey }
func (k GUIActionKind) IsZero() bool   { return !k.IsValid() }
func (k GUIActionKind) String() string { return enumTableName(uint8(k), guiActionNames()) }
func (k GUIActionKind) AppendText(b []byte) ([]byte, error) {
	return appendEnumText(b, k.IsValid(), k.String(), ErrInvalidGUIInput)
}
func (k GUIActionKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *GUIActionKind) UnmarshalText(t []byte) error {
	return unmarshalEnum(k, 0, t, ParseGUIActionKind)
}
func (d ScrollDirection) IsValid() bool  { return d >= ScrollUp && d <= ScrollRight }
func (d ScrollDirection) IsZero() bool   { return !d.IsValid() }
func (d ScrollDirection) String() string { return enumTableName(uint8(d), scrollDirNames()) }
func (d ScrollDirection) AppendText(b []byte) ([]byte, error) {
	return appendEnumText(b, d.IsValid(), d.String(), ErrInvalidGUIInput)
}
func (d ScrollDirection) MarshalText() ([]byte, error) { return d.AppendText(nil) }
func (d *ScrollDirection) UnmarshalText(t []byte) error {
	return unmarshalEnum(d, 0, t, ParseScrollDirection)
}
func (k GUISessionKind) IsValid() bool  { return k == GUISessionX11 || k == GUISessionVNC }
func (k GUISessionKind) IsZero() bool   { return !k.IsValid() }
func (k GUISessionKind) String() string { return enumTableName(uint8(k), guiSessionNames()) }
func (k GUISessionKind) AppendText(b []byte) ([]byte, error) {
	return appendEnumText(b, k.IsValid(), k.String(), ErrInvalidGUIInput)
}
func (k GUISessionKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *GUISessionKind) UnmarshalText(t []byte) error {
	return unmarshalEnum(k, 0, t, ParseGUISessionKind)
}

// LogTarget 表示经校验的远端日志采集目标（常规文件路径或安全白名单 Docker 容器名）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type LogTarget struct {
	kind      LogTargetKind
	filePath  pathalg.RemotePath
	container string
	valid     bool
}

// NewFileLogTarget 与 NewDockerLogTarget 构造校验后的远端日志目标。
func NewFileLogTarget(p pathalg.RemotePath) (LogTarget, error) {
	if !p.IsValid() || !p.IsAbs() {
		return LogTarget{}, fmt.Errorf("%w: 远端日志文件路径必须为有效绝对路径", ErrInvalidLogTarget)
	}
	return LogTarget{kind: LogTargetFile, filePath: p, valid: true}, nil
}
func NewDockerLogTarget(container string) (LogTarget, error) {
	if !isValidDockerContainerName(container) {
		return LogTarget{}, fmt.Errorf("%w: 非法 Docker 容器名称 %q", ErrInvalidLogTarget, container)
	}
	return LogTarget{kind: LogTargetDocker, container: container, valid: true}, nil
}
func (t LogTarget) IsValid() bool {
	return t.valid && t.kind.IsValid() && pickIf(t.kind == LogTargetFile, t.filePath.IsValid() && t.filePath.IsAbs(), isValidDockerContainerName(t.container))
}
func (t LogTarget) IsZero() bool                 { return !t.IsValid() }
func (t LogTarget) Kind() LogTargetKind          { return pickIf(t.IsValid(), t.kind, LogTargetInvalid) }
func (t LogTarget) FilePath() pathalg.RemotePath { return t.filePath }
func (t LogTarget) Container() string            { return t.container }

// LogStreamRequest 与 LogStreamResult 描述远端日志采集输入与不可变结果快照。
type LogStreamRequest struct {
	Plan            plan.SealedConnectionPlan
	NodeID          string
	Profile         algebraic.Option[execution.LaunchProfile]
	Target          LogTarget
	TailLines       int
	Follow          bool
	MaxBytes        uint64
	Timeout         algebraic.Option[algebraic.Duration]
	Output          io.Writer
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

//xops:opaque
//xops:failclosed
type LogStreamResult struct {
	outcome          execution.ExecutionOutcome
	data             []byte
	duration         algebraic.Duration
	truncated, valid bool
}

func (r LogStreamResult) IsValid() bool {
	return r.valid && r.outcome != nil && r.outcome.IsValid() && !r.duration.IsNegative()
}
func (r LogStreamResult) IsZero() bool                        { return !r.IsValid() }
func (r LogStreamResult) Outcome() execution.ExecutionOutcome { return r.outcome }
func (r LogStreamResult) Data() []byte                        { return bytes.Clone(r.data) }
func (r LogStreamResult) Truncated() bool                     { return r.IsValid() && r.truncated }
func (r LogStreamResult) Duration() algebraic.Duration        { return r.duration }

// DiskMetric、ProcessMetric、HostMetricsFrame、MetricsStreamRequest 与 MetricsStreamResult（零裸 time.Duration）。
type (
	DiskMetric struct {
		Mount       string  `json:"mount"`
		UsedBytes   uint64  `json:"used_bytes"`
		TotalBytes  uint64  `json:"total_bytes"`
		UsedPercent float64 `json:"used_percent"`
	}
	ProcessMetric struct {
		PID        int32   `json:"pid"`
		User       string  `json:"user"`
		CPUPercent float64 `json:"cpu_percent"`
		MemPercent float64 `json:"mem_percent"`
		Command    string  `json:"command"`
	}
	HostMetricsFrame struct {
		NodeID     string             `json:"node_id"`
		SampledAt  time.Time          `json:"sampled_at"`
		Hostname   string             `json:"hostname,omitzero"`
		CPUPercent float64            `json:"cpu_percent"`
		Load1      float64            `json:"load_1"`
		Load5      float64            `json:"load_5"`
		Load15     float64            `json:"load_15"`
		MemUsed    uint64             `json:"mem_used_bytes"`
		MemTotal   uint64             `json:"mem_total_bytes"`
		MemPercent float64            `json:"mem_percent"`
		Uptime     algebraic.Duration `json:"uptime"`
		Disks      []DiskMetric       `json:"disks,omitzero"`
		Processes  []ProcessMetric    `json:"processes,omitzero"`
	}
	MetricsStreamRequest struct {
		Plan                     plan.SealedConnectionPlan
		NodeID                   string
		Profile                  algebraic.Option[execution.LaunchProfile]
		Interval                 algebraic.Option[algebraic.Duration]
		MaxSamples, TopProcesses int
		SortBy                   algebraic.Option[ProcessSortBy]
		Timeout                  algebraic.Option[algebraic.Duration]
		OnFrame                  func(HostMetricsFrame)
		Risk                     algebraic.Option[security.RiskLevel]
		Approval                 algebraic.Option[gate.ApprovalSubmission]
		OperationStream          *events.OperationStream
	}
)

//xops:opaque
//xops:failclosed
type MetricsStreamResult struct {
	frames   []HostMetricsFrame
	outcome  execution.ExecutionOutcome
	duration algebraic.Duration
	valid    bool
}

func (r MetricsStreamResult) IsValid() bool {
	return r.valid && r.outcome != nil && r.outcome.IsValid() && !r.duration.IsNegative()
}
func (r MetricsStreamResult) IsZero() bool                        { return !r.IsValid() }
func (r MetricsStreamResult) Frames() []HostMetricsFrame          { return slices.Clone(r.frames) }
func (r MetricsStreamResult) Outcome() execution.ExecutionOutcome { return r.outcome }
func (r MetricsStreamResult) Duration() algebraic.Duration        { return r.duration }

// GUIActionSpec、GUIArtifactDest、GUIExecRequest、ProcessedScreenshot、GUIExecResult 与 GUI 会话类型。
type (
	GUIActionSpec struct {
		Action                  GUIActionKind
		Display, WaylandDisplay string
		X, Y, StartX, StartY    int
		EndX, EndY, Clicks      int
		Direction               ScrollDirection
		Text, Key               string
		IncludeShot             bool
	}
	GUIArtifactDest struct {
		RootDir pathalg.LocalDir
		File    pathalg.LocalRootedDest
	}
	GUIExecRequest struct {
		Plan            plan.SealedConnectionPlan
		NodeID          string
		Profile         algebraic.Option[execution.LaunchProfile]
		Spec            GUIActionSpec
		Artifact        algebraic.Option[GUIArtifactDest]
		Timeout         algebraic.Option[algebraic.Duration]
		Risk            algebraic.Option[security.RiskLevel]
		Approval        algebraic.Option[gate.ApprovalSubmission]
		OperationStream *events.OperationStream
	}
	ProcessedScreenshot struct {
		MIMEType   string `json:"mime_type"`
		Width      int    `json:"width"`
		Height     int    `json:"height"`
		OrigWidth  int    `json:"orig_width"`
		OrigHeight int    `json:"orig_height"`
		Data       []byte `json:"-"`
	}
	GUISessionSpec struct {
		Kind                                GUISessionKind
		DisplayNum                          int
		UseUnixSocket, AllowNonLoopbackBind bool
		LocalBindHost                       string
		LocalBindPort                       uint16
	}
	OpenGUISessionRequest struct {
		Plan            plan.SealedConnectionPlan
		NodeID          string
		Spec            GUISessionSpec
		Risk            algebraic.Option[security.RiskLevel]
		Approval        algebraic.Option[gate.ApprovalSubmission]
		OperationStream *events.OperationStream
	}
)

//xops:opaque
//xops:failclosed
type GUIExecResult struct {
	action         GUIActionKind
	outcome        execution.ExecutionOutcome
	screenshot     algebraic.Option[ProcessedScreenshot]
	artifact       algebraic.Option[pathalg.LocalRootedDest]
	stdout, stderr string
	duration       algebraic.Duration
	valid          bool
}

func (r GUIExecResult) IsValid() bool {
	return r.valid && r.action.IsValid() && r.outcome != nil && r.outcome.IsValid() && !r.duration.IsNegative()
}
func (r GUIExecResult) IsZero() bool                        { return !r.IsValid() }
func (r GUIExecResult) Action() GUIActionKind               { return pickIf(r.IsValid(), r.action, GUIActionInvalid) }
func (r GUIExecResult) Outcome() execution.ExecutionOutcome { return r.outcome }
func (r GUIExecResult) Screenshot() algebraic.Option[ProcessedScreenshot] {
	shot, ok := r.screenshot.Get()
	if !ok {
		return algebraic.None[ProcessedScreenshot]()
	}
	shot.Data = bytes.Clone(shot.Data)
	return algebraic.Some(shot)
}
func (r GUIExecResult) Artifact() algebraic.Option[pathalg.LocalRootedDest] { return r.artifact }
func (r GUIExecResult) Stdout() string                                      { return r.stdout }
func (r GUIExecResult) Stderr() string                                      { return r.stderr }
func (r GUIExecResult) Duration() algebraic.Duration                        { return r.duration }

//xops:opaque
//xops:failclosed
type GUISessionInfo struct {
	handle               plan.ManagedHandle[plan.KindTunnel]
	kind                 GUISessionKind
	display              int
	boundAddr, remoteEnd string
	valid                bool
}

func (i GUISessionInfo) IsValid() bool {
	return i.valid && i.handle.IsValid() && i.kind.IsValid() && i.boundAddr != ""
}
func (i GUISessionInfo) IsZero() bool { return !i.IsValid() }
func (i GUISessionInfo) Handle() plan.ManagedHandle[plan.KindTunnel] {
	return pickIf(i.IsValid(), i.handle, zeroVal[plan.ManagedHandle[plan.KindTunnel]]())
}
func (i GUISessionInfo) Kind() GUISessionKind { return pickIf(i.IsValid(), i.kind, GUISessionInvalid) }
func (i GUISessionInfo) DisplayNum() int      { return i.display }
func (i GUISessionInfo) BoundAddr() string    { return i.boundAddr }
func (i GUISessionInfo) RemoteTarget() string { return i.remoteEnd }

//xops:opaque
//xops:failclosed
type GUISessionStatus struct {
	handleStatus         pool.HandleStatus
	kind                 GUISessionKind
	display              int
	boundAddr, remoteEnd string
	active, valid        bool
	err                  error
}

func (s GUISessionStatus) IsValid() bool {
	return s.valid && s.handleStatus.IsValid() && s.kind.IsValid()
}
func (s GUISessionStatus) IsZero() bool                    { return !s.IsValid() }
func (s GUISessionStatus) HandleStatus() pool.HandleStatus { return s.handleStatus }
func (s GUISessionStatus) Kind() GUISessionKind {
	return pickIf(s.IsValid(), s.kind, GUISessionInvalid)
}
func (s GUISessionStatus) DisplayNum() int      { return s.display }
func (s GUISessionStatus) BoundAddr() string    { return s.boundAddr }
func (s GUISessionStatus) RemoteTarget() string { return s.remoteEnd }
func (s GUISessionStatus) Active() bool         { return s.IsValid() && s.active }
func (s GUISessionStatus) Err() error           { return s.err }

// ProjectionConfig 与不可变投影视图 DTO（零裸 time.Duration，供 Phase 5 entry/tui 直接消费）。
type (
	ProjectionConfig struct {
		SystemBus                                                                          *events.SystemBus
		BusBuffer, MaxLogEntries, MaxDiagnostics, MaxPoolEvents, MaxOperations, MaxMetrics int
	}
	OperationView struct {
		OperationID  string             `json:"operation_id"`
		TraceID      string             `json:"trace_id"`
		NodeID       string             `json:"node_id,omitzero"`
		Tool         string             `json:"tool,omitzero"`
		Action       string             `json:"action,omitzero"`
		Summary      string             `json:"summary,omitzero"`
		Completed    bool               `json:"completed"`
		Succeeded    bool               `json:"succeeded"`
		Unknown      bool               `json:"unknown,omitzero"`
		LastCode     string             `json:"last_code,omitzero"`
		LastMessage  string             `json:"last_message,omitzero"`
		LastStepID   string             `json:"last_step_id,omitzero"`
		LastStepStat string             `json:"last_step_status,omitzero"`
		Duration     algebraic.Duration `json:"duration"`
		UpdatedAt    time.Time          `json:"updated_at"`
	}
	MetricPoint struct {
		Key        string             `json:"key"`
		NodeID     string             `json:"node_id,omitzero"`
		Name       string             `json:"name"`
		Unit       string             `json:"unit,omitzero"`
		Value      float64            `json:"value"`
		Interval   algebraic.Duration `json:"interval"`
		Labels     map[string]string  `json:"labels,omitzero"`
		OccurredAt time.Time          `json:"occurred_at"`
	}
	LogEntry struct {
		TraceID     string                  `json:"trace_id"`
		OperationID string                  `json:"operation_id,omitzero"`
		NodeID      string                  `json:"node_id,omitzero"`
		Stream      events.OutputStreamKind `json:"stream"`
		ChunkIndex  uint64                  `json:"chunk_index"`
		Data        string                  `json:"data"`
		Truncated   bool                    `json:"truncated,omitzero"`
		OccurredAt  time.Time               `json:"occurred_at"`
	}
	DiagnosticRecord struct {
		Scope      events.DiagnosticScope `json:"scope"`
		Severity   events.Severity        `json:"severity"`
		Code       string                 `json:"code"`
		Message    string                 `json:"message"`
		Attrs      map[string]string      `json:"attrs,omitzero"`
		OccurredAt time.Time              `json:"occurred_at"`
	}
	PoolRecord struct {
		Action       events.PoolEventAction `json:"action"`
		Endpoint     string                 `json:"endpoint,omitzero"`
		ActiveLeases uint32                 `json:"active_leases"`
		Latency      algebraic.Duration     `json:"latency"`
		Detail       string                 `json:"detail,omitzero"`
		OccurredAt   time.Time              `json:"occurred_at"`
	}
)

// ProjectionSnapshot 是 Projection 的并发安全不可变投影快照；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ProjectionSnapshot struct {
	wire  projectionSnapshotWire
	valid bool
}

func (s ProjectionSnapshot) IsValid() bool               { return s.valid }
func (s ProjectionSnapshot) IsZero() bool                { return !s.valid }
func (s ProjectionSnapshot) Version() uint64             { return s.wire.Version }
func (s ProjectionSnapshot) TotalEvents() uint64         { return s.wire.TotalEvents }
func (s ProjectionSnapshot) DroppedEvents() uint64       { return s.wire.DroppedEvents }
func (s ProjectionSnapshot) GateHalted() bool            { return s.valid && s.wire.GateHalted }
func (s ProjectionSnapshot) HasUnknownOutcome() bool     { return s.valid && s.wire.HasUnknownOutcome }
func (s ProjectionSnapshot) ActiveStreams() int          { return s.wire.ActiveStreams }
func (s ProjectionSnapshot) Operations() []OperationView { return slices.Clone(s.wire.Operations) }
func (s ProjectionSnapshot) Logs() []LogEntry            { return slices.Clone(s.wire.Logs) }
func (s ProjectionSnapshot) PoolEvents() []PoolRecord    { return slices.Clone(s.wire.PoolEvents) }
func (s ProjectionSnapshot) Metrics() []MetricPoint {
	out := slices.Clone(s.wire.Metrics)
	for i := range out {
		out[i].Labels = maps.Clone(out[i].Labels)
	}
	return out
}
func (s ProjectionSnapshot) Diagnostics() []DiagnosticRecord {
	out := slices.Clone(s.wire.Diagnostics)
	for i := range out {
		out[i].Attrs = maps.Clone(out[i].Attrs)
	}
	return out
}

type projectionSnapshotWire struct {
	Version           uint64             `json:"version"`
	TotalEvents       uint64             `json:"total_events"`
	DroppedEvents     uint64             `json:"dropped_events"`
	GateHalted        bool               `json:"gate_halted"`
	HasUnknownOutcome bool               `json:"has_unknown_outcome"`
	ActiveStreams     int                `json:"active_streams"`
	Operations        []OperationView    `json:"operations,omitzero"`
	Metrics           []MetricPoint      `json:"metrics,omitzero"`
	Logs              []LogEntry         `json:"logs,omitzero"`
	Diagnostics       []DiagnosticRecord `json:"diagnostics,omitzero"`
	PoolEvents        []PoolRecord       `json:"pool_events,omitzero"`
}

// MarshalJSONTo 与 CanonicalJSON 实现 ProjectionSnapshot 的 Go 1.27 encoding/json/v2 确定性编码。
func (s ProjectionSnapshot) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !s.valid {
		return ErrInvalidRequest
	}
	return jsonv2.MarshalEncode(enc, s.wire)
}
func (s ProjectionSnapshot) CanonicalJSON() ([]byte, error) {
	if !s.valid {
		return nil, ErrInvalidRequest
	}
	return jsonv2.Marshal(s, jsonv2.Deterministic(true))
}
