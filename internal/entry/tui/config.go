package tui

import (
	"context"
	"io"

	tea "charm.land/bubbletea/v2"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/i18n"
)

const (
	defaultMaxLogLines     = 512
	defaultMaxMetrics      = 256
	defaultMaxOperations   = 256
	defaultMaxSystemItems  = 256
	defaultStreamBuffer    = 64
	defaultTopProcesses    = 10
	defaultLogTailLines    = 100
	defaultActionQueueCap  = 32
	defaultWindowWidth     = 100
	defaultWindowHeight    = 30
	defaultRemoteLogPath   = "/var/log/syslog"
	metricsBatchMaxSamples = 10000
	maxLineBufferBytes     = 64 << 10
)

// 本包导出的不可变结构化哨兵错误，供组合根 cmd/xops、entry/cli 与测试通过 errors.Is 精确区分故障类别。
var (
	ErrNilContext       = i18n.Sentinel(i18n.KeyTUINilContext)
	ErrInvalidConfig    = i18n.Sentinel(i18n.KeyTUIInvalidConfig)
	ErrInvalidEvent     = i18n.Sentinel(i18n.KeyTUIInvalidEvent)
	ErrTerminalRestore  = i18n.Sentinel(i18n.KeyTUITerminalRestore)
	ErrTakeoverDisabled = i18n.Sentinel(i18n.KeyTUITakeoverDisabled)
)

// EngineClient 定义 TUI 工作台消费 core/engine 门面所需的最小强类型契约（由 *engine.Engine 原生实现）。
type EngineClient interface {
	ListHosts(ctx context.Context, req engine.InventoryQueryRequest) ([]inventory.Host, engine.Revision, error)
	ListIdentities(ctx context.Context, req engine.InventoryQueryRequest) ([]inventory.Identity, engine.Revision, error)
	ListNodes(ctx context.Context, req engine.InventoryQueryRequest) ([]inventory.Node, engine.Revision, error)
	NewProjection(ctx context.Context, cfg engine.ProjectionConfig) (*engine.Projection, error)
	NewOperationStream(ctx context.Context, buffer int) (*events.OperationStream, error)
	StreamMetrics(ctx context.Context, req engine.MetricsStreamRequest) (engine.MetricsStreamResult, error)
	StreamLogs(ctx context.Context, req engine.LogStreamRequest) (engine.LogStreamResult, error)
	SystemBus() *events.SystemBus
	IsHalted() bool
	HaltInfo() (engine.HaltInfo, bool)
}

// ProjectionSource 定义实时事件投影聚合器的只读监听契约（由 *engine.Projection 原生实现）。
type ProjectionSource interface {
	AttachOperationStream(s *events.OperationStream) error
	Snapshot() engine.ProjectionSnapshot
	WaitUpdate(ctx context.Context, sinceVersion uint64) (engine.ProjectionSnapshot, error)
	Close() error
}

// InventorySnapshotClient 为支持单次原子资产图快照查询的可选扩展接口（由 *engine.Engine 原生实现），
// 优先使用可避免多次拆分列表调用引发的撕裂读与冗余审计条目。
type InventorySnapshotClient interface {
	GetInventorySnapshot(ctx context.Context, req engine.InventoryQueryRequest) (engine.InventorySnapshot, error)
}

// 编译期契约断言：确保 *engine.Engine 与 *engine.Projection 完整满足本包入站依赖接口。
var (
	_ EngineClient            = (*engine.Engine)(nil)
	_ InventorySnapshotClient = (*engine.Engine)(nil)
	_ ProjectionSource        = (*engine.Projection)(nil)
)

// TerminalHooks 提供可选的宿主终端接管/释放/恢复生命周期钩子，供组合根与无头测试观测终端状态确定性收尾。
type TerminalHooks struct {
	// OnEnter 在启动 Bubble Tea 程序前调用（可选）。
	OnEnter func() error
	// OnRelease 在 TUI 完整排空并临时让出终端给交互会话（如 SSH/SFTP）前调用（可选）。
	OnRelease func() error
	// OnRestore 在 TUI 正常退出、Ctrl+C、ctx 取消或发生错误后无条件执行（幂等确定性恢复，可选）。
	OnRestore func() error
}

// TakeoverRequest 描述从 TUI 工作台触发交互式终端接管（如切入 SSH 或 SFTP 会话）的目标上下文。
type TakeoverRequest struct {
	NodeID     string
	TargetSpec string
}

// TakeoverFunc 在 TUI 完整排空并归还终端控制权后执行受 Nursery 监督的交互接管动作；返回后自动恢复工作台。
type TakeoverFunc func(ctx context.Context, req TakeoverRequest) error

// Config 定义 Bubble Tea v2 实时工作台入口 Run 的全显式依赖注入配置（零全局单例、零隐式环境读取）。
type Config struct {
	// Engine 为核心业务门面（通常直接传入 *engine.Engine）；与 Projection/SystemBus/OperationStreams 至少提供其一。
	Engine EngineClient
	// Projection 为可选预建实时投影源；为 nil 且 Engine 非空时由 Run 自动经 Engine.NewProjection 创建并逆序关闭。
	Projection ProjectionSource
	// ProjectionConfig 在 Run 自动创建 Projection 时透传的缓冲容量配置。
	ProjectionConfig engine.ProjectionConfig
	// SystemBus 为可选系统诊断事件总线（当未提供 Projection 且未传 SystemBus 时自动从 Engine.SystemBus() 获取）。
	SystemBus *events.SystemBus
	// OperationStreams 为启动时即挂载投影至 tea.Msg 的初始单次操作事件流列表（均受 Nursery 监督直至确定性 EOF）。
	OperationStreams []*events.OperationStream

	// Input 与 Output 分别为终端输入输出流；无头测试可配合 DisableInput/DisableRenderer 注入内存缓冲区。
	Input  io.Reader
	Output io.Writer
	// Environment 可选透传给 Bubble Tea 的环境变量键值表（避免在 entry 层直接调用 os.Environ）。
	Environment []string

	// DisableInput 禁用输入读取器（传递 tea.WithInput(nil)，避免非 TTY 无头环境打开控制终端）。
	DisableInput bool
	// DisableRenderer 禁用 ANSI 渲染器（传递 tea.WithoutRenderer()，用于纯事件投影无头测试）。
	DisableRenderer bool
	// DisableAltScreen 禁用交替屏幕缓冲区（默认 false 即启用 AltScreen）。
	DisableAltScreen bool
	// DisableSignalHandler 禁用 Bubble Tea 内置信号处理（当上层 cmd/xops 已通过 signal.NotifyContext 托管信号时建议设为 true）。
	DisableSignalHandler bool

	// InitialView / InitialWidth / InitialHeight 指定初始视图与初始窗口尺寸（0 取安全默认值）。
	InitialView   ViewKind
	InitialWidth  int
	InitialHeight int

	// InitialTarget / CLIOptions 指定默认目标与 CLI 层 OpenSSH 选项覆盖，用于指标/日志流快速启动。
	InitialTarget string
	CLIOptions    option.OptionLayer

	// MetricsInterval / MetricsMaxSamples / MetricsTopProcesses / DefaultLogTarget / LogTailLines 控制实时指标与日志流默认参数。
	// MetricsMaxSamples 为 0 时采用核心允许的单批最大连续采样数（10000），并在到达批次上限后自动续接，避免单样本退出与 0% 增量 CPU。
	MetricsInterval     algebraic.Option[algebraic.Duration]
	MetricsMaxSamples   int
	MetricsTopProcesses int
	DefaultLogTarget    algebraic.Option[engine.LogTarget]
	LogTailLines        int

	// MaxLogLines / MaxStreamBuffer 控制视图环形保留上限与新建 OperationStream 缓冲区大小（0 取安全默认值）。
	MaxLogLines     int
	MaxStreamBuffer int

	// TerminalHooks 提供可选的终端接管/释放/恢复生命周期回调。
	TerminalHooks TerminalHooks
	// OnTakeover 提供可选的交互会话接管回调（用户在主机列表按 Enter 时触发完整排空 -> 接管 -> 恢复闭环）。
	OnTakeover TakeoverFunc
	// ExternalMsgs 为可选外部注入消息流（受 Nursery 监督转发至 Bubble Tea，便于无头确定性驱动与集成测试）。
	ExternalMsgs <-chan tea.Msg

	// Catalog 为可选预加载只读双语词库；为 nil 或无效时自动从内置内存 embed.FS 加载（零触盘、零包级 var）。
	Catalog *i18n.Catalog
	// Locale 指定初始界面语言；未设置或无效时回退 domi18n.LocaleEn。
	Locale domi18n.Locale
	// OnLocaleChange 在用户按大写 L 热切换语言时同步/非阻塞通知外部组件（如同步交互接管提示语种）。
	OnLocaleChange func(domi18n.Locale)
}

func validateConfig(cfg Config) error {
	if cfg.Engine == nil && cfg.Projection == nil && cfg.SystemBus == nil && len(cfg.OperationStreams) == 0 {
		return i18n.EF(ErrInvalidConfig, i18n.KeyTUIConfigNoSource)
	}
	if cfg.InitialView != ViewInvalid && !cfg.InitialView.IsValid() {
		return i18n.EF(ErrInvalidConfig, i18n.KeyTUIConfigInvalidView, i18n.Int("view", int(cfg.InitialView)))
	}
	if cfg.InitialWidth < 0 || cfg.InitialHeight < 0 || cfg.MaxLogLines < 0 || cfg.MaxStreamBuffer < 0 ||
		cfg.MetricsMaxSamples < 0 || cfg.MetricsMaxSamples > metricsBatchMaxSamples ||
		cfg.MetricsTopProcesses < 0 || cfg.LogTailLines < 0 {
		return i18n.EF(ErrInvalidConfig, i18n.KeyTUIConfigOutOfBounds)
	}
	if err := cfg.CLIOptions.Validate(); err != nil {
		return i18n.WrapS(ErrInvalidConfig, err, i18n.KeyTUIConfigInvalidCLIOpts)
	}
	if err := validateOptionalStreamConfig(cfg); err != nil {
		return err
	}
	for i, s := range cfg.OperationStreams {
		if s == nil {
			return i18n.EF(ErrInvalidConfig, i18n.KeyTUIConfigNilOpStream, i18n.Int("index", i))
		}
	}
	return nil
}

func validateOptionalStreamConfig(cfg Config) error {
	if iv, ok := cfg.MetricsInterval.Get(); ok && !iv.IsPositive() {
		return i18n.EF(ErrInvalidConfig, i18n.KeyTUIConfigMetricsInterval)
	}
	if lt, ok := cfg.DefaultLogTarget.Get(); ok && !lt.IsValid() {
		return i18n.EF(ErrInvalidConfig, i18n.KeyTUIConfigInvalidLogTarget)
	}
	return nil
}

// resolveCatalog 返回有效只读双语词库；若未注入则回退纯内存内置 embed.FS 词库（零触盘、零全局状态）。
func resolveCatalog(cat *i18n.Catalog) *i18n.Catalog {
	if cat.IsValid() {
		return cat
	}
	loaded, err := i18n.LoadCatalog()
	if err != nil {
		return nil
	}
	return loaded
}

// resolveCatalogOrLoad 为 Run 入口加载或复用只读双语词库，失败时返回结构化错误而非静默降级。
func resolveCatalogOrLoad(cat *i18n.Catalog) (*i18n.Catalog, error) {
	if cat.IsValid() {
		return cat, nil
	}
	return i18n.LoadCatalog()
}

// resolveLocale 返回有效界面语言；零值或无效值默认回退英文（domi18n.LocaleEn）。
func resolveLocale(loc domi18n.Locale) domi18n.Locale {
	if loc.IsValid() {
		return loc
	}
	return domi18n.LocaleEn
}

// zeroVal 返回类型 T 的零值，用于在错误返回路径替代对跨包 //xops:opaque 类型的空复合字面量构造。
func zeroVal[T any]() (z T) { return z }

func resolveDefaultLogTarget(cfg Config) (engine.LogTarget, error) {
	if lt, ok := cfg.DefaultLogTarget.Get(); ok {
		return lt, nil
	}
	rp, err := pathalg.ParseAbsRemotePath(defaultRemoteLogPath)
	if err != nil {
		return zeroVal[engine.LogTarget](), err
	}
	return engine.NewFileLogTarget(rp)
}
