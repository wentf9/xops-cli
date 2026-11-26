package mcpruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/tools"
	ucauto "github.com/wentf9/xops-cli/core/internal/usecase/automation"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	ucobs "github.com/wentf9/xops-cli/core/internal/usecase/observability"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultServerName         = "xops-mcp"
	defaultServerVersion      = "2.0.0"
	defaultMaxMessageBytes    = 4 << 20  // 4 MiB 单条 JSON-RPC 报文上限
	maxAllowedMessageBytes    = 32 << 20 // 32 MiB 硬上限
	defaultHTTPChunkSize      = 1 << 20  // 1 MiB 10 GiB HTTP 流式分片大小
	minHTTPChunkSize          = 4 << 10  // 4 KiB 最小 HTTP 分片
	defaultMaxHTTPSessions    = 64
	defaultHTTPReadHeaderTime = 10 * time.Second
	defaultHTTPShutdownTime   = 5 * time.Second
)

// AuditReconcileFunc 定义启动期 O(1) 跨进程崩溃审计对账函数签名（由 core/engine 接线至 Gate.ReconcileCrashedAudits）。
type AuditReconcileFunc func(ctx context.Context) (ports.CrashReconcileReport, error)

// ServerConfig 定义 MCP 运行时 Server 的全显式依赖注入配置；
// 物理上严禁接收 ports.OperatorReadFS，且所有时长配置均使用 algebraic.Duration（零裸 time.Duration）。
type ServerConfig struct {
	// Gate 是必填的安全能力门控授权器（用于实时探测 Halted 熔断与策略配置档）。
	Gate gate.Authorizer
	// ReconcileAudits 为启动期 O(1) 崩溃审计对账回调（StrictAgentProfile 下默认必填）。
	ReconcileAudits AuditReconcileFunc
	// AllowOptionalReconciler 仅在测试或非严格场景显式允许缺少 AuditReconciler 时跳过审计对账（默认 false 失败关闭）。
	AllowOptionalReconciler bool

	// 用例服务依赖（均由 core/engine 注入；其中 Transfer 与 Automation 物理不携带 OperatorReadFS）。
	Inventory     *ucinv.Service
	Session       *ucsess.Service
	Transfer      *uctrans.Service
	Automation    *ucauto.Service
	Observability *ucobs.Service

	// ScopedFS 为基于 os.Root 的沙箱本地文件系统端口（物理禁止 OperatorReadFS）。
	ScopedFS ports.ScopedRootFS
	// TransferRoot 可选指定 MCP 流式传输本地下载/沙箱源根目录（位于 ScopedFS 管控下）。
	TransferRoot algebraic.Option[pathalg.LocalDir]
	// ArtifactRoot 可选指定 GUI 截图产物沙箱根目录（未设置时回退 TransferRoot）。
	ArtifactRoot algebraic.Option[pathalg.LocalDir]

	// Clock 与 Entropy 为必填的确定性时钟与显式熵源端口（零 time.Now / crypto/rand）。
	Clock     ports.Clock
	Entropy   ports.Entropy
	SystemBus *events.SystemBus

	// MCP 协议元信息与传输安全限制。
	ServerName              string
	ServerVersion           string
	Instructions            string
	MaxMessageBytes         int64
	MaxTrackedHandles       int
	HTTPChunkSize           int64
	MaxHTTPSessions         int
	AllowNonLoopbackHTTP    bool
	HTTPAllowedOrigins      []string
	HTTPAllowedHosts        []string
	HTTPReadHeaderTimeout   algebraic.Option[algebraic.Duration]
	HTTPShutdownTimeout     algebraic.Option[algebraic.Duration]
	PruneSupersededJournals bool
	FailOnCorruptJournal    bool
}

// TransferRecoverySummary 记录单条传输任务在启动期恢复扫描中的脱敏摘要（零副作用）。
type TransferRecoverySummary struct {
	TransferID        security.OperationID  `json:"transfer_id"`
	StateKind         fsm.TransferStateKind `json:"state_kind,omitzero"`
	SelectedGen       uint64                `json:"selected_gen"`
	PrunedGenerations []uint64              `json:"pruned_generations,omitzero"`
	UncertainCommit   bool                  `json:"uncertain_commit,omitzero"`
	Error             string                `json:"error,omitzero"`
}

// StartupReport 封装 MCP Server 启动期自动执行的 O(1) 崩溃审计对账与双代 Journal 恢复结果；
// 零值恒未就绪（valid == false）。
//
//xops:opaque
//xops:failclosed
type StartupReport struct {
	auditReport        algebraic.Option[ports.CrashReconcileReport]
	recoveredTransfers []TransferRecoverySummary
	uncertainTransfers []TransferRecoverySummary
	corruptTransfers   []TransferRecoverySummary
	valid              bool
}

// IsValid 报告启动期对账与恢复是否已成功完成。
func (r StartupReport) IsValid() bool { return r.valid }

// IsZero 报告启动报告是否处于未就绪零值态。
func (r StartupReport) IsZero() bool { return !r.valid }

// AuditReport 返回启动期崩溃审计对账报告（若已执行）。
func (r StartupReport) AuditReport() algebraic.Option[ports.CrashReconcileReport] {
	return r.auditReport
}

// RecoveredTransfers 返回启动期健康恢复的传输摘要副本。
func (r StartupReport) RecoveredTransfers() []TransferRecoverySummary {
	return append([]TransferRecoverySummary(nil), r.recoveredTransfers...)
}

// UncertainTransfers 返回启动期发现的 TransferUncertainCommit 隔离摘要副本（零副作用）。
func (r StartupReport) UncertainTransfers() []TransferRecoverySummary {
	return append([]TransferRecoverySummary(nil), r.uncertainTransfers...)
}

// CorruptTransfers 返回启动期发现的损坏日志摘要副本（零副作用）。
func (r StartupReport) CorruptTransfers() []TransferRecoverySummary {
	return append([]TransferRecoverySummary(nil), r.corruptTransfers...)
}

// Server 是 XOps v2 MCP 协议运行时核心（支持 stdio 与 Streamable HTTP 双传输 + 10 GiB 流式端点）；
// 零值恒未初始化并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Server struct {
	gate                    gate.Authorizer
	reconcileAudits         AuditReconcileFunc
	allowOptionalReconciler bool
	transferSvc             *uctrans.Service
	registry                *tools.Registry
	descriptors             []protocol.ToolDescriptor
	clock                   ports.Clock
	entropy                 ports.Entropy
	bus                     *events.SystemBus

	serverName            string
	serverVersion         string
	instructions          string
	maxMessageBytes       int64
	httpChunkSize         int64
	maxHTTPSessions       int
	allowNonLoopbackHTTP  bool
	allowedOrigins        []string
	allowedHosts          []string
	httpReadHeaderTimeout time.Duration
	httpShutdownTimeout   time.Duration
	pruneSuperseded       bool
	failOnCorruptJournal  bool

	prepMu   sync.Mutex
	prepared bool
	report   StartupReport

	sessMu   sync.Mutex
	sessSeq  uint64
	sessions map[string]mcpHTTPSession

	lifeCtx    context.Context
	lifeCancel context.CancelCauseFunc
	stateMu    sync.Mutex
	closing    bool
	inflight   int
	drainCh    chan struct{}
	closeOnce  sync.Once
	closeErr   error
	diagSeq    atomic.Uint64
	valid      bool
}

type mcpHTTPSession struct {
	id              string
	protocolVersion string
	seq             uint64
	createdAt       time.Time
}

// NewServer 校验全部显式依赖、编译 7 个判别式工具 Schema 并构造 MCP Server 实例。
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := validateServerConfig(cfg); err != nil {
		return nil, err
	}
	descriptors, err := protocol.ToolDescriptors()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	reg, err := tools.NewRegistry(tools.RegistryConfig{
		Gate:          cfg.Gate,
		Inventory:     cfg.Inventory,
		Session:       cfg.Session,
		Transfer:      cfg.Transfer,
		Automation:    cfg.Automation,
		Observability: cfg.Observability,
		ScopedFS:      cfg.ScopedFS,
		TransferRoot:  cfg.TransferRoot,
		ArtifactRoot:  cfg.ArtifactRoot,
		MaxHandles:    cfg.MaxTrackedHandles,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	maxMsg, chunkSize, maxSess, readHdr, shutDur := resolveServerDefaults(cfg)
	lifeCtx, lifeCancel := context.WithCancelCause(context.Background())
	return &Server{
		gate:                    cfg.Gate,
		reconcileAudits:         cfg.ReconcileAudits,
		allowOptionalReconciler: cfg.AllowOptionalReconciler,
		transferSvc:             cfg.Transfer,
		registry:                reg,
		descriptors:             descriptors,
		clock:                   cfg.Clock,
		entropy:                 cfg.Entropy,
		bus:                     cfg.SystemBus,
		serverName:              orString(cfg.ServerName, defaultServerName),
		serverVersion:           orString(cfg.ServerVersion, defaultServerVersion),
		instructions:            cfg.Instructions,
		maxMessageBytes:         maxMsg,
		httpChunkSize:           chunkSize,
		maxHTTPSessions:         maxSess,
		allowNonLoopbackHTTP:    cfg.AllowNonLoopbackHTTP,
		allowedOrigins:          append([]string(nil), cfg.HTTPAllowedOrigins...),
		allowedHosts:            append([]string(nil), cfg.HTTPAllowedHosts...),
		httpReadHeaderTimeout:   readHdr,
		httpShutdownTimeout:     shutDur,
		pruneSuperseded:         cfg.PruneSupersededJournals,
		failOnCorruptJournal:    cfg.FailOnCorruptJournal,
		sessions:                make(map[string]mcpHTTPSession),
		lifeCtx:                 lifeCtx,
		lifeCancel:              lifeCancel,
		valid:                   true,
	}, nil
}

func validateServerConfig(cfg ServerConfig) error {
	switch {
	case cfg.Gate == nil || cfg.Clock == nil || cfg.Entropy == nil:
		return fmt.Errorf("%w: Gate/Clock/Entropy 必填", ErrInvalidConfig)
	case cfg.SystemBus != nil && cfg.SystemBus.IsClosed():
		return fmt.Errorf("%w: 注入的 SystemBus 已关闭", ErrInvalidConfig)
	case cfg.MaxMessageBytes < 0 || cfg.MaxMessageBytes > maxAllowedMessageBytes:
		return fmt.Errorf("%w: MaxMessageBytes=%d 越界", ErrInvalidConfig, cfg.MaxMessageBytes)
	case cfg.HTTPChunkSize < 0 || (cfg.HTTPChunkSize > 0 && (cfg.HTTPChunkSize < minHTTPChunkSize || uint64(cfg.HTTPChunkSize) > fsm.MaxTransferChunkBytes)):
		return fmt.Errorf("%w: HTTPChunkSize=%d 越界", ErrInvalidConfig, cfg.HTTPChunkSize)
	case cfg.MaxHTTPSessions < 0:
		return fmt.Errorf("%w: MaxHTTPSessions 不能为负", ErrInvalidConfig)
	}
	if d, ok := cfg.HTTPReadHeaderTimeout.Get(); ok && !d.IsPositive() {
		return fmt.Errorf("%w: HTTPReadHeaderTimeout 必须为正时长", ErrInvalidConfig)
	}
	if d, ok := cfg.HTTPShutdownTimeout.Get(); ok && !d.IsPositive() {
		return fmt.Errorf("%w: HTTPShutdownTimeout 必须为正时长", ErrInvalidConfig)
	}
	return nil
}

func resolveServerDefaults(cfg ServerConfig) (maxMsg, chunkSize int64, maxSess int, readHdr, shutDur time.Duration) {
	maxMsg = cfg.MaxMessageBytes
	if maxMsg == 0 {
		maxMsg = defaultMaxMessageBytes
	}
	chunkSize = cfg.HTTPChunkSize
	if chunkSize == 0 {
		chunkSize = defaultHTTPChunkSize
	}
	maxSess = cfg.MaxHTTPSessions
	if maxSess == 0 {
		maxSess = defaultMaxHTTPSessions
	}
	readHdr = defaultHTTPReadHeaderTime
	if d, ok := cfg.HTTPReadHeaderTimeout.Get(); ok {
		readHdr = d.Std()
	}
	shutDur = defaultHTTPShutdownTime
	if d, ok := cfg.HTTPShutdownTimeout.Get(); ok {
		shutDur = d.Std()
	}
	return maxMsg, chunkSize, maxSess, readHdr, shutDur
}

func orString(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

// Prepare 执行 MCP Server 启动期自动对账（O(1) 崩溃审计对账）与传输日志恢复（RecoverJournals）；
// 幂等且并发安全：一旦启动期检查成功完成即缓存报告，遇门控熔断或基础设施故障严格 Fail-Closed 拒绝放行。
func (s *Server) Prepare(ctx context.Context) (StartupReport, error) {
	if err := s.checkReady(ctx); err != nil {
		return StartupReport{}, err
	}
	s.prepMu.Lock()
	defer s.prepMu.Unlock()
	if s.gate.IsHalted() {
		s.registry.ClearTrackedHandles()
		return StartupReport{}, gate.ErrGateHalted
	}
	if s.prepared {
		return cloneStartupReport(s.report), nil
	}
	rep, err := s.runStartupReconcileAndRecovery(ctx)
	if err != nil {
		return StartupReport{}, err
	}
	s.report = rep
	s.prepared = true
	return cloneStartupReport(rep), nil
}

func (s *Server) runStartupReconcileAndRecovery(ctx context.Context) (StartupReport, error) {
	rep := StartupReport{valid: true}
	if err := s.runStartupAuditReconcile(ctx, &rep); err != nil {
		return StartupReport{}, err
	}
	if err := s.runStartupJournalRecovery(ctx, &rep); err != nil {
		return StartupReport{}, err
	}
	return rep, nil
}

func (s *Server) runStartupAuditReconcile(ctx context.Context, rep *StartupReport) error {
	if s.reconcileAudits == nil {
		if s.gate.Profile() == gate.PolicyProfileStrictAgent && !s.allowOptionalReconciler {
			return fmt.Errorf("%w: %w", ErrStartupReconcileFailed, gate.ErrReconcilerUnavailable)
		}
		return nil
	}
	auditRep, err := s.reconcileAudits(ctx)
	if err != nil {
		if errors.Is(err, gate.ErrReconcilerUnavailable) && (s.gate.Profile() != gate.PolicyProfileStrictAgent || s.allowOptionalReconciler) {
			return nil
		}
		s.emitDiag(events.SeverityError, "mcp_startup_reconcile_failed", err.Error(), nil)
		return fmt.Errorf("%w: %w", ErrStartupReconcileFailed, err)
	}
	rep.auditReport = algebraic.Some(auditRep)
	return nil
}

func (s *Server) runStartupJournalRecovery(ctx context.Context, rep *StartupReport) error {
	if s.transferSvc == nil {
		return nil
	}
	recRes, err := s.transferSvc.RecoverAllTransfers(ctx, uctrans.RecoverAllRequest{
		PruneSuperseded: s.pruneSuperseded,
	})
	if err != nil {
		if errors.Is(err, uctrans.ErrJournalStoreUnavailable) {
			return nil
		}
		s.emitDiag(events.SeverityError, "mcp_startup_recovery_failed", err.Error(), nil)
		return fmt.Errorf("%w: %w", ErrStartupRecoveryFailed, err)
	}
	for _, entry := range recRes.Entries {
		sum := buildTransferSummary(entry)
		switch {
		case entry.Result.UncertainCommit || errors.Is(entry.Err, uctrans.ErrUncertainCommit):
			// 忠实记录 TransferUncertainCommit，严禁重试、覆写或删除日志（零副作用）。
			rep.uncertainTransfers = append(rep.uncertainTransfers, sum)
			s.emitDiag(events.SeverityError, "mcp_startup_uncertain_transfer", "发现处于 TransferUncertainCommit 的传输，已隔离零副作用保留", map[string]string{
				"transfer_id": entry.TransferID.String(),
			})
		case entry.Err != nil:
			rep.corruptTransfers = append(rep.corruptTransfers, sum)
			s.emitDiag(events.SeverityError, "mcp_startup_corrupt_transfer", sum.Error, map[string]string{
				"transfer_id": entry.TransferID.String(),
			})
		default:
			rep.recoveredTransfers = append(rep.recoveredTransfers, sum)
		}
	}
	if s.failOnCorruptJournal && len(rep.corruptTransfers) > 0 {
		return fmt.Errorf("%w: 发现 %d 条损坏传输日志且 FailOnCorruptJournal 已启用", ErrStartupRecoveryFailed, len(rep.corruptTransfers))
	}
	return nil
}

func buildTransferSummary(entry uctrans.TransferRecoveryEntry) TransferRecoverySummary {
	sum := TransferRecoverySummary{
		TransferID:        entry.TransferID,
		SelectedGen:       entry.Result.SelectedGen,
		PrunedGenerations: append([]uint64(nil), entry.Result.PrunedGenerations...),
		UncertainCommit:   entry.Result.UncertainCommit,
	}
	if entry.Result.State != nil && entry.Result.State.IsValid() {
		sum.StateKind = entry.Result.State.Kind()
	}
	if entry.Err != nil {
		sum.Error = security.SanitizePromptText(entry.Err.Error())
	}
	return sum
}

func cloneStartupReport(r StartupReport) StartupReport {
	return StartupReport{
		auditReport:        r.auditReport,
		recoveredTransfers: append([]TransferRecoverySummary(nil), r.recoveredTransfers...),
		uncertainTransfers: append([]TransferRecoverySummary(nil), r.uncertainTransfers...),
		corruptTransfers:   append([]TransferRecoverySummary(nil), r.corruptTransfers...),
		valid:              r.valid,
	}
}

// StartupReport 返回最近一次成功 Prepare 的启动期对账与恢复报告快照；未就绪时返回零值。
func (s *Server) StartupReport() StartupReport {
	if s == nil || !s.valid {
		return StartupReport{}
	}
	s.prepMu.Lock()
	defer s.prepMu.Unlock()
	return cloneStartupReport(s.report)
}

// Close 幂等优雅关闭 MCP Server，取消全部在途传输与会话并等待收敛（受 ctx 有界约束）：
// 尽力释放本 Server 追踪的非持久化活跃句柄（PTY/Forward/GUI/Mux）并清空本地索引，
// 故意不中止带 Journal 的可恢复 10 GiB 流式传输以保留断点续传与崩溃恢复契约（底层池句柄由 Engine.Close 统一回收）。
func (s *Server) Close(ctx context.Context) error {
	if s == nil || !s.valid {
		return ErrServerNotInitialized
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	s.closeOnce.Do(func() {
		s.stateMu.Lock()
		s.closing = true
		var waitCh chan struct{}
		if s.inflight > 0 {
			if s.drainCh == nil {
				s.drainCh = make(chan struct{})
			}
			waitCh = s.drainCh
		}
		s.stateMu.Unlock()

		s.lifeCancel(ErrServerClosed)
		s.registry.CloseEphemeralHandles(ctx)
		s.sessMu.Lock()
		clear(s.sessions)
		s.sessMu.Unlock()

		if waitCh != nil {
			select {
			case <-waitCh:
			case <-ctx.Done():
				s.closeErr = ctx.Err()
			}
		}
	})
	return s.closeErr
}

// IsClosed 报告 MCP Server 是否已关闭；未初始化零值失败关闭返回 true。
func (s *Server) IsClosed() bool {
	if s == nil || !s.valid {
		return true
	}
	s.stateMu.Lock()
	closed := s.closing
	s.stateMu.Unlock()
	return closed
}
