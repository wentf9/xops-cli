// Package tools 实现 XOps v2 MCP 运行时的全部 7 个强类型判别式工具处理器
// （nodes、terminal_exec、terminal_session、file、transfer、tunnel、gui，ADR-006 / ADR-007 / ADR-008 / Plan P3-T5）。
//
// 核心安全与架构不变量：
//   - 物理禁止引用 ports.OperatorReadFS（由 xopsvet/archbound 强制），所有本地沙箱落盘与读写均仅走 ports.ScopedRootFS；
//   - 严禁导入 core/internal/pool、core/internal/sshnet/** 或 core/osfs，全部业务逻辑唯一经 usecase/* 权威用例服务执行；
//   - 所有入站工具调用均前置核验 Gate.IsHalted()：StrictAgentProfile 进入不可逆 Halted 熔断态后立即拒绝一切请求；
//   - 全部工具入参严格采用 encoding/json/v2 RejectUnknownMembers(true) 解码并经显式 action 判别式分派，
//     完整支持两步审批（ApprovalChallengeError -> ApprovalSubmission）与零机密泄露；
//   - 全包 0 init()、0 可变包级 var、0 裸 go、0 裸 time.Duration DTO、0 path/filepath 远端路径操作、0 nolint 豁免。
package tools

import (
	"context"
	"encoding/json/jsontext"
	"sync"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	ucauto "github.com/wentf9/xops-cli/core/internal/usecase/automation"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	ucobs "github.com/wentf9/xops-cli/core/internal/usecase/observability"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

// 本包导出的不可变哨兵错误。
var (
	// ErrInvalidConfig 表示 RegistryConfig 缺少必填服务依赖或沙箱根目录无效。
	ErrInvalidConfig = domi18n.Sentinel(domi18n.KeyMCPToolsInvalidConfig)
	// ErrRegistryNotInitialized 表示在 nil 或零值未初始化 Registry 上调用方法。
	ErrRegistryNotInitialized = domi18n.Sentinel(domi18n.KeyMCPToolsNotInit)
	// ErrServiceUnavailable 表示当前工具所需的底层用例服务未装配。
	ErrServiceUnavailable = domi18n.Sentinel(domi18n.KeyMCPToolsSvcUnavail)
	// ErrHandleNotFound 表示指定的句柄令牌未在当前运行时登记或已释放。
	ErrHandleNotFound = domi18n.Sentinel(domi18n.KeyMCPToolsHandleNotFnd)
)

const (
	defaultMaxTrackedHandles = 256
	defaultMaxExecOutBytes   = 1 << 20 // 1 MiB MCP 响应单次命令输出上限
	maxExecOutBytesCap       = 8 << 20 // 8 MiB 单次响应硬上限
)

// TransferBinding 记录活跃 10 GiB 流式传输在 MCP 控制面与 HTTP 数据面之间的不可变路由绑定；零值恒无效。
//
//xops:opaque
//xops:failclosed
type TransferBinding struct {
	transferID security.OperationID
	plan       plan.SealedConnectionPlan
	nodeID     string
	handle     plan.ManagedHandle[plan.KindTransfer]
	direction  fsm.TransferDirection
	localRoot  algebraic.Option[pathalg.LocalDir]
	localDest  algebraic.Option[pathalg.LocalRootedDest]
	totalBytes uint64
	valid      bool
}

// IsValid 报告流式传输绑定是否有效。
func (b TransferBinding) IsValid() bool {
	return b.valid && b.transferID.IsValid() && b.plan.IsValid() && b.handle.IsValid() && b.direction.IsValid()
}

// TransferBinding 零值安全只读访问器。
func (b TransferBinding) TransferID() security.OperationID                     { return b.transferID }
func (b TransferBinding) Plan() plan.SealedConnectionPlan                      { return b.plan }
func (b TransferBinding) NodeID() string                                       { return b.nodeID }
func (b TransferBinding) Handle() plan.ManagedHandle[plan.KindTransfer]        { return b.handle }
func (b TransferBinding) Direction() fsm.TransferDirection                     { return b.direction }
func (b TransferBinding) LocalRoot() algebraic.Option[pathalg.LocalDir]        { return b.localRoot }
func (b TransferBinding) LocalDest() algebraic.Option[pathalg.LocalRootedDest] { return b.localDest }
func (b TransferBinding) TotalBytes() uint64                                   { return b.totalBytes }

// RegistryConfig 定义 7 个判别式 MCP 工具注册表的全显式依赖注入规格；
// 物理上绝不接受 ports.OperatorReadFS，仅接受基于 os.Root 的 ports.ScopedRootFS。
type RegistryConfig struct {
	Gate          gate.Authorizer
	Inventory     *ucinv.Service
	Session       *ucsess.Service
	Transfer      *uctrans.Service
	Automation    *ucauto.Service
	Observability *ucobs.Service
	ScopedFS      ports.ScopedRootFS
	TransferRoot  algebraic.Option[pathalg.LocalDir]
	ArtifactRoot  algebraic.Option[pathalg.LocalDir]
	MaxHandles    int
}

// Registry 承载全部 7 个强类型判别式 MCP 工具的分派执行与跨请求受管句柄索引；
// 零值恒未初始化并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Registry struct {
	gate          gate.Authorizer
	inventory     *ucinv.Service
	session       *ucsess.Service
	transfer      *uctrans.Service
	automation    *ucauto.Service
	observability *ucobs.Service
	scopedFS      ports.ScopedRootFS
	transferRoot  algebraic.Option[pathalg.LocalDir]
	artifactRoot  algebraic.Option[pathalg.LocalDir]
	maxHandles    int

	mu            sync.Mutex
	ptyHandles    map[string]plan.ManagedHandle[plan.KindPTY]
	tunnelHandles map[string]plan.ManagedHandle[plan.KindTunnel]
	guiHandles    map[string]plan.ManagedHandle[plan.KindTunnel]
	muxHandles    map[string]plan.ManagedHandle[plan.KindMux]
	transfers     map[string]TransferBinding
	valid         bool
}

// NewRegistry 校验必填能力门控与可选沙箱根目录，构造不可绕过护栏的工具注册表。
func NewRegistry(cfg RegistryConfig) (*Registry, error) {
	if cfg.Gate == nil {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonFieldNil, domi18n.Str("field", "Gate"))
	}
	if tr, ok := cfg.TransferRoot.Get(); ok && !tr.IsValid() {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "TransferRoot"))
	}
	if ar, ok := cfg.ArtifactRoot.Get(); ok && !ar.IsValid() {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ArtifactRoot"))
	}
	if cfg.MaxHandles < 0 {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonFieldNegative, domi18n.Str("field", "MaxHandles"))
	}
	maxH := cfg.MaxHandles
	if maxH == 0 {
		maxH = defaultMaxTrackedHandles
	}
	return &Registry{
		gate:          cfg.Gate,
		inventory:     cfg.Inventory,
		session:       cfg.Session,
		transfer:      cfg.Transfer,
		automation:    cfg.Automation,
		observability: cfg.Observability,
		scopedFS:      cfg.ScopedFS,
		transferRoot:  cfg.TransferRoot,
		artifactRoot:  cfg.ArtifactRoot,
		maxHandles:    maxH,
		ptyHandles:    make(map[string]plan.ManagedHandle[plan.KindPTY]),
		tunnelHandles: make(map[string]plan.ManagedHandle[plan.KindTunnel]),
		guiHandles:    make(map[string]plan.ManagedHandle[plan.KindTunnel]),
		muxHandles:    make(map[string]plan.ManagedHandle[plan.KindMux]),
		transfers:     make(map[string]TransferBinding),
		valid:         true,
	}, nil
}

// CallTool 校验熔断态并按工具名分派至对应强类型判别式处理器；
// 返回的 rpcCode 在 Gate Halted 等系统级故障时供上层协议层决定是否同步返回 JSON-RPC 错误。
func (r *Registry) CallTool(ctx context.Context, name string, rawArgs jsontext.Value) (protocol.CallToolResult, int, error) {
	if r == nil || !r.valid {
		return protocol.CallToolResult{}, protocol.CodeInternalError, ErrRegistryNotInitialized
	}
	if ctx == nil {
		return protocol.CallToolResult{}, protocol.CodeInvalidParams, ports.ErrNilContext
	}
	if r.gate.IsHalted() {
		r.ClearTrackedHandles()
		return protocol.CallToolResult{}, protocol.CodeGateHalted, gate.ErrGateHalted
	}
	var (
		res protocol.CallToolResult
		err error
	)
	switch name {
	case protocol.ToolNameNodes:
		res, err = r.callNodes(ctx, rawArgs)
	case protocol.ToolNameTerminalExec:
		res, err = r.callTerminalExec(ctx, rawArgs)
	case protocol.ToolNameTerminalSession:
		res, err = r.callTerminalSession(ctx, rawArgs)
	case protocol.ToolNameFile:
		res, err = r.callFile(ctx, rawArgs)
	case protocol.ToolNameTransfer:
		res, err = r.callTransfer(ctx, rawArgs)
	case protocol.ToolNameTunnel:
		res, err = r.callTunnel(ctx, rawArgs)
	case protocol.ToolNameGUI:
		res, err = r.callGUI(ctx, rawArgs)
	default:
		err = domi18n.EF(protocol.ErrToolNotFound, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "MCP tool"), domi18n.BoundStr("value", name))
	}
	if err != nil {
		if r.gate.IsHalted() {
			r.ClearTrackedHandles()
		}
		errRes, code, encErr := protocol.NewToolErrorResult(err)
		if encErr != nil {
			return protocol.CallToolResult{}, protocol.CodeInternalError, encErr
		}
		return errRes, code, err
	}
	return res, 0, nil
}
