// Package engine 是 XOps v2 六边形核心（core）面向外部宿主（cmd/xops、internal/entry/{cli,tui,sftpshell,mcpcmd,muxdaemon} 与外部 xops-mcp）
// 唯一公开的运行期装配与全量业务门面（ADR-001 / ADR-008 / ADR-009 / ADR-010 / Plan P3-T5）。
//
// 核心架构与安全不变量：
//   - 生产源码严格零引用 core/ports/tck 与 core/internal/sim（由 xopsvet/archbound 强制），
//     仅装配真实主机密钥信任库（sshnet/hostkey）、真实 SSH 拨号器（sshnet/dial）、双通道纯内存
//     Actor 连接池（pool）、独占能力门控（gate）、全部 6 大用例服务
//     （usecase/{inventory,credential,session,transfer,automation,observability}）以及沙箱隔离的 MCP 运行时（mcpruntime）；
//   - 严格将 gate.OnHaltFunc 接线至 pool.GateHalted：StrictAgentProfile 下任一 AuditPostWriteError
//     触发不可逆 Halted 熔断后，连接池立即失效全部活跃句柄并拒绝一切后续租约；
//   - 为 MCPServer 独立装配物理零 OperatorReadFS 的 Transfer/Automation 用例服务，阻断沙箱逃逸；
//   - 暴露不透明公开值类型与两步审批契约（ErrApprovalRequired / ExtractApprovalChallenge / ApprovalSubmission），
//     使 internal/entry/** 仅依赖 core/{domain,events,engine,conc} 即可驱动全量业务而零触碰 core/internal/** 或 core/ports；
//   - 退出期 Close(ctx) 严格按派生 MCPServer -> 在途 UseCases 排空 -> 连接池 Pool -> 自有 SystemBus 逆序优雅停机，
//     绝不代为关闭由外部组合根（cmd/xops）持有的 AuditSink、ScopedRootFS 或外部注入的 SystemBus；
//   - 全包 0 init()、0 可变包级变量、0 裸 go 语句、0 nolint 豁免。
package engine

import "errors"

// 本包导出的规范化哨兵错误，供组合根与入站驱动适配器通过 errors.Is 精确区分运行期故障类别。
var (
	// ErrNilContext 表示调用传入的 context.Context 为 nil。
	ErrNilContext = errors.New("engine: context 不能为 nil")
	// ErrInvalidConfig 表示 Engine 构造配置缺少必填端口或参数非法。
	ErrInvalidConfig = errors.New("engine: 无效的 Engine Config 配置")
	// ErrEngineNotInitialized 表示在 nil 或零值未初始化 Engine 上调用方法。
	ErrEngineNotInitialized = errors.New("engine: Engine 未初始化")
	// ErrEngineClosed 表示 Engine 已进入关闭或已关闭状态，拒绝新请求。
	ErrEngineClosed = errors.New("engine: Engine 已关闭")
	// ErrEngineHalted 表示底层安全门控已进入不可逆 Halted 熔断态。
	ErrEngineHalted = errors.New("engine: Engine 安全门控已进入不可逆 Halted 熔断态")
	// ErrInvalidRequest 表示 SSH 目标解析、执行或交互请求的入参非法。
	ErrInvalidRequest = errors.New("engine: 无效的请求参数")
	// ErrInvalidProfile 表示安全策略配置档值非法。
	ErrInvalidProfile = errors.New("engine: 无效的 PolicyProfile 策略配置档")
	// ErrInvalidFallback 表示不可交互回退策略值非法。
	ErrInvalidFallback = errors.New("engine: 无效的 NoElicitFallback 回退策略")
	// ErrInvalidRequestTTY 表示 RequestTTYMode 模式值非法。
	ErrInvalidRequestTTY = errors.New("engine: 无效的 RequestTTY 模式")
	// ErrReconcilerUnavailable 表示未注入 AuditReconciler 崩溃审计对账端口。
	ErrReconcilerUnavailable = errors.New("engine: 未配置 AuditReconciler 崩溃对账端口")
	// ErrVaultUnavailable 表示未注入 SecretVault 凭据库端口，无法执行凭据用例。
	ErrVaultUnavailable = errors.New("engine: 未配置 SecretVault 凭据库端口")
	// ErrMCPServerNotInitialized 表示在 nil 或零值未初始化 MCPServer 上调用方法。
	ErrMCPServerNotInitialized = errors.New("engine: MCPServer 未初始化")
	// ErrProjectionNotInitialized 表示在 nil 或零值未初始化 Projection 上调用方法。
	ErrProjectionNotInitialized = errors.New("engine: Projection 未初始化")
	// ErrApprovalRequired 表示操作被护栏拦截并签发了两步审批挑战信封。
	ErrApprovalRequired = errors.New("engine: 操作需要两步审批确认")
)

func zeroVal[T any]() (z T) { return z }
