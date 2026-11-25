// Package inventory 实现 XOps v2 资产与目标解析用例服务（ADR-004 / ADR-009 / Plan P2.5-T2）。
//
// Phase 2.5 Walking Skeleton 切片职责：
//   - 提供只读目标解析 ResolveTarget，支持 OriginAdHoc（临时 [user@]host[:port]）与
//     OriginOpenSSHVirtual（~/.ssh/config 只读虚拟节点）；
//   - 通过 ports.OpenSSHConfigSource.ResolveTier4 折叠 Tier-4 选项，递归展开多跳 ProxyJump
//     （带环路检测与最大深度上限护栏），并严格经由唯一纯入口 option.ResolveEffectivePolicyWithOriginalHost
//     求解四层策略 t1(CLI) > t2(空) > t3(XOpsGlobal) > t4(OpenSSH) + DefaultOptionLayer()；
//   - 将每跳有效策略编译为强类型、零明文的 inventory.AuthMethod 与不可变 Merkle 链式
//     plan.SealedConnectionPlan（遵循 IdentityFile=none、IdentitiesOnly、BatchMode 与 INV-D2 裁剪规则）；
//   - 严守六边形边界：全包零 core/osfs 导入、零 core/internal/sshnet 导入、零裸 go 语句与零 nolint 豁免。
package inventory

import "errors"

const (
	defaultMaxJumpDepth = 16 // 默认最大 ProxyJump 递归跳板深度
	maxAllowedJumpDepth = 31 // 与 plan.SealedConnectionPlan 上限 32 跳对齐（最多 31 跳板 + 1 末跳目标）
	maxPlanHops         = 32 // 连接计划总跳数硬上限（与 core/domain/plan 保持一致）
	maxRawTargetBytes   = 512
)

// 本包导出的规范化哨兵错误，供 core/engine、用例调用方与测试以 errors.Is 精确判定。
var (
	// ErrNilContext 表示调用方传入了 nil context.Context。
	ErrNilContext = errors.New("usecase/inventory: context 不能为 nil")
	// ErrInvalidConfig 表示 ServiceConfig 参数非法。
	ErrInvalidConfig = errors.New("usecase/inventory: 无效的 ServiceConfig 配置")
	// ErrServiceNotInitialized 表示在零值或未初始化 Service 上调用方法。
	ErrServiceNotInitialized = errors.New("usecase/inventory: Service 未初始化")
	// ErrInvalidTarget 表示目标规格 [user@]host[:port] 或别名格式非法。
	ErrInvalidTarget = errors.New("usecase/inventory: 无效的目标规格")
	// ErrUnsupportedOrigin 表示请求了当前只读切片尚不支持的目标来源类别。
	ErrUnsupportedOrigin = errors.New("usecase/inventory: 不支持的目标来源类别")
	// ErrMissingUsername 表示四层策略与本机身份快照均无法确定远端 SSH 用户名。
	ErrMissingUsername = errors.New("usecase/inventory: 无法确定目标 SSH 用户名")
	// ErrNoAuthMethod 表示在当前策略约束下（如 IdentityFile=none + IdentitiesOnly + BatchMode）无可用认证方式。
	ErrNoAuthMethod = errors.New("usecase/inventory: 当前策略下无可用 SSH 认证方式")
	// ErrProxyJumpCycle 表示 ProxyJump 跳板链存在自环或多跳循环引用。
	ErrProxyJumpCycle = errors.New("usecase/inventory: ProxyJump 跳板链存在循环引用")
	// ErrProxyJumpDepthExceeded 表示 ProxyJump 递归深度或总跳数超过安全上限。
	ErrProxyJumpDepthExceeded = errors.New("usecase/inventory: ProxyJump 递归深度或总跳数超过安全上限")
)

func zeroVal[T any]() (z T) { return z }
