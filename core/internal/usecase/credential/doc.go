// Package credential 实现 XOps v2 凭据库生命周期管理、5 位置引用安全回收与 VaultSagaFSM
// 执行用例服务（ADR-008 / ADR-011 / ADR-016 / Plan P3-T1）。
//
// 核心安全与架构不变量：
//   - 全作用域零逃逸：对外与对内统一采用 SecretVault.WithSecret、secret.WithBytes 与
//     InteractionPort.PromptSecret 作用域借用闭包（//xops:syncclosure + //xops:borrowed），
//     严禁返回裸 *secret.SecretBox 或将其存入结构体/错误/日志/事件；
//   - 零明文消费：本包不在 5 个明文消费白名单包内，严禁调用 (*secret.SecretBox).Use，
//     全部回读校验与交互确认均通过常量时间 (*secret.SecretBox).Equal 完成；
//   - 严格驱动纯状态机 fsm.VaultSagaFSM：先写 Vault 并执行常量时间回读与可选扩展核验，
//     再提交配置 CAS，最后在重新加载的全图 5 位置（SecretLocAuthPassword..SecretLocNodePrivilege）
//     与活跃 Pending 租约（SecretLocPending）零引用确认后回收旧凭据；
//   - 严分 OutcomeUnknown（进入 FailedUncertain 零重试零盲删）与 Applied && !Durable
//     （进入 UncertainDurability 零重试且绝不删新旧凭据），并向 gate.Authorized 上报
//     *execution.OutcomeUnknown 以保持审计账本忠实；
//   - 严守六边形边界：全包零 core/osfs 导入、零 core/internal/sshnet 导入、零裸 go 语句与零 nolint 豁免。
package credential

import (
	"slices"
	"time"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

const (
	toolCredential           = "credential"
	randomSecretItemBytes    = 16
	terminalEventEmitTimeout = 50 * time.Millisecond
	cleanupEffectTimeout     = 5 * time.Second
)

// 本包导出的规范哨兵错误，供用例调用方、core/engine 与测试以 errors.Is 精确判定故障类别。
var (
	// ErrNilContext 表示调用方传入了 nil context.Context。
	ErrNilContext = domi18n.Sentinel(domi18n.KeyUCCredNilContext)
	// ErrNilCallback 表示作用域闭包回调为 nil。
	ErrNilCallback = domi18n.Sentinel(domi18n.KeyUCCredNilCallback)
	// ErrInvalidConfig 表示 ServiceConfig 缺少必填依赖或参数非法。
	ErrInvalidConfig = domi18n.Sentinel(domi18n.KeyUCCredInvalidConfig)
	// ErrServiceNotInitialized 表示在零值或未初始化 Service 上调用方法。
	ErrServiceNotInitialized = domi18n.Sentinel(domi18n.KeyUCCredNotInitialized)
	// ErrInvalidRequest 表示凭据操作请求参数无效。
	ErrInvalidRequest = domi18n.Sentinel(domi18n.KeyUCCredInvalidRequest)
	// ErrInvalidSecretBox 表示传入的 *secret.SecretBox 为 nil、零值或已销毁。
	ErrInvalidSecretBox = domi18n.Sentinel(domi18n.KeyUCCredInvalidSecretBox)
	// ErrVaultControlUnavailable 表示未注入 ports.VaultControlPort，无法执行凭据库生命周期控制。
	ErrVaultControlUnavailable = domi18n.Sentinel(domi18n.KeyUCCredVaultCtrlUnavail)
	// ErrStoreUnavailable 表示未注入 ports.InventoryStore，无法执行配置 CAS 或 5 位置引用检查。
	ErrStoreUnavailable = domi18n.Sentinel(domi18n.KeyUCCredStoreUnavail)
	// ErrInteractionUnavailable 表示未注入 ports.InteractionPort 或当前环境不可交互。
	ErrInteractionUnavailable = domi18n.Sentinel(domi18n.KeyUCCredInteractUnavail)
	// ErrPassphraseConfirmMismatch 表示交互式两次输入的主口令常量时间比对不一致。
	ErrPassphraseConfirmMismatch = domi18n.Sentinel(domi18n.KeyUCCredPassphraseDiff)
	// ErrSecretStillReferenced 表示凭据仍被资产图 5 处位置或活跃 Pending 租约引用，拒绝删除。
	ErrSecretStillReferenced = domi18n.Sentinel(domi18n.KeyUCCredSecretReferenced)
	// ErrSagaRolledBack 表示 VaultSagaFSM 已安全回滚（未生效配置且已补偿清理新凭据）。
	ErrSagaRolledBack = domi18n.Sentinel(domi18n.KeyUCCredSagaRolledBack)
	// ErrUncertainDurability 表示配置 CAS 处于 Applied && !Durable 状态，停机禁重试且禁删凭据。
	ErrUncertainDurability = domi18n.Sentinel(domi18n.KeyUCCredUncertainDurable)
	// ErrSagaUncertain 表示 VaultSagaFSM 副作用结果未知或补偿失败，停机禁自动重试。
	ErrSagaUncertain = domi18n.Sentinel(domi18n.KeyUCCredSagaUncertain)
)

// PendingSecretRefProvider 向凭据服务提供当前运行期全部活跃的待确认暂存凭据引用（SecretLocPending），
// 防止 VaultSagaFSM 或手动删除误回收尚未落盘的首连暂存凭据。
type PendingSecretRefProvider interface {
	ActivePendingSecretRefs() []inventory.PendingSecretRef
}

// SecretReferencedError 携带阻止凭据删除或回收的精确 5 位置与 Pending 引用清单（零明文），
// 实现 Unwrap() -> ErrSecretStillReferenced 与 domi18n.LocalizableNode，支持 errors.Is、errors.AsType 与边界本地化。
//
//xops:opaque
//xops:failclosed
type SecretReferencedError struct {
	ref   secret.Ref
	refs  []inventory.SecretReference
	valid bool
}

// newSecretReferencedError 构造不可变的 *SecretReferencedError。
func newSecretReferencedError(ref secret.Ref, refs []inventory.SecretReference) *SecretReferencedError {
	return &SecretReferencedError{
		ref:   ref,
		refs:  slices.Clone(refs),
		valid: ref.IsValid() && len(refs) > 0,
	}
}

// IsValid 报告错误对象是否包含有效的目标引用与非空占用引用列表。
func (e *SecretReferencedError) IsValid() bool {
	return e != nil && e.valid && e.ref.IsValid() && len(e.refs) > 0
}

// Ref 返回被拒绝删除的目标凭据引用。
func (e *SecretReferencedError) Ref() secret.Ref {
	if !e.IsValid() {
		return zeroVal[secret.Ref]()
	}
	return e.ref
}

// References 返回仍占用该凭据的全部 5 位置与 Pending 引用副本。
func (e *SecretReferencedError) References() []inventory.SecretReference {
	if !e.IsValid() {
		return nil
	}
	return slices.Clone(e.refs)
}

// Unwrap 返回哨兵错误 ErrSecretStillReferenced。
func (e *SecretReferencedError) Unwrap() error {
	if !e.IsValid() {
		return nil
	}
	return ErrSecretStillReferenced
}

// LocalizableView 实现 domi18n.LocalizableNode，返回脱敏结构化错误节点视图（nil 或无效实例退化为无哨兵纯消息兜底，与 Unwrap()==nil 一致）。
func (e *SecretReferencedError) LocalizableView() domi18n.ErrorNode {
	if !e.IsValid() {
		return domi18n.ErrorNode{Message: domi18n.NewMessage(domi18n.KeyUCCredSecretReferenced)}
	}
	return domi18n.ErrorNode{
		Sentinel: ErrSecretStillReferenced,
		Message: domi18n.NewMessage(
			domi18n.KeyUCCredSecretRefDetail,
			domi18n.BoundStr("ref", e.ref.String()),
			domi18n.Int("count", len(e.refs)),
			domi18n.BoundStr("location", e.refs[0].Location.String()),
			domi18n.BoundStr("owner", e.refs[0].OwnerID),
		),
	}
}

// Error 返回恒定规范英文脱敏诊断描述（委托至 domi18n.CanonicalError，绝不含明文）。
func (e *SecretReferencedError) Error() string {
	return domi18n.CanonicalError(e)
}

func zeroVal[T any]() (z T) { return z }

func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}

func sanitizeASCIICode(raw, fallback string) string {
	if raw == "" || len(raw) > 64 {
		return fallback
	}
	for i := range len(raw) {
		if raw[i] < 0x21 || raw[i] > 0x7E {
			return fallback
		}
	}
	return raw
}
