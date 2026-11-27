// Package inventory 实现 XOps v2 全量资产管理与目标解析用例服务（ADR-004 / ADR-006 / ADR-008 / ADR-009 / Plan P2.5-T2 & P3-T1）。
//
// 核心职责：
//   - 目标解析 ResolveTarget：100% 兼容 Phase 2.5 只读切片并扩展支持托管节点与跨命名空间 ProxyJump；
//   - 乐观并发 CAS CRUD：写前全图 NewGraph 与跨命名空间 Tarjan SCC ProxyJump DAG 校验，严分 Durability 状态；
//   - 删除前反向引用与 5 位置+Pending 凭据保护/有界非取消安全回收；
//   - 统一 FormatImporter / ImportBundle 导入调度（100% 零 v1 代码）；
//   - 只读零泄露 Doctor、锁外执行 I/O 的全作用域 WithPendingEnrollment（PendingEnrollFSM）与加密私钥登记（VaultSagaFSM）。
package inventory

import (
	"slices"
	"time"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
)

const (
	toolInventory           = "inventory"
	defaultMaxJumpDepth     = 16
	maxAllowedJumpDepth     = 31
	maxPlanHops             = 32
	defaultPendingEnrollTTL = 5 * time.Minute
	cleanupEffectTimeout    = 5 * time.Second
)

// 本包导出的规范化哨兵错误，保持 Phase 2.5 既有哨兵 100% 兼容并补充 Phase 3 全量错误语义。
var (
	ErrNilContext             = domi18n.Sentinel(domi18n.KeyUCInvNilContext)        // 调用方传入 nil context
	ErrInvalidConfig          = domi18n.Sentinel(domi18n.KeyUCInvInvalidConfig)     // ServiceConfig 参数非法
	ErrServiceNotInitialized  = domi18n.Sentinel(domi18n.KeyUCInvNotInitialized)    // 零值或未初始化 Service
	ErrInvalidTarget          = domi18n.Sentinel(domi18n.KeyUCInvInvalidTarget)     // 目标解析规格非法
	ErrUnsupportedOrigin      = domi18n.Sentinel(domi18n.KeyUCInvUnsupportedOrigin) // 不支持的目标来源
	ErrMissingUsername        = domi18n.Sentinel(domi18n.KeyUCInvMissingUsername)   // 无法确定登录用户名
	ErrNoAuthMethod           = domi18n.Sentinel(domi18n.KeyUCInvNoAuthMethod)      // 无可用认证方式
	ErrProxyJumpCycle         = domi18n.Sentinel(domi18n.KeyUCInvProxyJumpCycle)    // 跳板链存在环路
	ErrProxyJumpDepthExceeded = domi18n.Sentinel(domi18n.KeyUCInvProxyJumpDepth)    // 跳板深度超限
	ErrNilCallback            = domi18n.Sentinel(domi18n.KeyUCInvNilCallback)       // 作用域闭包回调为空
	ErrInvalidRequest         = domi18n.Sentinel(domi18n.KeyUCInvInvalidRequest)    // 资产操作请求参数非法
	ErrStoreUnavailable       = domi18n.Sentinel(domi18n.KeyUCInvStoreUnavail)      // 缺少资产存储端口
	ErrGateUnavailable        = domi18n.Sentinel(domi18n.KeyUCInvGateUnavail)       // 缺少能力门控端口
	ErrVaultUnavailable       = domi18n.Sentinel(domi18n.KeyUCInvVaultUnavail)      // 缺少凭据库依赖
	ErrKeySignerUnavailable   = domi18n.Sentinel(domi18n.KeyUCInvKeySignerUnavail)  // 缺少私钥签名核验端口
	ErrInteractionUnavailable = domi18n.Sentinel(domi18n.KeyUCInvInteractUnavail)   // 不可交互环境
	ErrClockUnavailable       = domi18n.Sentinel(domi18n.KeyUCInvClockUnavail)      // 缺少时钟端口
	ErrAssetNotFound          = domi18n.Sentinel(domi18n.KeyUCInvAssetNotFound)     // 目标 Host/Identity/Node 缺失
	ErrAssetAlreadyExists     = domi18n.Sentinel(domi18n.KeyUCInvAssetExists)       // 目标标识重复
	ErrAssetStillReferenced   = domi18n.Sentinel(domi18n.KeyUCInvAssetReferenced)   // 存在反向资产引用
	ErrSecretStillReferenced  = domi18n.Sentinel(domi18n.KeyUCInvSecretReferenced)  // 存在 5 位置/Pending 凭据引用
	ErrUnknownImportFormat    = domi18n.Sentinel(domi18n.KeyUCInvUnknownImportFmt)  // 未注册 FormatImporter
	ErrImportConflict         = domi18n.Sentinel(domi18n.KeyUCInvImportConflict)    // 导入存在冲突
	ErrCommitNotApplied       = domi18n.Sentinel(domi18n.KeyUCInvCommitNotApplied)  // CAS 提交确认未生效
	ErrUncertainDurability    = domi18n.Sentinel(domi18n.KeyUCInvUncertainDurable)  // Applied && !Durable
	ErrCommitOutcomeUnknown   = domi18n.Sentinel(domi18n.KeyUCInvCommitUnknown)     // CAS 提交结果未知
	ErrLeaseExpired           = domi18n.Sentinel(domi18n.KeyUCInvLeaseExpired)      // 暂存租约已失效
	ErrEnrollmentAborted      = domi18n.Sentinel(domi18n.KeyUCInvEnrollAborted)     // 首连登记中止未落盘
	ErrEnrollmentUncertain    = domi18n.Sentinel(domi18n.KeyUCInvEnrollUncertain)   // 首连登记不确定终态
	ErrKeyFingerprintMismatch = domi18n.Sentinel(domi18n.KeyUCInvKeyFPMismatch)     // 私钥指纹失配
)

// RetainedSecret 复用 credential.RetainedSecret，描述因仍存在 5 位置或 Pending 引用而被安全保留的凭据条目。
type RetainedSecret = credential.RetainedSecret

// AssetReferencedError 与 SecretReferencedError 均为只读结构化删除拒绝错误，
// 分别 Unwrap 为 ErrAssetStillReferenced / ErrSecretStillReferenced 并实现 domi18n.LocalizableNode。
type (
	// AssetReferencedError 描述因仍被其他资产反向引用而拒绝删除的结构化错误。
	//
	//xops:opaque
	//xops:failclosed
	AssetReferencedError struct {
		assetKind, assetID string
		refs               []inventory.AssetReference
		valid              bool
	}
	// SecretReferencedError 描述因仍存在 5 位置或 Pending 凭据引用而拒绝删除的结构化错误。
	//
	//xops:opaque
	//xops:failclosed
	SecretReferencedError struct {
		subject string
		refs    []inventory.SecretReference
		valid   bool
	}
)

func newAssetReferencedError(kind, id string, refs []inventory.AssetReference) *AssetReferencedError {
	return &AssetReferencedError{assetKind: kind, assetID: id, refs: slices.Clone(refs), valid: kind != "" && id != "" && len(refs) > 0}
}

// AssetReferencedError 只读访问器与 error/Unwrap/LocalizableNode 接口实现（暴露 ErrAssetStillReferenced）。
func (e *AssetReferencedError) IsValid() bool {
	return e != nil && e.valid && e.assetKind != "" && e.assetID != "" && len(e.refs) > 0
}
func (e *AssetReferencedError) AssetKind() string {
	return ifValid(e, func(v *AssetReferencedError) string { return v.assetKind })
}
func (e *AssetReferencedError) AssetID() string {
	return ifValid(e, func(v *AssetReferencedError) string { return v.assetID })
}
func (e *AssetReferencedError) References() []inventory.AssetReference {
	return ifValid(e, func(v *AssetReferencedError) []inventory.AssetReference { return slices.Clone(v.refs) })
}
func (e *AssetReferencedError) Unwrap() error {
	return pickIf[error](e.IsValid(), ErrAssetStillReferenced, nil)
}
func (e *AssetReferencedError) LocalizableView() domi18n.ErrorNode {
	if !e.IsValid() {
		return domi18n.ErrorNode{Sentinel: ErrAssetStillReferenced}
	}
	return domi18n.ErrorNode{
		Sentinel: ErrAssetStillReferenced,
		Message: domi18n.NewMessage(
			domi18n.KeyUCInvAssetRefDetail,
			domi18n.BoundStr("kind", e.assetKind),
			domi18n.BoundStr("id", e.assetID),
			domi18n.Int("count", len(e.refs)),
		),
	}
}
func (e *AssetReferencedError) Error() string { return domi18n.CanonicalError(e) }

func newSecretReferencedError(subject string, refs []inventory.SecretReference) *SecretReferencedError {
	return &SecretReferencedError{subject: subject, refs: slices.Clone(refs), valid: subject != "" && len(refs) > 0}
}

// SecretReferencedError 只读访问器与 error/Unwrap/LocalizableNode 接口实现（暴露 ErrSecretStillReferenced）。
func (e *SecretReferencedError) IsValid() bool {
	return e != nil && e.valid && e.subject != "" && len(e.refs) > 0
}
func (e *SecretReferencedError) Subject() string {
	return ifValid(e, func(v *SecretReferencedError) string { return v.subject })
}
func (e *SecretReferencedError) References() []inventory.SecretReference {
	return ifValid(e, func(v *SecretReferencedError) []inventory.SecretReference { return slices.Clone(v.refs) })
}
func (e *SecretReferencedError) Unwrap() error {
	return pickIf[error](e.IsValid(), ErrSecretStillReferenced, nil)
}
func (e *SecretReferencedError) LocalizableView() domi18n.ErrorNode {
	if !e.IsValid() {
		return domi18n.ErrorNode{Sentinel: ErrSecretStillReferenced}
	}
	return domi18n.ErrorNode{
		Sentinel: ErrSecretStillReferenced,
		Message: domi18n.NewMessage(
			domi18n.KeyUCInvSecretRefDetail,
			domi18n.BoundStr("subject", e.subject),
			domi18n.Int("count", len(e.refs)),
		),
	}
}
func (e *SecretReferencedError) Error() string { return domi18n.CanonicalError(e) }

func ifValid[R interface{ IsValid() bool }, T any](r R, fn func(R) T) T {
	return ifValidOr(r, zeroVal[T](), fn)
}
func ifValidOr[R interface{ IsValid() bool }, T any](r R, fallback T, fn func(R) T) T {
	if !r.IsValid() {
		return fallback
	}
	return fn(r)
}

func zeroVal[T any]() (z T) { return z }
func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}
