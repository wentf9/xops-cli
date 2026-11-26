// Package inventory 实现 XOps v2 全量资产管理与目标解析用例服务（ADR-004 / ADR-006 / ADR-008 / ADR-009 / Plan P2.5-T2 & P3-T1）。
//
// 核心职责：
//   - 目标解析 ResolveTarget：100% 兼容 Phase 2.5 只读切片并扩展支持托管节点与跨命名空间 ProxyJump；
//   - 乐观并发 CAS CRUD：写前全图 NewGraph 与跨命名空间 Tarjan SCC ProxyJump DAG 校验，严分 Durability 状态；
//   - 删除前反向引用与 5 位置+Pending 凭据保护/回收；
//   - 统一 FormatImporter / ImportBundle 导入调度（100% 零 v1 代码）；
//   - 只读零泄露 Doctor、全作用域 WithPendingEnrollment（PendingEnrollFSM）与加密私钥登记（VaultSagaFSM）。
package inventory

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

const (
	toolInventory            = "inventory"
	defaultMaxJumpDepth      = 16
	maxAllowedJumpDepth      = 31
	maxPlanHops              = 32
	maxRawTargetBytes        = 512
	defaultPendingEnrollTTL  = 5 * time.Minute
	terminalEventEmitTimeout = 50 * time.Millisecond
)

// 本包导出的规范化哨兵错误，保持 Phase 2.5 既有哨兵 100% 兼容并补充 Phase 3 全量错误语义。
var (
	ErrNilContext             = errors.New("usecase/inventory: context 不能为 nil")
	ErrInvalidConfig          = errors.New("usecase/inventory: 无效的 ServiceConfig 配置")
	ErrServiceNotInitialized  = errors.New("usecase/inventory: Service 未初始化")
	ErrInvalidTarget          = errors.New("usecase/inventory: 无效的目标规格")
	ErrUnsupportedOrigin      = errors.New("usecase/inventory: 不支持的目标来源类别")
	ErrMissingUsername        = errors.New("usecase/inventory: 无法确定目标 SSH 用户名")
	ErrNoAuthMethod           = errors.New("usecase/inventory: 当前策略下无可用 SSH 认证方式")
	ErrProxyJumpCycle         = errors.New("usecase/inventory: ProxyJump 跳板链存在循环引用")
	ErrProxyJumpDepthExceeded = errors.New("usecase/inventory: ProxyJump 递归深度或总跳数超过安全上限")
	ErrNilCallback            = errors.New("usecase/inventory: 回调函数不能为 nil")
	ErrInvalidRequest         = errors.New("usecase/inventory: 无效的资产操作请求")
	ErrStoreUnavailable       = errors.New("usecase/inventory: 未配置 InventoryStore")
	ErrGateUnavailable        = errors.New("usecase/inventory: 未配置 Gate 能力门控授权器")
	ErrVaultUnavailable       = errors.New("usecase/inventory: 未配置 SecretVault 或 CredentialService")
	ErrKeySignerUnavailable   = errors.New("usecase/inventory: 未配置 KeySignerPort")
	ErrInteractionUnavailable = errors.New("usecase/inventory: 当前环境不支持交互式输入")
	ErrClockUnavailable       = errors.New("usecase/inventory: 未配置 Clock 时钟端口")
	ErrAssetNotFound          = errors.New("usecase/inventory: 目标资产不存在")
	ErrAssetAlreadyExists     = errors.New("usecase/inventory: 目标资产标识已存在")
	ErrAssetStillReferenced   = errors.New("usecase/inventory: 目标资产仍被其他节点引用，拒绝删除")
	ErrSecretStillReferenced  = errors.New("usecase/inventory: 凭据或存储仍存在 5 位置或 Pending 引用")
	ErrUnknownImportFormat    = errors.New("usecase/inventory: 未注册的导入格式")
	ErrImportConflict         = errors.New("usecase/inventory: 导入预检发现冲突，拒绝写入")
	ErrCommitNotApplied       = errors.New("usecase/inventory: 配置 CAS 提交确认未生效")
	ErrUncertainDurability    = errors.New("usecase/inventory: 配置 CAS 提交已生效但未确认持久化，禁重试禁删凭据")
	ErrCommitOutcomeUnknown   = errors.New("usecase/inventory: 配置 CAS 提交结果未知，禁自动重试")
	ErrLeaseExpired           = errors.New("usecase/inventory: 首连暂存租约已超出作用域或失效")
	ErrEnrollmentAborted      = errors.New("usecase/inventory: 首连暂存登记已中止")
	ErrEnrollmentUncertain    = errors.New("usecase/inventory: 首连暂存登记陷入不确定终态，已保留凭据钉住")
	ErrKeyFingerprintMismatch = errors.New("usecase/inventory: 私钥解析指纹与预期指纹不匹配")
)

// AssetReferencedError、SecretReferencedError 与 RetainedSecret 描述删除保护错误与安全保留凭据。
type (
	//xops:opaque
	//xops:failclosed
	AssetReferencedError struct {
		assetKind, assetID string
		refs               []inventory.AssetReference
		valid              bool
	}
	//xops:opaque
	//xops:failclosed
	SecretReferencedError struct {
		subject string
		refs    []inventory.SecretReference
		valid   bool
	}
	RetainedSecret struct {
		Ref        secret.Ref
		References []inventory.SecretReference
	}
)

func newAssetReferencedError(kind, id string, refs []inventory.AssetReference) *AssetReferencedError {
	return &AssetReferencedError{kind, id, slices.Clone(refs), kind != "" && id != "" && len(refs) > 0}
}
func (e *AssetReferencedError) IsValid() bool {
	return e != nil && e.valid && e.assetKind != "" && e.assetID != "" && len(e.refs) > 0
}
func (e *AssetReferencedError) AssetKind() string {
	return getIfValid(e, func(v *AssetReferencedError) string { return v.assetKind })
}
func (e *AssetReferencedError) AssetID() string {
	return getIfValid(e, func(v *AssetReferencedError) string { return v.assetID })
}
func (e *AssetReferencedError) References() []inventory.AssetReference {
	return getIfValid(e, func(v *AssetReferencedError) []inventory.AssetReference { return slices.Clone(v.refs) })
}
func (e *AssetReferencedError) Unwrap() error {
	return pickIf[error](e.IsValid(), ErrAssetStillReferenced, nil)
}
func (e *AssetReferencedError) Error() string {
	if !e.IsValid() {
		return ErrAssetStillReferenced.Error()
	}
	return fmt.Sprintf("%s: %s %q 仍被 %d 处引用", ErrAssetStillReferenced, e.assetKind, e.assetID, len(e.refs))
}

func newSecretReferencedError(subject string, refs []inventory.SecretReference) *SecretReferencedError {
	return &SecretReferencedError{subject, slices.Clone(refs), subject != "" && len(refs) > 0}
}
func (e *SecretReferencedError) IsValid() bool {
	return e != nil && e.valid && e.subject != "" && len(e.refs) > 0
}
func (e *SecretReferencedError) Subject() string {
	return getIfValid(e, func(v *SecretReferencedError) string { return v.subject })
}
func (e *SecretReferencedError) References() []inventory.SecretReference {
	return getIfValid(e, func(v *SecretReferencedError) []inventory.SecretReference { return slices.Clone(v.refs) })
}
func (e *SecretReferencedError) Unwrap() error {
	return pickIf[error](e.IsValid(), ErrSecretStillReferenced, nil)
}
func (e *SecretReferencedError) Error() string {
	if !e.IsValid() {
		return ErrSecretStillReferenced.Error()
	}
	return fmt.Sprintf("%s: %s 仍存在 %d 处引用", ErrSecretStillReferenced, e.subject, len(e.refs))
}

func getIfValid[R interface{ IsValid() bool }, T any](r R, fn func(R) T) T {
	if !r.IsValid() {
		return zeroVal[T]()
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
