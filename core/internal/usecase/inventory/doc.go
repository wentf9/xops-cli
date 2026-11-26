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
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
)

const (
	toolInventory           = "inventory"
	defaultMaxJumpDepth     = 16
	maxAllowedJumpDepth     = 31
	maxPlanHops             = 32
	maxRawTargetBytes       = 512
	defaultPendingEnrollTTL = 5 * time.Minute
	cleanupEffectTimeout    = 5 * time.Second
)

// 本包导出的规范化哨兵错误，保持 Phase 2.5 既有哨兵 100% 兼容并补充 Phase 3 全量错误语义。
var (
	ErrNilContext             = errors.New("usecase/inventory: context 不能为 nil")                     // 调用方传入 nil context
	ErrInvalidConfig          = errors.New("usecase/inventory: 无效的 ServiceConfig 配置")                // ServiceConfig 参数非法
	ErrServiceNotInitialized  = errors.New("usecase/inventory: Service 未初始化")                        // 零值或未初始化 Service
	ErrInvalidTarget          = errors.New("usecase/inventory: 无效的目标规格")                             // 目标解析规格非法
	ErrUnsupportedOrigin      = errors.New("usecase/inventory: 不支持的目标来源类别")                          // 不支持的目标来源
	ErrMissingUsername        = errors.New("usecase/inventory: 无法确定目标 SSH 用户名")                      // 无法确定登录用户名
	ErrNoAuthMethod           = errors.New("usecase/inventory: 当前策略下无可用 SSH 认证方式")                   // 无可用认证方式
	ErrProxyJumpCycle         = errors.New("usecase/inventory: ProxyJump 跳板链存在循环引用")                 // 跳板链存在环路
	ErrProxyJumpDepthExceeded = errors.New("usecase/inventory: ProxyJump 递归深度或总跳数超过安全上限")            // 跳板深度超限
	ErrNilCallback            = errors.New("usecase/inventory: 回调函数不能为 nil")                         // 作用域闭包回调为空
	ErrInvalidRequest         = errors.New("usecase/inventory: 无效的资产操作请求")                           // 资产操作请求参数非法
	ErrStoreUnavailable       = errors.New("usecase/inventory: 未配置 InventoryStore")                  // 缺少资产存储端口
	ErrGateUnavailable        = errors.New("usecase/inventory: 未配置 Gate 能力门控授权器")                    // 缺少能力门控端口
	ErrVaultUnavailable       = errors.New("usecase/inventory: 未配置 SecretVault 或 CredentialService") // 缺少凭据库依赖
	ErrKeySignerUnavailable   = errors.New("usecase/inventory: 未配置 KeySignerPort")                   // 缺少私钥签名核验端口
	ErrInteractionUnavailable = errors.New("usecase/inventory: 当前环境不支持交互式输入")                        // 不可交互环境
	ErrClockUnavailable       = errors.New("usecase/inventory: 未配置 Clock 时钟端口")                      // 缺少时钟端口
	ErrAssetNotFound          = errors.New("usecase/inventory: 目标资产不存在")                             // 目标 Host/Identity/Node 缺失
	ErrAssetAlreadyExists     = errors.New("usecase/inventory: 目标资产标识已存在")                           // 目标标识重复
	ErrAssetStillReferenced   = errors.New("usecase/inventory: 目标资产仍被其他节点引用，拒绝删除")                   // 存在反向资产引用
	ErrSecretStillReferenced  = errors.New("usecase/inventory: 凭据或存储仍存在 5 位置或 Pending 引用")           // 存在 5 位置/Pending 凭据引用
	ErrUnknownImportFormat    = errors.New("usecase/inventory: 未注册的导入格式")                            // 未注册 FormatImporter
	ErrImportConflict         = errors.New("usecase/inventory: 导入预检发现冲突，拒绝写入")                       // 导入存在冲突
	ErrCommitNotApplied       = errors.New("usecase/inventory: 配置 CAS 提交确认未生效")                      // CAS 提交确认未生效
	ErrUncertainDurability    = errors.New("usecase/inventory: 配置 CAS 提交已生效但未确认持久化，禁重试禁删凭据")         // Applied && !Durable
	ErrCommitOutcomeUnknown   = errors.New("usecase/inventory: 配置 CAS 提交结果未知，禁自动重试")                 // CAS 提交结果未知
	ErrLeaseExpired           = errors.New("usecase/inventory: 首连暂存租约已超出作用域或失效")                     // 暂存租约已失效
	ErrEnrollmentAborted      = errors.New("usecase/inventory: 首连暂存登记已中止")                           // 首连登记中止未落盘
	ErrEnrollmentUncertain    = errors.New("usecase/inventory: 首连暂存登记陷入不确定终态，已保留凭据钉住")               // 首连登记不确定终态
	ErrKeyFingerprintMismatch = errors.New("usecase/inventory: 私钥解析指纹与预期指纹不匹配")                      // 私钥指纹失配
)

// RetainedSecret 复用 credential.RetainedSecret，描述因仍存在 5 位置或 Pending 引用而被安全保留的凭据条目。
type RetainedSecret = credential.RetainedSecret

// AssetReferencedError 与 SecretReferencedError 均为只读结构化删除拒绝错误（分别 Unwrap 为 ErrAssetStillReferenced / ErrSecretStillReferenced）。
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

// AssetReferencedError 只读访问器与 error/Unwrap 接口实现（暴露 ErrAssetStillReferenced）。
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
func (e *AssetReferencedError) Error() string {
	return ifValidOr(e, ErrAssetStillReferenced.Error(), func(v *AssetReferencedError) string {
		return fmt.Sprintf("%s: %s %q 仍被 %d 处引用", ErrAssetStillReferenced, v.assetKind, v.assetID, len(v.refs))
	})
}

func newSecretReferencedError(subject string, refs []inventory.SecretReference) *SecretReferencedError {
	return &SecretReferencedError{subject: subject, refs: slices.Clone(refs), valid: subject != "" && len(refs) > 0}
}

// SecretReferencedError 只读访问器与 error/Unwrap 接口实现（暴露 ErrSecretStillReferenced）。
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
func (e *SecretReferencedError) Error() string {
	return ifValidOr(e, ErrSecretStillReferenced.Error(), func(v *SecretReferencedError) string {
		return fmt.Sprintf("%s: %s 仍存在 %d 处引用", ErrSecretStillReferenced, v.subject, len(v.refs))
	})
}

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
