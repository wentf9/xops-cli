package fsm

import (
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// VaultSagaStateKind、VaultSagaEffectKind 与 VaultSagaEventKind 为 VaultSagaFSM 失败关闭枚举。
type (
	//xops:opaque
	//xops:failclosed
	VaultSagaStateKind uint8
	//xops:opaque
	//xops:failclosed
	VaultSagaEffectKind uint8
	//xops:opaque
	//xops:failclosed
	VaultSagaEventKind uint8
)

const (
	VaultSagaKindInvalid VaultSagaStateKind = iota
	VaultSagaKindInit
	VaultSagaKindWritingNew
	VaultSagaKindVerifyingReadback
	VaultSagaKindCommittingConfig
	VaultSagaKindCheckingOldRefs
	VaultSagaKindDeletingOld
	VaultSagaKindCompensating
	VaultSagaKindCompleted
	VaultSagaKindRolledBack
	VaultSagaKindUncertainDurability
	VaultSagaKindFailedUncertain
)
const (
	vaultInInvalid uint8 = iota
	vaultInStart
	vaultInWriteNew
	vaultInReadback
	vaultInCommitCAS
	vaultInOldRefs
	vaultInDeleteOld
	vaultInCompensate
)
const (
	VaultEffectInvalid VaultSagaEffectKind = iota
	VaultEffectWriteNew
	VaultEffectVerifyReadback
	VaultEffectCommitConfigCAS
	VaultEffectCheckOldRefs
	VaultEffectDeleteOld
	VaultEffectCompensateDeleteNew
)
const (
	VaultEventInvalid VaultSagaEventKind = iota
	VaultEventStarted
	VaultEventNewSecretWritten
	VaultEventReadbackVerified
	VaultEventReadbackFailed
	VaultEventConfigCommitted
	VaultEventConfigRejected
	VaultEventOldRefsZero
	VaultEventOldSecretGCDeferred
	VaultEventOldSecretDeleted
	VaultEventCompensated
	VaultEventCompleted
	VaultEventRolledBack
	VaultEventUncertainDurability
	VaultEventHaltedUncertain
)

// VaultSagaContextSpec 与 VaultSagaContext 承载单次凭据轮换/写入 Saga 的不可变只读元数据（零明文、零凭据摘要）。
type (
	VaultSagaContextSpec struct {
		SagaID             security.OperationID
		NewRef             secret.Ref
		OldRef             algebraic.Option[secret.Ref]
		ExpectedCASVersion uint64
	}
	//xops:opaque
	//xops:failclosed
	VaultSagaContext struct {
		sagaID             security.OperationID
		newRef             secret.Ref
		oldRef             algebraic.Option[secret.Ref]
		expectedCASVersion uint64
		valid              bool
	}
)

// NewVaultSagaContext 校验 Saga 标识与新旧凭据引用（OldRef 若存在须有效且不同于 NewRef），零明文、零凭据摘要。
func NewVaultSagaContext(spec VaultSagaContextSpec) (VaultSagaContext, error) {
	if !spec.SagaID.IsValid() || !spec.NewRef.IsValid() {
		return VaultSagaContext{}, fmt.Errorf("%w: saga_id 与 new_ref 均须有效", ErrInvalidContext)
	}
	if old, ok := spec.OldRef.Get(); ok && (!old.IsValid() || old.Equal(spec.NewRef)) {
		return VaultSagaContext{}, fmt.Errorf("%w: old_ref 必须有效且不同于 new_ref", ErrInvalidContext)
	}
	return VaultSagaContext{spec.SagaID, spec.NewRef, spec.OldRef, spec.ExpectedCASVersion, true}, nil
}
func (c VaultSagaContext) IsValid() bool                        { return c.valid && c.sagaID.IsValid() && c.newRef.IsValid() }
func (c VaultSagaContext) SagaID() security.OperationID         { return c.sagaID }
func (c VaultSagaContext) NewRef() secret.Ref                   { return c.newRef }
func (c VaultSagaContext) OldRef() algebraic.Option[secret.Ref] { return c.oldRef }
func (c VaultSagaContext) ExpectedCASVersion() uint64           { return c.expectedCASVersion }

// VaultSagaState 是 VaultSagaFSM 的封闭状态代数和类型（RFC §3.6），由 xopsvet/sumexhaust 穷尽检查。
//
//xops:failclosed
type VaultSagaState interface {
	sealedVaultSagaState()
	rawCtx() VaultSagaContext
	rawKind() VaultSagaStateKind
	rawReason() string
	Kind() VaultSagaStateKind
	IsValid() bool
	IsTerminal() bool
}
type sealedVaultMixin struct {
	ctx    VaultSagaContext
	kind   VaultSagaStateKind
	reason string
	valid  bool
}

func (*sealedVaultMixin) sealedVaultSagaState()         {}
func (m *sealedVaultMixin) rawCtx() VaultSagaContext    { return m.ctx }
func (m *sealedVaultMixin) rawKind() VaultSagaStateKind { return m.kind }
func (m *sealedVaultMixin) rawReason() string           { return m.reason }
func vMix(ctx VaultSagaContext, kind VaultSagaStateKind, reason string) sealedVaultMixin {
	return sealedVaultMixin{ctx: ctx, kind: kind, reason: reason, valid: true}
}

// VaultSagaState 的 11 个不可变封闭指针变体（全部全私有字段、内置正向 valid 门控，零值恒无效）。
// 其中 VaultSagaUncertainDurability 对应 Applied && !Durable 零重试零删凭据停机态，
// VaultSagaFailedUncertain 对应副作用结果未知或补偿失败后的不可自动重试终态。
type (
	//xops:opaque
	//xops:failclosed
	VaultSagaInit struct{ sealedVaultMixin }
	//xops:opaque
	//xops:failclosed
	VaultSagaWritingNew struct{ sealedVaultMixin }
	//xops:opaque
	//xops:failclosed
	VaultSagaVerifyingReadback struct{ sealedVaultMixin }
	//xops:opaque
	//xops:failclosed
	VaultSagaCommittingConfig struct{ sealedVaultMixin }
	//xops:opaque
	//xops:failclosed
	VaultSagaCheckingOldRefs struct{ sealedVaultMixin }
	//xops:opaque
	//xops:failclosed
	VaultSagaDeletingOld struct{ sealedVaultMixin }
	//xops:opaque
	//xops:failclosed
	VaultSagaCompensating struct{ sealedVaultMixin }
	//xops:opaque
	//xops:failclosed
	VaultSagaCompleted struct {
		sealedVaultMixin
		oldDeleted bool
	}
	//xops:opaque
	//xops:failclosed
	VaultSagaRolledBack struct {
		sealedVaultMixin
		compensated bool
	}
	//xops:opaque
	//xops:failclosed
	VaultSagaUncertainDurability struct{ sealedVaultMixin }
	//xops:opaque
	//xops:failclosed
	VaultSagaFailedUncertain struct {
		sealedVaultMixin
		step VaultSagaStateKind
	}
)

func (s *VaultSagaInit) IsValid() bool                           { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaWritingNew) IsValid() bool                     { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaVerifyingReadback) IsValid() bool              { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaCommittingConfig) IsValid() bool               { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaCheckingOldRefs) IsValid() bool                { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaDeletingOld) IsValid() bool                    { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaCompensating) IsValid() bool                   { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaCompleted) IsValid() bool                      { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaRolledBack) IsValid() bool                     { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaUncertainDurability) IsValid() bool            { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaFailedUncertain) IsValid() bool                { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaInit) Kind() VaultSagaStateKind                { return vKind(s) }
func (s *VaultSagaWritingNew) Kind() VaultSagaStateKind          { return vKind(s) }
func (s *VaultSagaVerifyingReadback) Kind() VaultSagaStateKind   { return vKind(s) }
func (s *VaultSagaCommittingConfig) Kind() VaultSagaStateKind    { return vKind(s) }
func (s *VaultSagaCheckingOldRefs) Kind() VaultSagaStateKind     { return vKind(s) }
func (s *VaultSagaDeletingOld) Kind() VaultSagaStateKind         { return vKind(s) }
func (s *VaultSagaCompensating) Kind() VaultSagaStateKind        { return vKind(s) }
func (s *VaultSagaCompleted) Kind() VaultSagaStateKind           { return vKind(s) }
func (s *VaultSagaRolledBack) Kind() VaultSagaStateKind          { return vKind(s) }
func (s *VaultSagaUncertainDurability) Kind() VaultSagaStateKind { return vKind(s) }
func (s *VaultSagaFailedUncertain) Kind() VaultSagaStateKind     { return vKind(s) }
func (*VaultSagaInit) IsTerminal() bool                          { return false }
func (*VaultSagaWritingNew) IsTerminal() bool                    { return false }
func (*VaultSagaVerifyingReadback) IsTerminal() bool             { return false }
func (*VaultSagaCommittingConfig) IsTerminal() bool              { return false }
func (*VaultSagaCheckingOldRefs) IsTerminal() bool               { return false }
func (*VaultSagaDeletingOld) IsTerminal() bool                   { return false }
func (*VaultSagaCompensating) IsTerminal() bool                  { return false }
func (s *VaultSagaCompleted) IsTerminal() bool                   { return s.IsValid() }
func (s *VaultSagaRolledBack) IsTerminal() bool                  { return s.IsValid() }
func (s *VaultSagaUncertainDurability) IsTerminal() bool         { return s.IsValid() }
func (s *VaultSagaFailedUncertain) IsTerminal() bool             { return s.IsValid() }
func (s *VaultSagaCompensating) Reason() string                  { return vText(s) }
func (s *VaultSagaCompleted) OldDeleted() bool                   { return s.IsValid() && s.oldDeleted }
func (s *VaultSagaCompleted) Note() string                       { return vText(s) }
func (s *VaultSagaRolledBack) Compensated() bool                 { return s.IsValid() && s.compensated }
func (s *VaultSagaRolledBack) Reason() string                    { return vText(s) }
func (s *VaultSagaUncertainDurability) Reason() string           { return vText(s) }
func (s *VaultSagaFailedUncertain) Reason() string               { return vText(s) }
func (s *VaultSagaFailedUncertain) Step() VaultSagaStateKind {
	if s.IsValid() {
		return s.step
	}
	return VaultSagaKindInvalid
}
func vKind(s VaultSagaState) VaultSagaStateKind {
	if s != nil && s.IsValid() {
		return s.rawKind()
	}
	return VaultSagaKindInvalid
}
func vText(s VaultSagaState) string {
	if s != nil && s.IsValid() {
		return s.rawReason()
	}
	return ""
}

// VaultSagaContextOf 提取任意 VaultSagaState 携带的不可变上下文；nil 或无效零值失败关闭返回零值。
func VaultSagaContextOf(state VaultSagaState) VaultSagaContext {
	if state == nil || !state.IsValid() {
		return VaultSagaContext{}
	}
	return state.rawCtx()
}

// VaultSagaInput、VaultSagaEffect 与 VaultSagaEvent 为 VaultSagaFSM 的不透明值对象。
type (
	//xops:opaque
	//xops:failclosed
	VaultSagaInput struct {
		kind       uint8
		outcome    SideEffectOutcome
		durability DurabilityStatus
		ok         bool
		refCount   int
		reason     string
		valid      bool
	}
	//xops:opaque
	//xops:failclosed
	VaultSagaEffect struct {
		kind       VaultSagaEffectKind
		ref        secret.Ref
		casVersion uint64
		valid      bool
	}
)

func (i VaultSagaInput) IsValid() bool {
	return i.valid && i.kind >= vaultInStart && i.kind <= vaultInCompensate
}
func (e VaultSagaEffect) IsValid() bool             { return e.valid && e.kind.IsValid() }
func (e VaultSagaEffect) Kind() VaultSagaEffectKind { return e.kind }
func (e VaultSagaEffect) Ref() secret.Ref           { return e.ref }
func (e VaultSagaEffect) CASVersion() uint64        { return e.casVersion }

// VaultSagaEvent 为 VaultSagaFSM 发出的不可变脱敏事件。
type VaultSagaEvent = Event[VaultSagaEventKind]
