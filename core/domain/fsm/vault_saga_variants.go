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

func (k VaultSagaStateKind) IsValid() bool {
	return k >= VaultSagaKindInit && k <= VaultSagaKindFailedUncertain
}
func (k VaultSagaEffectKind) IsValid() bool {
	return k >= VaultEffectWriteNew && k <= VaultEffectCompensateDeleteNew
}
func (k VaultSagaEventKind) IsValid() bool {
	return k >= VaultEventStarted && k <= VaultEventHaltedUncertain
}
func (k VaultSagaStateKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "init", "writing_new", "verifying_readback", "committing_config", "checking_old_refs", "deleting_old", "compensating", "completed", "rolled_back", "uncertain_durability", "failed_uncertain")
}
func (k VaultSagaEffectKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "write_new", "verify_readback", "commit_config_cas", "check_old_refs", "delete_old", "compensate_delete_new")
}
func (k VaultSagaEventKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "started", "new_secret_written", "readback_verified", "readback_failed", "config_committed", "config_rejected", "old_refs_zero", "old_secret_gc_deferred", "old_secret_deleted", "compensated", "completed", "rolled_back", "uncertain_durability", "halted_uncertain")
}

// VaultSagaContextSpec 与 VaultSagaContext 承载单次凭据轮换/写入 Saga 的不可变只读元数据（零明文机密）。
type VaultSagaContextSpec struct {
	SagaID             security.OperationID
	NewRef             secret.Ref
	OldRef             algebraic.Option[secret.Ref]
	ExpectedCASVersion uint64
	ExpectedDigest     security.Digest
}

//xops:opaque
//xops:failclosed
type VaultSagaContext struct {
	sagaID             security.OperationID
	newRef             secret.Ref
	oldRef             algebraic.Option[secret.Ref]
	expectedCASVersion uint64
	expectedDigest     security.Digest
	valid              bool
}

// NewVaultSagaContext 校验 Saga 标识、新旧凭据引用（OldRef 不可与 NewRef 相同）与预期回读摘要。
func NewVaultSagaContext(spec VaultSagaContextSpec) (VaultSagaContext, error) {
	if !spec.SagaID.IsValid() || !spec.NewRef.IsValid() || !spec.ExpectedDigest.IsValid() {
		return VaultSagaContext{}, fmt.Errorf("%w: saga_id/new_ref/expected_digest 均须有效", ErrInvalidContext)
	}
	if old, ok := spec.OldRef.Get(); ok && (!old.IsValid() || old.Equal(spec.NewRef)) {
		return VaultSagaContext{}, fmt.Errorf("%w: old_ref 必须有效且不同于 new_ref", ErrInvalidContext)
	}
	return VaultSagaContext{spec.SagaID, spec.NewRef, spec.OldRef, spec.ExpectedCASVersion, spec.ExpectedDigest, true}, nil
}

func (c VaultSagaContext) IsValid() bool {
	return c.valid && c.sagaID.IsValid() && c.newRef.IsValid() && c.expectedDigest.IsValid()
}
func (c VaultSagaContext) SagaID() security.OperationID         { return c.sagaID }
func (c VaultSagaContext) NewRef() secret.Ref                   { return c.newRef }
func (c VaultSagaContext) OldRef() algebraic.Option[secret.Ref] { return c.oldRef }
func (c VaultSagaContext) ExpectedCASVersion() uint64           { return c.expectedCASVersion }
func (c VaultSagaContext) ExpectedDigest() security.Digest      { return c.expectedDigest }

// VaultSagaState 是 VaultSagaFSM 的封闭状态代数和类型（RFC §3.6），由 xopsvet/sumexhaust 穷尽检查。
//
//xops:failclosed
type VaultSagaState interface {
	sealedVaultSagaState()
	rawCtx() VaultSagaContext
	Kind() VaultSagaStateKind
	IsValid() bool
	IsTerminal() bool
}

type sealedVaultMixin struct {
	ctx   VaultSagaContext
	valid bool
}

func (*sealedVaultMixin) sealedVaultSagaState()      {}
func (m *sealedVaultMixin) rawCtx() VaultSagaContext { return m.ctx }

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
	VaultSagaCompensating struct {
		sealedVaultMixin
		reason string
	}
	//xops:opaque
	//xops:failclosed
	VaultSagaCompleted struct {
		sealedVaultMixin
		oldDeleted bool
		note       string
	}
	//xops:opaque
	//xops:failclosed
	VaultSagaRolledBack struct {
		sealedVaultMixin
		compensated bool
		reason      string
	}
	//xops:opaque
	//xops:failclosed
	VaultSagaUncertainDurability struct {
		sealedVaultMixin
		reason string
	}
	//xops:opaque
	//xops:failclosed
	VaultSagaFailedUncertain struct {
		sealedVaultMixin
		step   VaultSagaStateKind
		reason string
	}
)

func (s *VaultSagaInit) IsValid() bool                { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaWritingNew) IsValid() bool          { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaVerifyingReadback) IsValid() bool   { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaCommittingConfig) IsValid() bool    { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaCheckingOldRefs) IsValid() bool     { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaDeletingOld) IsValid() bool         { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaCompensating) IsValid() bool        { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaCompleted) IsValid() bool           { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaRolledBack) IsValid() bool          { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaUncertainDurability) IsValid() bool { return s != nil && s.valid && s.ctx.IsValid() }
func (s *VaultSagaFailedUncertain) IsValid() bool     { return s != nil && s.valid && s.ctx.IsValid() }

func (s *VaultSagaInit) Kind() VaultSagaStateKind { return vk(s.IsValid(), VaultSagaKindInit) }
func (s *VaultSagaWritingNew) Kind() VaultSagaStateKind {
	return vk(s.IsValid(), VaultSagaKindWritingNew)
}
func (s *VaultSagaVerifyingReadback) Kind() VaultSagaStateKind {
	return vk(s.IsValid(), VaultSagaKindVerifyingReadback)
}
func (s *VaultSagaCommittingConfig) Kind() VaultSagaStateKind {
	return vk(s.IsValid(), VaultSagaKindCommittingConfig)
}
func (s *VaultSagaCheckingOldRefs) Kind() VaultSagaStateKind {
	return vk(s.IsValid(), VaultSagaKindCheckingOldRefs)
}
func (s *VaultSagaDeletingOld) Kind() VaultSagaStateKind {
	return vk(s.IsValid(), VaultSagaKindDeletingOld)
}
func (s *VaultSagaCompensating) Kind() VaultSagaStateKind {
	return vk(s.IsValid(), VaultSagaKindCompensating)
}
func (s *VaultSagaCompleted) Kind() VaultSagaStateKind {
	return vk(s.IsValid(), VaultSagaKindCompleted)
}
func (s *VaultSagaRolledBack) Kind() VaultSagaStateKind {
	return vk(s.IsValid(), VaultSagaKindRolledBack)
}
func (s *VaultSagaUncertainDurability) Kind() VaultSagaStateKind {
	return vk(s.IsValid(), VaultSagaKindUncertainDurability)
}
func (s *VaultSagaFailedUncertain) Kind() VaultSagaStateKind {
	return vk(s.IsValid(), VaultSagaKindFailedUncertain)
}

func vk(ok bool, k VaultSagaStateKind) VaultSagaStateKind { return pickIf(ok, k, VaultSagaKindInvalid) }

// VaultSagaContextOf 提取任意 VaultSagaState 携带的不可变上下文；nil 或无效零值失败关闭返回零值。
func VaultSagaContextOf(state VaultSagaState) VaultSagaContext {
	if state == nil || !state.IsValid() {
		return VaultSagaContext{}
	}
	return state.rawCtx()
}

func (*VaultSagaInit) IsTerminal() bool                  { return false }
func (*VaultSagaWritingNew) IsTerminal() bool            { return false }
func (*VaultSagaVerifyingReadback) IsTerminal() bool     { return false }
func (*VaultSagaCommittingConfig) IsTerminal() bool      { return false }
func (*VaultSagaCheckingOldRefs) IsTerminal() bool       { return false }
func (*VaultSagaDeletingOld) IsTerminal() bool           { return false }
func (*VaultSagaCompensating) IsTerminal() bool          { return false }
func (s *VaultSagaCompleted) IsTerminal() bool           { return s.IsValid() }
func (s *VaultSagaRolledBack) IsTerminal() bool          { return s.IsValid() }
func (s *VaultSagaUncertainDurability) IsTerminal() bool { return s.IsValid() }
func (s *VaultSagaFailedUncertain) IsTerminal() bool     { return s.IsValid() }

func (s *VaultSagaCompensating) Reason() string {
	return pickLazy(s.IsValid(), func() string { return s.reason })
}
func (s *VaultSagaCompleted) OldDeleted() bool { return s.IsValid() && s.oldDeleted }
func (s *VaultSagaCompleted) Note() string {
	return pickLazy(s.IsValid(), func() string { return s.note })
}
func (s *VaultSagaRolledBack) Compensated() bool { return s.IsValid() && s.compensated }
func (s *VaultSagaRolledBack) Reason() string {
	return pickLazy(s.IsValid(), func() string { return s.reason })
}
func (s *VaultSagaUncertainDurability) Reason() string {
	return pickLazy(s.IsValid(), func() string { return s.reason })
}
func (s *VaultSagaFailedUncertain) Step() VaultSagaStateKind {
	return pickLazy(s.IsValid(), func() VaultSagaStateKind { return s.step })
}
func (s *VaultSagaFailedUncertain) Reason() string {
	return pickLazy(s.IsValid(), func() string { return s.reason })
}

// VaultSagaInput、VaultSagaEffect 与 VaultSagaEvent 为 VaultSagaFSM 的不透明值对象。
type (
	//xops:opaque
	//xops:failclosed
	VaultSagaInput struct {
		kind         uint8
		outcome      SideEffectOutcome
		durability   DurabilityStatus
		ok           bool
		actualDigest security.Digest
		refCount     int
		reason       string
		valid        bool
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
