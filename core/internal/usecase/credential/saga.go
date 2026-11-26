package credential

import (
	"context"
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

const maxVaultSagaSteps = 16

// GraphMutator 根据最新资产图快照与已落盘校验的新凭据引用构造下一版待 CAS 提交的资产图。
type GraphMutator func(ctx context.Context, snap ports.InventorySnapshot, newRef secret.Ref) (inventory.Graph, error)

// NewSecretVerifier 是紧随常量时间回读之后执行的可选只读扩展核验回调
// （例如 KeySignerPort.InspectPrivateKeyFingerprint），失败时自动触发 VaultSagaFSM 补偿 GC。
type NewSecretVerifier func(ctx context.Context, newRef secret.Ref) error

// VaultSagaRequest 描述单次 VaultSagaFSM 凭据写入/轮换编排请求（绝不含明文或 SecretBox）。
type VaultSagaRequest struct {
	// NewRef 可选显式指定新凭据引用；为空时须提供 TargetStore，由 Entropy 自动分配唯一条目名。
	NewRef secret.Ref
	// TargetStore 在 NewRef 为零值时用于自动分配 <TargetStore>/sec-<hex> 新凭据引用。
	TargetStore string
	// OldRef 可选指定将被替换的旧凭据引用；仅在 CAS DurabilityCommitted 且 5 位置+Pending 零引用时 GC。
	OldRef algebraic.Option[secret.Ref]
	// ExpectedRevision 可选显式要求 CAS 期望配置版本；失配时立即返回 NotApplied 并补偿删除新凭据。
	ExpectedRevision algebraic.Option[ports.Revision]
	// ExpectedCASVersion 可选记录入 VaultSagaContext 的单调期望版本号元数据。
	ExpectedCASVersion uint64
	// VerifyNewRef 可选扩展核验钩子（在常量时间回读匹配后、配置 CAS 前执行）。
	VerifyNewRef NewSecretVerifier
	// MutateGraph 必填：基于当前快照与 newRef 构造待提交的完整已校验 inventory.Graph。
	MutateGraph GraphMutator
	// ExtraPending 可选附加运行期待确认凭据引用（与 Service.PendingRefs 合并参与 5 位置 GC 校验）。
	ExtraPending []inventory.PendingSecretRef
	// Action 可选审计动作标识（空则默认 "vault_saga"）。
	Action          string
	NodeID          string
	ScopeSummary    string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// InteractiveVaultSagaRequest 描述经 InteractionPort.PromptSecret 采集新机密并驱动 VaultSagaFSM 的请求。
type InteractiveVaultSagaRequest struct {
	Prompt ports.SecretPromptRequest
	Saga   VaultSagaRequest
}

// RotateSecretRequest 描述将资产图全部 5 处位置中指向 OldRef 的凭据安全轮换至 NewRef/TargetStore 的请求。
type RotateSecretRequest struct {
	OldRef             secret.Ref
	NewRef             secret.Ref
	TargetStore        string
	ExpectedRevision   algebraic.Option[ports.Revision]
	ExpectedCASVersion uint64
	VerifyNewRef       NewSecretVerifier
	ExtraPending       []inventory.PendingSecretRef
	ScopeSummary       string
	Risk               algebraic.Option[security.RiskLevel]
	Approval           algebraic.Option[gate.ApprovalSubmission]
	OperationStream    *events.OperationStream
}

// InteractiveRotateSecretRequest 描述交互式采集新机密并轮换 OldRef 的请求。
type InteractiveRotateSecretRequest struct {
	Prompt ports.SecretPromptRequest
	Rotate RotateSecretRequest
}

// SagaResult 封装 VaultSagaFSM 执行到达终态后的不可变结果快照（零明文）；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type SagaResult struct {
	state      fsm.VaultSagaState
	newRef     secret.Ref
	oldRef     algebraic.Option[secret.Ref]
	revision   algebraic.Option[ports.Revision]
	durability algebraic.Option[ports.DurabilityOutcome]
	events     []fsm.VaultSagaEvent
	valid      bool
}

// IsValid 报告 SagaResult 是否包含合法的终态 VaultSagaState 与新凭据引用。
func (r SagaResult) IsValid() bool {
	return r.valid && r.state != nil && r.state.IsValid() && r.state.IsTerminal() && r.newRef.IsValid()
}

// IsZero 报告 SagaResult 是否处于无效零值态。
func (r SagaResult) IsZero() bool { return !r.IsValid() }

// State 返回终态封闭和类型 fsm.VaultSagaState；无效时返回 nil。
func (r SagaResult) State() fsm.VaultSagaState {
	if !r.IsValid() {
		return nil
	}
	return r.state
}

// StateKind 返回终态枚举类别；无效时返回 fsm.VaultSagaKindInvalid。
func (r SagaResult) StateKind() fsm.VaultSagaStateKind {
	if !r.IsValid() {
		return fsm.VaultSagaKindInvalid
	}
	return r.state.Kind()
}

// NewRef 返回本次 Saga 写入的新凭据引用。
func (r SagaResult) NewRef() secret.Ref { return r.newRef }

// OldRef 返回本次 Saga 替换的可选旧凭据引用。
func (r SagaResult) OldRef() algebraic.Option[secret.Ref] { return r.oldRef }

// Revision 返回配置提交返回的最新 CAS Revision（若存在）。
func (r SagaResult) Revision() algebraic.Option[ports.Revision] { return r.revision }

// Durability 返回配置提交返回的 DurabilityOutcome（若已执行提交）。
func (r SagaResult) Durability() algebraic.Option[ports.DurabilityOutcome] { return r.durability }

// Events 返回本次 Saga 期间由纯状态机发出的脱敏领域事件防御性副本。
func (r SagaResult) Events() []fsm.VaultSagaEvent { return slices.Clone(r.events) }

// OldDeleted 报告旧凭据是否在 5 位置+Pending 零引用确认后完成回收删除。
func (r SagaResult) OldDeleted() bool {
	if done, ok := r.State().(*fsm.VaultSagaCompleted); ok && done.IsValid() {
		return done.OldDeleted()
	}
	return false
}

// Compensated 报告回滚路径是否已补偿删除新写入凭据。
func (r SagaResult) Compensated() bool {
	if rb, ok := r.State().(*fsm.VaultSagaRolledBack); ok && rb.IsValid() {
		return rb.Compensated()
	}
	return false
}

// IsUncertainDurability 报告是否停机于 Applied && !Durable 的零重试零删凭据终态。
func (r SagaResult) IsUncertainDurability() bool {
	return r.StateKind() == fsm.VaultSagaKindUncertainDurability
}

// IsFailedUncertain 报告是否停机于副作用结果未知或补偿失败的零重试终态。
func (r SagaResult) IsFailedUncertain() bool {
	return r.StateKind() == fsm.VaultSagaKindFailedUncertain
}

// ExecuteVaultSaga 以借用 *secret.SecretBox 完整驱动纯函数 fsm.VaultSagaFSM：
// 严格执行 WriteNew -> VerifyReadback(SecretBox.Equal + 可选扩展核验) -> CommitConfigCAS ->
// CheckOldRefs(5 位置 + SecretLocPending) -> DeleteOld，对 OutcomeUnknown 与 Applied && !Durable
// 零重试且绝不误删凭据。
func (s *Service) ExecuteVaultSaga(
	ctx context.Context,
	req VaultSagaRequest,
	//xops:borrowed
	newSecret *secret.SecretBox,
) (SagaResult, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateSagaRequest(ctx, req); err != nil {
		return SagaResult{}, err
	}
	return s.executeSagaWithValidatedInputs(ctx, req, newSecret)
}

// ExecuteVaultSagaFromBytes 经 secret.WithBytes 深拷贝并立即清零 raw 后驱动 VaultSagaFSM。
func (s *Service) ExecuteVaultSagaFromBytes(ctx context.Context, req VaultSagaRequest, raw []byte) (SagaResult, error) {
	var res SagaResult
	err := secret.WithBytes(raw, func(box *secret.SecretBox) error {
		var runErr error
		res, runErr = s.ExecuteVaultSaga(ctx, req, box)
		return runErr
	})
	return res, err
}

// ExecuteVaultSagaInteractive 经 InteractionPort.PromptSecret 采集新机密后驱动 VaultSagaFSM。
func (s *Service) ExecuteVaultSagaInteractive(ctx context.Context, req InteractiveVaultSagaRequest) (SagaResult, error) {
	if req.Saga.OperationStream != nil {
		defer req.Saga.OperationStream.Close()
	}
	if err := s.validateInteractionCall(ctx, req.Prompt); err != nil {
		return SagaResult{}, err
	}
	if err := s.validateSagaRequest(ctx, req.Saga); err != nil {
		return SagaResult{}, err
	}
	if s.gate.IsHalted() {
		return SagaResult{}, gate.ErrGateHalted
	}
	var res SagaResult
	err := s.interaction.PromptSecret(ctx, req.Prompt, func(box *secret.SecretBox) error {
		var runErr error
		res, runErr = s.executeSagaWithValidatedInputs(ctx, req.Saga, box)
		return runErr
	})
	return res, err
}

// RotateSecret 将资产图全部 5 位置中指向 req.OldRef 的引用原子轮换至新凭据，并经 VaultSagaFSM 回收旧凭据。
func (s *Service) RotateSecret(
	ctx context.Context,
	req RotateSecretRequest,
	//xops:borrowed
	newSecret *secret.SecretBox,
) (SagaResult, error) {
	sagaReq, err := buildRotateSagaRequest(req)
	if err != nil {
		if req.OperationStream != nil {
			req.OperationStream.Close()
		}
		return SagaResult{}, err
	}
	return s.ExecuteVaultSaga(ctx, sagaReq, newSecret)
}

// RotateSecretInteractive 通过 InteractionPort.PromptSecret 采集新机密并执行全图 5 位置轮换。
func (s *Service) RotateSecretInteractive(ctx context.Context, req InteractiveRotateSecretRequest) (SagaResult, error) {
	sagaReq, err := buildRotateSagaRequest(req.Rotate)
	if err != nil {
		if req.Rotate.OperationStream != nil {
			req.Rotate.OperationStream.Close()
		}
		return SagaResult{}, err
	}
	return s.ExecuteVaultSagaInteractive(ctx, InteractiveVaultSagaRequest{
		Prompt: req.Prompt,
		Saga:   sagaReq,
	})
}

func buildRotateSagaRequest(req RotateSecretRequest) (VaultSagaRequest, error) {
	if !req.OldRef.IsValid() {
		return VaultSagaRequest{}, fmt.Errorf("%w: RotateSecret 需要有效的 OldRef", ErrInvalidRequest)
	}
	targetStore := req.TargetStore
	if !req.NewRef.IsValid() && targetStore == "" {
		targetStore = req.OldRef.Store()
	}
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, "rotate secret "+req.OldRef.String())
	return VaultSagaRequest{
		NewRef:             req.NewRef,
		TargetStore:        targetStore,
		OldRef:             algebraic.Some(req.OldRef),
		ExpectedRevision:   req.ExpectedRevision,
		ExpectedCASVersion: req.ExpectedCASVersion,
		VerifyNewRef:       req.VerifyNewRef,
		MutateGraph: func(_ context.Context, snap ports.InventorySnapshot, newRef secret.Ref) (inventory.Graph, error) {
			nextGraph, replaced, err := ReplaceSecretRefInGraph(snap.Graph(), req.OldRef, newRef)
			if err != nil {
				return zeroVal[inventory.Graph](), err
			}
			if replaced == 0 {
				return zeroVal[inventory.Graph](), fmt.Errorf("%w: 资产图中不存在对 %s 的引用", ports.ErrNotFound, req.OldRef)
			}
			return nextGraph, nil
		},
		ExtraPending:    req.ExtraPending,
		Action:          "vault_rotate",
		ScopeSummary:    summary,
		Risk:            req.Risk,
		Approval:        req.Approval,
		OperationStream: req.OperationStream,
	}, nil
}

func (s *Service) executeSagaWithValidatedInputs(
	ctx context.Context,
	req VaultSagaRequest,
	//xops:borrowed
	newSecret *secret.SecretBox,
) (SagaResult, error) {
	if !newSecret.IsValid() {
		return SagaResult{}, ErrInvalidSecretBox
	}
	newRef, err := s.resolveSagaNewRef(req)
	if err != nil {
		return SagaResult{}, err
	}
	return s.executeSagaAuthorized(ctx, req, newRef, newSecret)
}

func (s *Service) validateSagaRequest(ctx context.Context, req VaultSagaRequest) error {
	if err := s.validateBaseCall(ctx, req.Risk); err != nil {
		return err
	}
	if s.store == nil {
		return ErrStoreUnavailable
	}
	if req.MutateGraph == nil {
		return fmt.Errorf("%w: MutateGraph 回调不能为 nil", ErrInvalidRequest)
	}
	if !req.NewRef.IsValid() && req.TargetStore == "" {
		return fmt.Errorf("%w: 必须提供有效 NewRef 或非空 TargetStore", ErrInvalidRequest)
	}
	if old, ok := req.OldRef.Get(); ok && !old.IsValid() {
		return fmt.Errorf("%w: OldRef 无效", ErrInvalidRequest)
	}
	if rev, ok := req.ExpectedRevision.Get(); ok && !rev.IsValid() {
		return fmt.Errorf("%w: ExpectedRevision 无效", ErrInvalidRequest)
	}
	for _, p := range req.ExtraPending {
		if !p.Ref.IsValid() {
			return fmt.Errorf("%w: ExtraPending 包含无效 Ref", ErrInvalidRequest)
		}
	}
	return nil
}

func (s *Service) resolveSagaNewRef(req VaultSagaRequest) (secret.Ref, error) {
	if req.NewRef.IsValid() {
		return req.NewRef, nil
	}
	ref, err := s.allocateRandomRef(req.TargetStore)
	if err != nil {
		return zeroVal[secret.Ref](), fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return ref, nil
}
