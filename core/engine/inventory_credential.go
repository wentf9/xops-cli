package engine

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	uccred "github.com/wentf9/xops-cli/core/internal/usecase/credential"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
)

func toInvQuery(opts CallOptions) ucinv.QueryRequest {
	return ucinv.QueryRequest{Risk: opts.Risk, Approval: toGateApproval(opts.Approval), OperationStream: opts.OperationStream}
}

//xops:syncclosure
func runCredOp[T any](e *Engine, ctx context.Context, fn func(context.Context, *uccred.Service) (T, error)) (T, error) {
	if e == nil || !e.initialized {
		return zeroVal[T](), ErrEngineNotInitialized
	}
	if e.credential == nil {
		return zeroVal[T](), ErrVaultUnavailable
	}
	return runOp(e, ctx, func(c context.Context) (T, error) { return fn(c, e.credential) })
}

//xops:syncclosure
func runCredOpErr(e *Engine, ctx context.Context, fn func(context.Context, *uccred.Service) error) error {
	if e == nil || !e.initialized {
		return ErrEngineNotInitialized
	}
	if e.credential == nil {
		return ErrVaultUnavailable
	}
	return runOpErr(e, ctx, func(c context.Context) error { return fn(c, e.credential) })
}

//xops:syncclosure
func runListOp[T any](e *Engine, ctx context.Context, fn func(context.Context) ([]T, Revision, error)) ([]T, Revision, error) {
	type res struct {
		items []T
		rev   Revision
	}
	out, err := runOp(e, ctx, func(c context.Context) (res, error) {
		items, rev, err := fn(c)
		return res{items, rev}, err
	})
	return out.items, out.rev, err
}

// GetInventorySnapshot / ListHosts / ListIdentities / ListNodes 暴露资产只读快照与列表查询。
func (e *Engine) GetInventorySnapshot(ctx context.Context, req InventoryQueryRequest) (InventorySnapshot, error) {
	return runOp(e, ctx, func(c context.Context) (InventorySnapshot, error) {
		return e.inventory.GetSnapshot(c, toInvQuery(req.CallOptions))
	})
}
func (e *Engine) ListHosts(ctx context.Context, req InventoryQueryRequest) ([]inventory.Host, Revision, error) {
	return runListOp(e, ctx, func(c context.Context) ([]inventory.Host, Revision, error) {
		return e.inventory.ListHosts(c, toInvQuery(req.CallOptions))
	})
}
func (e *Engine) ListIdentities(ctx context.Context, req InventoryQueryRequest) ([]inventory.Identity, Revision, error) {
	return runListOp(e, ctx, func(c context.Context) ([]inventory.Identity, Revision, error) {
		return e.inventory.ListIdentities(c, toInvQuery(req.CallOptions))
	})
}
func (e *Engine) ListNodes(ctx context.Context, req InventoryQueryRequest) ([]inventory.Node, Revision, error) {
	return runListOp(e, ctx, func(c context.Context) ([]inventory.Node, Revision, error) {
		return e.inventory.ListNodes(c, toInvQuery(req.CallOptions))
	})
}

// CreateHost / UpdateHost / DeleteHost 执行乐观并发 CAS Host 变更。
func (e *Engine) CreateHost(ctx context.Context, req HostMutationRequest) (MutationResult, error) {
	return runOp(e, ctx, func(c context.Context) (MutationResult, error) { return e.inventory.CreateHost(c, toInvHostReq(req)) })
}
func (e *Engine) UpdateHost(ctx context.Context, req HostMutationRequest) (MutationResult, error) {
	return runOp(e, ctx, func(c context.Context) (MutationResult, error) { return e.inventory.UpdateHost(c, toInvHostReq(req)) })
}
func (e *Engine) DeleteHost(ctx context.Context, req DeleteAssetRequest) (MutationResult, error) {
	id, err := inventory.ParseHostID(req.ID)
	if err != nil {
		return zeroVal[MutationResult](), fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return runOp(e, ctx, func(c context.Context) (MutationResult, error) {
		return e.inventory.DeleteHost(c, ucinv.DeleteHostRequest{
			ID: id, ExpectedRevision: req.ExpectedRevision, ScopeSummary: req.ScopeSummary,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}

// CreateIdentity / UpdateIdentity / DeleteIdentity 执行乐观并发 CAS Identity 变更。
func (e *Engine) CreateIdentity(ctx context.Context, req IdentityMutationRequest) (MutationResult, error) {
	return runOp(e, ctx, func(c context.Context) (MutationResult, error) {
		return e.inventory.CreateIdentity(c, toInvIdentityReq(req))
	})
}
func (e *Engine) UpdateIdentity(ctx context.Context, req IdentityMutationRequest) (MutationResult, error) {
	return runOp(e, ctx, func(c context.Context) (MutationResult, error) {
		return e.inventory.UpdateIdentity(c, toInvIdentityReq(req))
	})
}
func (e *Engine) DeleteIdentity(ctx context.Context, req DeleteAssetRequest) (MutationResult, error) {
	id, err := inventory.ParseIdentityID(req.ID)
	if err != nil {
		return zeroVal[MutationResult](), fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return runOp(e, ctx, func(c context.Context) (MutationResult, error) {
		return e.inventory.DeleteIdentity(c, ucinv.DeleteIdentityRequest{
			ID: id, ExpectedRevision: req.ExpectedRevision, DeleteUnusedSecrets: req.DeleteUnusedSecrets,
			RequireSecretsUnreferenced: req.RequireSecretsUnreferenced, ScopeSummary: req.ScopeSummary,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}

// CreateNode / UpdateNode / DeleteNode 执行带跨命名空间 Tarjan DAG 校验的乐观并发 CAS Node 变更。
func (e *Engine) CreateNode(ctx context.Context, req NodeMutationRequest) (MutationResult, error) {
	return runOp(e, ctx, func(c context.Context) (MutationResult, error) { return e.inventory.CreateNode(c, toInvNodeReq(req)) })
}
func (e *Engine) UpdateNode(ctx context.Context, req NodeMutationRequest) (MutationResult, error) {
	return runOp(e, ctx, func(c context.Context) (MutationResult, error) { return e.inventory.UpdateNode(c, toInvNodeReq(req)) })
}
func (e *Engine) DeleteNode(ctx context.Context, req DeleteAssetRequest) (MutationResult, error) {
	id, err := inventory.ParseNodeID(req.ID)
	if err != nil {
		return zeroVal[MutationResult](), fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return runOp(e, ctx, func(c context.Context) (MutationResult, error) {
		return e.inventory.DeleteNode(c, ucinv.DeleteNodeRequest{
			ID: id, ExpectedRevision: req.ExpectedRevision, DeleteUnusedSecrets: req.DeleteUnusedSecrets,
			RequireSecretsUnreferenced: req.RequireSecretsUnreferenced, ScopeSummary: req.ScopeSummary,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}

// ValidateDAG / InventoryDoctor / SupportedImportFormats / PlanImport / ApplyImport 暴露资产诊断与统一导入能力。
func (e *Engine) ValidateDAG(ctx context.Context, req InventoryQueryRequest) (inventory.DAGReport, error) {
	return runOp(e, ctx, func(c context.Context) (inventory.DAGReport, error) {
		return e.inventory.ValidateDAG(c, toInvQuery(req.CallOptions))
	})
}
func (e *Engine) InventoryDoctor(ctx context.Context, req InventoryDoctorRequest) (InventoryDoctorRep, error) {
	return runOp(e, ctx, func(c context.Context) (InventoryDoctorRep, error) {
		return e.inventory.Doctor(c, ucinv.DoctorRequest{
			CheckVaultSecrets: req.CheckVaultSecrets, CheckPrivateKeys: req.CheckPrivateKeys,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}
func (e *Engine) SupportedImportFormats() []string {
	if e == nil || !e.initialized {
		return nil
	}
	return e.inventory.SupportedImportFormats()
}
func (e *Engine) PlanImport(ctx context.Context, req ImportRequest) (ImportPreview, error) {
	return runOp(e, ctx, func(c context.Context) (ImportPreview, error) {
		return e.inventory.PlanImport(c, toImportSourceReq(req))
	})
}
func (e *Engine) ApplyImport(ctx context.Context, req ImportRequest) (ImportResult, error) {
	return runOp(e, ctx, func(c context.Context) (ImportResult, error) {
		return e.inventory.ApplyImport(c, ucinv.ApplyImportRequest{
			Source: toImportSourceReq(req), ExpectedRevision: req.ExpectedRevision, DryRun: req.DryRun, ScopeSummary: req.ScopeSummary,
		})
	})
}

// VaultStatus / VaultInit / VaultUnlock / VaultLock / VaultDoctor / WithSecret / DeleteSecret / GCUnreferencedSecrets / RotateSecret。
func (e *Engine) VaultStatus(ctx context.Context, req VaultOpRequest) (VaultStatus, error) {
	return runCredOp(e, ctx, func(c context.Context, svc *uccred.Service) (VaultStatus, error) {
		return svc.Status(c, uccred.StatusRequest{Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream})
	})
}
func (e *Engine) VaultInit(
	ctx context.Context, req VaultOpRequest,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	return runCredOpErr(e, ctx, func(c context.Context, svc *uccred.Service) error { return svc.Init(c, toVaultCtrlReq(req), pass) })
}
func (e *Engine) VaultUnlock(
	ctx context.Context, req VaultOpRequest,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	return runCredOpErr(e, ctx, func(c context.Context, svc *uccred.Service) error { return svc.Unlock(c, toVaultCtrlReq(req), pass) })
}
func (e *Engine) VaultLock(ctx context.Context, req VaultOpRequest) error {
	return runCredOpErr(e, ctx, func(c context.Context, svc *uccred.Service) error { return svc.Lock(c, toVaultCtrlReq(req)) })
}
func (e *Engine) VaultDoctor(ctx context.Context, skipProbe bool, opts CallOptions) (CredentialDoctorRep, error) {
	return runCredOp(e, ctx, func(c context.Context, svc *uccred.Service) (CredentialDoctorRep, error) {
		return svc.Doctor(c, uccred.DoctorRequest{SkipSecretProbe: skipProbe, Risk: opts.Risk, Approval: toGateApproval(opts.Approval), OperationStream: opts.OperationStream})
	})
}

// WithSecret 经门控鉴权在同步借用闭包内借出 *secret.SecretBox，退出后由 Vault 无条件清零。
//
//xops:syncclosure
//xops:borrowed
func (e *Engine) WithSecret(ctx context.Context, req WithSecretRequest, fn func(box *secret.SecretBox) error) error {
	return runCredOpErr(e, ctx, func(c context.Context, svc *uccred.Service) error {
		return svc.WithSecret(c, uccred.WithSecretRequest{
			Ref: req.Ref, NodeID: req.NodeID, ScopeSummary: req.ScopeSummary,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		}, func(box *secret.SecretBox) error { return fn(box) })
	})
}
func (e *Engine) DeleteSecret(ctx context.Context, req DeleteSecretRequest) error {
	return runCredOpErr(e, ctx, func(c context.Context, svc *uccred.Service) error {
		return svc.DeleteSecret(c, uccred.DeleteSecretRequest{
			Ref: req.Ref, ScopeSummary: req.ScopeSummary, Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}
func (e *Engine) GCUnreferencedSecrets(ctx context.Context, req GCUnreferencedRequest) (GCUnreferencedResult, error) {
	return runCredOp(e, ctx, func(c context.Context, svc *uccred.Service) (GCUnreferencedResult, error) {
		return svc.GCUnreferencedSecrets(c, uccred.GCUnreferencedRequest{
			Candidates: req.Candidates, ScopeSummary: req.ScopeSummary, Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}
func (e *Engine) RotateSecret(
	ctx context.Context, req RotateSecretRequest,
	//xops:borrowed
	newSecret *secret.SecretBox,
) (SagaResult, error) {
	return runCredOp(e, ctx, func(c context.Context, svc *uccred.Service) (SagaResult, error) {
		return svc.RotateSecret(c, uccred.RotateSecretRequest{
			OldRef: req.OldRef, NewRef: req.NewRef, TargetStore: req.TargetStore, ExpectedRevision: req.ExpectedRevision,
			ScopeSummary: req.ScopeSummary, Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		}, newSecret)
	})
}

func toInvHostReq(req HostMutationRequest) ucinv.HostMutationRequest {
	return ucinv.HostMutationRequest{Host: req.Host, ExpectedRevision: req.ExpectedRevision, ScopeSummary: req.ScopeSummary, Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream}
}
func toInvIdentityReq(req IdentityMutationRequest) ucinv.IdentityMutationRequest {
	return ucinv.IdentityMutationRequest{Identity: req.Identity, ExpectedRevision: req.ExpectedRevision, GCUnreferencedOldSecrets: req.GCUnreferencedOldSecrets, ScopeSummary: req.ScopeSummary, Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream}
}
func toInvNodeReq(req NodeMutationRequest) ucinv.NodeMutationRequest {
	return ucinv.NodeMutationRequest{Node: req.Node, ExpectedRevision: req.ExpectedRevision, GCUnreferencedOldSecrets: req.GCUnreferencedOldSecrets, ScopeSummary: req.ScopeSummary, Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream}
}
func toImportSourceReq(req ImportRequest) ucinv.ImportSourceRequest {
	return ucinv.ImportSourceRequest{Format: req.Format, SourceName: req.SourceName, Reader: req.Reader, Bundle: req.Bundle, Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream}
}
func toVaultCtrlReq(req VaultOpRequest) uccred.VaultControlRequest {
	return uccred.VaultControlRequest{ScopeSummary: req.ScopeSummary, Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream}
}
