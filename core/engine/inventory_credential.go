package engine

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	uccred "github.com/wentf9/xops-cli/core/internal/usecase/credential"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
)

func callInv[A, R any](e *Engine, ctx context.Context, stream *events.OperationStream, fn func(*ucinv.Service, context.Context, A) (R, error), arg A) (R, error) {
	return runOpStream(e, ctx, stream, func(c context.Context) (R, error) { return fn(e.inventory, c, arg) })
}
func callInvItemRev[A, R any](e *Engine, ctx context.Context, stream *events.OperationStream, fn func(*ucinv.Service, context.Context, A) (R, Revision, error), arg A) (R, Revision, error) {
	type res struct {
		item R
		rev  Revision
	}
	out, err := runOpStream(e, ctx, stream, func(c context.Context) (res, error) {
		item, rev, fErr := fn(e.inventory, c, arg)
		return res{item, rev}, fErr
	})
	return out.item, out.rev, err
}
func callInvByID[ID, R any](e *Engine, ctx context.Context, fn func(*ucinv.Service, context.Context, ID, InventoryQueryRequest) (R, Revision, error), id ID, req InventoryQueryRequest) (R, Revision, error) {
	return callInvItemRev(e, ctx, req.OperationStream, func(s *ucinv.Service, c context.Context, q InventoryQueryRequest) (R, Revision, error) {
		return fn(s, c, id, q)
	}, req)
}
func callCred[A, R any](e *Engine, ctx context.Context, stream *events.OperationStream, fn func(*uccred.Service, context.Context, A) (R, error), arg A) (R, error) {
	return runCredOp(e, ctx, stream, func(c context.Context, svc *uccred.Service) (R, error) { return fn(svc, c, arg) })
}
func callCredErr[A any](e *Engine, ctx context.Context, stream *events.OperationStream, fn func(*uccred.Service, context.Context, A) error, arg A) error {
	return runCredOpErr(e, ctx, stream, func(c context.Context, svc *uccred.Service) error { return fn(svc, c, arg) })
}
func callCredBytesErr[A any](e *Engine, ctx context.Context, stream *events.OperationStream, fn func(*uccred.Service, context.Context, A, []byte) error, arg A, raw []byte) error {
	return runCredOpErr(e, ctx, stream, func(c context.Context, svc *uccred.Service) error { return fn(svc, c, arg, raw) })
}

//xops:syncclosure
func runCredOp[T any](e *Engine, ctx context.Context, stream *events.OperationStream, fn func(context.Context, *uccred.Service) (T, error)) (T, error) {
	defer closeStreamIfNonNil(stream)
	if e == nil || !e.initialized {
		return zeroVal[T](), ErrEngineNotInitialized
	}
	if e.credential == nil {
		return zeroVal[T](), ErrVaultUnavailable
	}
	return runOp(e, ctx, func(c context.Context) (T, error) { return fn(c, e.credential) })
}

//xops:syncclosure
func runCredOpErr(e *Engine, ctx context.Context, stream *events.OperationStream, fn func(context.Context, *uccred.Service) error) error {
	_, err := runCredOp(e, ctx, stream, func(c context.Context, svc *uccred.Service) (struct{}, error) { return struct{}{}, fn(c, svc) })
	return err
}

// GetInventorySnapshot / GetHost / GetIdentity / GetNode / ListHosts / ListIdentities / ListNodes 暴露资产只读快照、单项与列表查询。
func (e *Engine) GetInventorySnapshot(ctx context.Context, req InventoryQueryRequest) (InventorySnapshot, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).GetSnapshot, req)
}
func (e *Engine) GetHost(ctx context.Context, id inventory.HostID, req InventoryQueryRequest) (inventory.Host, Revision, error) {
	return callInvByID(e, ctx, (*ucinv.Service).GetHost, id, req)
}
func (e *Engine) GetIdentity(ctx context.Context, id inventory.IdentityID, req InventoryQueryRequest) (inventory.Identity, Revision, error) {
	return callInvByID(e, ctx, (*ucinv.Service).GetIdentity, id, req)
}
func (e *Engine) GetNode(ctx context.Context, id inventory.NodeID, req InventoryQueryRequest) (inventory.Node, Revision, error) {
	return callInvByID(e, ctx, (*ucinv.Service).GetNode, id, req)
}
func (e *Engine) ListHosts(ctx context.Context, req InventoryQueryRequest) ([]inventory.Host, Revision, error) {
	return callInvItemRev(e, ctx, req.OperationStream, (*ucinv.Service).ListHosts, req)
}
func (e *Engine) ListIdentities(ctx context.Context, req InventoryQueryRequest) ([]inventory.Identity, Revision, error) {
	return callInvItemRev(e, ctx, req.OperationStream, (*ucinv.Service).ListIdentities, req)
}
func (e *Engine) ListNodes(ctx context.Context, req InventoryQueryRequest) ([]inventory.Node, Revision, error) {
	return callInvItemRev(e, ctx, req.OperationStream, (*ucinv.Service).ListNodes, req)
}

// CreateHost / UpdateHost / DeleteHost / CreateIdentity / UpdateIdentity / DeleteIdentity / CreateNode / UpdateNode / DeleteNode 执行乐观并发 CAS 资产变更。
func (e *Engine) CreateHost(ctx context.Context, req HostMutationRequest) (MutationResult, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).CreateHost, req)
}
func (e *Engine) UpdateHost(ctx context.Context, req HostMutationRequest) (MutationResult, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).UpdateHost, req)
}
func (e *Engine) DeleteHost(ctx context.Context, req DeleteAssetRequest) (MutationResult, error) {
	return runDeleteAsset(e, ctx, req, inventory.ParseHostID, func(c context.Context, id inventory.HostID) (MutationResult, error) {
		return e.inventory.DeleteHost(c, ucinv.DeleteHostRequest{ID: id, ExpectedRevision: req.ExpectedRevision, ScopeSummary: req.ScopeSummary, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
	})
}
func (e *Engine) CreateIdentity(ctx context.Context, req IdentityMutationRequest) (MutationResult, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).CreateIdentity, req)
}
func (e *Engine) UpdateIdentity(ctx context.Context, req IdentityMutationRequest) (MutationResult, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).UpdateIdentity, req)
}
func (e *Engine) DeleteIdentity(ctx context.Context, req DeleteAssetRequest) (MutationResult, error) {
	return runDeleteAsset(e, ctx, req, inventory.ParseIdentityID, func(c context.Context, id inventory.IdentityID) (MutationResult, error) {
		return e.inventory.DeleteIdentity(c, ucinv.DeleteIdentityRequest{ID: id, ExpectedRevision: req.ExpectedRevision, DeleteUnusedSecrets: req.DeleteUnusedSecrets, RequireSecretsUnreferenced: req.RequireSecretsUnreferenced, ExtraPending: req.ExtraPending, ScopeSummary: req.ScopeSummary, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
	})
}
func (e *Engine) CreateNode(ctx context.Context, req NodeMutationRequest) (MutationResult, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).CreateNode, req)
}
func (e *Engine) UpdateNode(ctx context.Context, req NodeMutationRequest) (MutationResult, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).UpdateNode, req)
}
func (e *Engine) DeleteNode(ctx context.Context, req DeleteAssetRequest) (MutationResult, error) {
	return runDeleteAsset(e, ctx, req, inventory.ParseNodeID, func(c context.Context, id inventory.NodeID) (MutationResult, error) {
		return e.inventory.DeleteNode(c, ucinv.DeleteNodeRequest{ID: id, ExpectedRevision: req.ExpectedRevision, DeleteUnusedSecrets: req.DeleteUnusedSecrets, RequireSecretsUnreferenced: req.RequireSecretsUnreferenced, ExtraPending: req.ExtraPending, ScopeSummary: req.ScopeSummary, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
	})
}

//xops:syncclosure
func runDeleteAsset[ID any](e *Engine, ctx context.Context, req DeleteAssetRequest, parse func(string) (ID, error), del func(context.Context, ID) (MutationResult, error)) (MutationResult, error) {
	return runOpStream(e, ctx, req.OperationStream, func(c context.Context) (MutationResult, error) {
		id, err := parse(req.ID)
		if err != nil {
			return zeroVal[MutationResult](), fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		return del(c, id)
	})
}

// ValidateDAG / CheckSecretReferences / InventoryDoctor / SupportedImportFormats / PlanImport / ApplyImport 暴露资产诊断、5 位置引用检查与统一导入能力。
func (e *Engine) ValidateDAG(ctx context.Context, req InventoryQueryRequest) (inventory.DAGReport, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).ValidateDAG, req)
}
func (e *Engine) CheckSecretReferences(ctx context.Context, req SecretRefCheckRequest) ([]inventory.SecretReference, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).CheckSecretReferences, req)
}
func (e *Engine) InventoryDoctor(ctx context.Context, req InventoryDoctorRequest) (InventoryDoctorRep, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).Doctor, req)
}
func (e *Engine) SupportedImportFormats() []string {
	if e == nil || !e.initialized {
		return nil
	}
	return e.inventory.SupportedImportFormats()
}
func (e *Engine) PlanImport(ctx context.Context, req ImportRequest) (ImportPreview, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).PlanImport, toImportSourceReq(req))
}
func (e *Engine) ApplyImport(ctx context.Context, req ImportRequest) (ImportResult, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).ApplyImport, ucinv.ApplyImportRequest{Source: toImportSourceReq(req), ExpectedRevision: req.ExpectedRevision, DryRun: req.DryRun, ScopeSummary: req.ScopeSummary})
}
func toImportSourceReq(req ImportRequest) ucinv.ImportSourceRequest {
	return ucinv.ImportSourceRequest{Format: req.Format, SourceName: req.SourceName, Reader: req.Reader, Bundle: req.Bundle, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream}
}

// WithPendingEnrollment 在同步借用闭包内驱动首连「先验证后入库」暂存租约（RFC §3.6.3 #5），退出后自动清理独占暂存凭据。
//
//xops:syncclosure
//xops:borrowed
func (e *Engine) WithPendingEnrollment(ctx context.Context, req PendingEnrollmentRequest, fn func(ctx context.Context, lease *PendingEnrollmentLease) error) (PendingEnrollmentResult, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	if fn == nil {
		return zeroVal[PendingEnrollmentResult](), fmt.Errorf("%w: 回调函数不能为 nil", ErrInvalidRequest)
	}
	return runOp(e, ctx, func(c context.Context) (PendingEnrollmentResult, error) {
		return e.inventory.WithPendingEnrollment(c, req, func(lCtx context.Context, lease *PendingEnrollmentLease) error { return fn(lCtx, lease) })
	})
}

// ResolvePendingEnrollmentTarget 基于活跃首连暂存租约的未落盘资产快照编译多跳连接计划（零写盘）。
func (e *Engine) ResolvePendingEnrollmentTarget(ctx context.Context,
	//xops:borrowed
	lease *PendingEnrollmentLease,
	cliOpts option.OptionLayer,
) (ResolvedTarget, error) {
	return runOp(e, ctx, func(c context.Context) (ResolvedTarget, error) {
		return e.inventory.ResolvePendingEnrollmentTarget(c, lease, cliOpts)
	})
}

// ProbePendingEnrollmentTarget 经 gate.WithAuthorized[CapInspect] 包裹 pool.WithLease 对未落盘暂存目标执行真实建连握手，
// 并返回经 HostTrustPort 观测器核验的真实服务端主机密钥指纹（INV-F2 零伪造闭环）。
func (e *Engine) ProbePendingEnrollmentTarget(ctx context.Context,
	//xops:borrowed
	lease *PendingEnrollmentLease,
	req ProbePendingEnrollmentRequest,
) (inventory.KeyFingerprint, error) {
	return runOpStream(e, ctx, req.OperationStream, func(c context.Context) (inventory.KeyFingerprint, error) {
		return e.probePendingEnrollment(c, lease, req)
	})
}
func (e *Engine) probePendingEnrollment(ctx context.Context,
	//xops:borrowed
	lease *PendingEnrollmentLease,
	req ProbePendingEnrollmentRequest,
) (zeroFP inventory.KeyFingerprint, err error) {
	if r, ok := req.Risk.Get(); ok && !r.IsValid() {
		return zeroFP, fmt.Errorf("%w: Risk 无效", ErrInvalidRequest)
	}
	if e.hostTrustObs == nil {
		return zeroFP, fmt.Errorf("%w: 当前拨号器未启用主机密钥信任观测器，无法核验服务端指纹", ErrUnsupported)
	}
	res, err := e.inventory.ResolvePendingEnrollmentTarget(ctx, lease, req.CLIOptions)
	if err != nil {
		return zeroFP, err
	}
	targetHop, ok := res.Plan().Target()
	if !ok {
		return zeroFP, fmt.Errorf("%w: 暂存连接计划缺少末跳目标", ErrInvalidRequest)
	}
	ep := targetHop.Endpoint()
	gateReq, err := uccred.BuildGateRequest[security.CapInspect](
		security.CapabilityInspect, "inventory", "probe_pending_enrollment", res.NodeID(),
		map[string]string{"endpoint": ep.String(), "plan_digest": res.Plan().PlanDigest().String()},
		req.Risk.OrElse(security.RiskSafe), "probe pending enrollment "+res.NodeID(), req.Approval, req.OperationStream,
	)
	if err != nil {
		return zeroFP, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	var verified inventory.KeyFingerprint
	err = gate.WithAuthorized[security.CapInspect](ctx, e.gate, gateReq, func(authCtx context.Context, _ gate.Authorized[security.CapInspect]) error {
		return e.pool.WithLease(authCtx, res.Plan(), func(context.Context, *pool.Lease) error {
			fp, found := e.hostTrustObs.lookup(ep)
			if !found {
				return fmt.Errorf("%w: 握手完成但未观测到已通过验证的主机密钥指纹 (%s)", ErrHostKeyUnknown, ep)
			}
			verified = fp
			return nil
		})
	})
	return verified, err
}

// EnrollEncryptedPrivateKeyIdentity / FromBytes / WithSecret 驱动加密私钥身份的原子 VaultSagaFSM 登记。
// 注意：交互式 CLI/TUI 入口应优先使用 EnrollEncryptedPrivateKeyIdentity（经 InteractionPort.PromptSecret 零明文留痕）；
// EnrollEncryptedPrivateKeyIdentityFromBytes 仅限非交互脚本/测试路径，调用方须在返回后尽快清零源切片。
func (e *Engine) EnrollEncryptedPrivateKeyIdentity(ctx context.Context, req EnrollEncryptedPrivateKeyRequest) (EnrollEncryptedPrivateKeyResult, error) {
	return callInv(e, ctx, req.OperationStream, (*ucinv.Service).EnrollEncryptedPrivateKeyIdentity, req)
}
func (e *Engine) EnrollEncryptedPrivateKeyIdentityFromBytes(ctx context.Context, req EnrollEncryptedPrivateKeyRequest, rawPassphrase []byte) (EnrollEncryptedPrivateKeyResult, error) {
	return runOpStream(e, ctx, req.OperationStream, func(c context.Context) (EnrollEncryptedPrivateKeyResult, error) {
		return e.inventory.EnrollEncryptedPrivateKeyIdentityFromBytes(c, req, rawPassphrase)
	})
}
func (e *Engine) EnrollEncryptedPrivateKeyIdentityWithSecret(ctx context.Context, req EnrollEncryptedPrivateKeyRequest,
	//xops:borrowed
	passphrase *secret.SecretBox,
) (EnrollEncryptedPrivateKeyResult, error) {
	return runOpStream(e, ctx, req.OperationStream, func(c context.Context) (EnrollEncryptedPrivateKeyResult, error) {
		return e.inventory.EnrollEncryptedPrivateKeyIdentityWithSecret(c, req, passphrase)
	})
}

// VaultStatus / VaultInit* / VaultUnlock* / VaultLock / VaultDoctor / FindSecretReferences / WithSecret / WithPromptedSecret / DeleteSecret / GC / VaultSaga / RotateSecret。
// 注意：交互式 CLI/TUI 入口应优先使用 *Interactive 与 WithPromptedSecret；*FromBytes 仅限非交互脚本/自动化桥接路径。
func (e *Engine) VaultStatus(ctx context.Context, req VaultOpRequest) (VaultStatus, error) {
	return callCred(e, ctx, req.OperationStream, (*uccred.Service).Status, uccred.StatusRequest{Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
}
func (e *Engine) VaultInit(ctx context.Context, req VaultOpRequest,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	return runCredOpErr(e, ctx, req.OperationStream, func(c context.Context, svc *uccred.Service) error { return svc.Init(c, req, pass) })
}
func (e *Engine) VaultInitFromBytes(ctx context.Context, req VaultOpRequest, rawPassphrase []byte) error {
	return callCredBytesErr(e, ctx, req.OperationStream, (*uccred.Service).InitFromBytes, req, rawPassphrase)
}
func (e *Engine) VaultInitInteractive(ctx context.Context, req InteractiveVaultOpRequest) error {
	return callCredErr(e, ctx, req.OperationStream, (*uccred.Service).InitInteractive, req)
}
func (e *Engine) VaultUnlock(ctx context.Context, req VaultOpRequest,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	return runCredOpErr(e, ctx, req.OperationStream, func(c context.Context, svc *uccred.Service) error { return svc.Unlock(c, req, pass) })
}
func (e *Engine) VaultUnlockFromBytes(ctx context.Context, req VaultOpRequest, rawPassphrase []byte) error {
	return callCredBytesErr(e, ctx, req.OperationStream, (*uccred.Service).UnlockFromBytes, req, rawPassphrase)
}
func (e *Engine) VaultUnlockInteractive(ctx context.Context, req InteractiveVaultOpRequest) error {
	return callCredErr(e, ctx, req.OperationStream, (*uccred.Service).UnlockInteractive, req)
}
func (e *Engine) VaultLock(ctx context.Context, req VaultOpRequest) error {
	return callCredErr(e, ctx, req.OperationStream, (*uccred.Service).Lock, req)
}
func (e *Engine) VaultDoctor(ctx context.Context, req VaultDoctorRequest) (CredentialDoctorRep, error) {
	return callCred(e, ctx, req.OperationStream, (*uccred.Service).Doctor, req)
}
func (e *Engine) FindSecretReferences(ctx context.Context, req FindSecretReferencesRequest) ([]inventory.SecretReference, error) {
	return callCred(e, ctx, req.OperationStream, (*uccred.Service).FindReferences, req)
}

// WithSecret 经门控鉴权在同步借用闭包内借出 *secret.SecretBox，退出后由 Vault 无条件清零。
//
//xops:syncclosure
//xops:borrowed
func (e *Engine) WithSecret(ctx context.Context, req WithSecretRequest, fn func(box *secret.SecretBox) error) error {
	defer closeStreamIfNonNil(req.OperationStream)
	if fn == nil {
		return fmt.Errorf("%w: 回调函数不能为 nil", ErrInvalidRequest)
	}
	return runCredOpErr(e, ctx, req.OperationStream, func(c context.Context, svc *uccred.Service) error {
		return svc.WithSecret(c, req, func(box *secret.SecretBox) error { return fn(box) })
	})
}

// WithPromptedSecret 经门控鉴权后通过 InteractionPort.PromptSecret 在同步闭包内借出用户输入 *secret.SecretBox。
//
//xops:syncclosure
//xops:borrowed
func (e *Engine) WithPromptedSecret(ctx context.Context, prompt SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	if fn == nil {
		return fmt.Errorf("%w: 回调函数不能为 nil", ErrInvalidRequest)
	}
	return runCredOpErr(e, ctx, nil, func(c context.Context, svc *uccred.Service) error {
		return svc.WithPromptedSecret(c, prompt, func(box *secret.SecretBox) error { return fn(box) })
	})
}
func (e *Engine) DeleteSecret(ctx context.Context, req DeleteSecretRequest) error {
	return callCredErr(e, ctx, req.OperationStream, (*uccred.Service).DeleteSecret, req)
}
func (e *Engine) GCUnreferencedSecrets(ctx context.Context, req GCUnreferencedRequest) (GCUnreferencedResult, error) {
	return callCred(e, ctx, req.OperationStream, (*uccred.Service).GCUnreferencedSecrets, req)
}
func (e *Engine) ExecuteVaultSaga(ctx context.Context, req VaultSagaRequest,
	//xops:borrowed
	newSecret *secret.SecretBox,
) (SagaResult, error) {
	return runCredOp(e, ctx, req.OperationStream, func(c context.Context, svc *uccred.Service) (SagaResult, error) {
		return svc.ExecuteVaultSaga(c, req, newSecret)
	})
}
func (e *Engine) ExecuteVaultSagaFromBytes(ctx context.Context, req VaultSagaRequest, rawSecret []byte) (SagaResult, error) {
	return runCredOp(e, ctx, req.OperationStream, func(c context.Context, svc *uccred.Service) (SagaResult, error) {
		return svc.ExecuteVaultSagaFromBytes(c, req, rawSecret)
	})
}
func (e *Engine) ExecuteVaultSagaInteractive(ctx context.Context, req InteractiveVaultSagaRequest) (SagaResult, error) {
	return callCred(e, ctx, req.Saga.OperationStream, (*uccred.Service).ExecuteVaultSagaInteractive, req)
}
func (e *Engine) RotateSecret(ctx context.Context, req RotateSecretRequest,
	//xops:borrowed
	newSecret *secret.SecretBox,
) (SagaResult, error) {
	return runCredOp(e, ctx, req.OperationStream, func(c context.Context, svc *uccred.Service) (SagaResult, error) {
		return svc.RotateSecret(c, req, newSecret)
	})
}
func (e *Engine) RotateSecretInteractive(ctx context.Context, req InteractiveRotateSecretRequest) (SagaResult, error) {
	return callCred(e, ctx, req.Rotate.OperationStream, (*uccred.Service).RotateSecretInteractive, req)
}
