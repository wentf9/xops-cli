package inventory

import (
	"context"
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
	"github.com/wentf9/xops-cli/core/ports"
)

// 加密私钥身份原子登记契约类型定义（经 VaultSagaFSM 与 KeySignerPort.InspectPrivateKeyFingerprint 驱动）。
type (
	// EnrollEncryptedPrivateKeyRequest 描述加密私钥身份登记请求。
	EnrollEncryptedPrivateKeyRequest struct {
		IdentityID          inventory.IdentityID
		User                option.Username
		KeyPath             inventory.KeyPathSpec
		CertPaths           []inventory.CertPathSpec
		Description         string
		Tags                []inventory.Tag
		TargetStore         string
		NewRef              secret.Ref
		ExpectedFingerprint algebraic.Option[inventory.KeyFingerprint]
		ReplaceExisting     bool
		ExpectedRevision    algebraic.Option[ports.Revision]
		Prompt              ports.SecretPromptRequest
		ExtraPending        []inventory.PendingSecretRef
		ScopeSummary        string
		Risk                algebraic.Option[security.RiskLevel]
		Approval            algebraic.Option[gate.ApprovalSubmission]
		OperationStream     *events.OperationStream
	}
	// EnrollEncryptedPrivateKeyResult 封装加密私钥登记成功后的不可变产物；失败时仍可通过 SagaResult() 查询终态。
	//
	//xops:opaque
	//xops:failclosed
	EnrollEncryptedPrivateKeyResult struct {
		identity      inventory.Identity
		fingerprint   inventory.KeyFingerprint
		passphraseRef secret.Ref
		revision      ports.Revision
		saga          credential.SagaResult
		valid         bool
	}
	keyEnrollState struct {
		verifiedFP      inventory.KeyFingerprint
		builtIdent      inventory.Identity
		expectedOldRefs []secret.Ref
	}
)

// EnrollEncryptedPrivateKeyResult 只读访问器（回滚或 Uncertain 失败时仍可经 SagaResult() 观测底层 Saga 终态）。
func (r EnrollEncryptedPrivateKeyResult) IsValid() bool {
	return r.valid && r.identity.IsValid() && r.fingerprint.IsValid() && r.passphraseRef.IsValid() && r.revision.IsValid() && r.saga.IsValid()
}
func (r EnrollEncryptedPrivateKeyResult) IsZero() bool                          { return !r.IsValid() }
func (r EnrollEncryptedPrivateKeyResult) Identity() inventory.Identity          { return r.identity }
func (r EnrollEncryptedPrivateKeyResult) Fingerprint() inventory.KeyFingerprint { return r.fingerprint }
func (r EnrollEncryptedPrivateKeyResult) PassphraseRef() secret.Ref             { return r.passphraseRef }
func (r EnrollEncryptedPrivateKeyResult) Revision() ports.Revision              { return r.revision }
func (r EnrollEncryptedPrivateKeyResult) SagaResult() credential.SagaResult     { return r.saga }

// EnrollEncryptedPrivateKeyIdentity 经 Gate 授权后通过无回显交互提示采集口令，并驱动 VaultSagaFSM 原子登记加密私钥身份。
func (s *Service) EnrollEncryptedPrivateKeyIdentity(ctx context.Context, req EnrollEncryptedPrivateKeyRequest) (EnrollEncryptedPrivateKeyResult, error) {
	return s.runKeyEnroll(ctx, req, true, nil)
}

// EnrollEncryptedPrivateKeyIdentityWithSecret 使用借用 *secret.SecretBox 驱动加密私钥身份 VaultSagaFSM 原子登记。
func (s *Service) EnrollEncryptedPrivateKeyIdentityWithSecret(ctx context.Context, req EnrollEncryptedPrivateKeyRequest,
	//xops:borrowed
	passphrase *secret.SecretBox,
) (EnrollEncryptedPrivateKeyResult, error) {
	return s.runKeyEnroll(ctx, req, false, passphrase)
}

// EnrollEncryptedPrivateKeyIdentityFromBytes 经 secret.WithBytes 深拷贝并立即清零 rawPassphrase 后执行加密私钥原子登记。
func (s *Service) EnrollEncryptedPrivateKeyIdentityFromBytes(ctx context.Context, req EnrollEncryptedPrivateKeyRequest, rawPassphrase []byte) (res EnrollEncryptedPrivateKeyResult, err error) {
	err = secret.WithBytes(rawPassphrase, func(box *secret.SecretBox) (rErr error) {
		res, rErr = s.runKeyEnroll(ctx, req, false, box)
		return rErr
	})
	return res, err
}

func (s *Service) runKeyEnroll(ctx context.Context, req EnrollEncryptedPrivateKeyRequest, interactive bool,
	//xops:borrowed
	passphrase *secret.SecretBox,
) (EnrollEncryptedPrivateKeyResult, error) {
	prompt, err := s.validateKeyEnrollCall(ctx, req, interactive)
	if err != nil {
		closeIfNonNil(req.OperationStream)
		return EnrollEncryptedPrivateKeyResult{}, err
	}
	st, sagaReq := s.buildEnrollKeySagaRequest(req)
	var sagaRes credential.SagaResult
	if interactive {
		sagaRes, err = s.credSvc.ExecuteVaultSagaInteractive(ctx, credential.InteractiveVaultSagaRequest{Prompt: prompt, Saga: sagaReq})
	} else {
		sagaRes, err = s.credSvc.ExecuteVaultSaga(ctx, sagaReq, passphrase)
	}
	if err != nil {
		return EnrollEncryptedPrivateKeyResult{saga: sagaRes}, err
	}
	if rev, ok := sagaRes.Revision().Get(); ok && rev.IsValid() {
		return EnrollEncryptedPrivateKeyResult{
			identity: st.builtIdent, fingerprint: st.verifiedFP, passphraseRef: sagaRes.NewRef(), revision: rev, saga: sagaRes, valid: true,
		}, nil
	}
	return EnrollEncryptedPrivateKeyResult{saga: sagaRes}, fmt.Errorf("%w: VaultSaga 完成后缺少有效 Revision", ErrCommitOutcomeUnknown)
}
func closeIfNonNil(stream *events.OperationStream) {
	if stream != nil {
		stream.Close()
	}
}
func (s *Service) validateKeyEnrollCall(ctx context.Context, req EnrollEncryptedPrivateKeyRequest, interactive bool) (z ports.SecretPromptRequest, err error) {
	if err = s.requireStoreAndGate(ctx, req.Risk); err != nil {
		return z, err
	}
	fp, hasFP := req.ExpectedFingerprint.Get()
	switch {
	case s.credSvc == nil:
		return z, ErrVaultUnavailable
	case s.keySigner == nil:
		return z, ErrKeySignerUnavailable
	case interactive && (s.interaction == nil || !s.interaction.CanInteract()):
		return z, ErrInteractionUnavailable
	case !req.IdentityID.IsValid() || !req.User.IsValid() || !req.KeyPath.IsValid() || (!req.NewRef.IsValid() && req.TargetStore == "") || (hasFP && !fp.IsValid()):
		return z, fmt.Errorf("%w: 加密私钥登记请求参数无效", ErrInvalidRequest)
	case !interactive:
		return z, nil
	case !req.Prompt.IsZero():
		if !req.Prompt.IsValid() {
			return z, fmt.Errorf("%w: SecretPromptRequest 无效", ErrInvalidRequest)
		}
		return req.Prompt, nil
	default:
		return ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Title: "Private Key Passphrase", Prompt: "Enter passphrase for encrypted private key", Subject: req.IdentityID.String()})
	}
}
func (s *Service) buildEnrollKeySagaRequest(req EnrollEncryptedPrivateKeyRequest) (*keyEnrollState, credential.VaultSagaRequest) {
	st := &keyEnrollState{}
	var resolveOld credential.OldSecretRefsResolver
	if req.ReplaceExisting {
		// 严格在 gate.WithAuthorized 内读取既有身份全部旧凭据（覆盖 *AuthComposite 多凭据后置 GC）。
		resolveOld = func(c context.Context) (algebraic.Option[secret.Ref], []secret.Ref, error) {
			snap, err := s.store.Load(c)
			if err != nil {
				return algebraic.None[secret.Ref](), nil, err
			}
			st.expectedOldRefs = secretRefsForIdentity(snap.Graph(), req.IdentityID)
			if len(st.expectedOldRefs) == 0 {
				return algebraic.None[secret.Ref](), nil, nil
			}
			return algebraic.Some(st.expectedOldRefs[0]), st.expectedOldRefs[1:], nil
		}
	}
	return st, credential.VaultSagaRequest{
		NewRef: req.NewRef, TargetStore: req.TargetStore, ResolveOldRefs: resolveOld, ExpectedRevision: req.ExpectedRevision, ExtraPending: req.ExtraPending,
		Action: "enroll_encrypted_private_key", ScopeSummary: pickIf(req.ScopeSummary != "", req.ScopeSummary, "enroll encrypted private key "+req.IdentityID.String()),
		Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream,
		VerifyNewRef: func(c context.Context, newRef secret.Ref) error { return s.verifyEnrolledKey(c, req, newRef, st) },
		MutateGraph: func(c context.Context, snap ports.InventorySnapshot, newRef secret.Ref) (inventory.Graph, error) {
			return s.mutateGraphForKeyEnroll(c, snap.Graph(), req, newRef, st)
		},
	}
}
func (s *Service) verifyEnrolledKey(ctx context.Context, req EnrollEncryptedPrivateKeyRequest, newRef secret.Ref, st *keyEnrollState) error {
	fp, err := s.keySigner.InspectPrivateKeyFingerprint(ctx, req.KeyPath, algebraic.Some(newRef))
	if err != nil {
		return err
	}
	if !fp.IsValid() {
		return fmt.Errorf("%w: KeySignerPort 返回无效公钥指纹", ErrKeyFingerprintMismatch)
	}
	if expFP, ok := req.ExpectedFingerprint.Get(); ok && !fp.Equal(expFP) {
		return fmt.Errorf("%w: 实际指纹 %s 与预期指纹 %s 不一致", ErrKeyFingerprintMismatch, fp, expFP)
	}
	st.verifiedFP = fp
	return nil
}
func (s *Service) mutateGraphForKeyEnroll(ctx context.Context, g inventory.Graph, req EnrollEncryptedPrivateKeyRequest, newRef secret.Ref, st *keyEnrollState) (z inventory.Graph, err error) {
	if !st.verifiedFP.IsValid() {
		return z, fmt.Errorf("%w: 缺少经验证的私钥指纹", ErrKeyFingerprintMismatch)
	}
	binding, err := inventory.NewKeyPassphraseBinding(newRef, st.verifiedFP)
	var auth *inventory.AuthPrivateKey
	if err == nil {
		auth, err = inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(req.KeyPath), algebraic.Some(binding), req.CertPaths)
	}
	var ident inventory.Identity
	if err == nil {
		ident, err = inventory.NewIdentity(inventory.IdentitySpec{ID: req.IdentityID, User: req.User, Auth: auth, Description: req.Description, Tags: req.Tags})
	}
	if err != nil {
		return z, err
	}
	idents := g.Identities()
	if idx := slices.IndexFunc(idents, func(i inventory.Identity) bool { return i.ID().Equal(req.IdentityID) }); idx >= 0 {
		if !req.ReplaceExisting {
			return z, fmt.Errorf("%w: identity %q", ErrAssetAlreadyExists, req.IdentityID)
		}
		if !slices.EqualFunc(secretRefsForIdentity(g, req.IdentityID), st.expectedOldRefs, secret.Ref.Equal) {
			return z, ports.ErrRevisionConflict
		}
		idents[idx] = ident
	} else {
		idents = append(idents, ident)
	}
	next, err := s.buildValidatedGraph(ctx, g, g.Hosts(), idents, g.Nodes())
	if err == nil {
		st.builtIdent = ident
	}
	return next, err
}
