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

// EnrollEncryptedPrivateKeyRequest 与 EnrollEncryptedPrivateKeyResult 定义加密私钥登记请求与结果。
// 全流程由 VaultSagaFSM 驱动，经 KeySignerPort.InspectPrivateKeyFingerprint 校验指纹，任意失败自动补偿 GC，零孤儿凭据。
type (
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
		verifiedFP inventory.KeyFingerprint
		builtIdent inventory.Identity
	}
)

// EnrollEncryptedPrivateKeyResult 只读访问器（SagaResult 在回滚或 Uncertain 失败时亦可查询）。
func (r EnrollEncryptedPrivateKeyResult) IsValid() bool {
	return r.valid && r.identity.IsValid() && r.fingerprint.IsValid() && r.passphraseRef.IsValid() && r.revision.IsValid() && r.saga.IsValid()
}
func (r EnrollEncryptedPrivateKeyResult) IsZero() bool { return !r.IsValid() }
func (r EnrollEncryptedPrivateKeyResult) Identity() inventory.Identity {
	return getIfValid(r, func(v EnrollEncryptedPrivateKeyResult) inventory.Identity { return v.identity })
}
func (r EnrollEncryptedPrivateKeyResult) Fingerprint() inventory.KeyFingerprint {
	return getIfValid(r, func(v EnrollEncryptedPrivateKeyResult) inventory.KeyFingerprint { return v.fingerprint })
}
func (r EnrollEncryptedPrivateKeyResult) PassphraseRef() secret.Ref {
	return getIfValid(r, func(v EnrollEncryptedPrivateKeyResult) secret.Ref { return v.passphraseRef })
}
func (r EnrollEncryptedPrivateKeyResult) Revision() ports.Revision {
	return getIfValid(r, func(v EnrollEncryptedPrivateKeyResult) ports.Revision { return v.revision })
}
func (r EnrollEncryptedPrivateKeyResult) SagaResult() credential.SagaResult { return r.saga }

// EnrollEncryptedPrivateKeyIdentity、EnrollEncryptedPrivateKeyIdentityWithSecret 与 EnrollEncryptedPrivateKeyIdentityFromBytes
// 分别通过交互无回显提示、借用 *SecretBox 与 secret.WithBytes 驱动加密私钥 VaultSaga 原子登记。
func (s *Service) EnrollEncryptedPrivateKeyIdentity(ctx context.Context, req EnrollEncryptedPrivateKeyRequest) (EnrollEncryptedPrivateKeyResult, error) {
	return s.runKeyEnroll(ctx, req, true, nil)
}
func (s *Service) EnrollEncryptedPrivateKeyIdentityWithSecret(ctx context.Context, req EnrollEncryptedPrivateKeyRequest,
	//xops:borrowed
	passphrase *secret.SecretBox,
) (EnrollEncryptedPrivateKeyResult, error) {
	return s.runKeyEnroll(ctx, req, false, passphrase)
}
func (s *Service) EnrollEncryptedPrivateKeyIdentityFromBytes(ctx context.Context, req EnrollEncryptedPrivateKeyRequest, rawPassphrase []byte) (EnrollEncryptedPrivateKeyResult, error) {
	var res EnrollEncryptedPrivateKeyResult
	err := secret.WithBytes(rawPassphrase, func(box *secret.SecretBox) error {
		var runErr error
		res, runErr = s.runKeyEnroll(ctx, req, false, box)
		return runErr
	})
	return res, err
}

func (s *Service) runKeyEnroll(ctx context.Context, req EnrollEncryptedPrivateKeyRequest, interactive bool,
	//xops:borrowed
	passphrase *secret.SecretBox,
) (EnrollEncryptedPrivateKeyResult, error) {
	prompt, err := s.validateKeyEnrollCall(ctx, req, interactive)
	var st *keyEnrollState
	var sagaReq credential.VaultSagaRequest
	if err == nil {
		st, sagaReq, err = s.prepareEnrollKeySaga(ctx, req)
	}
	if err != nil {
		closeIfNonNil(req.OperationStream)
		return EnrollEncryptedPrivateKeyResult{}, err
	}
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
		return EnrollEncryptedPrivateKeyResult{st.builtIdent, st.verifiedFP, sagaRes.NewRef(), rev, sagaRes, true}, nil
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
		return pickIf(req.Prompt.IsValid(), req.Prompt, z), pickIf[error](req.Prompt.IsValid(), nil, fmt.Errorf("%w: SecretPromptRequest 无效", ErrInvalidRequest))
	default:
		return ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Title: "Private Key Passphrase", Prompt: "Enter passphrase for encrypted private key", Subject: req.IdentityID.String()})
	}
}
func (s *Service) prepareEnrollKeySaga(ctx context.Context, req EnrollEncryptedPrivateKeyRequest) (*keyEnrollState, credential.VaultSagaRequest, error) {
	var oldRef algebraic.Option[secret.Ref]
	if req.ReplaceExisting {
		snap, err := s.store.Load(ctx)
		if err != nil {
			return nil, credential.VaultSagaRequest{}, err
		}
		if idx := slices.IndexFunc(snap.Graph().Identities(), func(i inventory.Identity) bool { return i.ID().Equal(req.IdentityID) }); idx >= 0 {
			if oldRef, err = extractPrimaryPassphraseRef(snap.Graph().Identities()[idx].Auth()); err != nil {
				return nil, credential.VaultSagaRequest{}, err
			}
		}
	}
	st := &keyEnrollState{}
	return st, credential.VaultSagaRequest{
		NewRef: req.NewRef, TargetStore: req.TargetStore, OldRef: oldRef, ExpectedRevision: req.ExpectedRevision, ExtraPending: req.ExtraPending,
		Action: "enroll_encrypted_private_key", ScopeSummary: pickIf(req.ScopeSummary != "", req.ScopeSummary, "enroll encrypted private key "+req.IdentityID.String()),
		Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream,
		VerifyNewRef: func(vCtx context.Context, newRef secret.Ref) error {
			fp, err := s.keySigner.InspectPrivateKeyFingerprint(vCtx, req.KeyPath, algebraic.Some(newRef))
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
		},
		MutateGraph: func(mCtx context.Context, snap ports.InventorySnapshot, newRef secret.Ref) (inventory.Graph, error) {
			return s.mutateGraphForKeyEnroll(mCtx, snap.Graph(), req, newRef, oldRef, st)
		},
	}, nil
}
func (s *Service) mutateGraphForKeyEnroll(ctx context.Context, g inventory.Graph, req EnrollEncryptedPrivateKeyRequest, newRef secret.Ref, expectedOldRef algebraic.Option[secret.Ref], st *keyEnrollState) (z inventory.Graph, err error) {
	if !st.verifiedFP.IsValid() {
		return z, fmt.Errorf("%w: 缺少经验证的私钥指纹", ErrKeyFingerprintMismatch)
	}
	ident, err := buildEncryptedKeyIdentity(req, newRef, st.verifiedFP)
	if err != nil {
		return z, err
	}
	idents := g.Identities()
	if idx := slices.IndexFunc(idents, func(i inventory.Identity) bool { return i.ID().Equal(req.IdentityID) }); idx >= 0 {
		if !req.ReplaceExisting {
			return z, fmt.Errorf("%w: identity %q", ErrAssetAlreadyExists, req.IdentityID)
		}
		if curOld, cErr := extractPrimaryPassphraseRef(idents[idx].Auth()); cErr != nil {
			return z, cErr
		} else if !algebraic.EqualOption(curOld, expectedOldRef) {
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
func buildEncryptedKeyIdentity(req EnrollEncryptedPrivateKeyRequest, newRef secret.Ref, fp inventory.KeyFingerprint) (z inventory.Identity, err error) {
	binding, err := inventory.NewKeyPassphraseBinding(newRef, fp)
	if err != nil {
		return z, err
	}
	auth, err := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(req.KeyPath), algebraic.Some(binding), req.CertPaths)
	if err != nil {
		return z, err
	}
	return inventory.NewIdentity(inventory.IdentitySpec{ID: req.IdentityID, User: req.User, Auth: auth, Description: req.Description, Tags: req.Tags})
}
func extractPrimaryPassphraseRef(auth inventory.AuthMethod) (algebraic.Option[secret.Ref], error) {
	switch v := auth.(type) {
	case *inventory.AuthPrivateKey:
		if pb, ok := v.Passphrase().Get(); ok && pb.IsValid() {
			return algebraic.Some(pb.PassphraseRef()), nil
		}
		return algebraic.None[secret.Ref](), nil
	case *inventory.AuthComposite:
		for _, sub := range v.Methods() {
			if ref, err := extractPrimaryPassphraseRef(sub); err != nil || ref.IsSome() {
				return ref, err
			}
		}
		return algebraic.None[secret.Ref](), nil
	case *inventory.AuthPassword, *inventory.AuthAgent, *inventory.AuthKeyboardInteractive:
		return algebraic.None[secret.Ref](), nil
	default:
		return algebraic.None[secret.Ref](), inventory.ErrInvalidAuthMethod
	}
}
