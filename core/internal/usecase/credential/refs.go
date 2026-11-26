package credential

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

// FindReferencesRequest 描述查询单个凭据引用在全图 5 位置与 Pending 租约占用情况的请求。
type FindReferencesRequest struct {
	Ref             secret.Ref
	ExtraPending    []inventory.PendingSecretRef
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// DeleteSecretRequest 描述删除单条 Vault 凭据的授权请求（强制先过 5 位置 + Pending 零引用校验）。
type DeleteSecretRequest struct {
	Ref             secret.Ref
	ExtraPending    []inventory.PendingSecretRef
	ScopeSummary    string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// GCUnreferencedRequest 描述批量安全回收候选凭据列表的授权请求（有引用项自动保留，绝不误删）。
type GCUnreferencedRequest struct {
	Candidates      []secret.Ref
	ExtraPending    []inventory.PendingSecretRef
	ScopeSummary    string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// GCUnreferencedResult 封装批量安全回收的结果摘要（区分已删除、仍被引用保留与缺失项）。
type GCUnreferencedResult struct {
	Deleted  []secret.Ref
	Retained []RetainedSecret
	Missing  []secret.Ref
}

// RetainedSecret 描述因仍存在 5 位置或 Pending 引用而被安全保留的凭据条目。
type RetainedSecret struct {
	Ref        secret.Ref
	References []inventory.SecretReference
}

// FindReferences 经 CapInspect 鉴权扫描全图 5 位置与活跃 Pending 租约，返回占用 req.Ref 的全部引用。
func (s *Service) FindReferences(ctx context.Context, req FindReferencesRequest) ([]inventory.SecretReference, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateBaseCall(ctx, req.Risk); err != nil {
		return nil, err
	}
	if s.store == nil {
		return nil, ErrStoreUnavailable
	}
	if !req.Ref.IsValid() {
		return nil, fmt.Errorf("%w: Ref 无效", ErrInvalidRequest)
	}
	gateReq, err := buildInspectGateRequest(
		"find_secret_references", "", map[string]string{"secret_ref": req.Ref.String()},
		req.Risk.OrElse(security.RiskSafe), "find secret references "+req.Ref.String(), req.Approval, req.OperationStream,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	var refs []inventory.SecretReference
	err = gate.WithAuthorized[security.CapInspect](ctx, s.gate, gateReq, func(authCtx context.Context, _ gate.Authorized[security.CapInspect]) error {
		snap, lErr := s.store.Load(authCtx)
		if lErr != nil {
			return lErr
		}
		pending, pErr := s.collectPendingRefs(req.ExtraPending)
		if pErr != nil {
			return pErr
		}
		refs = snap.Graph().FindSecretReferences(req.Ref, pending...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return refs, nil
}

// DeleteSecret 经 CapMutate 鉴权删除单条 Vault 凭据；
// 删除前强制重载资产图并执行 5 位置（AuthPassword..NodePrivilege）+ SecretLocPending 零引用核验，
// 任一位置存在引用均严格失败关闭返回 *SecretReferencedError 且绝不调用 Vault.Delete。
func (s *Service) DeleteSecret(ctx context.Context, req DeleteSecretRequest) error {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateBaseCall(ctx, req.Risk); err != nil {
		return err
	}
	if s.store == nil {
		return ErrStoreUnavailable
	}
	if !req.Ref.IsValid() {
		return fmt.Errorf("%w: Ref 无效", ErrInvalidRequest)
	}
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, "delete secret "+req.Ref.String())
	gateReq, err := buildMutateGateRequest(
		"vault_delete_secret", "", map[string]string{"secret_ref": req.Ref.String()},
		req.Risk.OrElse(security.RiskDangerous), summary, req.Approval, req.OperationStream,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return gate.WithAuthorized[security.CapMutate](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[security.CapMutate]) error {
		snap, lErr := s.store.Load(authCtx)
		if lErr != nil {
			return lErr
		}
		pending, pErr := s.collectPendingRefs(req.ExtraPending)
		if pErr != nil {
			return pErr
		}
		canGC, refs := snap.Graph().CanGCSecret(req.Ref, pending...)
		if !canGC {
			return newSecretReferencedError(req.Ref, refs)
		}
		delErr := s.vault.Delete(authCtx, req.Ref)
		if delErr != nil && !errors.Is(delErr, ports.ErrSecretNotFound) && classifyVaultDeleteError(delErr) == fsm.SideEffectOutcomeUnknown {
			reportUnknownAuditOutcome(auth, "vault_delete_outcome_unknown", delErr.Error())
		}
		return delErr
	})
}

// GCUnreferencedSecrets 对去重排序后的候选凭据执行 5 位置 + Pending 零引用核验并安全删除无引用凭据，
// 任何仍被占用的凭据均保留在 Retained 列表中而不报错中止；即使 Candidates 为空也必须经 Gate 过闸遵守 Halted 熔断器。
func (s *Service) GCUnreferencedSecrets(ctx context.Context, req GCUnreferencedRequest) (GCUnreferencedResult, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateBaseCall(ctx, req.Risk); err != nil {
		return GCUnreferencedResult{}, err
	}
	if s.store == nil {
		return GCUnreferencedResult{}, ErrStoreUnavailable
	}
	candidates, err := canonicalizeSecretRefs(req.Candidates)
	if err != nil {
		return GCUnreferencedResult{}, err
	}
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, fmt.Sprintf("gc %d candidate secrets", len(candidates)))
	gateReq, err := buildMutateGateRequest("vault_gc_secrets", "", nil, req.Risk.OrElse(security.RiskModerate), summary, req.Approval, req.OperationStream)
	if err != nil {
		return GCUnreferencedResult{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	var out GCUnreferencedResult
	err = gate.WithAuthorized[security.CapMutate](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[security.CapMutate]) error {
		if len(candidates) == 0 {
			return nil
		}
		var deleteAttempted bool
		var runErr error
		out, deleteAttempted, runErr = s.gcCandidatesAuthorized(authCtx, candidates, req.ExtraPending)
		if runErr != nil && deleteAttempted && (len(out.Deleted) > 0 || classifyVaultDeleteError(runErr) == fsm.SideEffectOutcomeUnknown) {
			reportUnknownAuditOutcome(auth, "vault_gc_partial_or_unknown", runErr.Error())
		}
		return runErr
	})
	return out, err
}

func (s *Service) gcCandidatesAuthorized(
	ctx context.Context,
	candidates []secret.Ref,
	extraPending []inventory.PendingSecretRef,
) (GCUnreferencedResult, bool, error) {
	snap, err := s.store.Load(ctx)
	if err != nil {
		return GCUnreferencedResult{}, false, err
	}
	pending, err := s.collectPendingRefs(extraPending)
	if err != nil {
		return GCUnreferencedResult{}, false, err
	}
	res, gcErr := GCUnreferencedOnGraph(ctx, s.vault, snap.Graph(), candidates, pending)
	return res, true, gcErr
}

// GCUnreferencedOnGraph 基于已加载的资产图 g 与活跃 Pending 集合，对去重排序后的候选凭据执行 5 位置+Pending
// 零引用核验并删除无引用条目（供 credential 与 inventory 后置 GC / 暂存清理统一复用）。
func GCUnreferencedOnGraph(
	ctx context.Context,
	vault ports.SecretVault,
	g inventory.Graph,
	candidates []secret.Ref,
	pending []inventory.PendingSecretRef,
) (GCUnreferencedResult, error) {
	uniq, err := canonicalizeSecretRefs(candidates)
	if err != nil || len(uniq) == 0 {
		return GCUnreferencedResult{}, err
	}
	var res GCUnreferencedResult
	for _, ref := range uniq {
		canGC, refs := g.CanGCSecret(ref, pending...)
		if !canGC {
			res.Retained = append(res.Retained, RetainedSecret{Ref: ref, References: refs})
			continue
		}
		delErr := vault.Delete(ctx, ref)
		switch {
		case delErr == nil:
			res.Deleted = append(res.Deleted, ref)
		case errors.Is(delErr, ports.ErrSecretNotFound):
			res.Missing = append(res.Missing, ref)
		default:
			return res, delErr
		}
	}
	return res, nil
}

func reportUnknownAuditOutcome(auth gate.Authorized[security.CapMutate], code, detail string) {
	if code == "" || !auth.IsValid() {
		return
	}
	if unk, err := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, code, detail); err == nil {
		_ = auth.ReportOutcome(unk)
	}
}

// ReplaceSecretRefInGraph 以纯函数方式将资产图全部 5 位置中等于 oldRef 的凭据引用替换为 newRef，
// 保留私钥指纹绑定、AuthComposite 嵌套结构与全图不变量，返回新图与替换计数。
func ReplaceSecretRefInGraph(g inventory.Graph, oldRef, newRef secret.Ref) (inventory.Graph, int, error) {
	if !g.IsValid() || !oldRef.IsValid() || !newRef.IsValid() || oldRef.Equal(newRef) {
		return zeroVal[inventory.Graph](), 0, fmt.Errorf("%w: 图或新旧凭据引用无效", ErrInvalidRequest)
	}
	nextIdents, identCount, err := replaceSecretInIdentities(g.Identities(), oldRef, newRef)
	if err != nil {
		return zeroVal[inventory.Graph](), 0, err
	}
	nextNodes, nodeCount, err := replaceSecretInNodes(g.Nodes(), oldRef, newRef)
	if err != nil {
		return zeroVal[inventory.Graph](), 0, err
	}
	knownStores := g.KnownStores()
	if len(knownStores) > 0 && !slices.Contains(knownStores, newRef.Store()) {
		return zeroVal[inventory.Graph](), 0, fmt.Errorf("%w: 新凭据存储 %q 不在 KnownStores 内", inventory.ErrUnknownSecretStore, newRef.Store())
	}
	nextGraph, err := inventory.NewGraph(inventory.GraphSpec{
		Hosts:        g.Hosts(),
		Identities:   nextIdents,
		Nodes:        nextNodes,
		OpenSSHNodes: g.OpenSSHNodes(),
		KnownStores:  knownStores,
	})
	if err != nil {
		return zeroVal[inventory.Graph](), 0, err
	}
	return nextGraph, identCount + nodeCount, nil
}

func replaceSecretInIdentities(idents []inventory.Identity, oldRef, newRef secret.Ref) ([]inventory.Identity, int, error) {
	out := make([]inventory.Identity, len(idents))
	replaced := 0
	for i, id := range idents {
		nextAuth, n, err := replaceSecretInAuth(id.Auth(), oldRef, newRef)
		if err != nil {
			return nil, 0, err
		}
		if n == 0 {
			out[i] = id
			continue
		}
		updated, err := inventory.NewIdentity(inventory.IdentitySpec{
			ID: id.ID(), User: id.User(), Auth: nextAuth, Description: id.Description(), Tags: id.Tags(),
		})
		if err != nil {
			return nil, 0, err
		}
		out[i] = updated
		replaced += n
	}
	return out, replaced, nil
}

func replaceSecretInAuth(auth inventory.AuthMethod, oldRef, newRef secret.Ref) (inventory.AuthMethod, int, error) {
	switch v := auth.(type) {
	case *inventory.AuthPassword:
		if !v.PasswordRef().Equal(oldRef) {
			return v, 0, nil
		}
		next, err := inventory.NewAuthPassword(newRef)
		return next, 1, err
	case *inventory.AuthPrivateKey:
		return replaceSecretInPrivateKey(v, oldRef, newRef)
	case *inventory.AuthAgent:
		return v, 0, nil
	case *inventory.AuthKeyboardInteractive:
		return replaceSecretInKI(v, oldRef, newRef)
	case *inventory.AuthComposite:
		return replaceSecretInComposite(v, oldRef, newRef)
	default:
		return nil, 0, inventory.ErrInvalidAuthMethod
	}
}

func replaceSecretInPrivateKey(v *inventory.AuthPrivateKey, oldRef, newRef secret.Ref) (inventory.AuthMethod, int, error) {
	pb, ok := v.Passphrase().Get()
	if !ok || !pb.PassphraseRef().Equal(oldRef) {
		return v, 0, nil
	}
	nextBind, err := inventory.NewKeyPassphraseBinding(newRef, pb.KeyFingerprint())
	if err != nil {
		return nil, 0, err
	}
	next, err := inventory.NewAuthPrivateKey(v.KeyPaths(), algebraic.Some(nextBind), v.CertPaths())
	return next, 1, err
}

func replaceSecretInKI(v *inventory.AuthKeyboardInteractive, oldRef, newRef secret.Ref) (inventory.AuthMethod, int, error) {
	rules := v.Rules()
	nextRules := make([]inventory.ChallengeRule, len(rules))
	replaced := 0
	for i, r := range rules {
		nr, n, err := replaceSecretInRule(r, oldRef, newRef)
		if err != nil {
			return nil, 0, err
		}
		nextRules[i] = nr
		replaced += n
	}
	if replaced == 0 {
		return v, 0, nil
	}
	ne, err := algebraic.NonEmptyFromSlice(nextRules)
	if err != nil {
		return nil, 0, err
	}
	next, err := inventory.NewAuthKeyboardInteractive(ne)
	return next, replaced, err
}

func replaceSecretInRule(r inventory.ChallengeRule, oldRef, newRef secret.Ref) (inventory.ChallengeRule, int, error) {
	meta := inventory.ChallengeRuleMeta{
		Name: r.Name(), PromptPattern: r.PromptPattern(), InstructionPattern: r.InstructionPattern(),
	}
	switch v := r.(type) {
	case *inventory.RuleTOTP:
		if !v.TOTPSecretRef().Equal(oldRef) {
			return v, 0, nil
		}
		next, err := inventory.NewRuleTOTP(meta, newRef)
		return next, 1, err
	case *inventory.RuleSecretRef:
		if !v.SecretRef().Equal(oldRef) {
			return v, 0, nil
		}
		next, err := inventory.NewRuleSecretRef(meta, newRef)
		return next, 1, err
	case *inventory.RuleCommand, *inventory.RuleLoginPassword:
		return v, 0, nil
	default:
		return nil, 0, inventory.ErrInvalidChallengeRule
	}
}

func replaceSecretInComposite(v *inventory.AuthComposite, oldRef, newRef secret.Ref) (inventory.AuthMethod, int, error) {
	subs := v.Methods()
	nextSubs := make([]inventory.AuthMethod, len(subs))
	replaced := 0
	for i, sub := range subs {
		ns, n, err := replaceSecretInAuth(sub, oldRef, newRef)
		if err != nil {
			return nil, 0, err
		}
		nextSubs[i] = ns
		replaced += n
	}
	if replaced == 0 {
		return v, 0, nil
	}
	ne, err := algebraic.NonEmptyFromSlice(nextSubs)
	if err != nil {
		return nil, 0, err
	}
	next, err := inventory.NewAuthComposite(ne)
	return next, replaced, err
}

func replaceSecretInNodes(nodes []inventory.Node, oldRef, newRef secret.Ref) ([]inventory.Node, int, error) {
	out := make([]inventory.Node, len(nodes))
	replaced := 0
	for i, n := range nodes {
		ref, ok := n.PrivilegePasswordRef().Get()
		if !ok || !ref.Equal(oldRef) {
			out[i] = n
			continue
		}
		updated, err := inventory.NewNode(inventory.NodeSpec{
			ID: n.ID(), HostRef: n.HostRef(), IdentityRef: n.IdentityRef(),
			Aliases: n.Aliases(), Tags: n.Tags(), Proxy: n.Proxy(), Execution: n.Execution(),
			Options: n.Options(), PrivilegePasswordRef: algebraic.Some(newRef),
			Origin: n.Origin(), Description: n.Description(),
		})
		if err != nil {
			return nil, 0, err
		}
		out[i] = updated
		replaced++
	}
	return out, replaced, nil
}

func canonicalizeSecretRefs(raw []secret.Ref) ([]secret.Ref, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := slices.Clone(raw)
	for _, r := range out {
		if !r.IsValid() {
			return nil, fmt.Errorf("%w: Candidates 包含无效 Ref", ErrInvalidRequest)
		}
	}
	slices.SortFunc(out, secret.Ref.Compare)
	return slices.CompactFunc(out, secret.Ref.Equal), nil
}
