package inventory

import (
	"context"
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
	"github.com/wentf9/xops-cli/core/ports"
)

// QueryRequest、SecretRefCheckRequest、资产 CAS 写请求与 MutationResult 定义。
type (
	// QueryRequest 描述只读资产查询与 DAG 校验的通用门控参数。
	QueryRequest struct {
		Risk            algebraic.Option[security.RiskLevel]
		Approval        algebraic.Option[gate.ApprovalSubmission]
		OperationStream *events.OperationStream
	}
	// SecretRefCheckRequest 描述全图 5 位置与 Pending 凭据引用检查请求（Ref 与 StoreID 二选一）。
	SecretRefCheckRequest struct {
		Ref             secret.Ref
		StoreID         string
		ExtraPending    []inventory.PendingSecretRef
		Risk            algebraic.Option[security.RiskLevel]
		Approval        algebraic.Option[gate.ApprovalSubmission]
		OperationStream *events.OperationStream
	}
	// HostMutationRequest 描述创建或更新 Host 的乐观并发 CAS 写请求。
	HostMutationRequest struct {
		Host             inventory.Host
		ExpectedRevision algebraic.Option[ports.Revision]
		ScopeSummary     string
		Risk             algebraic.Option[security.RiskLevel]
		Approval         algebraic.Option[gate.ApprovalSubmission]
		OperationStream  *events.OperationStream
	}
	// DeleteHostRequest 描述删除 Host 的 CAS 写请求（受节点反向引用保护）。
	DeleteHostRequest struct {
		ID               inventory.HostID
		ExpectedRevision algebraic.Option[ports.Revision]
		ScopeSummary     string
		Risk             algebraic.Option[security.RiskLevel]
		Approval         algebraic.Option[gate.ApprovalSubmission]
		OperationStream  *events.OperationStream
	}
	// IdentityMutationRequest 描述创建或更新 Identity 的 CAS 写请求（可选回收旧凭据）。
	IdentityMutationRequest struct {
		Identity                 inventory.Identity
		ExpectedRevision         algebraic.Option[ports.Revision]
		GCUnreferencedOldSecrets bool
		ScopeSummary             string
		Risk                     algebraic.Option[security.RiskLevel]
		Approval                 algebraic.Option[gate.ApprovalSubmission]
		OperationStream          *events.OperationStream
	}
	// DeleteIdentityRequest 描述删除 Identity 的 CAS 写请求（受反向引用及 5 位置+Pending 凭据保护）。
	DeleteIdentityRequest struct {
		ID                                              inventory.IdentityID
		ExpectedRevision                                algebraic.Option[ports.Revision]
		DeleteUnusedSecrets, RequireSecretsUnreferenced bool
		ExtraPending                                    []inventory.PendingSecretRef
		ScopeSummary                                    string
		Risk                                            algebraic.Option[security.RiskLevel]
		Approval                                        algebraic.Option[gate.ApprovalSubmission]
		OperationStream                                 *events.OperationStream
	}
	// NodeMutationRequest 描述创建或更新 Node 的 CAS 写请求（执行跨命名空间 Tarjan DAG 校验）。
	NodeMutationRequest struct {
		Node                     inventory.Node
		ExpectedRevision         algebraic.Option[ports.Revision]
		GCUnreferencedOldSecrets bool
		ScopeSummary             string
		Risk                     algebraic.Option[security.RiskLevel]
		Approval                 algebraic.Option[gate.ApprovalSubmission]
		OperationStream          *events.OperationStream
	}
	// DeleteNodeRequest 描述删除 Node 的 CAS 写请求（受 ProxyJump 反向引用及提权凭据保护）。
	DeleteNodeRequest struct {
		ID                                              inventory.NodeID
		ExpectedRevision                                algebraic.Option[ports.Revision]
		DeleteUnusedSecrets, RequireSecretsUnreferenced bool
		ExtraPending                                    []inventory.PendingSecretRef
		ScopeSummary                                    string
		Risk                                            algebraic.Option[security.RiskLevel]
		Approval                                        algebraic.Option[gate.ApprovalSubmission]
		OperationStream                                 *events.OperationStream
	}
	// MutationResult 封装 CAS 资产写入/删除成功后的不可变版本、持久化结论与凭据回收摘要；零值恒无效。
	//
	//xops:opaque
	//xops:failclosed
	MutationResult struct {
		revision        ports.Revision
		durability      ports.DurabilityOutcome
		deletedSecrets  []secret.Ref
		retainedSecrets []RetainedSecret
		valid           bool
	}
	casMutationSpec struct {
		valid, gcSecrets, requireSecretsUnref bool
		label, action, nodeID, targetID, sum  string
		expectedRevision                      algebraic.Option[ports.Revision]
		extraPending                          []inventory.PendingSecretRef
		risk                                  algebraic.Option[security.RiskLevel]
		approval                              algebraic.Option[gate.ApprovalSubmission]
		stream                                *events.OperationStream
		mutate                                func(inventory.Graph) ([]inventory.Host, []inventory.Identity, []inventory.Node, []secret.Ref, error)
	}
)

// MutationResult 只读访问器（零值恒无效）。
func (r MutationResult) IsValid() bool {
	return r.valid && r.revision.IsValid() && r.durability.IsValid()
}
func (r MutationResult) IsZero() bool                        { return !r.IsValid() }
func (r MutationResult) Revision() ports.Revision            { return r.revision }
func (r MutationResult) Durability() ports.DurabilityOutcome { return r.durability }
func (r MutationResult) DeletedSecrets() []secret.Ref        { return slices.Clone(r.deletedSecrets) }
func (r MutationResult) RetainedSecrets() []RetainedSecret   { return slices.Clone(r.retainedSecrets) }

// GetSnapshot、List* 与 Get* 提供经 CapInspect 鉴权的只读快照、全量列表与按 ID 单实体查询。
func (s *Service) GetSnapshot(ctx context.Context, req QueryRequest) (ports.InventorySnapshot, error) {
	return runInspect(ctx, s, "get_snapshot", "load inventory snapshot", req.Risk, req.Approval, req.OperationStream, func(c context.Context) (ports.InventorySnapshot, error) { return s.store.Load(c) })
}
func (s *Service) ListHosts(ctx context.Context, req QueryRequest) ([]inventory.Host, ports.Revision, error) {
	return listAssets(ctx, s, req, inventory.Graph.Hosts)
}
func (s *Service) ListIdentities(ctx context.Context, req QueryRequest) ([]inventory.Identity, ports.Revision, error) {
	return listAssets(ctx, s, req, inventory.Graph.Identities)
}
func (s *Service) ListNodes(ctx context.Context, req QueryRequest) ([]inventory.Node, ports.Revision, error) {
	return listAssets(ctx, s, req, inventory.Graph.Nodes)
}
func listAssets[T any](ctx context.Context, s *Service, req QueryRequest, extract func(inventory.Graph) []T) ([]T, ports.Revision, error) {
	snap, err := s.GetSnapshot(ctx, req)
	if err != nil {
		return nil, zeroVal[ports.Revision](), err
	}
	return extract(snap.Graph()), snap.Revision(), nil
}
func (s *Service) GetHost(ctx context.Context, id inventory.HostID, req QueryRequest) (inventory.Host, ports.Revision, error) {
	return getAssetByID(ctx, s, req, "host", id, id.IsValid(), inventory.Graph.Hosts, func(h inventory.Host) bool { return h.ID().Equal(id) })
}
func (s *Service) GetIdentity(ctx context.Context, id inventory.IdentityID, req QueryRequest) (inventory.Identity, ports.Revision, error) {
	return getAssetByID(ctx, s, req, "identity", id, id.IsValid(), inventory.Graph.Identities, func(i inventory.Identity) bool { return i.ID().Equal(id) })
}
func (s *Service) GetNode(ctx context.Context, id inventory.NodeID, req QueryRequest) (inventory.Node, ports.Revision, error) {
	return getAssetByID(ctx, s, req, "node", id, id.IsValid(), inventory.Graph.Nodes, func(n inventory.Node) bool { return n.ID().Equal(id) })
}
func getAssetByID[T any, ID fmt.Stringer](ctx context.Context, s *Service, req QueryRequest, kind string, id ID, idValid bool, extract func(inventory.Graph) []T, match func(T) bool) (z T, rev ports.Revision, err error) {
	if !idValid {
		closeIfNonNil(req.OperationStream)
		return z, rev, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", kind+"_id"))
	}
	items, rev, err := listAssets(ctx, s, req, extract)
	if err != nil {
		return z, rev, err
	}
	if idx := slices.IndexFunc(items, match); idx >= 0 {
		return items[idx], rev, nil
	}
	return z, zeroVal[ports.Revision](), domi18n.WrapSentinelDetail(ErrAssetNotFound, nil, kind+" "+id.String())
}

// ValidateDAG 经 CapInspect 鉴权对托管资产图与全部 OpenSSH 虚拟主机执行跨命名空间 Tarjan SCC ProxyJump 校验；
// 检测到环路返回 ErrProxyJumpCycle 时保留 DAGReport.Cycles 供调用方诊断。
func (s *Service) ValidateDAG(ctx context.Context, req QueryRequest) (inventory.DAGReport, error) {
	return runInspect(ctx, s, "validate_dag", "validate cross-namespace proxy DAG", req.Risk, req.Approval, req.OperationStream, func(c context.Context) (inventory.DAGReport, error) {
		snap, err := s.store.Load(c)
		if err != nil {
			return inventory.DAGReport{}, err
		}
		openSSH, err := s.collectOpenSSHJumpNodes(c)
		if err != nil {
			return inventory.DAGReport{}, err
		}
		return inventory.ValidateProxyDAG(snap.Graph().Nodes(), openSSH, s.maxJumpDepth)
	})
}

// CheckSecretReferences 经 CapInspect 鉴权在受权回调内同步快照 5 位置与活跃 Pending 租约，返回指定 Ref 或 StoreID 的全部引用清单。
func (s *Service) CheckSecretReferences(ctx context.Context, req SecretRefCheckRequest) ([]inventory.SecretReference, error) {
	hasRef := req.Ref.IsValid()
	if hasRef == (req.StoreID != "") {
		closeIfNonNil(req.OperationStream)
		return nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonOneOfRequired, domi18n.Str("options", "Ref, StoreID"))
	}
	if err := validateExtraPending(req.ExtraPending); err != nil {
		closeIfNonNil(req.OperationStream)
		return nil, err
	}
	return runInspect(ctx, s, "check_secret_references", "check 5-location secret references", req.Risk, req.Approval, req.OperationStream, func(c context.Context) ([]inventory.SecretReference, error) {
		snap, err := s.store.Load(c)
		if err != nil {
			return nil, err
		}
		pending, err := s.mergePendingRefsExcluding(zeroVal[security.OperationID](), req.ExtraPending)
		if err != nil {
			return nil, err
		}
		if hasRef {
			return snap.Graph().FindSecretReferences(req.Ref, pending...), nil
		}
		return snap.Graph().FindStoreReferences(req.StoreID, pending...), nil
	})
}

// Create*/Update* 提供经 CapMutate 鉴权、跨命名空间 Tarjan DAG 校验与可选旧凭据安全 GC 的乐观并发 CAS 写操作。
func (s *Service) CreateHost(ctx context.Context, req HostMutationRequest) (MutationResult, error) {
	return s.mutateHost(ctx, req, false)
}
func (s *Service) UpdateHost(ctx context.Context, req HostMutationRequest) (MutationResult, error) {
	return s.mutateHost(ctx, req, true)
}
func (s *Service) CreateIdentity(ctx context.Context, req IdentityMutationRequest) (MutationResult, error) {
	return s.mutateIdentity(ctx, req, false)
}
func (s *Service) UpdateIdentity(ctx context.Context, req IdentityMutationRequest) (MutationResult, error) {
	return s.mutateIdentity(ctx, req, true)
}
func (s *Service) CreateNode(ctx context.Context, req NodeMutationRequest) (MutationResult, error) {
	return s.mutateNode(ctx, req, false)
}
func (s *Service) UpdateNode(ctx context.Context, req NodeMutationRequest) (MutationResult, error) {
	return s.mutateNode(ctx, req, true)
}

func (s *Service) mutateHost(ctx context.Context, req HostMutationRequest, upd bool) (MutationResult, error) {
	return s.runCASMutation(ctx, casMutationSpec{
		valid: req.Host.IsValid(), label: "Host", action: pickIf(upd, "update_host", "create_host"), targetID: req.Host.ID().String(),
		sum: req.ScopeSummary, expectedRevision: req.ExpectedRevision, risk: req.Risk, approval: req.Approval, stream: req.OperationStream,
		mutate: func(g inventory.Graph) ([]inventory.Host, []inventory.Identity, []inventory.Node, []secret.Ref, error) {
			hosts, _, err := upsertAsset(g.Hosts(), req.Host, upd, "host", req.Host.ID().String(), func(h inventory.Host) bool { return h.ID().Equal(req.Host.ID()) })
			return hosts, g.Identities(), g.Nodes(), nil, err
		},
	})
}

// DeleteHost 经 CapMutate 鉴权与节点反向引用保护后执行 CAS 删除 Host。
func (s *Service) DeleteHost(ctx context.Context, req DeleteHostRequest) (MutationResult, error) {
	return s.runCASMutation(ctx, casMutationSpec{
		valid: req.ID.IsValid(), label: "HostID", action: "delete_host", targetID: req.ID.String(),
		sum: req.ScopeSummary, expectedRevision: req.ExpectedRevision, risk: req.Risk, approval: req.Approval, stream: req.OperationStream,
		mutate: func(g inventory.Graph) ([]inventory.Host, []inventory.Identity, []inventory.Node, []secret.Ref, error) {
			hosts, _, err := removeProtectedAsset(g.Hosts(), "host", req.ID.String(), func(h inventory.Host) bool { return h.ID().Equal(req.ID) }, func() (bool, []inventory.AssetReference) { return g.CanDeleteHost(req.ID) })
			return hosts, g.Identities(), g.Nodes(), nil, err
		},
	})
}
func (s *Service) mutateIdentity(ctx context.Context, req IdentityMutationRequest, upd bool) (MutationResult, error) {
	return s.runCASMutation(ctx, casMutationSpec{
		valid: req.Identity.IsValid(), label: "Identity", action: pickIf(upd, "update_identity", "create_identity"), targetID: req.Identity.ID().String(),
		sum: req.ScopeSummary, expectedRevision: req.ExpectedRevision, gcSecrets: upd && req.GCUnreferencedOldSecrets, risk: req.Risk, approval: req.Approval, stream: req.OperationStream,
		mutate: func(g inventory.Graph) ([]inventory.Host, []inventory.Identity, []inventory.Node, []secret.Ref, error) {
			idents, prev, err := upsertAsset(g.Identities(), req.Identity, upd, "identity", req.Identity.ID().String(), func(i inventory.Identity) bool { return i.ID().Equal(req.Identity.ID()) })
			return g.Hosts(), idents, g.Nodes(), secretRefsIf(err == nil && upd, func() []secret.Ref { return secretRefsForIdentity(g, prev.ID()) }), err
		},
	})
}

// DeleteIdentity 经 CapMutate 鉴权、反向引用保护及 5 位置+Pending 凭据完整性校验后执行 CAS 删除 Identity。
func (s *Service) DeleteIdentity(ctx context.Context, req DeleteIdentityRequest) (MutationResult, error) {
	return s.runCASMutation(ctx, casMutationSpec{
		valid: req.ID.IsValid(), label: "IdentityID", action: "delete_identity", targetID: req.ID.String(),
		sum: req.ScopeSummary, expectedRevision: req.ExpectedRevision, gcSecrets: req.DeleteUnusedSecrets,
		requireSecretsUnref: req.RequireSecretsUnreferenced, extraPending: req.ExtraPending, risk: req.Risk, approval: req.Approval, stream: req.OperationStream,
		mutate: func(g inventory.Graph) ([]inventory.Host, []inventory.Identity, []inventory.Node, []secret.Ref, error) {
			idents, _, err := removeProtectedAsset(g.Identities(), "identity", req.ID.String(), func(i inventory.Identity) bool { return i.ID().Equal(req.ID) }, func() (bool, []inventory.AssetReference) { return g.CanDeleteIdentity(req.ID) })
			return g.Hosts(), idents, g.Nodes(), secretRefsIf(err == nil, func() []secret.Ref { return secretRefsForIdentity(g, req.ID) }), err
		},
	})
}
func (s *Service) mutateNode(ctx context.Context, req NodeMutationRequest, upd bool) (MutationResult, error) {
	return s.runCASMutation(ctx, casMutationSpec{
		valid: req.Node.IsValid(), label: "Node", action: pickIf(upd, "update_node", "create_node"), nodeID: req.Node.ID().String(), targetID: req.Node.ID().String(),
		sum: req.ScopeSummary, expectedRevision: req.ExpectedRevision, gcSecrets: upd && req.GCUnreferencedOldSecrets, risk: req.Risk, approval: req.Approval, stream: req.OperationStream,
		mutate: func(g inventory.Graph) ([]inventory.Host, []inventory.Identity, []inventory.Node, []secret.Ref, error) {
			nodes, prev, err := upsertAsset(g.Nodes(), req.Node, upd, "node", req.Node.ID().String(), func(n inventory.Node) bool { return n.ID().Equal(req.Node.ID()) })
			return g.Hosts(), g.Identities(), nodes, secretRefsIf(err == nil && upd, func() []secret.Ref { return nodePrivSecretRefs(prev) }), err
		},
	})
}

// DeleteNode 经 CapMutate 鉴权、跨命名空间 ProxyJump 反向引用与提权凭据保护后执行 CAS 删除 Node。
func (s *Service) DeleteNode(ctx context.Context, req DeleteNodeRequest) (MutationResult, error) {
	return s.runCASMutation(ctx, casMutationSpec{
		valid: req.ID.IsValid(), label: "NodeID", action: "delete_node", nodeID: req.ID.String(), targetID: req.ID.String(),
		sum: req.ScopeSummary, expectedRevision: req.ExpectedRevision, gcSecrets: req.DeleteUnusedSecrets,
		requireSecretsUnref: req.RequireSecretsUnreferenced, extraPending: req.ExtraPending, risk: req.Risk, approval: req.Approval, stream: req.OperationStream,
		mutate: func(g inventory.Graph) ([]inventory.Host, []inventory.Identity, []inventory.Node, []secret.Ref, error) {
			nodes, rem, err := removeProtectedAsset(g.Nodes(), "node", req.ID.String(), func(n inventory.Node) bool { return n.ID().Equal(req.ID) }, func() (bool, []inventory.AssetReference) { return g.CanDeleteNode(req.ID) })
			return g.Hosts(), g.Identities(), nodes, secretRefsIf(err == nil, func() []secret.Ref { return nodePrivSecretRefs(rem) }), err
		},
	})
}
func secretRefsIf(ok bool, fn func() []secret.Ref) []secret.Ref {
	if !ok {
		return nil
	}
	return fn()
}

func upsertAsset[T any](items []T, item T, upd bool, kind, id string, match func(T) bool) ([]T, T, error) {
	idx := slices.IndexFunc(items, match)
	switch {
	case !upd && idx >= 0:
		return nil, zeroVal[T](), domi18n.EF(ErrAssetAlreadyExists, domi18n.KeyCommonDuplicateItem, domi18n.Str("kind", kind), domi18n.BoundStr("value", id))
	case upd && idx < 0:
		return nil, zeroVal[T](), domi18n.WrapSentinelDetail(ErrAssetNotFound, nil, kind+" "+id)
	case upd:
		prev := items[idx]
		items[idx] = item
		return items, prev, nil
	default:
		return append(items, item), zeroVal[T](), nil
	}
}
func removeProtectedAsset[T any](items []T, kind, id string, match func(T) bool, canDel func() (bool, []inventory.AssetReference)) ([]T, T, error) {
	idx := slices.IndexFunc(items, match)
	if idx < 0 {
		return nil, zeroVal[T](), domi18n.WrapSentinelDetail(ErrAssetNotFound, nil, kind+" "+id)
	}
	if ok, refs := canDel(); !ok {
		return nil, zeroVal[T](), newAssetReferencedError(kind, id, refs)
	}
	rem := items[idx]
	return slices.Delete(items, idx, idx+1), rem, nil
}
func (s *Service) runCASMutation(ctx context.Context, spec casMutationSpec) (MutationResult, error) {
	var vErr error
	switch {
	case !spec.valid:
		vErr = domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", spec.label))
	case spec.expectedRevision.IsSome() && !spec.expectedRevision.OrElse(zeroVal[ports.Revision]()).IsValid():
		vErr = domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ExpectedRevision"))
	case spec.gcSecrets && s.vault == nil:
		vErr = ErrVaultUnavailable // 显式请求凭据 GC 但未注入 SecretVault 时写前失败关闭，严禁静默跳过
	default:
		vErr = validateExtraPending(spec.extraPending)
	}
	if vErr != nil {
		closeIfNonNil(spec.stream)
		return MutationResult{}, vErr
	}
	return runMutate(ctx, s, spec.action, spec.nodeID, pickIf(spec.sum != "", spec.sum, spec.action+" "+spec.targetID), spec.risk, spec.approval, spec.stream, func(c context.Context, _ security.TraceID, _ security.OperationID) (MutationResult, string, string, error) {
		res, unkCode, err := s.execCASMutation(c, spec)
		return res, unkCode, errMsg(err), err
	})
}
func errMsg(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
func (s *Service) execCASMutation(ctx context.Context, spec casMutationSpec) (MutationResult, string, error) {
	snap, err := s.loadSnapshotAt(ctx, spec.expectedRevision)
	if err != nil {
		return MutationResult{}, "", err
	}
	hosts, idents, nodes, refs, err := spec.mutate(snap.Graph())
	var nextGraph inventory.Graph
	if err == nil {
		nextGraph, err = s.buildValidatedGraph(ctx, snap.Graph(), hosts, idents, nodes)
	}
	if err == nil && spec.requireSecretsUnref && len(refs) > 0 {
		err = s.ensureRefsUnreferenced(nextGraph, refs, spec.extraPending)
	}
	if err != nil {
		return MutationResult{}, "", err
	}
	_, newRev, out, unkCode, err := s.commitGraphCAS(ctx, snap.Revision(), nextGraph, "commit_missing_revision")
	if err != nil || !spec.gcSecrets || len(refs) == 0 {
		return MutationResult{revision: newRev, durability: out, valid: err == nil}, unkCode, err
	}
	gcRes, _, gcErr := s.gcSecretsDetached(ctx, zeroVal[security.OperationID](), refs, spec.extraPending)
	res := MutationResult{revision: newRev, durability: out, deletedSecrets: gcRes.Deleted, retainedSecrets: gcRes.Retained, valid: true}
	return res, pickIf(gcErr != nil, "post_commit_secret_gc_failed", ""), gcErr // 配置已生效，后置 GC 失败须上报 OutcomeUnknown
}
func (s *Service) ensureRefsUnreferenced(next inventory.Graph, refs []secret.Ref, extra []inventory.PendingSecretRef) error {
	pending, err := s.mergePendingRefsExcluding(zeroVal[security.OperationID](), extra)
	if err != nil {
		return err
	}
	sorted := slices.Clone(refs)
	slices.SortFunc(sorted, secret.Ref.Compare)
	for _, ref := range slices.CompactFunc(sorted, secret.Ref.Equal) {
		if canGC, blocking := next.CanGCSecret(ref, pending...); !canGC {
			return newSecretReferencedError(ref.String(), blocking)
		}
	}
	return nil
}

// gcSecretsDetached 在有界 context.WithoutCancel 下重载快照并复用 credential.GCUnreferencedOnGraph 安全清理无引用凭据，
// 返回 loadFailed 以便区分加载失败（SideEffectFailedNotApplied）与删除失败（SideEffectOutcomeUnknown）。
func (s *Service) gcSecretsDetached(ctx context.Context, excludeLease security.OperationID, candidates []secret.Ref, extra []inventory.PendingSecretRef) (credential.GCUnreferencedResult, bool, error) {
	cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupEffectTimeout)
	defer cancel()
	snap, err := s.store.Load(cleanCtx)
	if err != nil {
		return credential.GCUnreferencedResult{}, true, err
	}
	pending, err := s.mergePendingRefsExcluding(excludeLease, extra)
	if err != nil {
		return credential.GCUnreferencedResult{}, true, err
	}
	res, delErr := credential.GCUnreferencedOnGraph(cleanCtx, s.vault, snap.Graph(), candidates, pending)
	return res, false, delErr
}
func nodePrivSecretRefs(n inventory.Node) []secret.Ref {
	if ref, ok := n.PrivilegePasswordRef().Get(); ok {
		return []secret.Ref{ref}
	}
	return nil
}
func secretRefsForIdentity(g inventory.Graph, id inventory.IdentityID) []secret.Ref {
	owner := id.String()
	var out []secret.Ref
	for _, sr := range g.AllSecretReferences() {
		if sr.Location >= inventory.SecretLocAuthPassword && sr.Location <= inventory.SecretLocChallengeSecret && sr.OwnerID == owner {
			out = append(out, sr.Ref)
		}
	}
	slices.SortFunc(out, secret.Ref.Compare)
	return slices.CompactFunc(out, secret.Ref.Equal)
}
