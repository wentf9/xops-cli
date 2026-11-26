package inventory

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

// QueryRequest、SecretRefCheckRequest、各类资产 CAS 写请求与不可变 MutationResult 定义。
type (
	QueryRequest struct {
		Risk            algebraic.Option[security.RiskLevel]
		Approval        algebraic.Option[gate.ApprovalSubmission]
		OperationStream *events.OperationStream
	}
	SecretRefCheckRequest struct {
		Ref             secret.Ref
		StoreID         string
		ExtraPending    []inventory.PendingSecretRef
		Risk            algebraic.Option[security.RiskLevel]
		Approval        algebraic.Option[gate.ApprovalSubmission]
		OperationStream *events.OperationStream
	}
	HostMutationRequest struct {
		Host             inventory.Host
		ExpectedRevision algebraic.Option[ports.Revision]
		ScopeSummary     string
		Risk             algebraic.Option[security.RiskLevel]
		Approval         algebraic.Option[gate.ApprovalSubmission]
		OperationStream  *events.OperationStream
	}
	DeleteHostRequest struct {
		ID               inventory.HostID
		ExpectedRevision algebraic.Option[ports.Revision]
		ScopeSummary     string
		Risk             algebraic.Option[security.RiskLevel]
		Approval         algebraic.Option[gate.ApprovalSubmission]
		OperationStream  *events.OperationStream
	}
	IdentityMutationRequest struct {
		Identity                 inventory.Identity
		ExpectedRevision         algebraic.Option[ports.Revision]
		GCUnreferencedOldSecrets bool
		ScopeSummary             string
		Risk                     algebraic.Option[security.RiskLevel]
		Approval                 algebraic.Option[gate.ApprovalSubmission]
		OperationStream          *events.OperationStream
	}
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
	NodeMutationRequest struct {
		Node                     inventory.Node
		ExpectedRevision         algebraic.Option[ports.Revision]
		GCUnreferencedOldSecrets bool
		ScopeSummary             string
		Risk                     algebraic.Option[security.RiskLevel]
		Approval                 algebraic.Option[gate.ApprovalSubmission]
		OperationStream          *events.OperationStream
	}
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
		action, nodeID, summary string
		expectedRevision        algebraic.Option[ports.Revision]
		gcSecrets               bool
		extraPending            []inventory.PendingSecretRef
		risk                    security.RiskLevel
		approval                algebraic.Option[gate.ApprovalSubmission]
		stream                  *events.OperationStream
		mutate                  func(authCtx context.Context, g inventory.Graph) (inventory.Graph, []secret.Ref, error)
	}
)

// MutationResult 只读访问器。
func (r MutationResult) IsValid() bool {
	return r.valid && r.revision.IsValid() && r.durability.IsValid()
}
func (r MutationResult) IsZero() bool                        { return !r.IsValid() }
func (r MutationResult) Revision() ports.Revision            { return r.revision }
func (r MutationResult) Durability() ports.DurabilityOutcome { return r.durability }
func (r MutationResult) DeletedSecrets() []secret.Ref        { return slices.Clone(r.deletedSecrets) }
func (r MutationResult) RetainedSecrets() []RetainedSecret   { return slices.Clone(r.retainedSecrets) }

// GetSnapshot、List*、Get*、ValidateDAG 与 CheckSecretReferences 提供经 CapInspect 鉴权的只读查询与校验。
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
		return z, rev, fmt.Errorf("%w: %s ID 无效", ErrInvalidRequest, kind)
	}
	items, rev, err := listAssets(ctx, s, req, extract)
	if err != nil {
		return z, rev, err
	}
	if idx := slices.IndexFunc(items, match); idx >= 0 {
		return items[idx], rev, nil
	}
	return z, zeroVal[ports.Revision](), fmt.Errorf("%w: %s %q", ErrAssetNotFound, kind, id)
}

// ValidateDAG 经 CapInspect 鉴权对托管资产图与实时 OpenSSH 虚拟主机执行跨命名空间 Tarjan SCC ProxyJump DAG 校验。
func (s *Service) ValidateDAG(ctx context.Context, req QueryRequest) (inventory.DAGReport, error) {
	return runInspect(ctx, s, "validate_dag", "validate cross-namespace proxy DAG", req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context) (inventory.DAGReport, error) {
		snap, err := s.store.Load(authCtx)
		if err != nil {
			return inventory.DAGReport{}, err
		}
		openSSHNodes, err := s.collectOpenSSHJumpNodes(authCtx)
		if err != nil {
			return inventory.DAGReport{}, err
		}
		return inventory.ValidateProxyDAG(snap.Graph().Nodes(), openSSHNodes, s.maxJumpDepth)
	})
}

// CheckSecretReferences 经 CapInspect 鉴权扫描全部 5 位置与活跃 Pending 租约，返回指向指定 Ref 或 StoreID 的引用清单。
func (s *Service) CheckSecretReferences(ctx context.Context, req SecretRefCheckRequest) ([]inventory.SecretReference, error) {
	hasRef, hasStore := req.Ref.IsValid(), req.StoreID != ""
	if hasRef == hasStore {
		closeIfNonNil(req.OperationStream)
		return nil, fmt.Errorf("%w: Ref 与 StoreID 必须二选一提供", ErrInvalidRequest)
	}
	pending, err := s.mergePendingRefsExcluding(zeroVal[security.OperationID](), req.ExtraPending)
	if err != nil {
		closeIfNonNil(req.OperationStream)
		return nil, err
	}
	return runInspect(ctx, s, "check_secret_references", "check 5-location secret references", req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context) ([]inventory.SecretReference, error) {
		snap, lErr := s.store.Load(authCtx)
		if lErr != nil {
			return nil, lErr
		}
		return pickIf(hasRef, snap.Graph().FindSecretReferences(req.Ref, pending...), snap.Graph().FindStoreReferences(req.StoreID, pending...)), nil
	})
}

// Create*/Update*/Delete* 提供经 CapMutate 鉴权、全图 Tarjan DAG 校验与 5 位置+Pending 凭据保护的 CAS 写操作。
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
func (s *Service) mutateHost(ctx context.Context, req HostMutationRequest, isUpdate bool) (MutationResult, error) {
	return runValidMutation(ctx, s, req.Host.IsValid(), "Host", pickIf(isUpdate, "update_host", "create_host"), "", req.Host.ID().String(), req.ScopeSummary, req.ExpectedRevision, false, nil, req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context, g inventory.Graph) (inventory.Graph, []secret.Ref, error) {
		hosts, _, err := upsertAsset(g.Hosts(), req.Host, isUpdate, "host", req.Host.ID().String(), func(h inventory.Host) bool { return h.ID().Equal(req.Host.ID()) })
		return s.finishGraph(authCtx, g, hosts, g.Identities(), g.Nodes(), nil, err)
	})
}
func (s *Service) DeleteHost(ctx context.Context, req DeleteHostRequest) (MutationResult, error) {
	return runValidMutation(ctx, s, req.ID.IsValid(), "HostID", "delete_host", "", req.ID.String(), req.ScopeSummary, req.ExpectedRevision, false, nil, req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context, g inventory.Graph) (inventory.Graph, []secret.Ref, error) {
		hosts, _, err := removeProtectedAsset(g.Hosts(), "host", req.ID.String(), func(h inventory.Host) bool { return h.ID().Equal(req.ID) }, func() (bool, []inventory.AssetReference) { return g.CanDeleteHost(req.ID) })
		return s.finishGraph(authCtx, g, hosts, g.Identities(), g.Nodes(), nil, err)
	})
}
func (s *Service) mutateIdentity(ctx context.Context, req IdentityMutationRequest, isUpdate bool) (MutationResult, error) {
	return runValidMutation(ctx, s, req.Identity.IsValid(), "Identity", pickIf(isUpdate, "update_identity", "create_identity"), "", req.Identity.ID().String(), req.ScopeSummary, req.ExpectedRevision, isUpdate && req.GCUnreferencedOldSecrets, nil, req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context, g inventory.Graph) (inventory.Graph, []secret.Ref, error) {
		idents, prev, err := upsertAsset(g.Identities(), req.Identity, isUpdate, "identity", req.Identity.ID().String(), func(i inventory.Identity) bool { return i.ID().Equal(req.Identity.ID()) })
		return s.finishGraph(authCtx, g, g.Hosts(), idents, g.Nodes(), pickIf(isUpdate, secretRefsForIdentity(g, prev.ID()), nil), err)
	})
}
func (s *Service) DeleteIdentity(ctx context.Context, req DeleteIdentityRequest) (MutationResult, error) {
	return runValidMutation(ctx, s, req.ID.IsValid(), "IdentityID", "delete_identity", "", req.ID.String(), req.ScopeSummary, req.ExpectedRevision, req.DeleteUnusedSecrets, req.ExtraPending, req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context, g inventory.Graph) (inventory.Graph, []secret.Ref, error) {
		idents, _, err := removeProtectedAsset(g.Identities(), "identity", req.ID.String(), func(i inventory.Identity) bool { return i.ID().Equal(req.ID) }, func() (bool, []inventory.AssetReference) { return g.CanDeleteIdentity(req.ID) })
		next, refs, bErr := s.finishGraph(authCtx, g, g.Hosts(), idents, g.Nodes(), secretRefsForIdentity(g, req.ID), err)
		return s.finalizeDeleteMutation(next, refs, req.RequireSecretsUnreferenced, req.ExtraPending, bErr)
	})
}
func (s *Service) mutateNode(ctx context.Context, req NodeMutationRequest, isUpdate bool) (MutationResult, error) {
	return runValidMutation(ctx, s, req.Node.IsValid(), "Node", pickIf(isUpdate, "update_node", "create_node"), req.Node.ID().String(), req.Node.ID().String(), req.ScopeSummary, req.ExpectedRevision, isUpdate && req.GCUnreferencedOldSecrets, nil, req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context, g inventory.Graph) (inventory.Graph, []secret.Ref, error) {
		nodes, prev, err := upsertAsset(g.Nodes(), req.Node, isUpdate, "node", req.Node.ID().String(), func(n inventory.Node) bool { return n.ID().Equal(req.Node.ID()) })
		return s.finishGraph(authCtx, g, g.Hosts(), g.Identities(), nodes, pickIf(isUpdate, nodePrivSecretRefs(prev), nil), err)
	})
}
func (s *Service) DeleteNode(ctx context.Context, req DeleteNodeRequest) (MutationResult, error) {
	return runValidMutation(ctx, s, req.ID.IsValid(), "NodeID", "delete_node", req.ID.String(), req.ID.String(), req.ScopeSummary, req.ExpectedRevision, req.DeleteUnusedSecrets, req.ExtraPending, req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context, g inventory.Graph) (inventory.Graph, []secret.Ref, error) {
		nodes, removed, err := removeProtectedAsset(g.Nodes(), "node", req.ID.String(), func(n inventory.Node) bool { return n.ID().Equal(req.ID) }, func() (bool, []inventory.AssetReference) { return g.CanDeleteNode(req.ID) })
		next, refs, bErr := s.finishGraph(authCtx, g, g.Hosts(), g.Identities(), nodes, nodePrivSecretRefs(removed), err)
		return s.finalizeDeleteMutation(next, refs, req.RequireSecretsUnreferenced, req.ExtraPending, bErr)
	})
}

func (s *Service) finishGraph(ctx context.Context, base inventory.Graph, hosts []inventory.Host, idents []inventory.Identity, nodes []inventory.Node, refs []secret.Ref, err error) (inventory.Graph, []secret.Ref, error) {
	if err != nil {
		return zeroVal[inventory.Graph](), nil, err
	}
	next, bErr := s.buildValidatedGraph(ctx, base, hosts, idents, nodes)
	return next, refs, bErr
}
func runValidMutation(ctx context.Context, s *Service, ok bool, label, action, nodeID, targetID, customSummary string, expRev algebraic.Option[ports.Revision], gc bool, extra []inventory.PendingSecretRef, risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission], stream *events.OperationStream, mutate func(context.Context, inventory.Graph) (inventory.Graph, []secret.Ref, error)) (MutationResult, error) {
	if !ok {
		closeIfNonNil(stream)
		return MutationResult{}, fmt.Errorf("%w: %s 无效", ErrInvalidRequest, label)
	}
	return s.runCASMutation(ctx, casMutationSpec{action, nodeID, pickIf(customSummary != "", customSummary, action+" "+targetID), expRev, gc, extra, risk.OrElse(security.RiskModerate), approval, stream, mutate})
}
func (s *Service) finalizeDeleteMutation(next inventory.Graph, ownedRefs []secret.Ref, requireUnref bool, extra []inventory.PendingSecretRef, err error) (inventory.Graph, []secret.Ref, error) {
	if err != nil || !requireUnref {
		return pickIf(err == nil, next, zeroVal[inventory.Graph]()), pickIf(err == nil, ownedRefs, nil), err
	}
	pending, pErr := s.mergePendingRefsExcluding(zeroVal[security.OperationID](), extra)
	if pErr != nil {
		return zeroVal[inventory.Graph](), nil, pErr
	}
	for _, ref := range deduplicateRefs(ownedRefs) {
		if canGC, blocking := next.CanGCSecret(ref, pending...); !canGC {
			return zeroVal[inventory.Graph](), nil, newSecretReferencedError(ref.String(), blocking)
		}
	}
	return next, ownedRefs, nil
}
func upsertAsset[T any](items []T, item T, isUpdate bool, kind, id string, match func(T) bool) ([]T, T, error) {
	idx := slices.IndexFunc(items, match)
	switch {
	case !isUpdate && idx >= 0:
		return nil, zeroVal[T](), fmt.Errorf("%w: %s %q", ErrAssetAlreadyExists, kind, id)
	case isUpdate && idx < 0:
		return nil, zeroVal[T](), fmt.Errorf("%w: %s %q", ErrAssetNotFound, kind, id)
	case isUpdate:
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
		return nil, zeroVal[T](), fmt.Errorf("%w: %s %q", ErrAssetNotFound, kind, id)
	}
	if ok, refs := canDel(); !ok {
		return nil, zeroVal[T](), newAssetReferencedError(kind, id, refs)
	}
	removed := items[idx]
	return slices.Delete(items, idx, idx+1), removed, nil
}
func (s *Service) runCASMutation(ctx context.Context, spec casMutationSpec) (MutationResult, error) {
	if rev, ok := spec.expectedRevision.Get(); ok && !rev.IsValid() {
		closeIfNonNil(spec.stream)
		return MutationResult{}, fmt.Errorf("%w: ExpectedRevision 无效", ErrInvalidRequest)
	}
	return runMutate(ctx, s, spec.action, spec.nodeID, spec.summary, algebraic.Some(spec.risk), spec.approval, spec.stream, func(authCtx context.Context, _ security.TraceID, _ security.OperationID) (MutationResult, string, string, error) {
		res, unkCode, mErr := s.execCASMutation(authCtx, spec)
		return res, unkCode, errMsg(mErr), mErr
	})
}
func errMsg(err error) string { return pickIf(err != nil, fmt.Sprint(err), "") }
func (s *Service) execCASMutation(ctx context.Context, spec casMutationSpec) (MutationResult, string, error) {
	snap, err := s.loadSnapshotAt(ctx, spec.expectedRevision)
	if err != nil {
		return MutationResult{}, "", err
	}
	nextGraph, candidateRefs, err := spec.mutate(ctx, snap.Graph())
	if err != nil {
		return MutationResult{}, "", err
	}
	newRev, out, unkCode, err := s.commitGraphCAS(ctx, snap.Revision(), nextGraph, "commit_missing_revision")
	if err != nil {
		return MutationResult{}, unkCode, err
	}
	if !spec.gcSecrets || len(candidateRefs) == 0 || s.vault == nil {
		return MutationResult{newRev, out, nil, nil, true}, "", nil
	}
	deleted, retained, gcErr := s.gcUnreferencedAfterCommit(ctx, candidateRefs, spec.extraPending)
	return MutationResult{newRev, out, deleted, retained, true}, "", gcErr
}
func (s *Service) gcUnreferencedAfterCommit(ctx context.Context, candidates []secret.Ref, extra []inventory.PendingSecretRef) ([]secret.Ref, []RetainedSecret, error) {
	snap, err := s.store.Load(ctx)
	if err != nil {
		return nil, nil, err
	}
	pending, err := s.mergePendingRefsExcluding(zeroVal[security.OperationID](), extra)
	if err != nil {
		return nil, nil, err
	}
	var deleted []secret.Ref
	var retained []RetainedSecret
	for _, ref := range deduplicateRefs(candidates) {
		if canGC, blocking := snap.Graph().CanGCSecret(ref, pending...); !canGC {
			retained = append(retained, RetainedSecret{ref, blocking})
		} else if delErr := s.vault.Delete(ctx, ref); delErr == nil {
			deleted = append(deleted, ref)
		} else if !errors.Is(delErr, ports.ErrSecretNotFound) {
			return deleted, retained, delErr
		}
	}
	return deleted, retained, nil
}

func nodePrivSecretRefs(n inventory.Node) []secret.Ref {
	ref, ok := n.PrivilegePasswordRef().Get()
	return pickIf(ok, []secret.Ref{ref}, nil)
}
func secretRefsForIdentity(g inventory.Graph, id inventory.IdentityID) []secret.Ref {
	owner := id.String()
	var out []secret.Ref
	for _, sr := range g.AllSecretReferences() {
		if sr.Location >= inventory.SecretLocAuthPassword && sr.Location <= inventory.SecretLocChallengeSecret && sr.OwnerID == owner {
			out = append(out, sr.Ref)
		}
	}
	return deduplicateRefs(out)
}
func deduplicateRefs(in []secret.Ref) []secret.Ref {
	out := slices.Clone(in)
	slices.SortFunc(out, secret.Ref.Compare)
	return slices.CompactFunc(out, secret.Ref.Equal)
}
