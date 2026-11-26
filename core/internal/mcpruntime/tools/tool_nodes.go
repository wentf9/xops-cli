package tools

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

type nodesArgs struct {
	Action                     string                                           `json:"action"`
	ID                         string                                           `json:"id,omitzero"`
	Target                     string                                           `json:"target,omitzero"`
	Host                       algebraic.Option[inventory.Host]                 `json:"host,omitzero"`
	Identity                   algebraic.Option[inventory.Identity]             `json:"identity,omitzero"`
	Node                       algebraic.Option[inventory.Node]                 `json:"node,omitzero"`
	ExpectedRevision           string                                           `json:"expected_revision,omitzero"`
	GCUnreferencedOldSecrets   bool                                             `json:"gc_unreferenced_old_secrets,omitzero"`
	DeleteUnusedSecrets        bool                                             `json:"delete_unused_secrets,omitzero"`
	RequireSecretsUnreferenced bool                                             `json:"require_secrets_unreferenced,omitzero"`
	CheckVaultSecrets          bool                                             `json:"check_vault_secrets,omitzero"`
	CheckPrivateKeys           bool                                             `json:"check_private_keys,omitzero"`
	Format                     string                                           `json:"format,omitzero"`
	SourceName                 string                                           `json:"source_name,omitzero"`
	Content                    string                                           `json:"content,omitzero"`
	Bundle                     algebraic.Option[inventory.ImportBundle]         `json:"bundle,omitzero"`
	DryRun                     bool                                             `json:"dry_run,omitzero"`
	ScopeSummary               string                                           `json:"scope_summary,omitzero"`
	Risk                       algebraic.Option[security.RiskLevel]             `json:"risk,omitzero"`
	Approval                   algebraic.Option[protocol.ApprovalSubmissionDTO] `json:"approval,omitzero"`
}

func (r *Registry) callNodes(ctx context.Context, rawArgs jsontext.Value) (protocol.CallToolResult, error) {
	if r.inventory == nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: InventoryService 未配置", ErrServiceUnavailable)
	}
	args, err := decodeToolArgs[nodesArgs](rawArgs)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	risk, approval, err := validateApprovalAndRisk(args.Risk, args.Approval)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	qReq := ucinv.QueryRequest{Risk: risk, Approval: approval}
	switch args.Action {
	case "list_hosts", "get_host", "list_identities", "get_identity", "list_nodes", "get_node":
		return r.nodesQuery(ctx, args, qReq)
	case "create_host", "update_host", "delete_host",
		"create_identity", "update_identity", "delete_identity",
		"create_node", "update_node", "delete_node":
		return r.nodesMutate(ctx, args, risk, approval)
	case "resolve", "validate_dag", "doctor":
		return r.nodesInspect(ctx, args, qReq)
	case "list_import_formats", "plan_import", "apply_import":
		return r.nodesImport(ctx, args, risk, approval)
	default:
		return protocol.CallToolResult{}, fmt.Errorf("%w: 未知 nodes action %q", protocol.ErrInvalidParams, args.Action)
	}
}

func (r *Registry) nodesQuery(ctx context.Context, args nodesArgs, qReq ucinv.QueryRequest) (protocol.CallToolResult, error) {
	switch args.Action {
	case "list_hosts", "get_host":
		return r.nodesQueryHost(ctx, args, qReq)
	case "list_identities", "get_identity":
		return r.nodesQueryIdentity(ctx, args, qReq)
	default:
		return r.nodesQueryNode(ctx, args, qReq)
	}
}

func (r *Registry) nodesQueryHost(ctx context.Context, args nodesArgs, qReq ucinv.QueryRequest) (protocol.CallToolResult, error) {
	if args.Action == "list_hosts" {
		items, rev, err := r.inventory.ListHosts(ctx, qReq)
		if err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(struct {
			Revision ports.Revision   `json:"revision"`
			Hosts    []inventory.Host `json:"hosts"`
		}{rev, items})
	}
	id, err := inventory.ParseHostID(args.ID)
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
	}
	h, rev, err := r.inventory.GetHost(ctx, id, qReq)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		Revision ports.Revision `json:"revision"`
		Host     inventory.Host `json:"host"`
	}{rev, h})
}

func (r *Registry) nodesQueryIdentity(ctx context.Context, args nodesArgs, qReq ucinv.QueryRequest) (protocol.CallToolResult, error) {
	if args.Action == "list_identities" {
		items, rev, err := r.inventory.ListIdentities(ctx, qReq)
		if err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(struct {
			Revision   ports.Revision       `json:"revision"`
			Identities []inventory.Identity `json:"identities"`
		}{rev, items})
	}
	id, err := inventory.ParseIdentityID(args.ID)
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
	}
	ident, rev, err := r.inventory.GetIdentity(ctx, id, qReq)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		Revision ports.Revision     `json:"revision"`
		Identity inventory.Identity `json:"identity"`
	}{rev, ident})
}

func (r *Registry) nodesQueryNode(ctx context.Context, args nodesArgs, qReq ucinv.QueryRequest) (protocol.CallToolResult, error) {
	if args.Action == "list_nodes" {
		items, rev, err := r.inventory.ListNodes(ctx, qReq)
		if err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(struct {
			Revision ports.Revision   `json:"revision"`
			Nodes    []inventory.Node `json:"nodes"`
		}{rev, items})
	}
	id, err := inventory.ParseNodeID(args.ID)
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
	}
	n, rev, err := r.inventory.GetNode(ctx, id, qReq)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		Revision ports.Revision `json:"revision"`
		Node     inventory.Node `json:"node"`
	}{rev, n})
}

func (r *Registry) nodesMutate(ctx context.Context, args nodesArgs, risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission]) (protocol.CallToolResult, error) {
	expRev, err := parseOptionalRevision(args.ExpectedRevision)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	var res ucinv.MutationResult
	switch args.Action {
	case "create_host", "update_host", "delete_host":
		res, err = r.nodesMutateHost(ctx, args, expRev, risk, approval)
	case "create_identity", "update_identity", "delete_identity":
		res, err = r.nodesMutateIdentity(ctx, args, expRev, risk, approval)
	default:
		res, err = r.nodesMutateNode(ctx, args, expRev, risk, approval)
	}
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		Revision       ports.Revision          `json:"revision"`
		Durability     ports.DurabilityOutcome `json:"durability"`
		DeletedSecrets int                     `json:"deleted_secret_count"`
		RetainedCount  int                     `json:"retained_secret_count"`
	}{res.Revision(), res.Durability(), len(res.DeletedSecrets()), len(res.RetainedSecrets())})
}

func (r *Registry) nodesMutateHost(ctx context.Context, args nodesArgs, expRev algebraic.Option[ports.Revision], risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission]) (ucinv.MutationResult, error) {
	zeroRes := zeroVal[ucinv.MutationResult]()
	if args.Action == "delete_host" {
		id, err := inventory.ParseHostID(args.ID)
		if err != nil {
			return zeroRes, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
		}
		return r.inventory.DeleteHost(ctx, ucinv.DeleteHostRequest{
			ID: id, ExpectedRevision: expRev, ScopeSummary: args.ScopeSummary, Risk: risk, Approval: approval,
		})
	}
	h, ok := args.Host.Get()
	if !ok {
		return zeroRes, fmt.Errorf("%w: 缺少 host 对象", protocol.ErrInvalidParams)
	}
	req := ucinv.HostMutationRequest{Host: h, ExpectedRevision: expRev, ScopeSummary: args.ScopeSummary, Risk: risk, Approval: approval}
	if args.Action == "create_host" {
		return r.inventory.CreateHost(ctx, req)
	}
	return r.inventory.UpdateHost(ctx, req)
}

func (r *Registry) nodesMutateIdentity(ctx context.Context, args nodesArgs, expRev algebraic.Option[ports.Revision], risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission]) (ucinv.MutationResult, error) {
	zeroRes := zeroVal[ucinv.MutationResult]()
	if args.Action == "delete_identity" {
		id, err := inventory.ParseIdentityID(args.ID)
		if err != nil {
			return zeroRes, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
		}
		return r.inventory.DeleteIdentity(ctx, ucinv.DeleteIdentityRequest{
			ID: id, ExpectedRevision: expRev, DeleteUnusedSecrets: args.DeleteUnusedSecrets,
			RequireSecretsUnreferenced: args.RequireSecretsUnreferenced, ScopeSummary: args.ScopeSummary, Risk: risk, Approval: approval,
		})
	}
	ident, ok := args.Identity.Get()
	if !ok {
		return zeroRes, fmt.Errorf("%w: 缺少 identity 对象", protocol.ErrInvalidParams)
	}
	req := ucinv.IdentityMutationRequest{
		Identity: ident, ExpectedRevision: expRev, GCUnreferencedOldSecrets: args.GCUnreferencedOldSecrets,
		ScopeSummary: args.ScopeSummary, Risk: risk, Approval: approval,
	}
	if args.Action == "create_identity" {
		return r.inventory.CreateIdentity(ctx, req)
	}
	return r.inventory.UpdateIdentity(ctx, req)
}

func (r *Registry) nodesMutateNode(ctx context.Context, args nodesArgs, expRev algebraic.Option[ports.Revision], risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission]) (ucinv.MutationResult, error) {
	zeroRes := zeroVal[ucinv.MutationResult]()
	if args.Action == "delete_node" {
		id, err := inventory.ParseNodeID(args.ID)
		if err != nil {
			return zeroRes, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
		}
		return r.inventory.DeleteNode(ctx, ucinv.DeleteNodeRequest{
			ID: id, ExpectedRevision: expRev, DeleteUnusedSecrets: args.DeleteUnusedSecrets,
			RequireSecretsUnreferenced: args.RequireSecretsUnreferenced, ScopeSummary: args.ScopeSummary, Risk: risk, Approval: approval,
		})
	}
	n, ok := args.Node.Get()
	if !ok {
		return zeroRes, fmt.Errorf("%w: 缺少 node 对象", protocol.ErrInvalidParams)
	}
	req := ucinv.NodeMutationRequest{
		Node: n, ExpectedRevision: expRev, GCUnreferencedOldSecrets: args.GCUnreferencedOldSecrets,
		ScopeSummary: args.ScopeSummary, Risk: risk, Approval: approval,
	}
	if args.Action == "create_node" {
		return r.inventory.CreateNode(ctx, req)
	}
	return r.inventory.UpdateNode(ctx, req)
}

func (r *Registry) nodesInspect(ctx context.Context, args nodesArgs, qReq ucinv.QueryRequest) (protocol.CallToolResult, error) {
	switch args.Action {
	case "resolve":
		return r.nodesResolveAuthorized(ctx, args.Target, qReq)
	case "validate_dag":
		rep, err := r.inventory.ValidateDAG(ctx, qReq)
		if err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(rep)
	default: // doctor
		rep, err := r.inventory.Doctor(ctx, ucinv.DoctorRequest{
			CheckVaultSecrets: args.CheckVaultSecrets,
			CheckPrivateKeys:  args.CheckPrivateKeys,
			Risk:              qReq.Risk,
			Approval:          qReq.Approval,
		})
		if err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(rep)
	}
}

// nodesResolveAuthorized 将 MCP 暴露的 nodes.resolve 收口进 gate.WithAuthorized[CapInspect] 与审计闭环（ADR-008）。
func (r *Registry) nodesResolveAuthorized(ctx context.Context, rawTarget string, qReq ucinv.QueryRequest) (protocol.CallToolResult, error) {
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		return protocol.CallToolResult{}, fmt.Errorf("%w: target 不能为空", protocol.ErrInvalidParams)
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[security.CapInspect](),
		Tool:       protocol.ToolNameNodes,
		Action:     "resolve",
		NodeID:     target,
		Parameters: map[string]string{"target": target},
	})
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
	}
	gReq, err := gate.NewGateRequest[security.CapInspect](gate.GateRequestSpec[security.CapInspect]{
		Binding:      binding,
		Risk:         qReq.Risk.OrElse(security.RiskSafe),
		ScopeSummary: "resolve target " + target,
		Approval:     qReq.Approval,
	})
	if err != nil {
		return protocol.CallToolResult{}, fmt.Errorf("%w: %w", protocol.ErrInvalidParams, err)
	}
	var resolved ucinv.ResolvedTarget
	if err := gate.WithAuthorized[security.CapInspect](ctx, r.gate, gReq, func(authCtx context.Context, _ gate.Authorized[security.CapInspect]) error {
		var rErr error
		resolved, rErr = r.resolveTarget(authCtx, rawTarget, option.UnsetOptionLayer())
		return rErr
	}); err != nil {
		return protocol.CallToolResult{}, err
	}
	hops := resolved.Plan().Hops().Slice()
	endpoints := make([]string, 0, len(hops))
	for _, h := range hops {
		endpoints = append(endpoints, h.Endpoint().String())
	}
	return protocol.NewToolSuccessResult(struct {
		NodeID     string            `json:"node_id"`
		OriginKind option.OriginKind `json:"origin_kind"`
		PlanDigest string            `json:"plan_digest"`
		HopCount   int               `json:"hop_count"`
		Endpoints  []string          `json:"endpoints"`
	}{resolved.NodeID(), resolved.OriginKind(), resolved.Plan().PlanDigest().String(), len(hops), endpoints})
}

func (r *Registry) nodesImport(
	ctx context.Context,
	args nodesArgs,
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[gate.ApprovalSubmission],
) (protocol.CallToolResult, error) {
	if args.Action == "list_import_formats" {
		return protocol.NewToolSuccessResult(struct {
			Formats []string `json:"formats"`
		}{r.inventory.SupportedImportFormats()})
	}
	srcReq := ucinv.ImportSourceRequest{
		Format:     args.Format,
		SourceName: args.SourceName,
		Bundle:     args.Bundle,
		Risk:       risk,
		Approval:   approval,
	}
	if args.Content != "" {
		srcReq.Reader = strings.NewReader(args.Content)
	}
	if args.Action == "plan_import" {
		prev, err := r.inventory.PlanImport(ctx, srcReq)
		if err != nil {
			return protocol.CallToolResult{}, err
		}
		return protocol.NewToolSuccessResult(struct {
			BaseRevision ports.Revision         `json:"base_revision"`
			Report       inventory.ImportReport `json:"report"`
		}{prev.BaseRevision(), prev.Report()})
	}
	expRev, err := parseOptionalRevision(args.ExpectedRevision)
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	res, err := r.inventory.ApplyImport(ctx, ucinv.ApplyImportRequest{
		Source:           srcReq,
		ExpectedRevision: expRev,
		DryRun:           args.DryRun,
		ScopeSummary:     args.ScopeSummary,
	})
	if err != nil {
		return protocol.CallToolResult{}, err
	}
	return protocol.NewToolSuccessResult(struct {
		Applied    bool                                      `json:"applied"`
		Revision   ports.Revision                            `json:"revision"`
		Durability algebraic.Option[ports.DurabilityOutcome] `json:"durability,omitzero"`
		Report     inventory.ImportReport                    `json:"report"`
	}{res.Applied(), res.Revision(), res.Durability(), res.Report()})
}
