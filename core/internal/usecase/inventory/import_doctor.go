package inventory

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
	"github.com/wentf9/xops-cli/core/ports"
)

// DoctorSeverity 与 DoctorFinding 复用 credential 包定义，保持全仓只读诊断模型与 JSON v2 往返完全统一。
type (
	DoctorSeverity = credential.DoctorSeverity
	DoctorFinding  = credential.DoctorFinding
)

// 诊断严重级别常量别名。
const (
	DoctorSeverityInvalid = credential.DoctorSeverityInvalid
	DoctorSeverityInfo    = credential.DoctorSeverityInfo
	DoctorSeverityWarn    = credential.DoctorSeverityWarn
	DoctorSeverityError   = credential.DoctorSeverityError
)

// 导入调度与只读零泄露 Doctor 契约类型定义（100% 零 v1 代码，支持 JSON v2 往返）。
type (
	// ImportSourceRequest 描述格式无关导入源请求（支持直接 ImportBundle 或经 FormatImporter 读取流）。
	ImportSourceRequest struct {
		Format, SourceName string
		Reader             io.Reader
		Bundle             algebraic.Option[inventory.ImportBundle]
		Risk               algebraic.Option[security.RiskLevel]
		Approval           algebraic.Option[gate.ApprovalSubmission]
		OperationStream    *events.OperationStream
	}
	// ApplyImportRequest 描述执行导入预检与 CAS 合并提交的请求。
	ApplyImportRequest struct {
		Source           ImportSourceRequest
		ExpectedRevision algebraic.Option[ports.Revision]
		DryRun           bool
		ScopeSummary     string
	}
	// ImportPreview 封装只读导入预检产出（基准 Revision、导入包与冲突报告）；零值恒无效。
	//
	//xops:opaque
	//xops:failclosed
	ImportPreview struct {
		baseRevision ports.Revision
		bundle       inventory.ImportBundle
		report       inventory.ImportReport
		valid        bool
	}
	// ImportResult 封装 ApplyImport 产出（最新 Revision、DurabilityOutcome、导入报告与是否落盘）；零值恒无效。
	//
	//xops:opaque
	//xops:failclosed
	ImportResult struct {
		revision       ports.Revision
		durability     algebraic.Option[ports.DurabilityOutcome]
		report         inventory.ImportReport
		applied, valid bool
	}
	// DoctorRequest 描述只读零泄露资产系统诊断请求。
	DoctorRequest struct {
		CheckVaultSecrets, CheckPrivateKeys bool
		ExtraPending                        []inventory.PendingSecretRef
		Risk                                algebraic.Option[security.RiskLevel]
		Approval                            algebraic.Option[gate.ApprovalSubmission]
		OperationStream                     *events.OperationStream
	}
	// DoctorReport 封装资产系统只读诊断报告（严禁包含任何明文机密，支持 JSON v2 往返）。
	DoctorReport struct {
		Healthy            bool                                `json:"healthy"`
		Revision           algebraic.Option[ports.Revision]    `json:"revision,omitzero"`
		VaultStatus        algebraic.Option[ports.VaultStatus] `json:"vault_status,omitzero"`
		HostCount          int                                 `json:"host_count"`
		IdentityCount      int                                 `json:"identity_count"`
		NodeCount          int                                 `json:"node_count"`
		SecretRefCount     int                                 `json:"secret_ref_count"`
		ActivePendingCount int                                 `json:"active_pending_count"`
		DAGMaxDepth        int                                 `json:"dag_max_depth"`
		ErrorCount         int                                 `json:"error_count"`
		WarnCount          int                                 `json:"warn_count"`
		InfoCount          int                                 `json:"info_count"`
		Findings           []DoctorFinding                     `json:"findings,omitzero"`
	}
)

// ImportPreview 与 ImportResult 零值安全只读访问器。
func (p ImportPreview) IsValid() bool {
	return p.valid && p.baseRevision.IsValid() && p.bundle.IsValid()
}
func (p ImportPreview) IsZero() bool                                         { return !p.IsValid() }
func (p ImportPreview) BaseRevision() ports.Revision                         { return p.baseRevision }
func (p ImportPreview) Bundle() inventory.ImportBundle                       { return p.bundle }
func (p ImportPreview) Report() inventory.ImportReport                       { return p.report }
func (r ImportResult) IsValid() bool                                         { return r.valid && r.revision.IsValid() }
func (r ImportResult) IsZero() bool                                          { return !r.IsValid() }
func (r ImportResult) Revision() ports.Revision                              { return r.revision }
func (r ImportResult) Durability() algebraic.Option[ports.DurabilityOutcome] { return r.durability }
func (r ImportResult) Report() inventory.ImportReport                        { return r.report }
func (r ImportResult) Applied() bool                                         { return r.IsValid() && r.applied }

// SupportedImportFormats 返回当前服务已注册的全部导入格式名（字典序排序）。
func (s *Service) SupportedImportFormats() []string {
	if s == nil || !s.valid || len(s.importers) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(s.importers))
}

// PlanImport 经 CapInspect 鉴权执行格式无关导入预检与跨命名空间 Tarjan DAG / s.maxJumpDepth 冲突核验（严格只读）。
func (s *Service) PlanImport(ctx context.Context, req ImportSourceRequest) (ImportPreview, error) {
	if err := validateImportSource(req, algebraic.None[ports.Revision]()); err != nil {
		closeIfNonNil(req.OperationStream)
		return ImportPreview{}, err
	}
	return runInspect(ctx, s, "plan_import", "plan inventory import", req.Risk, req.Approval, req.OperationStream, func(c context.Context) (ImportPreview, error) {
		snap, bundle, report, _, err := s.loadAndPlanImport(c, req, algebraic.None[ports.Revision]())
		return ImportPreview{baseRevision: snap.Revision(), bundle: bundle, report: report, valid: err == nil}, err
	})
}

// ApplyImport 经 CapMutate 鉴权执行统一导入调度、冲突失败关闭、跨命名空间 Tarjan DAG 校验与 CAS 提交。
func (s *Service) ApplyImport(ctx context.Context, req ApplyImportRequest) (ImportResult, error) {
	if err := validateImportSource(req.Source, req.ExpectedRevision); err != nil {
		closeIfNonNil(req.Source.OperationStream)
		return ImportResult{}, err
	}
	return runMutate(ctx, s, "apply_import", "", pickIf(req.ScopeSummary != "", req.ScopeSummary, "apply inventory import"), req.Source.Risk, req.Source.Approval, req.Source.OperationStream, func(c context.Context, _ security.TraceID, _ security.OperationID) (ImportResult, string, string, error) {
		res, unkCode, err := s.execApplyImport(c, req)
		return res, unkCode, errMsg(err), err
	})
}

func validateImportSource(src ImportSourceRequest, expRev algebraic.Option[ports.Revision]) error {
	hasBundle, hasFormat, hasReader := src.Bundle.IsSome(), strings.TrimSpace(src.Format) != "", src.Reader != nil
	b, _ := src.Bundle.Get()
	switch {
	case expRev.IsSome() && !expRev.OrElse(zeroVal[ports.Revision]()).IsValid():
		return fmt.Errorf("%w: ExpectedRevision 无效", ErrInvalidRequest)
	case hasBundle && (hasFormat || hasReader):
		return fmt.Errorf("%w: Bundle 与 Format/Reader 互斥，不可同时指定", ErrInvalidRequest)
	case hasBundle && !b.IsValid():
		return fmt.Errorf("%w: %w", ErrInvalidRequest, inventory.ErrInvalidImportBundle)
	case !hasBundle && (!hasFormat || !hasReader):
		return fmt.Errorf("%w: 必须提供 Bundle 或完整的 (Format, Reader)", ErrInvalidRequest)
	}
	return nil
}
func (s *Service) loadAndPlanImport(ctx context.Context, src ImportSourceRequest, expRev algebraic.Option[ports.Revision]) (snap ports.InventorySnapshot, bundle inventory.ImportBundle, report inventory.ImportReport, openSSH []inventory.OpenSSHJumpNode, err error) {
	if bundle, err = s.resolveImportBundle(ctx, src); err == nil {
		snap, err = s.loadSnapshotAt(ctx, expRev)
	}
	if err == nil {
		openSSH, err = s.collectOpenSSHJumpNodes(ctx)
	}
	var enriched inventory.Graph
	if err == nil {
		g := snap.Graph()
		enriched, err = s.buildValidatedGraphWithOpenSSH(ctx, g, g.Hosts(), g.Identities(), g.Nodes(), openSSH)
	}
	if err == nil {
		report, err = inventory.PlanImport(enriched, bundle)
	}
	if err != nil {
		return snap, bundle, report, nil, err
	}
	// 基于合并后候选节点集 (existing ∪ bundleAdded) 重新计算跨命名空间可达 OpenSSH 闭包并按 s.maxJumpDepth 执行权威 Tarjan DAG 校验。
	reconcileImportDAGReport(&report, snap.Graph().Nodes(), bundle.Nodes(), openSSH, s.maxJumpDepth)
	return snap, bundle, report, openSSH, nil
}
func reconcileImportDAGReport(report *inventory.ImportReport, existingNodes, bundleNodes []inventory.Node, allOpenSSH []inventory.OpenSSHJumpNode, maxJumpDepth int) {
	addNodes, cleaned := make(map[string]bool), make([]inventory.ImportEntry, 0, len(report.Entries))
	for _, e := range report.Entries {
		if e.AssetKind == "graph" && e.AssetID == "proxy_dag" {
			if e.Action == inventory.ImportActionConflict {
				report.ConflictCount--
			}
			continue
		}
		if e.AssetKind == "node" && e.Action == inventory.ImportActionAdd {
			addNodes[e.AssetID] = true
		}
		cleaned = append(cleaned, e)
	}
	merged := slices.Clone(existingNodes)
	for _, n := range bundleNodes {
		if addNodes[n.ID().String()] {
			merged = append(merged, n)
		}
	}
	if _, dagErr := inventory.ValidateProxyDAG(merged, filterReachableOpenSSHNodes(merged, allOpenSSH), maxJumpDepth); dagErr != nil {
		cleaned = append(cleaned, inventory.ImportEntry{AssetKind: "graph", AssetID: "proxy_dag", Action: inventory.ImportActionConflict, Reason: dagErr.Error()})
		report.ConflictCount++
	}
	report.Entries = cleaned
}
func (s *Service) execApplyImport(ctx context.Context, req ApplyImportRequest) (ImportResult, string, error) {
	snap, bundle, report, openSSH, err := s.loadAndPlanImport(ctx, req.Source, req.ExpectedRevision)
	if err != nil {
		return ImportResult{}, "", err
	}
	baseRes := ImportResult{revision: snap.Revision(), report: report, valid: true}
	if report.HasConflicts() {
		return baseRes, "", fmt.Errorf("%w: 发现 %d 处导入冲突", ErrImportConflict, report.ConflictCount)
	}
	if req.DryRun || report.AddCount == 0 {
		return baseRes, "", nil
	}
	nextGraph, err := s.mergeImportBundleIntoGraph(ctx, snap.Graph(), bundle, report, openSSH)
	if err != nil {
		return baseRes, "", err
	}
	_, newRev, out, unkCode, err := s.commitGraphCAS(ctx, snap.Revision(), nextGraph, "import_missing_revision")
	if err != nil {
		return baseRes, unkCode, err
	}
	return ImportResult{revision: newRev, durability: algebraic.Some(out), report: report, applied: true, valid: true}, "", nil
}
func (s *Service) resolveImportBundle(ctx context.Context, req ImportSourceRequest) (z inventory.ImportBundle, err error) {
	if b, ok := req.Bundle.Get(); ok {
		return b, nil
	}
	fmtName := strings.ToLower(strings.TrimSpace(req.Format))
	imp, ok := s.importers[fmtName]
	if !ok {
		return z, fmt.Errorf("%w: %q", ErrUnknownImportFormat, fmtName)
	}
	bundle, err := imp.Import(ctx, pickIf(strings.TrimSpace(req.SourceName) != "", req.SourceName, fmtName), req.Reader)
	if err != nil || !bundle.IsValid() {
		return z, pickIf[error](err != nil, err, fmt.Errorf("%w: 导入器 %q 返回无效 ImportBundle", inventory.ErrInvalidImportBundle, fmtName))
	}
	return bundle, nil
}
func (s *Service) mergeImportBundleIntoGraph(ctx context.Context, existing inventory.Graph, bundle inventory.ImportBundle, report inventory.ImportReport, openSSH []inventory.OpenSSHJumpNode) (inventory.Graph, error) {
	add := make(map[string]bool, report.AddCount)
	for _, e := range report.Entries {
		if e.Action == inventory.ImportActionAdd {
			add[e.AssetKind+":"+e.AssetID] = true
		}
	}
	return s.buildValidatedGraphWithOpenSSH(ctx, existing,
		append(existing.Hosts(), slices.DeleteFunc(bundle.Hosts(), func(h inventory.Host) bool { return !add["host:"+h.ID().String()] })...),
		append(existing.Identities(), slices.DeleteFunc(bundle.Identities(), func(i inventory.Identity) bool { return !add["identity:"+i.ID().String()] })...),
		append(existing.Nodes(), slices.DeleteFunc(bundle.Nodes(), func(n inventory.Node) bool { return !add["node:"+n.ID().String()] })...),
		openSSH,
	)
}

// Doctor 经 CapInspect 鉴权执行严格只读资产诊断：核验快照、跨命名空间 Tarjan DAG、OpenSSH 别名遮蔽、
// 权威凭据存储表与可选零明文 Vault 探活（复用 credential.InspectVaultAndSecrets）、全路径私钥检查与闲置资产提示。
func (s *Service) Doctor(ctx context.Context, req DoctorRequest) (DoctorReport, error) {
	if err := validateExtraPending(req.ExtraPending); err != nil {
		closeIfNonNil(req.OperationStream)
		return DoctorReport{}, err
	}
	return runInspect(ctx, s, "doctor", "inventory read-only doctor", req.Risk, req.Approval, req.OperationStream, func(c context.Context) (DoctorReport, error) {
		pending, err := s.mergePendingRefsExcluding(zeroVal[security.OperationID](), req.ExtraPending)
		if err != nil {
			return DoctorReport{}, err
		}
		return s.runDoctor(c, req, pending), nil
	})
}
func (s *Service) runDoctor(ctx context.Context, req DoctorRequest, pending []inventory.PendingSecretRef) DoctorReport {
	rep := DoctorReport{Healthy: true, ActivePendingCount: len(pending)}
	for _, p := range pending {
		addFinding(&rep, DoctorSeverityInfo, "active_pending_secret_pin", p.Ref.String(), "凭据正由暂存登记租约钉住防 GC: "+p.OwnerID)
	}
	var allRefs []inventory.SecretReference
	var graphStores []string
	if snap, err := s.store.Load(ctx); err != nil {
		addFinding(&rep, DoctorSeverityError, "store_load_failed", "", "加载资产存储快照失败: "+err.Error())
		for _, p := range pending {
			allRefs = append(allRefs, inventory.SecretReference{Location: inventory.SecretLocPending, OwnerID: p.OwnerID, Ref: p.Ref})
		}
	} else {
		g := snap.Graph()
		rep.Revision, rep.HostCount, rep.IdentityCount, rep.NodeCount = algebraic.Some(snap.Revision()), len(g.Hosts()), len(g.Identities()), len(g.Nodes())
		allRefs, graphStores = g.AllSecretReferences(pending...), g.KnownStores()
		s.doctorCheckGraphTopology(ctx, g, req.CheckPrivateKeys, &rep)
	}
	rep.SecretRefCount = len(allRefs)
	vRes := credential.InspectVaultAndSecrets(ctx, credential.VaultSecretCheckSpec{
		Vault: s.vault, VaultControl: s.vaultControl, AllRefs: allRefs,
		GraphKnownStores: graphStores, ExtraKnownStores: s.knownStores, ProbeSecrets: req.CheckVaultSecrets,
	})
	rep.VaultStatus = vRes.VaultStatus
	for _, f := range vRes.Findings {
		appendDoctorFinding(&rep, f)
	}
	return rep
}
func (s *Service) doctorCheckGraphTopology(ctx context.Context, g inventory.Graph, checkKeys bool, rep *DoctorReport) {
	if dagRep, err := inventory.ValidateProxyDAG(g.Nodes(), s.doctorCheckOpenSSH(ctx, g, rep), s.maxJumpDepth); err != nil {
		addFinding(rep, DoctorSeverityError, "proxy_dag_invalid", "", "跨命名空间 ProxyJump DAG 校验失败: "+err.Error())
	} else {
		rep.DAGMaxDepth = dagRep.MaxObservedDepth
	}
	if checkKeys {
		s.doctorCheckPrivateKeys(ctx, g, rep)
	}
	for _, h := range g.Hosts() {
		if len(g.FindHostReferences(h.ID())) == 0 {
			addFinding(rep, DoctorSeverityInfo, "unused_host", h.ID().String(), "Host 未被任何 Node 引用")
		}
	}
	for _, id := range g.Identities() {
		if len(g.FindIdentityReferences(id.ID())) == 0 {
			addFinding(rep, DoctorSeverityInfo, "unused_identity", id.ID().String(), "Identity 未被任何 Node 引用")
		}
	}
}
func (s *Service) doctorCheckOpenSSH(ctx context.Context, g inventory.Graph, rep *DoctorReport) []inventory.OpenSSHJumpNode {
	if s.openSSH == nil {
		return nil
	}
	vhs, err := s.openSSH.ListVirtualHosts(ctx)
	if err != nil {
		addFinding(rep, DoctorSeverityWarn, "openssh_source_error", "", "读取 OpenSSH 只读配置失败: "+err.Error())
		return nil
	}
	managed := indexManagedNames(g.Nodes())
	for _, vh := range vhs {
		if vh.IsValid() && managed[vh.Alias()] {
			addFinding(rep, DoctorSeverityWarn, "openssh_alias_shadowed", vh.Alias(), "托管节点 ID 或别名遮蔽了同名 OpenSSH Host 别名")
		}
	}
	jns, err := virtualHostsToJumpNodes(vhs)
	if err != nil {
		addFinding(rep, DoctorSeverityWarn, "openssh_jump_invalid", "", "OpenSSH 虚拟主机跳板配置无效: "+err.Error())
		return nil
	}
	return jns
}
func (s *Service) doctorCheckPrivateKeys(ctx context.Context, g inventory.Graph, rep *DoctorReport) {
	if s.keySigner == nil {
		addFinding(rep, DoctorSeverityWarn, "key_signer_unavailable", "", "未配置 KeySignerPort，无法执行私钥核验")
		return
	}
	for _, id := range g.Identities() {
		if err := s.inspectAuthPrivateKeys(ctx, id.ID().String(), id.Auth(), rep); err != nil {
			addFinding(rep, DoctorSeverityError, "unknown_auth_method", id.ID().String(), err.Error())
		}
	}
}
func (s *Service) inspectAuthPrivateKeys(ctx context.Context, ownerID string, auth inventory.AuthMethod, rep *DoctorReport) error {
	switch v := auth.(type) {
	case *inventory.AuthPrivateKey:
		s.checkPrivateKeySet(ctx, ownerID, v, rep)
	case *inventory.AuthComposite:
		for _, sub := range v.Methods() {
			if err := s.inspectAuthPrivateKeys(ctx, ownerID, sub, rep); err != nil {
				return err
			}
		}
	case *inventory.AuthPassword, *inventory.AuthAgent, *inventory.AuthKeyboardInteractive:
	default:
		return inventory.ErrInvalidAuthMethod
	}
	return nil
}
func (s *Service) checkPrivateKeySet(ctx context.Context, ownerID string, pk *inventory.AuthPrivateKey, rep *DoctorReport) {
	pb, hasPB := pk.Passphrase().Get()
	passOpt := pickIf(hasPB, algebraic.Some(pb.PassphraseRef()), algebraic.None[secret.Ref]())
	matched, inspected := !hasPB, false
	for _, kp := range pk.KeyPaths().Slice() {
		if fp, err := s.keySigner.InspectPrivateKeyFingerprint(ctx, kp, passOpt); err != nil {
			addFinding(rep, DoctorSeverityError, "private_key_inspect_failed", ownerID, "核验私钥失败 ("+kp.String()+"): "+err.Error())
		} else {
			inspected, matched = true, matched || (hasPB && fp.Equal(pb.KeyFingerprint()))
		}
	}
	if hasPB && inspected && !matched {
		addFinding(rep, DoctorSeverityError, "private_key_fingerprint_mismatch", ownerID, "加密私钥实际指纹与配置绑定指纹不一致")
	}
}
func addFinding(rep *DoctorReport, sev DoctorSeverity, code, subject, msg string) {
	appendDoctorFinding(rep, DoctorFinding{Severity: sev, Code: code, Subject: subject, Message: security.SanitizePromptText(msg)})
}
func appendDoctorFinding(rep *DoctorReport, f DoctorFinding) {
	rep.Findings = append(rep.Findings, f)
	switch f.Severity {
	case DoctorSeverityError:
		rep.ErrorCount, rep.Healthy = rep.ErrorCount+1, false
	case DoctorSeverityWarn:
		rep.WarnCount++
	case DoctorSeverityInfo:
		rep.InfoCount++
	}
}
