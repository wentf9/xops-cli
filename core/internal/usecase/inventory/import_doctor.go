package inventory

import (
	"context"
	"errors"
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

// 复用 credential.DoctorSeverity 与 credential.DoctorFinding，统一全仓只读诊断契约。
type (
	DoctorSeverity = credential.DoctorSeverity
	DoctorFinding  = credential.DoctorFinding
)

const (
	DoctorSeverityInvalid = credential.DoctorSeverityInvalid
	DoctorSeverityInfo    = credential.DoctorSeverityInfo
	DoctorSeverityWarn    = credential.DoctorSeverityWarn
	DoctorSeverityError   = credential.DoctorSeverityError
)

// Import 与 Doctor 请求及结果类型定义（100% 零 v1 代码，Doctor 严格只读零明文）。
type (
	ImportSourceRequest struct {
		Format, SourceName string
		Reader             io.Reader
		Bundle             algebraic.Option[inventory.ImportBundle]
		Risk               algebraic.Option[security.RiskLevel]
		Approval           algebraic.Option[gate.ApprovalSubmission]
		OperationStream    *events.OperationStream
	}
	ApplyImportRequest struct {
		Source           ImportSourceRequest
		ExpectedRevision algebraic.Option[ports.Revision]
		DryRun           bool
		ScopeSummary     string
	}
	//xops:opaque
	//xops:failclosed
	ImportPreview struct {
		baseRevision ports.Revision
		bundle       inventory.ImportBundle
		report       inventory.ImportReport
		valid        bool
	}
	//xops:opaque
	//xops:failclosed
	ImportResult struct {
		revision   ports.Revision
		durability algebraic.Option[ports.DurabilityOutcome]
		report     inventory.ImportReport
		applied    bool
		valid      bool
	}
	DoctorRequest struct {
		CheckVaultSecrets, CheckPrivateKeys bool
		ExtraPending                        []inventory.PendingSecretRef
		Risk                                algebraic.Option[security.RiskLevel]
		Approval                            algebraic.Option[gate.ApprovalSubmission]
		OperationStream                     *events.OperationStream
	}
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
	vaultDiagState struct {
		knownStores []string
		unlocked    bool
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

// PlanImport 经 CapInspect 鉴权执行格式无关导入预检与跨命名空间 DAG/冲突核验（严格只读）。
func (s *Service) PlanImport(ctx context.Context, req ImportSourceRequest) (ImportPreview, error) {
	if err := validateImportSource(req, algebraic.None[ports.Revision]()); err != nil {
		closeIfNonNil(req.OperationStream)
		return ImportPreview{}, err
	}
	return runInspect(ctx, s, "plan_import", "plan inventory import", req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context) (ImportPreview, error) {
		snap, bundle, report, err := s.loadAndPlanImport(authCtx, req, algebraic.None[ports.Revision]())
		return pickIf(err == nil, ImportPreview{snap.Revision(), bundle, report, true}, ImportPreview{}), err
	})
}

// ApplyImport 经 CapMutate 鉴权执行统一导入调度、冲突失败关闭、全图 Tarjan DAG 校验与 CAS 提交。
func (s *Service) ApplyImport(ctx context.Context, req ApplyImportRequest) (ImportResult, error) {
	if err := validateImportSource(req.Source, req.ExpectedRevision); err != nil {
		closeIfNonNil(req.Source.OperationStream)
		return ImportResult{}, err
	}
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, "apply inventory import")
	return runMutate(ctx, s, "apply_import", "", summary, req.Source.Risk, req.Source.Approval, req.Source.OperationStream, func(authCtx context.Context, _ security.TraceID, _ security.OperationID) (ImportResult, string, string, error) {
		res, unkCode, aErr := s.execApplyImport(authCtx, req)
		return res, unkCode, errMsg(aErr), aErr
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
func (s *Service) loadAndPlanImport(ctx context.Context, src ImportSourceRequest, expRev algebraic.Option[ports.Revision]) (snap ports.InventorySnapshot, bundle inventory.ImportBundle, report inventory.ImportReport, err error) {
	if bundle, err = s.resolveImportBundle(ctx, src); err != nil {
		return snap, bundle, report, err
	}
	if snap, err = s.loadSnapshotAt(ctx, expRev); err != nil {
		return snap, bundle, report, err
	}
	enriched, err := s.buildValidatedGraph(ctx, snap.Graph(), snap.Graph().Hosts(), snap.Graph().Identities(), snap.Graph().Nodes())
	if err != nil {
		return snap, bundle, report, err
	}
	report, err = inventory.PlanImport(enriched, bundle)
	return snap, bundle, report, err
}
func (s *Service) execApplyImport(ctx context.Context, req ApplyImportRequest) (ImportResult, string, error) {
	snap, bundle, report, err := s.loadAndPlanImport(ctx, req.Source, req.ExpectedRevision)
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
	nextGraph, err := s.mergeImportBundleIntoGraph(ctx, snap.Graph(), bundle, report)
	if err != nil {
		return baseRes, "", err
	}
	newRev, out, unkCode, err := s.commitGraphCAS(ctx, snap.Revision(), nextGraph, "import_missing_revision")
	if err != nil {
		return baseRes, unkCode, err
	}
	return ImportResult{newRev, algebraic.Some(out), report, true, true}, "", nil
}
func (s *Service) resolveImportBundle(ctx context.Context, req ImportSourceRequest) (inventory.ImportBundle, error) {
	if b, ok := req.Bundle.Get(); ok {
		return b, nil
	}
	fmtName := strings.ToLower(strings.TrimSpace(req.Format))
	imp, ok := s.importers[fmtName]
	if !ok {
		return zeroVal[inventory.ImportBundle](), fmt.Errorf("%w: %q", ErrUnknownImportFormat, fmtName)
	}
	bundle, err := imp.Import(ctx, pickIf(strings.TrimSpace(req.SourceName) != "", req.SourceName, fmtName), req.Reader)
	if err != nil || !bundle.IsValid() {
		return zeroVal[inventory.ImportBundle](), pickIf(err != nil, err, fmt.Errorf("%w: 导入器 %q 返回无效 ImportBundle", inventory.ErrInvalidImportBundle, fmtName))
	}
	return bundle, nil
}
func (s *Service) mergeImportBundleIntoGraph(ctx context.Context, existing inventory.Graph, bundle inventory.ImportBundle, report inventory.ImportReport) (inventory.Graph, error) {
	add := make(map[string]bool, report.AddCount)
	for _, e := range report.Entries {
		if e.Action == inventory.ImportActionAdd {
			add[e.AssetKind+":"+e.AssetID] = true
		}
	}
	return s.buildValidatedGraph(ctx, existing,
		append(existing.Hosts(), slices.DeleteFunc(bundle.Hosts(), func(h inventory.Host) bool { return !add["host:"+h.ID().String()] })...),
		append(existing.Identities(), slices.DeleteFunc(bundle.Identities(), func(i inventory.Identity) bool { return !add["identity:"+i.ID().String()] })...),
		append(existing.Nodes(), slices.DeleteFunc(bundle.Nodes(), func(n inventory.Node) bool { return !add["node:"+n.ID().String()] })...),
	)
}

// Doctor 经 CapInspect 鉴权执行严格只读资产诊断：核验快照、跨命名空间 Tarjan DAG、OpenSSH 别名遮蔽、
// 5 位置+Pending 凭据存储与可选只读探活（零 box.Use）、可选私钥指纹一致性与闲置资产提示。
func (s *Service) Doctor(ctx context.Context, req DoctorRequest) (DoctorReport, error) {
	pending, err := s.mergePendingRefsExcluding(zeroVal[security.OperationID](), req.ExtraPending)
	if err != nil {
		closeIfNonNil(req.OperationStream)
		return DoctorReport{}, err
	}
	return runInspect(ctx, s, "doctor", "inventory read-only doctor", req.Risk, req.Approval, req.OperationStream, func(authCtx context.Context) (DoctorReport, error) {
		return s.runDoctor(authCtx, req, pending), nil
	})
}
func (s *Service) runDoctor(ctx context.Context, req DoctorRequest, pending []inventory.PendingSecretRef) DoctorReport {
	rep := DoctorReport{Healthy: true, ActivePendingCount: len(pending)}
	vState := s.doctorCheckVault(ctx, &rep)
	for _, p := range pending {
		addFinding(&rep, DoctorSeverityInfo, "active_pending_secret_pin", p.Ref.String(), "凭据正由暂存登记租约钉住防 GC: "+p.OwnerID)
	}
	snap, err := s.store.Load(ctx)
	if err != nil {
		addFinding(&rep, DoctorSeverityError, "store_load_failed", "", "加载资产存储快照失败: "+err.Error())
		return rep
	}
	g := snap.Graph()
	rep.Revision, rep.HostCount, rep.IdentityCount, rep.NodeCount = algebraic.Some(snap.Revision()), len(g.Hosts()), len(g.Identities()), len(g.Nodes())
	if dagRep, dErr := inventory.ValidateProxyDAG(g.Nodes(), s.doctorCheckOpenSSH(ctx, g, &rep), s.maxJumpDepth); dErr != nil {
		addFinding(&rep, DoctorSeverityError, "proxy_dag_invalid", "", "跨命名空间 ProxyJump DAG 校验失败: "+dErr.Error())
	} else {
		rep.DAGMaxDepth = dagRep.MaxObservedDepth
	}
	s.doctorCheckSecrets(ctx, g, pending, vState, req.CheckVaultSecrets, &rep)
	s.doctorCheckPrivateKeys(ctx, g, req.CheckPrivateKeys, &rep)
	doctorCheckUnusedAssets(g, &rep)
	return rep
}
func (s *Service) doctorCheckPrivateKeys(ctx context.Context, g inventory.Graph, enabled bool, rep *DoctorReport) {
	if !enabled || s.keySigner == nil {
		return
	}
	for _, id := range g.Identities() {
		if kErr := s.inspectAuthPrivateKeys(ctx, id.ID().String(), id.Auth(), rep); kErr != nil {
			addFinding(rep, DoctorSeverityError, "unknown_auth_method", id.ID().String(), kErr.Error())
		}
	}
}

func (s *Service) doctorCheckVault(ctx context.Context, rep *DoctorReport) vaultDiagState {
	if s.vaultControl == nil {
		return vaultDiagState{s.knownStores, s.vault != nil}
	}
	st, err := s.vaultControl.Status(ctx)
	if err != nil {
		addFinding(rep, DoctorSeverityError, "vault_status_failed", "", "查询凭据库状态失败: "+err.Error())
		return vaultDiagState{knownStores: s.knownStores}
	}
	rep.VaultStatus = algebraic.Some(st)
	stores := mergeUniqueStrings(s.knownStores, st.KnownStores())
	switch st.State() {
	case ports.VaultStateUnlocked:
		return vaultDiagState{stores, true}
	case ports.VaultStateLocked:
		addFinding(rep, DoctorSeverityWarn, "vault_locked", "", "凭据库当前已锁定，跳过凭据只读探活")
	case ports.VaultStateUninitialized:
		addFinding(rep, DoctorSeverityWarn, "vault_uninitialized", "", "凭据库尚未初始化")
	default:
		addFinding(rep, DoctorSeverityError, "vault_state_invalid", "", "凭据库返回无效状态")
	}
	return vaultDiagState{knownStores: stores}
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
	jns, jErr := virtualHostsToJumpNodes(vhs)
	if jErr != nil {
		addFinding(rep, DoctorSeverityWarn, "openssh_jump_invalid", "", "OpenSSH 虚拟主机跳板配置无效: "+jErr.Error())
		return nil
	}
	return jns
}
func (s *Service) doctorCheckSecrets(ctx context.Context, g inventory.Graph, pending []inventory.PendingSecretRef, vState vaultDiagState, checkVault bool, rep *DoctorReport) {
	allRefs := g.AllSecretReferences(pending...)
	rep.SecretRefCount = len(allRefs)
	knownStores := mergeUniqueStrings(g.KnownStores(), vState.knownStores)
	raw := make([]secret.Ref, 0, len(allRefs))
	for _, sr := range allRefs {
		raw = append(raw, sr.Ref)
		if len(knownStores) > 0 && !slices.Contains(knownStores, sr.Ref.Store()) {
			addFinding(rep, DoctorSeverityError, "unknown_secret_store", sr.Ref.String(), fmt.Sprintf("%s (%s) 引用了未注册凭据存储 %q", sr.OwnerID, sr.Location, sr.Ref.Store()))
		}
	}
	if !checkVault || s.vault == nil || !vState.unlocked {
		return
	}
	for _, ref := range deduplicateRefs(raw) {
		switch err := s.vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error { return pickIf[error](box.IsValid(), nil, ports.ErrCorruptData) }); {
		case err == nil:
		case errors.Is(err, ports.ErrSecretNotFound):
			addFinding(rep, DoctorSeverityError, "secret_not_found", ref.String(), "凭据库中缺少被引用的凭据条目")
		case errors.Is(err, ports.ErrVaultLocked):
			addFinding(rep, DoctorSeverityWarn, "vault_locked", ref.String(), "凭据库已锁定，无法探活条目")
		default:
			addFinding(rep, DoctorSeverityError, "secret_probe_failed", ref.String(), "凭据只读探活失败: "+err.Error())
		}
	}
}
func (s *Service) inspectAuthPrivateKeys(ctx context.Context, ownerID string, auth inventory.AuthMethod, rep *DoctorReport) error {
	switch v := auth.(type) {
	case *inventory.AuthPrivateKey:
		pb, hasPB := v.Passphrase().Get()
		kp, hasKP := v.KeyPaths().Head()
		if !hasPB || !hasKP {
			return nil
		}
		s.checkPrivateKeyFingerprint(ctx, ownerID, kp, pb, rep)
		return nil
	case *inventory.AuthComposite:
		for _, sub := range v.Methods() {
			if err := s.inspectAuthPrivateKeys(ctx, ownerID, sub, rep); err != nil {
				return err
			}
		}
		return nil
	case *inventory.AuthPassword, *inventory.AuthAgent, *inventory.AuthKeyboardInteractive:
		return nil
	default:
		return inventory.ErrInvalidAuthMethod
	}
}
func (s *Service) checkPrivateKeyFingerprint(ctx context.Context, ownerID string, kp inventory.KeyPathSpec, pb inventory.KeyPassphraseBinding, rep *DoctorReport) {
	if fp, err := s.keySigner.InspectPrivateKeyFingerprint(ctx, kp, algebraic.Some(pb.PassphraseRef())); err != nil {
		addFinding(rep, DoctorSeverityError, "private_key_inspect_failed", ownerID, "核验加密私钥指纹失败: "+err.Error())
	} else if !fp.Equal(pb.KeyFingerprint()) {
		addFinding(rep, DoctorSeverityError, "private_key_fingerprint_mismatch", ownerID, "加密私钥实际指纹与配置绑定指纹不一致")
	}
}
func doctorCheckUnusedAssets(g inventory.Graph, rep *DoctorReport) {
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
func addFinding(rep *DoctorReport, sev DoctorSeverity, code, subject, msg string) {
	rep.Findings = append(rep.Findings, DoctorFinding{Severity: sev, Code: code, Subject: subject, Message: security.SanitizePromptText(msg)})
	switch sev {
	case DoctorSeverityError:
		rep.ErrorCount++
		rep.Healthy = false
	case DoctorSeverityWarn:
		rep.WarnCount++
	case DoctorSeverityInfo:
		rep.InfoCount++
	}
}
