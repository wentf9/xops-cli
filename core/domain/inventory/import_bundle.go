package inventory

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// ImportWarning 描述格式导入过程中产生的非致命诊断告警（已校验单行纯文本）。
//
//xops:opaque
//xops:failclosed
type ImportWarning struct {
	code, subject, message string
	valid                  bool
}

// NewImportWarning 校验告警码、主题与消息并构造不可变 ImportWarning。
func NewImportWarning(code, subject, message string) (ImportWarning, error) {
	if err := validateAssetIdent(code, false); err != nil {
		return ImportWarning{}, fmt.Errorf("%w: 非法告警码 %q", ErrInvalidImportBundle, code)
	}
	subj, err := sanitizeSingleLine(strings.TrimSpace(subject), maxIDLen)
	if err != nil {
		return ImportWarning{}, fmt.Errorf("%w: subject: %w", ErrInvalidImportBundle, err)
	}
	msg, err := sanitizeSingleLine(strings.TrimSpace(message), maxWarningMsgBytes)
	if err != nil || msg == "" {
		return ImportWarning{}, fmt.Errorf("%w: 告警消息为空或包含非法字符", ErrInvalidImportBundle)
	}
	return ImportWarning{code, subj, msg, true}, nil
}
func (w ImportWarning) IsValid() bool   { return w.valid && w.code != "" && w.message != "" }
func (w ImportWarning) Code() string    { return w.code }
func (w ImportWarning) Subject() string { return w.subject }
func (w ImportWarning) Message() string { return w.message }
func (w ImportWarning) Equal(o ImportWarning) bool {
	return w.IsValid() && o.IsValid() && w.code == o.code && w.subject == o.subject && w.message == o.message
}

// ImportBundleSpec 是构造格式无关 ImportBundle 的入参规格（ADR-006 100% 零 v1 代码）。
type ImportBundleSpec struct {
	SourceFormat string
	Hosts        []Host
	Identities   []Identity
	Nodes        []Node
	Warnings     []ImportWarning
}

// ImportBundle 是面向 FormatImporter 的格式无关资产导入容器（如 openssh/csv）；
// 构造期强制去重排序并校验包内 ID/别名唯一性，零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type ImportBundle struct {
	sourceFormat string
	hosts        []Host
	identities   []Identity
	nodes        []Node
	warnings     []ImportWarning
	valid        bool
}

// NewImportBundle 校验格式标识、资产集合唯一性与告警并构造不可变 ImportBundle。
func NewImportBundle(spec ImportBundleSpec) (ImportBundle, error) {
	fmtName := strings.ToLower(strings.TrimSpace(spec.SourceFormat))
	if fmtName == "" || len(fmtName) > maxFormatNameLen || validateAssetIdent(fmtName, false) != nil {
		return ImportBundle{}, fmt.Errorf("%w: 非法 source_format %q", ErrInvalidImportBundle, spec.SourceFormat)
	}
	hosts, _, err := validateUniqueHosts(spec.Hosts)
	if err != nil {
		return ImportBundle{}, fmt.Errorf("%w: %w", ErrInvalidImportBundle, err)
	}
	idents, _, err := indexUnique(spec.Identities, Identity.IsValid, Identity.ID, IdentityID.Compare, ErrInvalidIdentity)
	if err != nil {
		return ImportBundle{}, fmt.Errorf("%w: %w", ErrInvalidImportBundle, err)
	}
	nodes, err := validateBundleNodes(spec.Nodes)
	if err != nil {
		return ImportBundle{}, fmt.Errorf("%w: %w", ErrInvalidImportBundle, err)
	}
	warnings, err := cloneAndSortWarnings(spec.Warnings)
	if err != nil {
		return ImportBundle{}, err
	}
	return ImportBundle{fmtName, hosts, idents, nodes, warnings, true}, nil
}

func validateBundleNodes(raw []Node) ([]Node, error) {
	out, seenID, err := indexUnique(raw, Node.IsValid, Node.ID, NodeID.Compare, ErrInvalidNode)
	if err != nil {
		return nil, err
	}
	seenAlias := make(map[string]bool, len(out))
	for _, n := range out {
		for _, a := range n.aliases {
			s := a.String()
			if seenID[NodeID{assetIDToken{s}}] || seenAlias[s] {
				return nil, fmt.Errorf("%w: 导入包别名 %q 发生冲突", ErrDuplicateAssetID, s)
			}
			seenAlias[s] = true
		}
	}
	return out, nil
}

func cloneAndSortWarnings(raw []ImportWarning) ([]ImportWarning, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := slices.Clone(raw)
	if slices.ContainsFunc(out, func(w ImportWarning) bool { return !w.IsValid() }) {
		return nil, fmt.Errorf("%w: warnings 含无效条目", ErrInvalidImportBundle)
	}
	slices.SortFunc(out, func(a, b ImportWarning) int {
		return cmp.Or(cmp.Compare(a.code, b.code), cmp.Compare(a.subject, b.subject), cmp.Compare(a.message, b.message))
	})
	return out, nil
}

func (b ImportBundle) IsValid() bool             { return b.valid && b.sourceFormat != "" }
func (b ImportBundle) IsZero() bool              { return !b.IsValid() }
func (b ImportBundle) SourceFormat() string      { return b.sourceFormat }
func (b ImportBundle) Hosts() []Host             { return slices.Clone(b.hosts) }
func (b ImportBundle) Identities() []Identity    { return slices.Clone(b.identities) }
func (b ImportBundle) Nodes() []Node             { return slices.Clone(b.nodes) }
func (b ImportBundle) Warnings() []ImportWarning { return slices.Clone(b.warnings) }
func (b ImportBundle) Equal(o ImportBundle) bool {
	return b.IsValid() && o.IsValid() && b.sourceFormat == o.sourceFormat &&
		slices.EqualFunc(b.hosts, o.hosts, Host.Equal) && slices.EqualFunc(b.identities, o.identities, Identity.Equal) &&
		slices.EqualFunc(b.nodes, o.nodes, Node.Equal) && slices.EqualFunc(b.warnings, o.warnings, ImportWarning.Equal)
}

// ImportActionKind 标识导入预检对单条资产的分类决策；零值 ImportActionInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type ImportActionKind uint8

const (
	ImportActionInvalid   ImportActionKind = iota // 无效决策（零值失败关闭）
	ImportActionAdd                               // 新增资产
	ImportActionUnchanged                         // 与现有资产完全一致（幂等跳过）
	ImportActionConflict                          // 存在标识/别名/引用或合并环路冲突
)

func (k ImportActionKind) IsValid() bool { return k >= ImportActionAdd && k <= ImportActionConflict }
func (k ImportActionKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "add", "unchanged", "conflict")
}

// ImportEntry 与 ImportReport 描述 PlanImport 产出的不可变确定性冲突与合并分析报告。
type (
	ImportEntry struct {
		AssetKind, AssetID string
		Action             ImportActionKind
		Reason             string
	}
	ImportReport struct {
		SourceFormat                            string
		AddCount, UnchangedCount, ConflictCount int
		Entries                                 []ImportEntry
		Warnings                                []ImportWarning
	}
)

// HasConflicts 报告导入合并计划是否存在任意冲突项。
func (r ImportReport) HasConflicts() bool { return r.ConflictCount > 0 }

// PlanImport 对现有资产图 existing 与导入包 bundle 执行纯函数确定性冲突与合并预检：
// 逐项分类 Host（含 Host.Alias 冲突）/Identity/Node，校验跨集合引用、别名碰撞、合并 ProxyJump DAG 与 KnownStores。
func PlanImport(existing Graph, bundle ImportBundle) (ImportReport, error) {
	if !existing.IsValid() {
		return ImportReport{}, ErrInvalidGraph
	}
	if !bundle.IsValid() {
		return ImportReport{}, ErrInvalidImportBundle
	}
	report := ImportReport{SourceFormat: bundle.sourceFormat, Warnings: bundle.Warnings()}
	availHosts := classifyImportHosts(existing.hosts, bundle.hosts, &report)
	availIdents := classifyAssetSlice("identity", existing.identities, bundle.identities, Identity.ID, func(k IdentityID) string { return k.String() }, Identity.Equal, &report)
	classifyNodesAndCheckMerge(existing, bundle, availHosts, availIdents, &report)
	checkImportSecretStores(existing.knownStores, bundle, &report)
	return report, nil
}

func classifyImportHosts(existing, incoming []Host, report *ImportReport) map[HostID]bool {
	hostMap, aliasOwner := make(map[HostID]Host, len(existing)), make(map[string]HostID, len(existing))
	avail := make(map[HostID]bool, len(existing)+len(incoming))
	for _, h := range existing {
		hostMap[h.id], avail[h.id] = h, true
		if a, ok := h.alias.Get(); ok {
			aliasOwner[a.String()] = h.id
		}
	}
	for _, h := range incoming {
		avail[h.id] = true
		appendImportEntry(report, classifySingleImportHost(h, hostMap, aliasOwner))
	}
	return avail
}

func classifySingleImportHost(h Host, hostMap map[HostID]Host, aliasOwner map[string]HostID) ImportEntry {
	id := h.id.String()
	if prev, exists := hostMap[h.id]; exists {
		return ImportEntry{"host", id, pickIf(prev.Equal(h), ImportActionUnchanged, ImportActionConflict), pickIf(prev.Equal(h), "", "asset_id_mismatch")}
	}
	if owner, taken := aliasOwner[id]; taken {
		return ImportEntry{"host", id, ImportActionConflict, "host_id_collides_with_alias:" + owner.String()}
	}
	if a, ok := h.alias.Get(); ok {
		s := a.String()
		if _, idTaken := hostMap[HostID{assetIDToken{s}}]; idTaken {
			return ImportEntry{"host", id, ImportActionConflict, "host_alias_collides_with_host_id:" + s}
		}
		if owner, taken := aliasOwner[s]; taken {
			return ImportEntry{"host", id, ImportActionConflict, "host_alias_collision:" + owner.String()}
		}
	}
	return ImportEntry{"host", id, ImportActionAdd, ""}
}

func checkImportSecretStores(knownStores []string, bundle ImportBundle, report *ImportReport) {
	if len(knownStores) == 0 {
		return
	}
	var refs []SecretReference
	for _, id := range bundle.identities {
		if !collectAuthSecretRefs(id.id.String(), id.auth, &refs) {
			appendImportEntry(report, ImportEntry{"secret_store", id.id.String(), ImportActionConflict, "invalid_auth_method"})
			return
		}
	}
	for _, n := range bundle.nodes {
		if ref, ok := n.privilegePasswordRef.Get(); ok && ref.IsValid() {
			refs = append(refs, SecretReference{SecretLocNodePrivilege, n.id.String(), "", ref})
		}
	}
	for _, sr := range refs {
		if !slices.Contains(knownStores, sr.Ref.Store()) {
			appendImportEntry(report, ImportEntry{"secret_store", sr.OwnerID, ImportActionConflict, "unknown_secret_store:" + sr.Ref.Store()})
		}
	}
}

func classifyAssetSlice[T any, K comparable](kind string, existing, incoming []T, keyOf func(T) K, strOf func(K) string, eq func(T, T) bool, report *ImportReport) map[K]bool {
	byID, avail := make(map[K]T, len(existing)), make(map[K]bool, len(existing)+len(incoming))
	for _, item := range existing {
		k := keyOf(item)
		byID[k], avail[k] = item, true
	}
	for _, item := range incoming {
		k := keyOf(item)
		avail[k] = true
		prev, exists := byID[k]
		switch {
		case !exists:
			appendImportEntry(report, ImportEntry{kind, strOf(k), ImportActionAdd, ""})
		case eq(prev, item):
			appendImportEntry(report, ImportEntry{kind, strOf(k), ImportActionUnchanged, ""})
		default:
			appendImportEntry(report, ImportEntry{kind, strOf(k), ImportActionConflict, "asset_id_mismatch"})
		}
	}
	return avail
}

func classifyNodesAndCheckMerge(existing Graph, bundle ImportBundle, availHosts map[HostID]bool, availIdents map[IdentityID]bool, report *ImportReport) {
	nodeMap, aliasOwner := make(map[NodeID]Node, len(existing.nodes)), make(map[string]NodeID, len(existing.nodes))
	for _, n := range existing.nodes {
		nodeMap[n.id] = n
		for _, a := range n.aliases {
			aliasOwner[a.String()] = n.id
		}
	}
	mergedNodes := slices.Clone(existing.nodes)
	for _, n := range bundle.nodes {
		entry := classifySingleImportNode(n, nodeMap, aliasOwner, availHosts, availIdents)
		appendImportEntry(report, entry)
		if entry.Action == ImportActionAdd {
			mergedNodes = append(mergedNodes, n)
		}
	}
	if _, err := ValidateProxyDAG(mergedNodes, existing.openSSHNodes, DefaultMaxJumpDepth); err != nil {
		appendImportEntry(report, ImportEntry{"graph", "proxy_dag", ImportActionConflict, err.Error()})
	}
}

func classifySingleImportNode(n Node, nodeMap map[NodeID]Node, aliasOwner map[string]NodeID, availHosts map[HostID]bool, availIdents map[IdentityID]bool) ImportEntry {
	id := n.id.String()
	if !availHosts[n.hostRef] || !availIdents[n.identityRef] {
		return ImportEntry{"node", id, ImportActionConflict, "dangling_host_or_identity_ref"}
	}
	if prev, exists := nodeMap[n.id]; exists {
		return ImportEntry{"node", id, pickIf(prev.Equal(n), ImportActionUnchanged, ImportActionConflict), pickIf(prev.Equal(n), "", "node_id_mismatch")}
	}
	if owner, occupied := aliasOwner[id]; occupied {
		return ImportEntry{"node", id, ImportActionConflict, "node_id_collides_with_alias:" + owner.String()}
	}
	for _, a := range n.aliases {
		if _, idTaken := nodeMap[NodeID{assetIDToken{a.String()}}]; idTaken {
			return ImportEntry{"node", id, ImportActionConflict, "alias_collides_with_node_id:" + a.String()}
		}
		if owner, taken := aliasOwner[a.String()]; taken {
			return ImportEntry{"node", id, ImportActionConflict, "alias_collision:" + owner.String()}
		}
	}
	return ImportEntry{"node", id, ImportActionAdd, ""}
}

func appendImportEntry(report *ImportReport, e ImportEntry) {
	report.Entries = append(report.Entries, e)
	switch e.Action {
	case ImportActionAdd:
		report.AddCount++
	case ImportActionUnchanged:
		report.UnchangedCount++
	case ImportActionConflict:
		report.ConflictCount++
	}
}
