package security

import (
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

// ScopedPath 表示单条进入安全作用域判定的不可变路径条目及其受保护分区集合；
// 同路径按 recursive 逻辑或与受保护分区集合并集折叠，零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type ScopedPath struct {
	path           string
	recursive      bool
	protectedZones []string
	valid          bool
}

// NewScopedPath 校验路径与受保护分区标签并构造不可变 ScopedPath。
func NewScopedPath(path string, recursive bool, protectedZones ...string) (ScopedPath, error) {
	if path == "" || hasInvalidUTF8OrControl(path) {
		return ScopedPath{}, fmt.Errorf("%w: 路径不能为空且不得包含非法 UTF-8/控制/格式字符", ErrInvalidScopeSnapshot)
	}
	zones, err := canonicalizeUniqueStrings(protectedZones, "protected_zones", ErrInvalidScopeSnapshot)
	if err != nil {
		return ScopedPath{}, err
	}
	return ScopedPath{path: path, recursive: recursive, protectedZones: zones, valid: true}, nil
}

// IsValid 报告 ScopedPath 是否有效。
func (p ScopedPath) IsValid() bool { return p.valid && p.path != "" }

// IsZero 报告 ScopedPath 是否为无效零值。
func (p ScopedPath) IsZero() bool { return !p.IsValid() }

// Path 返回规范化路径文本。
func (p ScopedPath) Path() string { return p.path }

// IsRecursive 报告该路径条目是否覆盖递归后代目录。
func (p ScopedPath) IsRecursive() bool { return p.valid && p.recursive }

// IsProtected 报告该路径条目是否命中至少一个受保护分区。
func (p ScopedPath) IsProtected() bool { return p.valid && len(p.protectedZones) > 0 }

// ProtectedZones 返回按字典序排列去重后的受保护分区防御性拷贝。
func (p ScopedPath) ProtectedZones() []string { return slices.Clone(p.protectedZones) }

// Equal 严格比对两个 ScopedPath 是否均有效且完全一致（无效零值永不相等）。
func (p ScopedPath) Equal(other ScopedPath) bool {
	return p.IsValid() && other.IsValid() && p.path == other.path &&
		p.recursive == other.recursive && slices.Equal(p.protectedZones, other.protectedZones)
}

// JoinSamePath 对同路径的两条记录执行并半格合并（recursive || 与受保护分区并集）；非法或异路径返回零值。
func (p ScopedPath) JoinSamePath(other ScopedPath) ScopedPath {
	if !p.IsValid() || !other.IsValid() || p.path != other.path {
		return ScopedPath{}
	}
	return ScopedPath{
		path: p.path, recursive: p.recursive || other.recursive,
		protectedZones: mergeSortedUniqueStrings(p.protectedZones, other.protectedZones), valid: true,
	}
}

// ScopeSnapshotSpec 是构造不可变 ScopeSnapshot 的显式入参规格。
type ScopeSnapshotSpec struct {
	Capability CapabilityKind
	TargetNode string
	Endpoint   algebraic.Option[netaddr.Endpoint]
	Verdict    Verdict
	Risk       RiskLevel
	Decision   GuardrailDecision
	Paths      []ScopedPath
}

// ScopeSnapshot 表示词法预检（Round 1）或远端软链规范化（Round 2）阶段的不可变安全作用域快照；
// 内部路径按字典序规范排序并折叠重复项，零值恒无效并在 CanonicalScopeEscalated 中无条件失败关闭返回 true。
//
//xops:opaque
//xops:failclosed
type ScopeSnapshot struct {
	capability CapabilityKind
	targetNode string
	endpoint   algebraic.Option[netaddr.Endpoint]
	verdict    Verdict
	risk       RiskLevel
	decision   GuardrailDecision
	paths      []ScopedPath
	valid      bool
}

// NewScopeSnapshot 校验并构造不可变 ScopeSnapshot。
func NewScopeSnapshot(spec ScopeSnapshotSpec) (ScopeSnapshot, error) {
	if err := validateScopeSnapshotSpec(spec); err != nil {
		return ScopeSnapshot{}, err
	}
	paths, err := canonicalizeScopedPaths(spec.Paths)
	if err != nil {
		return ScopeSnapshot{}, err
	}
	return ScopeSnapshot{
		capability: spec.Capability, targetNode: spec.TargetNode, endpoint: spec.Endpoint,
		verdict: spec.Verdict, risk: spec.Risk, decision: NormalizeDecision(spec.Decision),
		paths: paths, valid: true,
	}, nil
}

func validateScopeSnapshotSpec(spec ScopeSnapshotSpec) error {
	switch {
	case !spec.Capability.IsValid():
		return fmt.Errorf("%w: %w", ErrInvalidScopeSnapshot, ErrInvalidCapability)
	case spec.TargetNode != "" && !isValidNodeID(spec.TargetNode):
		return fmt.Errorf("%w: 非法 target_node %q", ErrInvalidScopeSnapshot, spec.TargetNode)
	case !spec.Verdict.IsValid() || !spec.Risk.IsValid() || spec.Decision == nil || !spec.Decision.IsValid():
		return fmt.Errorf("%w: verdict/risk/decision 必须均有效", ErrInvalidScopeSnapshot)
	case optInvalid(spec.Endpoint):
		return fmt.Errorf("%w: endpoint 不可为无效零值", ErrInvalidScopeSnapshot)
	}
	return nil
}

func canonicalizeScopedPaths(raw []ScopedPath) ([]ScopedPath, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	cloned := make([]ScopedPath, len(raw))
	for i, sp := range raw {
		if !sp.IsValid() {
			return nil, fmt.Errorf("%w: paths[%d] 无效", ErrInvalidScopeSnapshot, i)
		}
		cloned[i] = cloneScopedPath(sp)
	}
	return sortAndMergeByKey(cloned, ScopedPath.Path, ScopedPath.JoinSamePath), nil
}

func cloneScopedPath(sp ScopedPath) ScopedPath {
	return ScopedPath{path: sp.path, recursive: sp.recursive, protectedZones: slices.Clone(sp.protectedZones), valid: true}
}

// IsValid 报告 ScopeSnapshot 是否完整有效。
func (s ScopeSnapshot) IsValid() bool {
	return s.valid && s.capability.IsValid() && s.verdict.IsValid() && s.risk.IsValid() &&
		s.decision != nil && s.decision.IsValid() && !slices.ContainsFunc(s.paths, ScopedPath.IsZero)
}

// IsZero 报告 ScopeSnapshot 是否为无效零值。
func (s ScopeSnapshot) IsZero() bool { return !s.IsValid() }

// Capability 返回快照绑定的能力类别。
func (s ScopeSnapshot) Capability() CapabilityKind { return s.capability }

// TargetNode 返回快照绑定的目标节点标识。
func (s ScopeSnapshot) TargetNode() string { return s.targetNode }

// Endpoint 返回可选目标端点。
func (s ScopeSnapshot) Endpoint() algebraic.Option[netaddr.Endpoint] { return s.endpoint }

// Verdict 返回快照对应的二值判定；无效时失败关闭返回 VerdictDeny。
func (s ScopeSnapshot) Verdict() Verdict { return pickIf(s.IsValid(), s.verdict, VerdictDeny) }

// Risk 返回快照对应的风险等级；无效时失败关闭返回 RiskUnknown。
func (s ScopeSnapshot) Risk() RiskLevel { return pickIf(s.IsValid(), s.risk, RiskUnknown) }

// Decision 返回快照对应的护栏决策副本；无效时失败关闭返回 *DecisionDeny。
func (s ScopeSnapshot) Decision() GuardrailDecision {
	if s.IsValid() {
		return NormalizeDecision(s.decision)
	}
	return invalidDecisionDeny()
}

// Paths 返回规范排序去重后的作用域路径防御性拷贝。
func (s ScopeSnapshot) Paths() []ScopedPath {
	if !s.IsValid() || len(s.paths) == 0 {
		return nil
	}
	out := make([]ScopedPath, len(s.paths))
	for i, p := range s.paths {
		out[i] = cloneScopedPath(p)
	}
	return out
}

// HasProtectedPath 报告快照中是否存在任意命中受保护分区的路径。
func (s ScopeSnapshot) HasProtectedPath() bool {
	return s.IsValid() && slices.ContainsFunc(s.paths, ScopedPath.IsProtected)
}

// Equal 严格比对两个 ScopeSnapshot 是否均有效且所有字段完全一致（无效零值永不相等）。
func (s ScopeSnapshot) Equal(other ScopeSnapshot) bool {
	return s.IsValid() && other.IsValid() && s.capability == other.capability &&
		s.targetNode == other.targetNode && equalOpt(s.endpoint, other.endpoint) &&
		s.verdict == other.verdict && s.risk == other.risk && EqualDecision(s.decision, other.decision) &&
		slices.EqualFunc(s.paths, other.paths, ScopedPath.Equal)
}

// Join 将同身份两份作用域快照按有界格折叠（Verdict Meet、Risk Join、Decision Join、Paths 并集折叠）。
// 任一快照无效或身份漂移时失败关闭返回零值；严格满足交换/结合/幂等律。
func (s ScopeSnapshot) Join(other ScopeSnapshot) ScopeSnapshot {
	if !s.IsValid() || !other.IsValid() || s.capability != other.capability ||
		s.targetNode != other.targetNode || !equalOpt(s.endpoint, other.endpoint) {
		return ScopeSnapshot{}
	}
	return ScopeSnapshot{
		capability: s.capability, targetNode: s.targetNode, endpoint: s.endpoint,
		verdict: s.verdict.Meet(other.verdict), risk: s.risk.Join(other.risk),
		decision: JoinDecisions(s.decision, other.decision),
		paths:    sortAndMergeByKey(append(s.Paths(), other.Paths()...), ScopedPath.Path, ScopedPath.JoinSamePath), valid: true,
	}
}

// FoldScopeSnapshots 对一组 ScopeSnapshot 执行顺序无关的代数格折叠；空输入失败关闭返回零值。
func FoldScopeSnapshots(snaps ...ScopeSnapshot) ScopeSnapshot {
	if len(snaps) == 0 || !snaps[0].IsValid() {
		return ScopeSnapshot{}
	}
	acc := snaps[0]
	for _, item := range snaps[1:] {
		if acc = acc.Join(item); !acc.IsValid() {
			return ScopeSnapshot{}
		}
	}
	return acc
}

func mergeSortedUniqueStrings(a, b []string) []string {
	merged := append(slices.Clone(a), b...)
	slices.Sort(merged)
	return slices.Compact(merged)
}
