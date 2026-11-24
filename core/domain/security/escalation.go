package security

import (
	"cmp"
	"slices"
)

// EscalationReason 表示 CanonicalScopeEscalated 触发重提示或拒绝的结构化升级原因枚举；零值恒为 EscalationUnknown。
//
//xops:opaque
//xops:failclosed
type EscalationReason uint8

const (
	EscalationUnknown               EscalationReason = iota // 未知或未分类升级原因（零值失败关闭）
	EscalationInvalidInput                                  // 词法或规范快照之一为零值/无效，失败关闭判定升级
	EscalationCapabilityDrift                               // 操作能力类别发生跨界漂移
	EscalationTargetNodeDrift                               // 目标节点身份发生漂移
	EscalationEndpointDrift                                 // 目标 SSH 端点（主机或端口）发生漂移
	EscalationVerdictTightened                              // 二值安全判定由 Allow 收紧为 Deny
	EscalationRiskIncreased                                 // 操作风险等级升高
	EscalationDecisionTightened                             // 护栏决策收紧
	EscalationDecisionRiskIncreased                         // 同为 NeedApproval 决策但内部审批风险等级升高
	EscalationProtectedTransition                           // 路径由非受保护区进入受保护区
	EscalationProtectedRedirect                             // 受保护路径发生软链重定向或新增受保护分区（含 Protected-A -> Protected-B）
	EscalationRecursiveExpanded                             // 同路径由非递归翻转为递归，或未匹配规范递归根数量净增
	EscalationPathPresenceDrift                             // 路径集合在空集与非空集之间发生结构性漂移
)

// IsValid 报告 r 是否为明确的已定义升级原因（不含零值 EscalationUnknown）。
func (r EscalationReason) IsValid() bool {
	return r >= EscalationInvalidInput && r <= EscalationPathPresenceDrift
}

// String 返回升级原因的规范小写标识。
func (r EscalationReason) String() string {
	return enumName(uint8(r), "unknown",
		"unknown", "invalid_input", "capability_drift", "target_node_drift", "endpoint_drift",
		"verdict_tightened", "risk_increased", "decision_tightened", "decision_risk_increased",
		"protected_transition", "protected_redirect", "recursive_expanded", "path_presence_drift",
	)
}

// ParseEscalationReason 解析规范小写升级原因标识。
func ParseEscalationReason(raw string) (EscalationReason, error) {
	return parseEnumByName(raw, EscalationInvalidInput, EscalationPathPresenceDrift, EscalationUnknown, EscalationReason.String, ErrInvalidScopeSnapshot)
}

// AppendText 实现 encoding.TextAppender（值接收者）；对零值 EscalationUnknown 失败关闭。
func (r EscalationReason) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, r.IsValid(), r.String(), ErrInvalidScopeSnapshot, uint8(r))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (r EscalationReason) MarshalText() ([]byte, error) { return r.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 EscalationUnknown。
func (r *EscalationReason) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(r, EscalationUnknown, text, ParseEscalationReason)
}

// ScopeEscalationResult 保存 InspectScopeEscalation 的纯函数判定结论与审计诊断详情；
// 内置正向有效门控 valid bool，未初始化零值调用 Escalated() 时严格失败关闭返回 true。
//
//xops:opaque
//xops:failclosed
type ScopeEscalationResult struct {
	escalated           bool
	reasons             []EscalationReason
	addedProtectedPaths []string
	valid               bool
}

// Escalated 报告规范化后的作用域相较词法预检是否发生升级、受保护重定向或输入异常；零值失败关闭返回 true。
func (r ScopeEscalationResult) Escalated() bool { return !r.valid || r.escalated }

// Reasons 返回按固定顺序排列的升级原因防御性拷贝；零值返回 EscalationInvalidInput。
func (r ScopeEscalationResult) Reasons() []EscalationReason {
	if !r.valid {
		return []EscalationReason{EscalationInvalidInput}
	}
	return slices.Clone(r.reasons)
}

// AddedProtectedPaths 返回规范化阶段新增或重定向命中的受保护路径列表防御性拷贝。
func (r ScopeEscalationResult) AddedProtectedPaths() []string {
	if !r.valid {
		return nil
	}
	return slices.Clone(r.addedProtectedPaths)
}

// HasReason 报告结果中是否包含指定的升级原因。
func (r ScopeEscalationResult) HasReason(target EscalationReason) bool {
	if !r.valid {
		return target == EscalationInvalidInput
	}
	return slices.Contains(r.reasons, target)
}

// CanonicalScopeEscalated 纯数学判定词法预检快照 lexical 与规范化解析快照 canonical 之间
// 是否发生安全作用域升级、受保护分区重定向（含同风险同决策的 Protected-A -> Protected-B）或目标漂移（INV-E5）。
// 遵循严格失败关闭原则：任一快照无效或为零值时恒返回 true。
func CanonicalScopeEscalated(lexical, canonical ScopeSnapshot) bool {
	return InspectScopeEscalation(lexical, canonical).Escalated()
}

// InspectScopeEscalation 对 lexical 与 canonical 快照执行完整多维升级检测，返回确定性诊断结果。
func InspectScopeEscalation(lexical, canonical ScopeSnapshot) ScopeEscalationResult {
	if !lexical.IsValid() || !canonical.IsValid() {
		return ScopeEscalationResult{escalated: true, reasons: []EscalationReason{EscalationInvalidInput}, valid: true}
	}
	reasons := appendIdentityDriftReasons(nil, lexical, canonical)
	reasons = appendLatticeEscalationReasons(reasons, lexical, canonical)
	reasons, addedProtected := appendPathEscalationReasons(reasons, lexical, canonical)
	return ScopeEscalationResult{escalated: len(reasons) > 0, reasons: reasons, addedProtectedPaths: addedProtected, valid: true}
}

func appendIdentityDriftReasons(reasons []EscalationReason, lexical, canonical ScopeSnapshot) []EscalationReason {
	if lexical.capability != canonical.capability {
		reasons = append(reasons, EscalationCapabilityDrift)
	}
	if lexical.targetNode != canonical.targetNode {
		reasons = append(reasons, EscalationTargetNodeDrift)
	}
	if !equalOpt(lexical.endpoint, canonical.endpoint) {
		reasons = append(reasons, EscalationEndpointDrift)
	}
	return reasons
}

func appendLatticeEscalationReasons(reasons []EscalationReason, lexical, canonical ScopeSnapshot) []EscalationReason {
	if canonical.verdict.Compare(lexical.verdict) < 0 {
		reasons = append(reasons, EscalationVerdictTightened)
	}
	if canonical.risk.CompareSeverity(lexical.risk) > 0 {
		reasons = append(reasons, EscalationRiskIncreased)
	}
	if canonical.decision.Kind().CompareStrictness(lexical.decision.Kind()) > 0 {
		reasons = append(reasons, EscalationDecisionTightened)
	}
	if decisionApprovalRiskIncreased(lexical.decision, canonical.decision) {
		reasons = append(reasons, EscalationDecisionRiskIncreased)
	}
	return reasons
}

func decisionApprovalRiskIncreased(lexical, canonical GuardrailDecision) bool {
	lexNA, okL := lexical.(*DecisionNeedApproval)
	canNA, okC := canonical.(*DecisionNeedApproval)
	return okL && okC && lexNA.IsValid() && canNA.IsValid() && canNA.risk.CompareSeverity(lexNA.risk) > 0
}

func appendPathEscalationReasons(reasons []EscalationReason, lexical, canonical ScopeSnapshot) ([]EscalationReason, []string) {
	if (len(lexical.paths) == 0) != (len(canonical.paths) == 0) {
		reasons = append(reasons, EscalationPathPresenceDrift)
	}
	if !lexical.HasProtectedPath() && canonical.HasProtectedPath() {
		reasons = append(reasons, EscalationProtectedTransition)
	}
	addedProtected, recursiveExpanded := diffScopedPaths(lexical.paths, canonical.paths)
	if len(addedProtected) > 0 {
		reasons = append(reasons, EscalationProtectedRedirect)
	}
	if recursiveExpanded {
		reasons = append(reasons, EscalationRecursiveExpanded)
	}
	return reasons, addedProtected
}

// diffScopedPaths 对比排序后的词法与规范路径集，检测两类升级：
//  1. 未被词法快照完全覆盖的规范受保护路径或新增受保护分区（捕获 Protected-A -> Protected-B）；
//  2. 同路径由非递归翻转为递归，或未匹配规范递归根数量严格大于已消失词法递归根数量（防止多路径/额外递归根掩盖）。
func diffScopedPaths(lexical, canonical []ScopedPath) (addedProtected []string, recursiveExpanded bool) {
	unmatchedCanRec := 0
	for _, cp := range canonical {
		isAddedProt, samePathFlip, unmatchedRec := classifyCanonicalPath(lexical, cp)
		if isAddedProt {
			addedProtected = append(addedProtected, cp.path)
		}
		recursiveExpanded = recursiveExpanded || samePathFlip
		if unmatchedRec {
			unmatchedCanRec++
		}
	}
	return addedProtected, recursiveExpanded || unmatchedCanRec > countDisappearedRecursive(lexical, canonical)
}

func classifyCanonicalPath(lexical []ScopedPath, cp ScopedPath) (addedProtected, samePathFlip, unmatchedRec bool) {
	lp, matched := findScopedPath(lexical, cp.path)
	if !matched {
		return cp.IsProtected(), false, cp.recursive
	}
	return cp.IsProtected() && !isSubsetSortedStrings(cp.protectedZones, lp.protectedZones), cp.recursive && !lp.recursive, false
}

func countDisappearedRecursive(lexical, canonical []ScopedPath) int {
	count := 0
	for _, lp := range lexical {
		if _, exists := findScopedPath(canonical, lp.path); lp.recursive && !exists {
			count++
		}
	}
	return count
}

func findScopedPath(sorted []ScopedPath, target string) (ScopedPath, bool) {
	idx, found := slices.BinarySearchFunc(sorted, target, func(item ScopedPath, key string) int {
		return cmp.Compare(item.path, key)
	})
	if !found {
		return ScopedPath{}, false
	}
	return sorted[idx], true
}

func isSubsetSortedStrings(sub, sup []string) bool {
	i, j := 0, 0
	for i < len(sub) && j < len(sup) {
		switch cmp.Compare(sub[i], sup[j]) {
		case 0:
			i, j = i+1, j+1
		case 1:
			j++
		default:
			return false
		}
	}
	return i == len(sub)
}
