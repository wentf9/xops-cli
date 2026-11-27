package security

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"maps"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// NodeOverrideRule 表示单条经过语法与阈值校验的不可变节点护栏覆盖规则；零值恒无效并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type NodeOverrideRule struct {
	pattern           string
	approvalThreshold RiskLevel
	decisionFloor     DecisionKind
	valid             bool
}

// NewNodeOverrideRule 校验模式与风险阈值，构造一条仅收紧审批阈值的节点覆盖规则。
func NewNodeOverrideRule(pattern string, approvalThreshold RiskLevel) (NodeOverrideRule, error) {
	return NewNodeOverrideRuleWithFloor(pattern, approvalThreshold, DecisionKindAllow)
}

// NewNodeOverrideRuleWithFloor 校验模式、审批阈值与强制决策下限，构造完整节点覆盖规则。
func NewNodeOverrideRuleWithFloor(pattern string, approvalThreshold RiskLevel, decisionFloor DecisionKind) (NodeOverrideRule, error) {
	if err := ValidateGlob(pattern); err != nil {
		return NodeOverrideRule{}, domi18n.WrapSentinel(ErrInvalidNodeOverride, err)
	}
	if !approvalThreshold.IsValid() {
		return NodeOverrideRule{}, domi18n.WrapSentinel(ErrInvalidNodeOverride, ErrInvalidRiskLevel)
	}
	if !decisionFloor.IsValid() {
		return NodeOverrideRule{}, domi18n.WrapSentinel(ErrInvalidNodeOverride, ErrInvalidDecision)
	}
	return NodeOverrideRule{pattern: pattern, approvalThreshold: approvalThreshold, decisionFloor: decisionFloor, valid: true}, nil
}

// IsValid 报告规则是否已通过构造器校验。
func (r NodeOverrideRule) IsValid() bool {
	return r.valid && r.pattern != "" && r.approvalThreshold.IsValid() && r.decisionFloor.IsValid()
}

// IsZero 报告规则是否为无效零值。
func (r NodeOverrideRule) IsZero() bool { return !r.IsValid() }

// Pattern 返回节点匹配通配符模式。
func (r NodeOverrideRule) Pattern() string { return r.pattern }

// ApprovalThreshold 返回规则指定的审批阈值；无效时返回 RiskUnknown。
func (r NodeOverrideRule) ApprovalThreshold() RiskLevel {
	return pickIf(r.IsValid(), r.approvalThreshold, RiskUnknown)
}

// DecisionFloor 返回规则指定的最低限制决策类别；无效时失败关闭返回 DecisionKindDeny。
func (r NodeOverrideRule) DecisionFloor() DecisionKind {
	return pickIf(r.IsValid(), r.decisionFloor, DecisionKindDeny)
}

// Equal 比较两条覆盖规则是否均有效且完全一致（零值永不相等）。
func (r NodeOverrideRule) Equal(other NodeOverrideRule) bool {
	return r.IsValid() && other.IsValid() && r.pattern == other.pattern &&
		r.approvalThreshold == other.approvalThreshold && r.decisionFloor == other.decisionFloor
}

// CombineSamePattern 对同模式的两条规则执行并半格收紧（最严阈值 + 最严决策下限）；非法或异模式返回零值。
func (r NodeOverrideRule) CombineSamePattern(other NodeOverrideRule) NodeOverrideRule {
	if !r.IsValid() || !other.IsValid() || r.pattern != other.pattern {
		return NodeOverrideRule{}
	}
	th, fl := r.approvalThreshold.StrictestThreshold(other.approvalThreshold), r.decisionFloor.Join(other.decisionFloor)
	if !th.IsValid() || !fl.IsValid() {
		return NodeOverrideRule{}
	}
	return NodeOverrideRule{pattern: r.pattern, approvalThreshold: th, decisionFloor: fl, valid: true}
}

type nodeOverrideRuleWire struct {
	Pattern           algebraic.Option[string]       `json:"pattern"`
	ApprovalThreshold algebraic.Option[RiskLevel]    `json:"approval_threshold"`
	DecisionFloor     algebraic.Option[DecisionKind] `json:"decision_floor"`
}

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者）；对零值规则失败关闭。
func (r NodeOverrideRule) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !r.IsValid() {
		return ErrInvalidNodeOverride
	}
	return jsonv2.MarshalEncode(enc, nodeOverrideRuleWire{
		Pattern: algebraic.Some(r.pattern), ApprovalThreshold: algebraic.Some(r.approvalThreshold),
		DecisionFloor: algebraic.Some(r.decisionFloor),
	})
}

// UnmarshalJSONFrom 实现 encoding/json/v2.UnmarshalerFrom；对 JSON null 或缺失必需字段失败关闭并重置零值。
func (r *NodeOverrideRule) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(r, dec, ErrInvalidNodeOverride, func(w nodeOverrideRuleWire) (NodeOverrideRule, error) {
		pat, okP := w.Pattern.Get()
		th, okT := w.ApprovalThreshold.Get()
		fl, okF := w.DecisionFloor.Get()
		if !okP || !okT || !okF {
			return NodeOverrideRule{}, domi18n.EF(ErrInvalidNodeOverride, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "pattern/approval_threshold/decision_floor"))
		}
		return NewNodeOverrideRuleWithFloor(pat, th, fl)
	})
}

// NodeOverrides 表示按 pattern 排序并自动合并同模式冲突的不可变节点覆盖规则格集合（INV-E3 / RFC §3.6）；
// 彻底消除 Go map 迭代序依赖，零值恒无效并失败关闭，空集合须经 EmptyNodeOverrides 显式构造。
//
//xops:opaque
//xops:failclosed
type NodeOverrides struct {
	rules []NodeOverrideRule
	valid bool
}

// EmptyNodeOverrides 返回显式为空且有效的 NodeOverrides（Join 运算单位元）。
func EmptyNodeOverrides() NodeOverrides { return NodeOverrides{valid: true} }

// NewNodeOverrides 校验并按规范顺序折叠一组规则为不可变 NodeOverrides，保证任意输入排列结果一致。
func NewNodeOverrides(rules ...NodeOverrideRule) (NodeOverrides, error) {
	if len(rules) == 0 {
		return EmptyNodeOverrides(), nil
	}
	cloned := make([]NodeOverrideRule, len(rules))
	for i, rule := range rules {
		if !rule.IsValid() {
			return NodeOverrides{}, domi18n.EF(ErrInvalidNodeOverride, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "rules"), domi18n.Int("index", i))
		}
		cloned[i] = rule
	}
	return NodeOverrides{rules: sortAndMergeByKey(cloned, NodeOverrideRule.Pattern, NodeOverrideRule.CombineSamePattern), valid: true}, nil
}

// NewNodeOverridesFromMap 将配置中的 map[pattern]RiskLevel 按确定性键序规范化为顺序无关的 NodeOverrides。
func NewNodeOverridesFromMap(entries map[string]RiskLevel) (NodeOverrides, error) {
	if len(entries) == 0 {
		return EmptyNodeOverrides(), nil
	}
	rules := make([]NodeOverrideRule, 0, len(entries))
	for _, pattern := range slices.Sorted(maps.Keys(entries)) {
		rule, err := NewNodeOverrideRule(pattern, entries[pattern])
		if err != nil {
			return NodeOverrides{}, err
		}
		rules = append(rules, rule)
	}
	return NodeOverrides{rules: rules, valid: true}, nil
}

// IsValid 报告规则集是否经构造器初始化且全部规则有效。
func (o NodeOverrides) IsValid() bool {
	return o.valid && !slices.ContainsFunc(o.rules, NodeOverrideRule.IsZero)
}

// IsZero 报告规则集是否为无效零值。
func (o NodeOverrides) IsZero() bool { return !o.IsValid() }

// Len 返回已规范去重后的规则数量。
func (o NodeOverrides) Len() int { return pickIf(o.IsValid(), len(o.rules), 0) }

// Rules 返回按 pattern 升序排列的规则防御性拷贝。
func (o NodeOverrides) Rules() []NodeOverrideRule {
	if !o.IsValid() {
		return nil
	}
	return slices.Clone(o.rules)
}

// Equal 比较两个 NodeOverrides 是否均有效且规则集完全相同。
func (o NodeOverrides) Equal(other NodeOverrides) bool {
	return o.IsValid() && other.IsValid() && slices.EqualFunc(o.rules, other.rules, NodeOverrideRule.Equal)
}

// Join 按严苛度并半格合并两个 NodeOverrides；任一侧无效返回零值，满足交换/结合/幂等/单调律。
func (o NodeOverrides) Join(other NodeOverrides) NodeOverrides {
	if !o.IsValid() || !other.IsValid() {
		return NodeOverrides{}
	}
	merged := append(slices.Clone(o.rules), other.rules...)
	return NodeOverrides{rules: sortAndMergeByKey(merged, NodeOverrideRule.Pattern, NodeOverrideRule.CombineSamePattern), valid: true}
}

func (o NodeOverrides) matchRules(nodeID string) (matchedAny bool, threshold RiskLevel, floor DecisionKind, err error) {
	// 即使 o 为 EmptyNodeOverrides()（len(rules)==0），仍须前置校验 nodeID 防止非法 UTF-8/控制字符绕过失败关闭。
	if !isValidNodeID(nodeID) {
		return false, RiskUnknown, DecisionKindDeny, domi18n.EF(ErrInvalidNodeOverride, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "node_id"), domi18n.BoundStr("value", nodeID))
	}
	threshold, floor = RiskDangerous, DecisionKindAllow
	for _, rule := range o.rules {
		matched, matchErr := MatchGlob(rule.pattern, nodeID)
		if matchErr != nil {
			return false, RiskUnknown, DecisionKindDeny, domi18n.WrapSentinel(ErrInvalidNodeOverride, matchErr)
		}
		if matched {
			threshold, floor, matchedAny = threshold.StrictestThreshold(rule.approvalThreshold), floor.Join(rule.decisionFloor), true
		}
	}
	return matchedAny, threshold, floor, nil
}

// ResolveThreshold 计算单节点 nodeID 的有效审批阈值（INV-E3）：空 nodeID 走全局 baseThreshold，
// 非空时前置校验 nodeID 并遍历全部命中规则按 StrictestThreshold 折叠，彻底消除规则顺序依赖。
func (o NodeOverrides) ResolveThreshold(baseThreshold RiskLevel, nodeID string) (RiskLevel, error) {
	if !o.IsValid() {
		return RiskUnknown, ErrInvalidNodeOverride
	}
	if !baseThreshold.IsValid() {
		return RiskUnknown, ErrInvalidRiskLevel
	}
	if nodeID == "" {
		return baseThreshold, nil
	}
	matchedAny, strictest, _, err := o.matchRules(nodeID)
	if err != nil {
		return RiskUnknown, err
	}
	return pickIf(matchedAny, strictest, baseThreshold), nil
}

// ResolveBatchThreshold 对批量目标节点执行单调严苛阈值折叠（INV-E3）：
// 始终以全局 baseThreshold 初始化折叠，确保批量操作绝不因单个宽松节点覆盖而弱化全局策略。
func (o NodeOverrides) ResolveBatchThreshold(baseThreshold RiskLevel, nodeIDs ...string) (RiskLevel, error) {
	acc, err := o.ResolveThreshold(baseThreshold, "")
	if err != nil {
		return RiskUnknown, err
	}
	for _, nodeID := range nodeIDs {
		resolved, err := o.ResolveThreshold(baseThreshold, nodeID)
		if err != nil {
			return RiskUnknown, err
		}
		acc = acc.StrictestThreshold(resolved)
	}
	return acc, nil
}

// EvaluateNode 在基准阈值与操作风险下对单个目标节点求值（空 nodeID 走全局基准阈值，非法 nodeID 失败关闭为 Deny）。
func (o NodeOverrides) EvaluateNode(baseThreshold, opRisk RiskLevel, nodeID string) GuardrailDecision {
	if !o.IsValid() {
		return NewDecisionDenyWithCode("invalid_overrides", "node overrides set is uninitialized or invalid")
	}
	if !baseThreshold.IsValid() || !opRisk.IsValid() || nodeID == "" {
		return EvaluateThreshold(opRisk, baseThreshold)
	}
	matchedAny, strictest, floor, err := o.matchRules(nodeID)
	if err != nil {
		return NewDecisionDenyWithCode("invalid_node_id", err.Error())
	}
	if !matchedAny {
		return EvaluateThreshold(opRisk, baseThreshold)
	}
	return JoinDecisions(EvaluateThreshold(opRisk, strictest), decisionFromFloor(floor, opRisk))
}

// EvaluateBatch 在全局基准阈值、操作风险与批量目标节点集合上执行严格单调且顺序无关的限制支配折叠（INV-E3）：
// 始终从全局 EvaluateThreshold(opRisk, baseThreshold) 起步折叠，确保任意新增目标节点只会维持或收紧决策。
func (o NodeOverrides) EvaluateBatch(baseThreshold, opRisk RiskLevel, nodeIDs ...string) GuardrailDecision {
	acc := o.EvaluateNode(baseThreshold, opRisk, "")
	if !o.IsValid() || !baseThreshold.IsValid() || !opRisk.IsValid() {
		return acc
	}
	for _, nodeID := range nodeIDs {
		acc = JoinDecisions(acc, o.EvaluateNode(baseThreshold, opRisk, nodeID))
	}
	return acc
}

func decisionFromFloor(floor DecisionKind, opRisk RiskLevel) GuardrailDecision {
	switch floor {
	case DecisionKindAllow:
		return NewDecisionAllow("node override permits threshold evaluation")
	case DecisionKindNeedApproval:
		if !opRisk.IsValid() {
			return NewDecisionDenyWithCode("unknown_risk", "node override approval floor with unknown risk")
		}
		return &DecisionNeedApproval{risk: opRisk, reason: "node override requires explicit approval", valid: true}
	default:
		return NewDecisionDenyWithCode("node_override_deny", "node override denies operation")
	}
}

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者），以规范排序数组编码；零值失败关闭。
func (o NodeOverrides) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !o.IsValid() {
		return ErrInvalidNodeOverride
	}
	return jsonv2.MarshalEncode(enc, pickIf(o.rules != nil, o.rules, []NodeOverrideRule{}))
}

// UnmarshalJSONFrom 实现 encoding/json/v2.UnmarshalerFrom；失败时重置为零值并失败关闭。
func (o *NodeOverrides) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(o, dec, ErrInvalidNodeOverride, func(rules []NodeOverrideRule) (NodeOverrides, error) {
		return NewNodeOverrides(rules...)
	})
}
