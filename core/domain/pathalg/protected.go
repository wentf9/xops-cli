package pathalg

import (
	"cmp"
	"slices"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"golang.org/x/text/unicode/norm"
)

// MatchKind 标识受保护路径规则的命中类别；零值 MatchNone 严格代表未命中。
//
//xops:failclosed
type MatchKind uint8

const (
	// MatchNone 表示未命中任何受保护路径规则（零值）。
	MatchNone MatchKind = iota
	// MatchDirect 表示目标路径自身直接命中受保护路径规则（精确、前缀或通配命中）。
	MatchDirect
	// MatchAncestorContainsProtected 表示递归目录目标自身位于某条受保护路径规则的祖先路径上（包含受保护后代）。
	MatchAncestorContainsProtected
)

// String 返回 MatchKind 的可读名称。
func (k MatchKind) String() string {
	switch k {
	case MatchDirect:
		return "direct"
	case MatchAncestorContainsProtected:
		return "ancestor_contains_protected"
	default:
		return "none"
	}
}

// ProtectedRule 表示一条已编译前校验的受保护路径规则及其所属安全区域/类别标签。
//
// 零值恒无效（IsValid() == false）。若通过 ParseProtectedRule 构造，Class 默认与规范化规则文本一致；
// 若通过 NewProtectedRule 构造，可为同区域多条规则赋予统一 Class，供 ApprovalFSM 精准判定
// Protected-A -> Protected-B 软链重定向升级。
//
//xops:opaque
//xops:failclosed
type ProtectedRule struct {
	canonical string
	class     string
	compiled  compiledProtectedRule
	valid     bool
}

// ParseProtectedRule 校验并编译单条受保护路径规则（Class 默认等于规范化规则文本）。
func ParseProtectedRule(pattern string) (ProtectedRule, error) {
	return NewProtectedRule(pattern, "")
}

// NewProtectedRule 校验并编译带显式区域/类别标签的受保护路径规则。
// 支持 POSIX 绝对规则（"/etc/**"、"/root"、"/etc/*.conf"）、Windows 盘符规则（"C:/Windows/**"、"C:\Windows\**"）、
// UNC 规则（"//server/share/**"）与全局递归规则（"**/.ssh/**"）；拒绝空串、相对裸路径与非法控制/Bidi 字符。
func NewProtectedRule(pattern, class string) (ProtectedRule, error) {
	if pattern == "" {
		return ProtectedRule{}, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "pattern"))
	}
	if len(pattern) > MaxRemotePathBytes {
		return ProtectedRule{}, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "pattern"), domi18n.Int("size", len(pattern)), domi18n.Int("limit", MaxRemotePathBytes))
	}
	if hasForbiddenPathText(pattern) {
		return ProtectedRule{}, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "pattern"))
	}
	if class != "" && hasForbiddenPathText(class) {
		return ProtectedRule{}, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "class"))
	}
	compiled, canonical, err := compileProtectedRule(norm.NFC.String(pattern))
	if err != nil {
		return ProtectedRule{}, err
	}
	effectiveClass := canonical
	if class != "" {
		effectiveClass = norm.NFC.String(class)
	}
	compiled.canonical = canonical
	compiled.class = effectiveClass
	return ProtectedRule{
		canonical: canonical,
		class:     effectiveClass,
		compiled:  compiled,
		valid:     true,
	}, nil
}

// IsValid 报告 ProtectedRule 是否有效。
func (r ProtectedRule) IsValid() bool { return r.valid }

// Canonical 返回经 NFC 与斜杠规范化后的规则文本；无效零值返回空串。
func (r ProtectedRule) Canonical() string { return r.canonical }

// Class 返回规则所属保护区域/类别标识；无效零值返回空串。
func (r ProtectedRule) Class() string { return r.class }

// ProtectedRuleMatch 记录单条命中的受保护路径规则摘要。
//
//xops:opaque
//xops:failclosed
type ProtectedRuleMatch struct {
	canonicalRule string
	class         string
	kind          MatchKind
}

// IsValid 报告命中记录是否有效（kind != MatchNone 且规则非空）。
func (m ProtectedRuleMatch) IsValid() bool {
	return m.kind != MatchNone && m.canonicalRule != ""
}

// CanonicalRule 返回命中的规范化规则文本。
func (m ProtectedRuleMatch) CanonicalRule() string { return m.canonicalRule }

// Class 返回命中规则的保护区域/类别标识。
func (m ProtectedRuleMatch) Class() string { return m.class }

// Kind 返回命中类别（MatchDirect 或 MatchAncestorContainsProtected）。
func (m ProtectedRuleMatch) Kind() MatchKind { return m.kind }

// ProtectedMatch 表示一次受保护路径匹配的确定性结果快照（全部命中规则按字典序排序且去重）。
//
// 零值恒无效（IsValid() == false）：在安全比较谓词 SameZones / IntroducesNewZoneOver 中遵循失败关闭原则。
//
//xops:opaque
//xops:failclosed
type ProtectedMatch struct {
	valid   bool
	matches []ProtectedRuleMatch
}

// IsValid 报告该匹配结果是否来自有效的 ProtectedPathMatcher 计算。
func (m ProtectedMatch) IsValid() bool { return m.valid }

// Matched 报告目标是否命中至少一条受保护路径规则。
func (m ProtectedMatch) Matched() bool { return m.valid && len(m.matches) > 0 }

// Rules 返回全部命中规则的确定性只读副本（按 Class、CanonicalRule、Kind 升序排列）。
func (m ProtectedMatch) Rules() []ProtectedRuleMatch {
	if !m.valid || len(m.matches) == 0 {
		return nil
	}
	return slices.Clone(m.matches)
}

// PrimaryRule 返回确定性首条命中规则（优先直接命中，其次按规范字典序）；未命中返回 (零值, false)。
func (m ProtectedMatch) PrimaryRule() (ProtectedRuleMatch, bool) {
	if !m.Matched() {
		return ProtectedRuleMatch{}, false
	}
	for _, r := range m.matches {
		if r.kind == MatchDirect {
			return r, true
		}
	}
	return m.matches[0], true
}

// Zones 返回去重且升序排列的命中保护区域（Class）集合。
func (m ProtectedMatch) Zones() []string {
	if !m.Matched() {
		return nil
	}
	zones := make([]string, 0, len(m.matches))
	for _, r := range m.matches {
		if len(zones) == 0 || zones[len(zones)-1] != r.class {
			zones = append(zones, r.class)
		}
	}
	return zones
}

// SameZones 判断两次有效匹配结果所命中的受保护区域集合是否完全一致；任一结果无效均失败关闭返回 false。
func (m ProtectedMatch) SameZones(other ProtectedMatch) bool {
	if !m.valid || !other.valid {
		return false
	}
	return equalStringSlice(m.Zones(), other.Zones())
}

// IntroducesNewZoneOver 判断当前（通常为规范化后）匹配结果是否相对 before（规范化前）引入了新的保护区域。
//
// 用于 ApprovalFSM 精确捕获“非受保护 -> 受保护”以及“Protected-A -> Protected-B”软链重定向升级；
// 若任一输入为无效零值，则严格失败关闭返回 true（视作发生范围升级）。
func (m ProtectedMatch) IntroducesNewZoneOver(before ProtectedMatch) bool {
	if !m.valid || !before.valid {
		return true
	}
	prevZones := before.Zones()
	for _, z := range m.Zones() {
		if !slices.Contains(prevZones, z) {
			return true
		}
	}
	return false
}

// ProtectedPathMatcher 是不可变的 OS 无关 UTF-8 受保护路径匹配器。
//
// 零值恒无效（IsValid() == false），调用 Match / MatchRecursive 会严格失败关闭返回错误。
//
//xops:opaque
//xops:failclosed
type ProtectedPathMatcher struct {
	valid bool
	rules []compiledProtectedRule
}

// NewProtectedPathMatcher 从一组受保护路径模式字符串构造不可变匹配器。
func NewProtectedPathMatcher(patterns []string) (ProtectedPathMatcher, error) {
	rules := make([]ProtectedRule, 0, len(patterns))
	for _, p := range patterns {
		r, err := ParseProtectedRule(p)
		if err != nil {
			return ProtectedPathMatcher{}, err
		}
		rules = append(rules, r)
	}
	return NewClassifiedProtectedPathMatcher(rules)
}

// NewClassifiedProtectedPathMatcher 从一组带显式区域/类别标签的 ProtectedRule 构造不可变匹配器。
func NewClassifiedProtectedPathMatcher(rules []ProtectedRule) (ProtectedPathMatcher, error) {
	compiled := make([]compiledProtectedRule, 0, len(rules))
	for _, r := range rules {
		if !r.IsValid() {
			return ProtectedPathMatcher{}, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "protected_rule"))
		}
		compiled = append(compiled, r.compiled)
	}
	slices.SortFunc(compiled, compareCompiledRule)
	compiled = deduplicateCompiledRules(compiled)
	return ProtectedPathMatcher{valid: true, rules: compiled}, nil
}

// IsValid 报告匹配器是否已合法构造。
func (m ProtectedPathMatcher) IsValid() bool { return m.valid }

// IsZero 报告匹配器是否为无效零值。
func (m ProtectedPathMatcher) IsZero() bool { return !m.valid }

// RuleCount 返回已编译并去重后的规则数量。
func (m ProtectedPathMatcher) RuleCount() int {
	if !m.valid {
		return 0
	}
	return len(m.rules)
}

// Match 判定单个路径目标是否直接命中任一受保护路径规则，并返回确定性命中集合。
// 匹配器未初始化或目标为空/含非法 UTF-8/控制/Bidi 字符时严格失败关闭返回错误。
func (m ProtectedPathMatcher) Match(target string) (ProtectedMatch, error) {
	return m.evaluate(target, false)
}

// MatchRemotePath 对已校验的 RemotePath 执行受保护路径直接匹配。
func (m ProtectedPathMatcher) MatchRemotePath(p RemotePath) (ProtectedMatch, error) {
	if !p.IsValid() {
		return ProtectedMatch{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "remote_path"))
	}
	return m.evaluate(p.clean, false)
}

// MatchRecursive 判定递归目录操作目标是否直接受保护，或其子树下包含受保护路径规则（祖先命中）。
func (m ProtectedPathMatcher) MatchRecursive(dir string) (ProtectedMatch, error) {
	return m.evaluate(dir, true)
}

func (m ProtectedPathMatcher) evaluate(target string, includeAncestors bool) (ProtectedMatch, error) {
	if !m.valid {
		return ProtectedMatch{}, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "protected_path_matcher"))
	}
	if target == "" || len(target) > MaxLocalPathBytes || hasForbiddenPathText(target) {
		return ProtectedMatch{}, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "target"), domi18n.BoundStr("value", target))
	}
	cands := extractMatchCandidates(norm.NFC.String(target))
	var hits []ProtectedRuleMatch
	for _, rule := range m.rules {
		best := bestRuleMatchKind(rule, cands, includeAncestors)
		if best != MatchNone {
			hits = append(hits, ProtectedRuleMatch{
				canonicalRule: rule.canonical,
				class:         rule.class,
				kind:          best,
			})
		}
	}
	slices.SortFunc(hits, compareRuleMatch)
	return ProtectedMatch{valid: true, matches: hits}, nil
}

func bestRuleMatchKind(rule compiledProtectedRule, cands []matchCandidate, includeAncestors bool) MatchKind {
	best := MatchNone
	for _, cand := range cands {
		k := rule.matchCandidate(cand, includeAncestors)
		if k == MatchDirect {
			return MatchDirect
		}
		if k == MatchAncestorContainsProtected && best == MatchNone {
			best = k
		}
	}
	return best
}

func compareCompiledRule(a, b compiledProtectedRule) int {
	if c := cmp.Compare(a.class, b.class); c != 0 {
		return c
	}
	return cmp.Compare(a.canonical, b.canonical)
}

func deduplicateCompiledRules(rules []compiledProtectedRule) []compiledProtectedRule {
	if len(rules) <= 1 {
		return rules
	}
	out := rules[:1]
	for _, r := range rules[1:] {
		last := out[len(out)-1]
		if last.class == r.class && last.canonical == r.canonical {
			continue
		}
		out = append(out, r)
	}
	return out
}

func compareRuleMatch(a, b ProtectedRuleMatch) int {
	if c := cmp.Compare(a.class, b.class); c != 0 {
		return c
	}
	if c := cmp.Compare(a.canonicalRule, b.canonicalRule); c != 0 {
		return c
	}
	return cmp.Compare(a.kind, b.kind)
}
