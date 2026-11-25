package openssh

import (
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
)

type aliasCandidate struct {
	alias      string
	sourceFile string
	origHost   option.OriginalHostSpec
}

// collectConcreteAliases 按遭遇序收集全部具体 Host 别名（排除通配符、否定模式与保留字 none）。
func collectConcreteAliases(root *parsedFile) []aliasCandidate {
	seen := make(map[string]bool)
	var out []aliasCandidate
	walkAliasesInFile(root, true, seen, &out)
	return out
}

func walkAliasesInFile(doc *parsedFile, inheritedActive bool, seen map[string]bool, out *[]aliasCandidate) {
	if doc == nil {
		return
	}
	// 无条件顶层区域内的 Include 均视为可见别名源；Host/Match 块内的条件 Include 不强行污染顶层别名。
	inTopSection := inheritedActive
	for _, stmt := range doc.stmts {
		switch stmt.kind {
		case stmtHost:
			inTopSection = false
			appendHostAliases(stmt, seen, out)
		case stmtMatch:
			inTopSection = false
		case stmtInclude:
			if inTopSection {
				for _, child := range stmt.included {
					walkAliasesInFile(child, true, seen, out)
				}
			}
		}
	}
}

func appendHostAliases(stmt configStmt, seen map[string]bool, out *[]aliasCandidate) {
	for _, pat := range stmt.patterns {
		if pat == "" || strings.HasPrefix(pat, "!") || hasGlobMeta(pat) || strings.EqualFold(pat, "none") || seen[pat] {
			continue
		}
		orig, err := option.ParseOriginalHost(pat)
		if err != nil {
			continue
		}
		seen[pat] = true
		*out = append(*out, aliasCandidate{alias: pat, sourceFile: stmt.file, origHost: orig})
	}
}

type evalContext struct {
	target    option.OriginalHostSpec
	endpoint  algebraic.Option[netaddr.Endpoint]
	localUser string
	layer     option.OptionLayer
}

// evaluateDocument 按遭遇序自上而下将所有命中的 Host / Match / Include 指令折叠进同一个 t4 OptionLayer（Plan §4 #8）：
//   - Pass 1 跳过 Match final 块并折叠所有常规 Host / Match / Include 指令；
//   - 若配置树包含 Match final 块，Pass 2 再自上而下仅折叠命中的 Match final 块至同一个 t4 OptionLayer；
//   - Match canonical 因不执行主机名规范化而恒失败关闭（false）。
func (s *ConfigSource) evaluateDocument(doc *parsedFile, target option.OriginalHostSpec, endpoint algebraic.Option[netaddr.Endpoint]) (option.OptionLayer, error) {
	localUser := ""
	if id, ok := s.localIdentity.Get(); ok {
		localUser = id.LocalUser()
	}
	ec := &evalContext{
		target:    target,
		endpoint:  endpoint,
		localUser: localUser,
		layer:     option.UnsetOptionLayer(),
	}
	if err := ec.evalFile(doc, true, false); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if doc != nil && doc.hasFinal {
		if err := ec.evalFile(doc, true, true); err != nil {
			return option.UnsetOptionLayer(), err
		}
	}
	return ec.layer, nil
}

func (ec *evalContext) evalFile(doc *parsedFile, parentActive, passFinal bool) error {
	if doc == nil {
		return nil
	}
	// Pass 2 仅对 Match final 块生效，顶层无条件指令已在 Pass 1 折叠，不得重复应用；
	// 顶层无条件 Include 仍须在 Pass 2 下钻，以确保被包含文件中的 Match final 块按遭遇序折叠。
	inHeader := parentActive
	active := parentActive && !passFinal
	for _, stmt := range doc.stmts {
		var err error
		inHeader, active, err = ec.evalStmt(stmt, parentActive, inHeader, active, passFinal)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ec *evalContext) evalStmt(stmt configStmt, parentActive, inHeader, active, passFinal bool) (bool, bool, error) {
	switch stmt.kind {
	case stmtHost:
		if passFinal {
			return false, false, nil
		}
		return false, parentActive && matchHostPatternList(ec.target.String(), stmt.patterns), nil
	case stmtMatch:
		return false, ec.evalMatchStmt(stmt, parentActive, passFinal), nil
	case stmtInclude:
		shouldDescend := active || (passFinal && inHeader)
		if !shouldDescend {
			return inHeader, active, nil
		}
		for _, child := range stmt.included {
			if err := ec.evalFile(child, true, passFinal); err != nil {
				return false, false, err
			}
		}
		return inHeader, active, nil
	case stmtDirective:
		if !active {
			return inHeader, active, nil
		}
		return inHeader, active, ec.applyDirective(stmt)
	default:
		return false, false, fmt.Errorf("%w: 未知语句类型 %d", ErrInvalidConfig, stmt.kind)
	}
}

func (ec *evalContext) evalMatchStmt(stmt configStmt, parentActive, passFinal bool) bool {
	if !parentActive || stmt.matchCanonical || stmt.matchFinal != passFinal {
		return false
	}
	return ec.evalMatchCriteria(stmt.patterns)
}

func (ec *evalContext) applyDirective(stmt configStmt) error {
	if _, known := option.CanonicalOptionKey(stmt.key); !known {
		// 跳过 core/domain/option 25 项核心注册表之外的合法 OpenSSH 扩展指令（如 AddKeysToAgent/Compression）。
		return nil
	}
	parsed, err := option.ParseOptionKV(stmt.key, stmt.rawVal)
	if err != nil {
		return fmt.Errorf("%w: %s:%d: %w", ErrInvalidConfig, stmt.file, stmt.line, err)
	}
	ec.layer = ec.layer.ApplyParsedOption(parsed)
	return nil
}

// validateMatchTokens 在解析期严格校验 Match 条件语法，拒绝畸形或存在安全绕过风险的写法：
//   - all 严禁带 ! 或 =，且禁止与其他条件组合（仅允许位于 canonical/final 修饰词之后并作为末尾词元）；
//   - canonical / final 严禁带 ! 或 =，且禁止裸写（必须跟随至少一个实质条件）；
//   - 任何带参条件缺少参数或参数为空均立即返回错误。
func validateMatchTokens(tokens []string) (hasFinal, hasCanonical bool, err error) {
	if len(tokens) == 0 {
		return false, false, fmt.Errorf("match 缺少条件")
	}
	criteriaCount := 0
	for i := 0; i < len(tokens); {
		kw, negated, inlineVal, hasEq := parseMatchKeyword(tokens[i])
		i++
		if kw == "" {
			return false, false, fmt.Errorf("match 条件关键字为空")
		}
		nextIdx, isFinal, isCanon, isCrit, stepErr := validateMatchStep(kw, negated, inlineVal, hasEq, tokens, i, criteriaCount)
		if stepErr != nil {
			return false, false, stepErr
		}
		hasFinal = hasFinal || isFinal
		hasCanonical = hasCanonical || isCanon
		if isCrit {
			criteriaCount++
		}
		i = nextIdx
	}
	if criteriaCount == 0 {
		return false, false, fmt.Errorf("match canonical/final 缺少后续匹配条件")
	}
	return hasFinal, hasCanonical, nil
}

func validateMatchStep(kw string, negated bool, inlineVal string, hasEq bool, tokens []string, idx, criteriaCount int) (nextIdx int, isFinal, isCanon, isCrit bool, err error) {
	switch kw {
	case "all":
		if negated || hasEq || criteriaCount > 0 || idx != len(tokens) {
			return idx, false, false, false, fmt.Errorf("match all 禁止取反、赋值或与其他条件混用")
		}
		return idx, false, false, true, nil
	case "canonical":
		if negated || hasEq || criteriaCount > 0 {
			return idx, false, false, false, fmt.Errorf("match canonical 禁止取反、赋值或置于其他条件之后")
		}
		return idx, false, true, false, nil
	case "final":
		if negated || hasEq || criteriaCount > 0 {
			return idx, false, false, false, fmt.Errorf("match final 禁止取反、赋值或置于其他条件之后")
		}
		return idx, true, false, false, nil
	default:
		_, afterIdx, ok := readMatchCriterionArg(tokens, idx, inlineVal, hasEq)
		if !ok {
			return afterIdx, false, false, false, fmt.Errorf("match 条件 %q 缺少有效参数", kw)
		}
		return afterIdx, false, false, true, nil
	}
}

func parseMatchKeyword(rawTok string) (kw string, negated bool, inlineVal string, hasEq bool) {
	negated = strings.HasPrefix(rawTok, "!")
	if negated {
		rawTok = rawTok[1:]
	}
	kw, inlineVal, hasEq = strings.Cut(rawTok, "=")
	return strings.ToLower(kw), negated, inlineVal, hasEq
}

func (ec *evalContext) evalMatchCriteria(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	for i := 0; i < len(tokens); {
		matched, nextIdx, done := ec.evalMatchToken(tokens, i)
		if !matched {
			return false
		}
		if done {
			return true
		}
		i = nextIdx
	}
	return true
}

func (ec *evalContext) evalMatchToken(tokens []string, idx int) (matched bool, nextIdx int, done bool) {
	kw, negated, inlineVal, hasEq := parseMatchKeyword(tokens[idx])
	idx++
	switch kw {
	case "all":
		return !hasEq && !negated && idx == len(tokens), idx, true
	case "canonical":
		// XOps v2 不执行 CanonicalizeHostname，canonical 块严格失败关闭。
		return false, idx, true
	case "final":
		// final 轮次控制已由 evalMatchStmt 强制分派，此处仅放行非取反无赋值修饰词并继续求值后续条件。
		return !hasEq && !negated && idx < len(tokens), idx, false
	}
	arg, afterIdx, ok := readMatchCriterionArg(tokens, idx, inlineVal, hasEq)
	if !ok {
		return false, afterIdx, true
	}
	res, supported := ec.evalSingleCriterion(kw, arg)
	if !supported {
		// 未知条件或 Match exec 即使带否定前缀（如 !exec）也必须严格失败关闭，绝不取反放行。
		return false, afterIdx, true
	}
	if negated {
		res = !res
	}
	return res, afterIdx, false
}

func readMatchCriterionArg(tokens []string, idx int, inlineVal string, hasEq bool) (string, int, bool) {
	if hasEq {
		return inlineVal, idx, inlineVal != ""
	}
	if idx >= len(tokens) {
		return "", idx, false
	}
	return tokens[idx], idx + 1, tokens[idx] != ""
}

func (ec *evalContext) evalSingleCriterion(kw, arg string) (matched, supported bool) {
	pats := strings.Split(arg, ",")
	switch kw {
	case "host":
		// OpenSSH match_cfg_line 对 Match host 与 Match originalhost 均执行大小写不敏感匹配。
		return matchHostPatternList(strings.ToLower(ec.currentEffectiveHost()), lowerStrings(pats)), true
	case "originalhost":
		return matchHostPatternList(strings.ToLower(ec.target.String()), lowerStrings(pats)), true
	case "user":
		u := ec.currentEffectiveUser()
		return u != "" && matchHostPatternList(u, pats), true
	case "localuser":
		return ec.localUser != "" && matchHostPatternList(ec.localUser, pats), true
	default:
		// 包含 Match exec 及一切未受控条件：严格失败关闭（绝不执行外部命令、绝不静默放行）。
		return false, false
	}
}

func lowerStrings(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func (ec *evalContext) currentEffectiveHost() string {
	if spec, ok := ec.layer.HostName().Get(); ok {
		if resolved, err := spec.ResolveHostFor(ec.target); err == nil {
			return resolved.String()
		}
		return spec.String()
	}
	if ep, ok := ec.endpoint.Get(); ok {
		return ep.Host().String()
	}
	return ec.target.String()
}

func (ec *evalContext) currentEffectiveUser() string {
	if u, ok := ec.layer.User().Get(); ok {
		return u.String()
	}
	return ec.localUser
}

// matchHostPatternList 实现 OpenSSH ssh_config(5) 模式列表语义：
// 至少命中一个正向模式且不命中任何否定模式（!pattern）时返回 true。
func matchHostPatternList(candidate string, patterns []string) bool {
	matchedPositive := false
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		if neg, isNeg := strings.CutPrefix(pat, "!"); isNeg {
			if matchOpenSSHWildcard(candidate, neg) {
				return false
			}
			continue
		}
		if matchOpenSSHWildcard(candidate, pat) {
			matchedPositive = true
		}
	}
	return matchedPositive
}

// matchOpenSSHWildcard 执行 O(|P|*|S|) 无回溯爆炸的 OpenSSH '*' / '?' 通配符匹配。
func matchOpenSSHWildcard(text, pattern string) bool {
	ti, pi, starIdx, matchIdx := 0, 0, -1, 0
	for ti < len(text) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
			ti, pi = ti+1, pi+1
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			starIdx, matchIdx, pi = pi, ti, pi+1
			continue
		}
		if starIdx >= 0 {
			pi, matchIdx = starIdx+1, matchIdx+1
			ti = matchIdx
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
