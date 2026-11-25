package option

import (
	"fmt"
	"slices"
	"strings"
)

// EnvFilter 表示 OpenSSH SendEnv 模式列表及 -PATTERN 减法语义的结合律幺半群。
// 正规形式 (clear, added) 在 Compose(higher, lower) 下先应用 lower 再应用 higher，满足结合律与单位元律。
//
//xops:opaque
//xops:failclosed
type EnvFilter struct {
	clear, added []string
}

// UnsetEnvFilter 返回单位元（零值）。
func UnsetEnvFilter() EnvFilter { return EnvFilter{} }

// ParseEnvFilter 解析空白分隔的一条或多条 SendEnv 模式（支持 PATTERN 与 -PATTERN）。
func ParseEnvFilter(raw string) (EnvFilter, error) {
	fields := strings.Fields(raw)
	if hasForbiddenControlChar(raw) || len(fields) == 0 {
		return EnvFilter{}, fmt.Errorf("%w: SendEnv 规则含控制字符或为空", ErrInvalidEnvFilter)
	}
	return ParseEnvFilterTokens(fields)
}

// ParseEnvFilterTokens 按序应用 SendEnv 令牌序列构造规范 EnvFilter。
func ParseEnvFilterTokens(tokens []string) (EnvFilter, error) {
	var clearSet, added []string
	for _, tok := range tokens {
		if hasAnySpaceOrControl(tok) || tok == "" {
			return EnvFilter{}, fmt.Errorf("%w: 非法 SendEnv 令牌 %q", ErrInvalidEnvFilter, tok)
		}
		if pat, isSub := strings.CutPrefix(tok, "-"); isSub {
			if !isValidEnvPattern(pat) {
				return EnvFilter{}, fmt.Errorf("%w: 非法减法模式 %q", ErrInvalidEnvFilter, tok)
			}
			clearSet, added = appendUniqueStrings(clearSet, []string{pat}), filterOutMatchedPatterns(added, []string{pat})
			continue
		}
		if !isValidEnvPattern(tok) {
			return EnvFilter{}, fmt.Errorf("%w: 非法模式 %q", ErrInvalidEnvFilter, tok)
		}
		added = appendUniqueStrings(added, []string{tok})
	}
	slices.Sort(clearSet)
	return EnvFilter{nilIfEmpty(clearSet), nilIfEmpty(added)}, nil
}

func isValidEnvPattern(pat string) bool {
	return len(pat) > 0 && len(pat) <= maxTokenLen && strings.IndexFunc(pat, func(r rune) bool {
		return r > 127 || (!isASCIIAlphaNum(byte(r)) && r != '_' && r != '*' && r != '?')
	}) < 0
}

// EnvFilter 只读访问器、折叠、匹配与筛选方法。
func (f EnvFilter) IsUnset() bool           { return len(f.clear) == 0 && len(f.added) == 0 }
func (f EnvFilter) IsZero() bool            { return f.IsUnset() }
func (f EnvFilter) Patterns() []string      { return slices.Clone(f.added) }
func (f EnvFilter) ClearPatterns() []string { return slices.Clone(f.clear) }
func (f EnvFilter) Equal(o EnvFilter) bool {
	return slices.Equal(f.clear, o.clear) && slices.Equal(f.added, o.added)
}
func (f EnvFilter) clone() EnvFilter { return EnvFilter{slices.Clone(f.clear), slices.Clone(f.added)} }
func FoldEnvFilters(layers ...EnvFilter) EnvFilter {
	return foldMonoid(UnsetEnvFilter(), EnvFilter.Compose, layers)
}
func (f EnvFilter) Match(envName string) bool {
	return isValidEnvName(envName) && len(f.added) > 0 && matchesAnyWildcard(envName, f.added)
}
func (f EnvFilter) FilterNames(names []string) []string {
	return nilIfEmpty(slices.DeleteFunc(slices.Clone(names), func(n string) bool { return !f.Match(n) }))
}
func (f EnvFilter) FilterSorted(env map[string]string) []string {
	var keys []string
	for k := range env {
		if f.Match(k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}
func (f EnvFilter) Filter(env map[string]string) map[string]string {
	keys := f.FilterSorted(env)
	if len(keys) == 0 {
		return nil
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = env[k]
	}
	return out
}

// Compose 执行高优先级 f 覆合低优先级 lower 的幺半群运算（先 lower 后 f）。
func (f EnvFilter) Compose(lower EnvFilter) EnvFilter {
	if f.IsUnset() {
		return lower.clone()
	}
	if lower.IsUnset() {
		return f.clone()
	}
	return EnvFilter{
		nilIfEmpty(unionSortedStrings(lower.clear, f.clear)),
		nilIfEmpty(appendUniqueStrings(filterOutMatchedPatterns(lower.added, f.clear), f.added)),
	}
}

func filterOutMatchedPatterns(patterns, clearSet []string) []string {
	if len(patterns) == 0 || len(clearSet) == 0 {
		return slices.Clone(patterns)
	}
	return nilIfEmpty(slices.DeleteFunc(slices.Clone(patterns), func(p string) bool { return matchesAnyWildcard(p, clearSet) }))
}

func matchesAnyWildcard(text string, patterns []string) bool {
	return slices.ContainsFunc(patterns, func(pat string) bool { return matchASCIIWildcard(text, pat) })
}

func matchASCIIWildcard(text, pattern string) bool {
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
