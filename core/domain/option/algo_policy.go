package option

import (
	"slices"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// AlgoOp 表示单条 OpenSSH 算法指令的列表算子类型；零值 AlgoOpUnset 代表幺半群单位元（未设置）。
//
//xops:failclosed
type AlgoOp uint8

const (
	AlgoOpUnset   AlgoOp = iota // 未设置（FirstWins 单位元，回退默认列表）
	AlgoOpExact                 // 精确替换默认列表
	AlgoOpAppend                // 追加至默认列表末尾（+）
	AlgoOpRemove                // 从默认列表移除匹配项，独占支持 */? 通配符（-）
	AlgoOpPrepend               // 前置至默认列表头部（^）
)

// IsSet 与 String 返回 AlgoOp 状态与规范名称。
func (o AlgoOp) IsSet() bool { return o >= AlgoOpExact && o <= AlgoOpPrepend }
func (o AlgoOp) String() string {
	return enumNameOr(uint8(o)+1, "invalid", "unset", "exact", "append", "remove", "prepend")
}

// AlgoPolicy 表示校准后的 OpenSSH 算法列表策略：
// 单条指令表达列表算子 Unset | Exact | Append(+) | Remove(-, 独占支持 */? 通配) | Prepend(^)，
// 跨指令与跨层合并严格遵循 FirstWins 幺半群（非 Unset 左吸收低层），仅在求解边界对默认集单次 Apply。
//
//xops:opaque
//xops:failclosed
type AlgoPolicy struct {
	op     AlgoOp
	tokens []string
}

// UnsetAlgoPolicy 与 IdentityAlgoPolicy 均返回未设置单位元（零值）。
func UnsetAlgoPolicy() AlgoPolicy    { return AlgoPolicy{} }
func IdentityAlgoPolicy() AlgoPolicy { return AlgoPolicy{} }

// ParseAlgoPolicy 解析单条 OpenSSH 算法策略（"a,b"、"+a,b"、"-a,*-cbc"、"^a,b"）。
// 仅当算子为 AlgoOpRemove（'-'）时允许 ASCII '*' 与 '?' 通配符；Exact/Append/Prepend 严格禁止通配符。
func ParseAlgoPolicy(raw string) (AlgoPolicy, error) {
	t := strings.TrimSpace(raw)
	if hasForbiddenControlChar(raw) || t == "" {
		return AlgoPolicy{}, domi18n.EF(ErrInvalidAlgoPolicy, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "algo_policy"), domi18n.BoundStr("value", raw))
	}
	op, body := AlgoOpExact, t
	if idx := strings.IndexByte("+-^", t[0]); idx >= 0 {
		op, body = [3]AlgoOp{AlgoOpAppend, AlgoOpRemove, AlgoOpPrepend}[idx], t[1:]
		if strings.TrimSpace(body) == "" {
			return AlgoPolicy{}, domi18n.EF(ErrInvalidAlgoPolicy, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "algo_modifier"), domi18n.BoundStr("value", t[:1]))
		}
	}
	var tokens []string
	for part := range strings.SplitSeq(body, ",") {
		tok := strings.TrimSpace(part)
		if !isValidAlgoEntry(tok, op == AlgoOpRemove) {
			return AlgoPolicy{}, domi18n.EF(ErrInvalidAlgoPolicy, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "algorithm"), domi18n.BoundStr("value", tok))
		}
		tokens = appendUniqueStrings(tokens, []string{tok})
	}
	return AlgoPolicy{op: op, tokens: tokens}, nil
}

func isValidAlgoEntry(tok string, allowWildcard bool) bool {
	if len(tok) == 0 || len(tok) > maxAlgoNameLen ||
		(!isASCIIAlphaNum(tok[0]) && (!allowWildcard || (tok[0] != '*' && tok[0] != '?'))) {
		return false
	}
	return strings.IndexFunc(tok[1:], func(r rune) bool {
		if r > 127 {
			return true
		}
		b := byte(r)
		return !isASCIIAlphaNum(b) && b != '-' && b != '_' && b != '.' && b != '@' && (!allowWildcard || (b != '*' && b != '?'))
	}) < 0
}

// AlgoPolicy 只读访问器、FirstWins 复合、折叠、单次求解与字符串表示。
func (p AlgoPolicy) Op() AlgoOp              { return p.op }
func (p AlgoPolicy) Tokens() []string        { return slices.Clone(p.tokens) }
func (p AlgoPolicy) IsUnset() bool           { return p.op == AlgoOpUnset }
func (p AlgoPolicy) IsIdentity() bool        { return p.op == AlgoOpUnset }
func (p AlgoPolicy) IsZero() bool            { return p.op == AlgoOpUnset }
func (p AlgoPolicy) IsExact() bool           { return p.op == AlgoOpExact }
func (p AlgoPolicy) clone() AlgoPolicy       { return AlgoPolicy{p.op, slices.Clone(p.tokens)} }
func (p AlgoPolicy) Equal(o AlgoPolicy) bool { return p.op == o.op && slices.Equal(p.tokens, o.tokens) }
func FoldAlgoPolicies(layers ...AlgoPolicy) AlgoPolicy {
	return foldMonoid(UnsetAlgoPolicy(), AlgoPolicy.Compose, layers)
}
func (p AlgoPolicy) Compose(lower AlgoPolicy) AlgoPolicy {
	if p.op == AlgoOpUnset {
		return lower.clone()
	}
	return p.clone()
}
func (p AlgoPolicy) Transform(defaults []string) []string {
	switch p.op {
	case AlgoOpUnset:
		return appendUniqueStrings(nil, defaults)
	case AlgoOpExact:
		return slices.Clone(p.tokens)
	case AlgoOpAppend:
		return appendUniqueStrings(appendUniqueStrings(nil, defaults), p.tokens)
	case AlgoOpRemove:
		var out []string
		for _, tok := range defaults {
			if tok != "" && !matchesAnyWildcard(tok, p.tokens) && !slices.Contains(out, tok) {
				out = append(out, tok)
			}
		}
		return out
	case AlgoOpPrepend:
		return appendUniqueStrings(slices.Clone(p.tokens), defaults)
	default:
		return nil
	}
}
func (p AlgoPolicy) Apply(defaults []string) ([]string, error) {
	if resolved := p.Transform(defaults); len(resolved) > 0 {
		return resolved, nil
	}
	return nil, ErrEmptyAlgorithmList
}
func (p AlgoPolicy) String() string {
	if p.op.IsSet() {
		return [5]string{"", "", "+", "-", "^"}[p.op] + strings.Join(p.tokens, ",")
	}
	return ""
}

func validateAlgoSlice(in []string, allowWildcard bool) ([]string, error) {
	var out []string
	for _, tok := range in {
		if !isValidAlgoEntry(tok, allowWildcard) {
			return nil, domi18n.EF(ErrInvalidAlgoPolicy, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "algorithm"), domi18n.BoundStr("value", tok))
		}
		out = appendUniqueStrings(out, []string{tok})
	}
	return out, nil
}
func appendUniqueStrings(dst, src []string) []string {
	for _, s := range src {
		if s != "" && !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}
func unionSortedStrings(a, b []string) []string {
	out := appendUniqueStrings(slices.Clone(a), b)
	slices.Sort(out)
	return out
}
func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
