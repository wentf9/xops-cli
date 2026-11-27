package security

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const (
	globLiteral uint8 = iota
	globAny
	globStar
	globClass
)

type runeRange struct{ lo, hi rune }

type globToken struct {
	kind    uint8
	lit     rune
	negated bool
	ranges  []runeRange
}

func (t globToken) matchesRune(r rune) bool {
	switch t.kind {
	case globAny:
		return true
	case globLiteral:
		return r == t.lit
	case globClass:
		return slices.ContainsFunc(t.ranges, func(rg runeRange) bool { return r >= rg.lo && r <= rg.hi }) != t.negated
	default:
		return false
	}
}

// ValidateGlob 校验操作系统无关的护栏 UTF-8 通配符模式语法，
// 拒绝空串、非法 UTF-8、控制字符、Unicode Cf（含 Bidi 双向控制与零宽字符）以及畸形字符类。
func ValidateGlob(pattern string) error { _, err := compileGlob(pattern); return err }

// MatchGlob 使用操作系统无关的 O(|P|*|S|) UTF-8 码点引擎执行通配符匹配（INV-E3）：
// '*' 跨 '/'、'\' 与换行匹配任意序列，'?' 匹配单码点，'[...]' 支持取反与范围，'\' 恒为字面字符。
func MatchGlob(pattern, target string) (bool, error) {
	if !utf8.ValidString(target) {
		return false, domi18n.EF(ErrInvalidGlob, domi18n.KeyCommonInvalidUTF8)
	}
	tokens, err := compileGlob(pattern)
	if err != nil {
		return false, err
	}
	return matchCompiledGlob(tokens, []rune(target)), nil
}

func matchCompiledGlob(tokens []globToken, rs []rune) bool {
	ti, si, starTi, starSi := 0, 0, -1, 0
	for si < len(rs) {
		switch {
		case ti < len(tokens) && tokens[ti].kind == globStar:
			starTi, starSi, ti = ti, si, ti+1
		case ti < len(tokens) && tokens[ti].matchesRune(rs[si]):
			ti, si = ti+1, si+1
		case starTi >= 0:
			starSi++
			si, ti = starSi, starTi+1
		default:
			return false
		}
	}
	for ti < len(tokens) && tokens[ti].kind == globStar {
		ti++
	}
	return ti == len(tokens)
}

func compileGlob(pattern string) ([]globToken, error) {
	if pattern == "" || hasInvalidUTF8OrControl(pattern) {
		return nil, domi18n.EF(ErrInvalidGlob, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "pattern"))
	}
	runes := []rune(pattern)
	tokens := make([]globToken, 0, len(runes))
	for i := 0; i < len(runes); {
		tok, next, err := parseNextGlobToken(runes, i)
		if err != nil {
			return nil, err
		}
		if tok.kind != globStar || len(tokens) == 0 || tokens[len(tokens)-1].kind != globStar {
			tokens = append(tokens, tok)
		}
		i = next
	}
	return tokens, nil
}

func parseNextGlobToken(runes []rune, idx int) (globToken, int, error) {
	switch runes[idx] {
	case '*':
		return globToken{kind: globStar}, idx + 1, nil
	case '?':
		return globToken{kind: globAny}, idx + 1, nil
	case '[':
		return parseGlobCharClass(runes, idx+1)
	default:
		return globToken{kind: globLiteral, lit: runes[idx]}, idx + 1, nil
	}
}

func parseGlobCharClass(runes []rune, i int) (globToken, int, error) {
	if i >= len(runes) {
		return globToken{}, 0, domi18n.EF(ErrInvalidGlob, domi18n.KeyPathalgGlobUnclosed)
	}
	negated := runes[i] == '^' || runes[i] == '!'
	if negated {
		i++
	}
	var ranges []runeRange
	for i < len(runes) {
		if runes[i] == ']' && len(ranges) > 0 {
			return globToken{kind: globClass, negated: negated, ranges: ranges}, i + 1, nil
		}
		rg, next, err := parseGlobRuneRange(runes, i)
		if err != nil {
			return globToken{}, 0, err
		}
		ranges, i = append(ranges, rg), next
	}
	return globToken{}, 0, domi18n.EF(ErrInvalidGlob, domi18n.KeyPathalgGlobUnclosed)
}

func parseGlobRuneRange(runes []rune, idx int) (runeRange, int, error) {
	lo := runes[idx]
	if idx+2 < len(runes) && runes[idx+1] == '-' && runes[idx+2] != ']' {
		hi := runes[idx+2]
		if hi < lo {
			return runeRange{}, 0, domi18n.EF(ErrInvalidGlob, domi18n.KeyPathalgGlobRangeInvalid, domi18n.BoundStr("lo", string(lo)), domi18n.BoundStr("hi", string(hi)))
		}
		return runeRange{lo: lo, hi: hi}, idx + 3, nil
	}
	return runeRange{lo: lo, hi: lo}, idx + 1, nil
}

// SanitizePromptText 将 C0/DEL/C1 控制字符、Unicode 行/段分隔符（U+2028/U+2029）、
// Unicode Cf 格式字符（含 Bidi 覆写/隔离与零宽字符）转义为可打印 ASCII 序列，
// 并将非法 UTF-8 原始字节显式转义为 \xHH，抵御审批提示伪造与 Trojan-Source 视觉欺骗。
func SanitizePromptText(raw string) string {
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRuneInString(raw[i:])
		if r == utf8.RuneError && size == 1 {
			v := raw[i]
			b.Write([]byte{'\\', 'x', hexDigits[v>>4], hexDigits[v&0x0f]})
			i++
			continue
		}
		if isForbiddenFormatOrControl(r) {
			quoted := strconv.QuoteRuneToASCII(r)
			b.WriteString(quoted[1 : len(quoted)-1])
		} else {
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

func isForbiddenFormatOrControl(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

func hasInvalidUTF8OrControl(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, isForbiddenFormatOrControl)
}
