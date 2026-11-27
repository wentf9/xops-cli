package pathalg

import (
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

type compiledProtectedRule struct {
	canonical string
	class     string
	ns        pathNamespace
	drive     byte
	server    string
	share     string
	segs      []compiledGlobSeg
	isRootAll bool
}

type compiledGlobSeg struct {
	isDoubleStar bool
	raw          string
	tokens       []globToken
}

type globTokenKind uint8

const (
	globLiteral globTokenKind = iota
	globAny
	globStar
	globClass
)

type runeRange struct {
	lo rune
	hi rune
}

type globToken struct {
	kind    globTokenKind
	lit     rune
	negated bool
	ranges  []runeRange
}

func compileProtectedRule(nfcPattern string) (compiledProtectedRule, string, error) {
	ns, drive, server, share, rawSegs, err := parseProtectedRuleHeader(nfcPattern)
	if err != nil {
		return compiledProtectedRule{}, "", err
	}
	segs, hasWildcard, err := compileRuleSegments(rawSegs)
	if err != nil {
		return compiledProtectedRule{}, "", err
	}
	canonical := formatCanonicalRule(ns, drive, server, share, segs)
	// 无通配符的字面路径规则（如 "/etc"、"C:/Windows"）等价于匹配自身及其全部子树后代。
	if !hasWildcard {
		segs = append(segs, compiledGlobSeg{isDoubleStar: true, raw: "**"})
	}
	isRootAll := ns == nsPOSIX && (canonical == "/" || canonical == "/**")
	return compiledProtectedRule{
		ns:        ns,
		drive:     drive,
		server:    server,
		share:     share,
		segs:      segs,
		isRootAll: isRootAll,
	}, canonical, nil
}

func formatCanonicalRule(ns pathNamespace, drive byte, server, share string, segs []compiledGlobSeg) string {
	rawSegs := make([]string, len(segs))
	for i, s := range segs {
		rawSegs[i] = s.raw
	}
	joined := strings.Join(rawSegs, "/")
	switch ns {
	case nsUniversal:
		return joined
	case nsWinDrive:
		return string([]byte{drive, ':', '/'}) + joined
	case nsWinUNC:
		if joined == "" {
			return "//" + server + "/" + share
		}
		return "//" + server + "/" + share + "/" + joined
	case nsWinDevice:
		return "//./" + joined
	case nsPOSIX:
		return "/" + joined
	default:
		return ""
	}
}

func parseProtectedRuleHeader(nfcPattern string) (ns pathNamespace, drive byte, server, share string, segs []string, err error) {
	if strings.HasPrefix(nfcPattern, "**/") || nfcPattern == "**" {
		rawSegs := cleanRuleSegments(strings.ReplaceAll(nfcPattern, "\\", "/"))
		return nsUniversal, 0, "", "", rawSegs, nil
	}
	if spec, ok := parseWin32HeaderSpec(nfcPattern); ok {
		return finalizeWin32RuleHeader(nfcPattern, spec)
	}
	if strings.HasPrefix(nfcPattern, "/") {
		cleaned := path.Clean(nfcPattern)
		rawSegs := splitCleanAbsSegments(cleaned)
		return nsPOSIX, 0, "", "", rawSegs, nil
	}
	return nsInvalid, 0, "", "", nil, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "pattern"), domi18n.BoundStr("value", nfcPattern))
}

func finalizeWin32RuleHeader(nfcPattern string, spec win32HeaderSpec) (pathNamespace, byte, string, string, []string, error) {
	rawSegs := cleanRuleSegments(strings.ReplaceAll(spec.rest, "\\", "/"))
	switch spec.ns {
	case nsWinDrive:
		return nsWinDrive, spec.drive, "", "", rawSegs, nil
	case nsWinUNC:
		if spec.share == "" {
			return nsInvalid, 0, "", "", nil, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "unc_rule"), domi18n.BoundStr("value", nfcPattern))
		}
		return nsWinUNC, 0, spec.server, spec.share, rawSegs, nil
	case nsWinDevice:
		if len(rawSegs) == 0 {
			return nsInvalid, 0, "", "", nil, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "win32_device_rule"), domi18n.BoundStr("value", nfcPattern))
		}
		return nsWinDevice, 0, "", "", rawSegs, nil
	default:
		return nsInvalid, 0, "", "", nil, domi18n.EF(ErrInvalidProtectedRule, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "win32_rule"), domi18n.BoundStr("value", nfcPattern))
	}
}

func cleanRuleSegments(rest string) []string {
	cleaned := path.Clean("/" + rest)
	return splitCleanAbsSegments(cleaned)
}

func compileRuleSegments(rawSegs []string) ([]compiledGlobSeg, bool, error) {
	segs := make([]compiledGlobSeg, 0, len(rawSegs))
	hasWildcard := false
	for _, raw := range rawSegs {
		if raw == "**" {
			hasWildcard = true
			if len(segs) == 0 || !segs[len(segs)-1].isDoubleStar {
				segs = append(segs, compiledGlobSeg{isDoubleStar: true, raw: "**"})
			}
			continue
		}
		tokens, segWild, err := parseSegmentGlob(raw)
		if err != nil {
			return nil, false, domi18n.WrapSentinel(ErrInvalidProtectedRule, err)
		}
		hasWildcard = hasWildcard || segWild
		segs = append(segs, compiledGlobSeg{raw: raw, tokens: tokens})
	}
	return segs, hasWildcard, nil
}

func (r compiledProtectedRule) matchCandidate(cand matchCandidate, includeAncestors bool) MatchKind {
	if r.isRootAll {
		if cand.ns == nsPOSIX || cand.ns == nsWinDrive || cand.ns == nsWinUNC || cand.ns == nsWinDevice {
			return MatchDirect
		}
		return MatchNone
	}
	caseFold, ok := r.namespaceCompatible(cand)
	if !ok {
		return MatchNone
	}
	direct, ancestor := matchSegmentDP(r.segs, cand.segs, caseFold)
	if direct {
		return MatchDirect
	}
	if includeAncestors && ancestor {
		return MatchAncestorContainsProtected
	}
	return MatchNone
}

func (r compiledProtectedRule) namespaceCompatible(cand matchCandidate) (caseFold, ok bool) {
	switch r.ns {
	case nsUniversal:
		return cand.ns == nsWinDrive || cand.ns == nsWinUNC || cand.ns == nsWinDevice, true
	case nsPOSIX:
		return false, cand.ns == nsPOSIX
	case nsWinDrive:
		return true, cand.ns == nsWinDrive && r.drive == cand.drive
	case nsWinUNC:
		return true, cand.ns == nsWinUNC && r.server == cand.server && r.share == cand.share
	case nsWinDevice:
		return true, cand.ns == nsWinDevice
	default:
		return false, false
	}
}

// matchSegmentDP 以 O(|ruleSegs| * |targetSegs|) 动态规划同时判定精确/通配直接命中与祖先前缀命中。
func matchSegmentDP(ruleSegs []compiledGlobSeg, targetSegs []string, caseFold bool) (direct, ancestor bool) {
	n := len(ruleSegs)
	dp := make([]bool, n+1)
	dp[0] = true
	propagateDoubleStar(ruleSegs, dp)

	for _, seg := range targetSegs {
		next := stepSegmentDP(ruleSegs, dp, seg, caseFold)
		propagateDoubleStar(ruleSegs, next)
		dp = next
	}
	if dp[n] {
		return true, false
	}
	for i := range n {
		if dp[i] {
			return false, true
		}
	}
	return false, false
}

func stepSegmentDP(ruleSegs []compiledGlobSeg, prev []bool, seg string, caseFold bool) []bool {
	next := make([]bool, len(ruleSegs)+1)
	for i, rs := range ruleSegs {
		if rs.isDoubleStar {
			if prev[i] || prev[i+1] {
				next[i+1] = true
			}
			continue
		}
		if prev[i] && matchGlobTokens(rs.tokens, seg, caseFold) {
			next[i+1] = true
		}
	}
	return next
}

func propagateDoubleStar(ruleSegs []compiledGlobSeg, dp []bool) {
	for i, seg := range ruleSegs {
		if dp[i] && seg.isDoubleStar {
			dp[i+1] = true
		}
	}
}

func parseSegmentGlob(pattern string) ([]globToken, bool, error) {
	if !utf8.ValidString(pattern) {
		return nil, false, domi18n.EF(ErrInvalidGlob, domi18n.KeyCommonInvalidUTF8)
	}
	runes := []rune(pattern)
	tokens := make([]globToken, 0, len(runes))
	hasWildcard := false
	for i := 0; i < len(runes); {
		switch runes[i] {
		case '*':
			hasWildcard = true
			if len(tokens) == 0 || tokens[len(tokens)-1].kind != globStar {
				tokens = append(tokens, globToken{kind: globStar})
			}
			i++
		case '?':
			hasWildcard = true
			tokens = append(tokens, globToken{kind: globAny})
			i++
		case '[':
			hasWildcard = true
			tok, next, err := parseCharClass(runes, i+1)
			if err != nil {
				return nil, false, err
			}
			tokens = append(tokens, tok)
			i = next
		default:
			tokens = append(tokens, globToken{kind: globLiteral, lit: runes[i]})
			i++
		}
	}
	return tokens, hasWildcard, nil
}

func parseCharClass(runes []rune, start int) (globToken, int, error) {
	i := start
	if i >= len(runes) {
		return globToken{}, 0, domi18n.EF(ErrInvalidGlob, domi18n.KeyPathalgGlobUnclosed)
	}
	negated := false
	if runes[i] == '^' || runes[i] == '!' {
		negated = true
		i++
	}
	var ranges []runeRange
	for i < len(runes) {
		if runes[i] == ']' && len(ranges) > 0 {
			return globToken{kind: globClass, negated: negated, ranges: ranges}, i + 1, nil
		}
		lo := runes[i]
		i++
		if i+1 < len(runes) && runes[i] == '-' && runes[i+1] != ']' {
			hi := runes[i+1]
			if hi < lo {
				return globToken{}, 0, domi18n.EF(ErrInvalidGlob, domi18n.KeyPathalgGlobRangeInvalid, domi18n.Str("lo", string(lo)), domi18n.Str("hi", string(hi)))
			}
			ranges = append(ranges, runeRange{lo: lo, hi: hi})
			i += 2
			continue
		}
		ranges = append(ranges, runeRange{lo: lo, hi: lo})
	}
	return globToken{}, 0, domi18n.EF(ErrInvalidGlob, domi18n.KeyPathalgGlobUnclosed)
}

// matchGlobTokens 在单段 UTF-8 码点序列上执行 O(|tokens| * |seg|) 双指针迭代通配匹配。
func matchGlobTokens(tokens []globToken, seg string, caseFold bool) bool {
	rs := []rune(seg)
	ti, si := 0, 0
	starTi, starSi := -1, 0
	for si < len(rs) {
		if ti < len(tokens) && tokens[ti].kind == globStar {
			starTi, starSi = ti, si
			ti++
			continue
		}
		if ti < len(tokens) && tokens[ti].matchesRune(rs[si], caseFold) {
			ti++
			si++
			continue
		}
		if starTi >= 0 {
			starSi++
			si = starSi
			ti = starTi + 1
			continue
		}
		return false
	}
	for ti < len(tokens) && tokens[ti].kind == globStar {
		ti++
	}
	return ti == len(tokens)
}

func (t globToken) matchesRune(r rune, caseFold bool) bool {
	switch t.kind {
	case globAny:
		return true
	case globLiteral:
		return runesEqual(r, t.lit, caseFold)
	case globClass:
		matched := matchesRuneRanges(r, t.ranges, caseFold)
		if t.negated {
			return !matched
		}
		return matched
	default:
		return false
	}
}

func matchesRuneRanges(r rune, ranges []runeRange, caseFold bool) bool {
	for _, rg := range ranges {
		if runeInRange(r, rg, caseFold) {
			return true
		}
	}
	return false
}

func runesEqual(a, b rune, caseFold bool) bool {
	if a == b {
		return true
	}
	return caseFold && canonicalSimpleFoldRune(a) == canonicalSimpleFoldRune(b)
}

func runeInRange(r rune, rg runeRange, caseFold bool) bool {
	if r >= rg.lo && r <= rg.hi {
		return true
	}
	if !caseFold {
		return false
	}
	for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
		if next >= rg.lo && next <= rg.hi {
			return true
		}
	}
	return false
}
