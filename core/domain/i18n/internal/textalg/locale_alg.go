package textalg

import "strings"

// MaxLocaleTagBytes 限制单条语言/区域标签的最大字节长度。
const MaxLocaleTagBytes = 64

// NormalizeLocaleCore 去除首尾空白、先剥离 @modifier 再剥离 .codeset，并将主体转为小写下划线形式。
func NormalizeLocaleCore(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > MaxLocaleTagBytes {
		return "", false
	}
	if before, mod, hasMod := strings.Cut(s, "@"); hasMod {
		if !IsValidLocaleSuffix(mod) {
			return "", false
		}
		s = before
	}
	if before, cs, hasCS := strings.Cut(s, "."); hasCS {
		if !IsValidLocaleSuffix(cs) {
			return "", false
		}
		s = before
	}
	if s == "" {
		return "", false
	}
	return strings.ReplaceAll(strings.ToLower(s), "-", "_"), true
}

// MatchNormalizedPrimary 校验归一化标签各子段均由非空小写 ASCII 字母数字构成，并返回主语言段。
func MatchNormalizedPrimary(norm string) (string, bool) {
	if !HasValidLocaleSubtags(norm) {
		return "", false
	}
	primary, _, _ := strings.Cut(norm, "_")
	return primary, true
}

// HasValidLocaleSubtags 校验归一化后的区域标签非空且每个 "_" 分段均由非空小写 ASCII 字母或数字构成。
func HasValidLocaleSubtags(norm string) bool {
	if norm == "" {
		return false
	}
	for sub := range strings.SplitSeq(norm, "_") {
		if !isASCIIAlnumNonEmpty(sub) {
			return false
		}
	}
	return true
}

// IsValidLocaleSuffix 校验 .codeset 与 @modifier 后缀，严格限定 POSIX 字符集 [A-Za-z0-9_-]。
func IsValidLocaleSuffix(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if !isAlpha && !isDigit && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isASCIIAlnumNonEmpty(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isLower && !isDigit {
			return false
		}
	}
	return true
}
