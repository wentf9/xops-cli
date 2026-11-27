package i18n

import (
	"cmp"
	"strings"
)

const maxLocaleTagBytes = 64

// Locale 表示 XOps v2 支持的不可变界面语言标识；零值 LocaleInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Locale uint8

const (
	// LocaleInvalid 表示未初始化或非法的语言标识（零值失败关闭）。
	LocaleInvalid Locale = 0
	// LocaleEn 表示英文（规范兜底与默认回退语种）。
	LocaleEn Locale = 1
	// LocaleZh 表示简体中文（所有 zh* 变体如 zh-CN/zh-Hans/zh-TW/zh-Hant 均显式归并至此）。
	LocaleZh Locale = 2
)

// IsValid 报告 l 是否为已定义的合法语言标识。
func (l Locale) IsValid() bool {
	return l == LocaleEn || l == LocaleZh
}

// IsZero 报告 l 是否为零值无效态（LocaleInvalid）。
func (l Locale) IsZero() bool {
	return l == LocaleInvalid
}

// String 返回规范小写 BCP-47 语种代码（"en"、"zh"）；无效值返回 "invalid"。
func (l Locale) String() string {
	switch l {
	case LocaleEn:
		return "en"
	case LocaleZh:
		return "zh"
	default:
		return "invalid"
	}
}

// Compare 定义 Locale 的确定性全序（非法值 < LocaleEn < LocaleZh）。
func (l Locale) Compare(other Locale) int {
	return cmp.Compare(l.canonicalOrder(), other.canonicalOrder())
}

// Next 返回交互式语言切换（如 TUI L 快捷键）的下一个确定性有效语种：
// LocaleEn <-> LocaleZh；无效或越界值安全回退为 LocaleEn。
func (l Locale) Next() Locale {
	if l == LocaleEn {
		return LocaleZh
	}
	return LocaleEn
}

func (l Locale) canonicalOrder() uint8 {
	if l.IsValid() {
		return uint8(l)
	}
	return 0
}

// ParseLocale 严格解析显式指定的语言标签（供 --lang 等 CLI 参数使用）。
// 仅接受已支持的 en* / zh* 标签，拒绝 "C"、"POSIX"、空串或未知标签，失败时返回包装 ErrInvalidLocale 的结构化错误。
func ParseLocale(raw string) (Locale, error) {
	loc, ok := parseKnownLocale(raw)
	if !ok {
		return LocaleInvalid, EF(ErrInvalidLocale, KeyLocaleInvalidValue, Str("value", BoundDisplayText(raw, maxLocaleTagBytes)))
	}
	return loc, nil
}

// MatchEnvLocale 解析环境变量或操作系统区域标签，遵循 POSIX 优先级语义：
//   - 纯空白串返回 (LocaleInvalid, false)，允许调用方继续回退下一优先级变量；
//   - 剥离 @modifier 与 .codeset 后若为 "c" 或 "posix"，显式返回 (LocaleEn, true)（阻断更低优先级变量）；
//   - 命中已知 en* / zh* 标签返回对应语种与 true；
//   - 其余非空未支持或畸形标签返回 (LocaleEn, true)（阻断继续穿透并回退默认英文）。
func MatchEnvLocale(raw string) (Locale, bool) {
	if strings.TrimSpace(raw) == "" {
		return LocaleInvalid, false
	}
	norm, ok := normalizeLocaleCore(raw)
	if !ok {
		return LocaleEn, true
	}
	if norm == "c" || norm == "posix" {
		return LocaleEn, true
	}
	if loc, matched := matchNormalizedLocale(norm); matched {
		return loc, true
	}
	return LocaleEn, true
}

// ResolveLocale 按优先级顺序依次评估候选区域标签，首个命中 MatchEnvLocale 的结果生效；
// 全为空白或未传入标签时回退 LocaleEn。
func ResolveLocale(tags ...string) Locale {
	for _, tag := range tags {
		if loc, ok := MatchEnvLocale(tag); ok {
			return loc
		}
	}
	return LocaleEn
}

// parseKnownLocale 是 ParseLocale 与 MatchEnvLocale 共享的无错解析核心（遵守 failclosed/error_swallow）。
func parseKnownLocale(raw string) (Locale, bool) {
	norm, ok := normalizeLocaleCore(raw)
	if !ok {
		return LocaleInvalid, false
	}
	return matchNormalizedLocale(norm)
}

// normalizeLocaleCore 去除首尾空白、先剥离 @modifier 再剥离 .codeset，并将主体转为小写下划线形式。
func normalizeLocaleCore(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > maxLocaleTagBytes {
		return "", false
	}
	if before, mod, hasMod := strings.Cut(s, "@"); hasMod {
		if !isValidLocaleSuffix(mod) {
			return "", false
		}
		s = before
	}
	if before, cs, hasCS := strings.Cut(s, "."); hasCS {
		if !isValidLocaleSuffix(cs) {
			return "", false
		}
		s = before
	}
	if s == "" {
		return "", false
	}
	return strings.ReplaceAll(strings.ToLower(s), "-", "_"), true
}

// matchNormalizedLocale 校验归一化标签各子段均由非空 ASCII 字母数字构成，并提取主语言段归并至 Locale。
func matchNormalizedLocale(norm string) (Locale, bool) {
	if !hasValidLocaleSubtags(norm) {
		return LocaleInvalid, false
	}
	primary, _, _ := strings.Cut(norm, "_")
	switch primary {
	case "en":
		return LocaleEn, true
	case "zh":
		// 所有中文变体（zh_cn / zh_hans / zh_tw / zh_hant）统一归并至简体中文 LocaleZh。
		return LocaleZh, true
	default:
		return LocaleInvalid, false
	}
}

func hasValidLocaleSubtags(norm string) bool {
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

// isValidLocaleSuffix 校验 .codeset 与 @modifier 后缀，严格限定 POSIX 字符集 [A-Za-z0-9_-]。
func isValidLocaleSuffix(s string) bool {
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
