package textalg

import (
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	// MaxMessageIDBytes 限制规范消息标识的最大字节长度。
	MaxMessageIDBytes = 128
	// MaxParamKeyBytes 限制参数键名与模板占位符键名的最大字节长度。
	MaxParamKeyBytes = 64
	// MaxTemplateBytes 限制单条消息模板或兜底文本的最大 UTF-8 字节长度。
	MaxTemplateBytes = 8192
)

// TemplateErr 表示模板严格语法解析的分类结果（零值 TemplateErrNone 表示通过）。
type TemplateErr uint8

const (
	// TemplateErrNone 表示模板语法合法。
	TemplateErrNone TemplateErr = 0
	// TemplateErrInvalid 表示模板超长或包含非法 UTF-8 字节序列。
	TemplateErrInvalid TemplateErr = 1
	// TemplateErrUnclosed 表示模板存在未闭合的占位符左花括号。
	TemplateErrUnclosed TemplateErr = 2
	// TemplateErrUnescaped 表示模板存在未转义的孤立右花括号。
	TemplateErrUnescaped TemplateErr = 3
	// TemplateErrBadKey 表示模板占位符键名不满足参数键规范。
	TemplateErrBadKey TemplateErr = 4
)

// IsValidMessageID 校验消息标识是否为非空规范小写点分/下划线标识符（[a-z][a-z0-9_.]* 且不含连续或尾部点号）。
func IsValidMessageID(s string) bool {
	if len(s) == 0 || len(s) > MaxMessageIDBytes || s[0] < 'a' || s[0] > 'z' || s[len(s)-1] == '.' {
		return false
	}
	prevDot := false
	for i := range len(s) {
		c := s[i]
		if c == '.' {
			if prevDot {
				return false
			}
			prevDot = true
			continue
		}
		prevDot = false
		isAllowed := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
		if !isAllowed {
			return false
		}
	}
	return true
}

// IsValidParamKey 校验参数键名与占位符名称：长度 1..MaxParamKeyBytes，首字符为 ASCII 字母/数字/下划线，
// 其余字符仅限 ASCII 字母、数字、下划线、点或连字符。
func IsValidParamKey(k string) bool {
	if len(k) == 0 || len(k) > MaxParamKeyBytes {
		return false
	}
	for i := range len(k) {
		c := k[i]
		isBase := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
		isSep := i > 0 && (c == '.' || c == '-')
		if !isBase && !isSep {
			return false
		}
	}
	return true
}

// BoundDisplayText 将任意外部字符串确定性净化为有效 UTF-8 并按完整 rune 边界裁剪至不超过 maxBytes 字节。
// 非法 UTF-8 字节序列以 Unicode 替换字符 U+FFFD 净化（不附加外层引号）；maxBytes <= 0 或空串时返回空串。
func BoundDisplayText(raw string, maxBytes int) string {
	if maxBytes <= 0 || raw == "" {
		return ""
	}
	if !utf8.ValidString(raw) {
		raw = strings.ToValidUTF8(raw, "\uFFFD")
	}
	if len(raw) <= maxBytes {
		return raw
	}
	// 显式按完整 UTF-8 rune 边界截断，保证输出字节长度不超过 maxBytes 且恒为合法 UTF-8。
	end := 0
	for end < len(raw) {
		_, size := utf8.DecodeRuneInString(raw[end:])
		if end+size > maxBytes {
			break
		}
		end += size
	}
	return raw[:end]
}

// SanitizeTemplate 将超长或包含非法 UTF-8 的模板确定性净化并按完整 rune 边界裁剪至 MaxTemplateBytes。
func SanitizeTemplate(tmpl string) string {
	if len(tmpl) > MaxTemplateBytes || !utf8.ValidString(tmpl) {
		return BoundDisplayText(tmpl, MaxTemplateBytes)
	}
	return tmpl
}

// BoundNonBlankText 对外部明细文本执行空白判定、UTF-8 净化与字节裁剪；
// 若原始或裁剪后文本为空或纯空白则返回 ("", false)。
func BoundNonBlankText(raw string, maxBytes int) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", false
	}
	bounded := BoundDisplayText(raw, maxBytes)
	if strings.TrimSpace(bounded) == "" {
		return "", false
	}
	return bounded, true
}

// FormatTemplate 对模板执行单遍零反射 {key} 占位符替换，支持 {{ 与 }} 转义为字面花括号。
// 缺失键值或 resolve 为 nil 时原样保留 "{key}"；畸形花括号片段按字面安全输出，永不 panic。
func FormatTemplate(tmpl string, resolve func(string) (string, bool)) string {
	if !strings.ContainsAny(tmpl, "{}") {
		return tmpl
	}
	var b strings.Builder
	b.Grow(len(tmpl))
	for i := 0; i < len(tmpl); {
		switch tmpl[i] {
		case '{':
			if i+1 < len(tmpl) && tmpl[i+1] == '{' {
				b.WriteByte('{')
				i += 2
				continue
			}
			rep, next, ok := consumeFormatPlaceholder(tmpl, i, resolve)
			if ok {
				b.WriteString(rep)
				i = next
				continue
			}
			b.WriteByte('{')
			i++
		case '}':
			if i+1 < len(tmpl) && tmpl[i+1] == '}' {
				b.WriteByte('}')
				i += 2
				continue
			}
			b.WriteByte('}')
			i++
		default:
			b.WriteByte(tmpl[i])
			i++
		}
	}
	return b.String()
}

// HasMissingPlaceholder 以 O(n) 零堆分配快路径扫描 tmpl，按与 FormatTemplate 100% 同构的词法规则
// 检查是否存在任一会被 FormatTemplate 消费但未被 hasKey 绑定的合法 {key} 占位符。
func HasMissingPlaceholder(tmpl string, hasKey func(string) bool) bool {
	if !strings.ContainsRune(tmpl, '{') {
		return false
	}
	for i := 0; i < len(tmpl); {
		if tmpl[i] != '{' {
			i++
			continue
		}
		if i+1 < len(tmpl) && tmpl[i+1] == '{' {
			i += 2
			continue
		}
		if key, next, ok := matchFormatPlaceholder(tmpl, i); ok {
			if hasKey == nil || !hasKey(key) {
				return true
			}
			i = next
			continue
		}
		i++
	}
	return false
}

// CollectFormatPlaceholderKeys 按与 FormatTemplate 100% 同构的宽容词法扫描 tmpl，
// 依首次出现顺序去重返回所有将被 FormatTemplate 识别的合法占位符键名（正确处理 {{ / }} / {{{k}}} 及前置畸形花括号）。
func CollectFormatPlaceholderKeys(tmpl string) []string {
	if !strings.ContainsRune(tmpl, '{') {
		return nil
	}
	var keys []string
	var seen map[string]struct{}
	for i := 0; i < len(tmpl); {
		if tmpl[i] != '{' {
			i++
			continue
		}
		if i+1 < len(tmpl) && tmpl[i+1] == '{' {
			i += 2
			continue
		}
		key, next, ok := matchFormatPlaceholder(tmpl, i)
		if !ok {
			i++
			continue
		}
		if seen == nil {
			seen = make(map[string]struct{})
		}
		if _, dup := seen[key]; !dup {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
		i = next
	}
	return keys
}

// ParsePlaceholderKeys 执行严格模板语法校验与占位符扫描，返回升序去重后的占位符键名切片及错误分类码。
func ParsePlaceholderKeys(tmpl string) ([]string, TemplateErr, string) {
	if len(tmpl) > MaxTemplateBytes || !utf8.ValidString(tmpl) {
		return nil, TemplateErrInvalid, ""
	}
	var keys []string
	for i := 0; i < len(tmpl); {
		key, next, hasKey, errKind, badKey := stepParsePlaceholder(tmpl, i)
		if errKind != TemplateErrNone {
			return nil, errKind, badKey
		}
		if hasKey {
			keys = append(keys, key)
		}
		i = next
	}
	slices.Sort(keys)
	return slices.Compact(keys), TemplateErrNone, ""
}

func consumeFormatPlaceholder(tmpl string, start int, resolve func(string) (string, bool)) (string, int, bool) {
	key, next, ok := matchFormatPlaceholder(tmpl, start)
	if !ok {
		return "", 0, false
	}
	if resolve != nil {
		if val, found := resolve(key); found {
			return val, next, true
		}
	}
	return tmpl[start:next], next, true
}

func matchFormatPlaceholder(tmpl string, start int) (string, int, bool) {
	end := findPlaceholderEnd(tmpl, start+1)
	if end < 0 {
		return "", 0, false
	}
	key := tmpl[start+1 : end]
	if !IsValidParamKey(key) {
		return "", 0, false
	}
	return key, end + 1, true
}

// findPlaceholderEnd 从 '{' 之后扫描对应 '}'；若先遇到另一 '{' 或末尾则返回 -1。
func findPlaceholderEnd(tmpl string, from int) int {
	for j := from; j < len(tmpl); j++ {
		if tmpl[j] == '{' {
			return -1
		}
		if tmpl[j] == '}' {
			return j
		}
	}
	return -1
}

func stepParsePlaceholder(tmpl string, i int) (string, int, bool, TemplateErr, string) {
	switch tmpl[i] {
	case '{':
		if i+1 < len(tmpl) && tmpl[i+1] == '{' {
			return "", i + 2, false, TemplateErrNone, ""
		}
		key, next, errKind, badKey := parseStrictPlaceholderKey(tmpl, i)
		return key, next, errKind == TemplateErrNone, errKind, badKey
	case '}':
		if i+1 < len(tmpl) && tmpl[i+1] == '}' {
			return "", i + 2, false, TemplateErrNone, ""
		}
		return "", 0, false, TemplateErrUnescaped, ""
	default:
		return "", i + 1, false, TemplateErrNone, ""
	}
}

func parseStrictPlaceholderKey(tmpl string, start int) (string, int, TemplateErr, string) {
	end := findPlaceholderEnd(tmpl, start+1)
	if end < 0 {
		return "", 0, TemplateErrUnclosed, ""
	}
	key := tmpl[start+1 : end]
	if !IsValidParamKey(key) {
		return "", 0, TemplateErrBadKey, key
	}
	return key, end + 1, TemplateErrNone, ""
}
