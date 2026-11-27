package pathalg

import (
	"strings"
	"unicode"
	"unicode/utf8"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// ValidateLocalComponent 以三平台（Linux/macOS/Windows）完全一致的失败关闭规则校验单个本地路径分量。
//
// 本函数不依赖当前运行 OS，统一拒绝：
//   - 空串、"."、".." 以及超长（> 255 UTF-8 字节）分量；
//   - 非法 UTF-8、NUL、ASCII/Unicode 控制字符（Cc）、不可见与双向排版格式字符（Cf，如 U+202E/U+200B/U+FEFF）
//     以及 Unicode 行/段分隔符（U+2028/U+2029）；
//   - 路径分隔符 '/' 与 '\'，冒号 ':'（阻断盘符前缀与 NTFS ADS 备用数据流）以及 Windows/NTFS 禁用字符
//     '*'、'?'、'"'、'<'、'>'、'|'；
//   - 尾随点 '.' 或尾随 ASCII 空格 ' '（防止 Windows 静默裁剪导致同名覆写与扩展名欺骗）；
//   - Windows DOS 保留设备名（在首个 '.' 之前、忽略尾随 ASCII 空格且大小写不敏感）：
//     CON、PRN、AUX、NUL、CONIN$、CONOUT$、COM1–COM9、LPT1–LPT9 及 Latin-1 上标变体 COM¹–COM³、LPT¹–LPT³。
//
// 所有拒绝错误均包装 ErrInvalidComponent。
func ValidateLocalComponent(name string) error {
	if name == "" {
		return domi18n.EF(ErrInvalidComponent, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "component"))
	}
	if len(name) > MaxComponentBytes {
		return domi18n.EF(ErrInvalidComponent, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "component"), domi18n.Int("size", len(name)), domi18n.Int("limit", MaxComponentBytes))
	}
	if name == "." || name == ".." {
		return domi18n.EF(ErrInvalidComponent, domi18n.KeyPathalgTraversalForbidden, domi18n.BoundStr("segment", name))
	}
	if !utf8.ValidString(name) {
		return domi18n.EF(ErrInvalidComponent, domi18n.KeyCommonInvalidUTF8)
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return domi18n.EF(ErrInvalidComponent, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "component"), domi18n.BoundStr("value", name))
	}
	if err := validateLocalComponentRunes(name); err != nil {
		return err
	}
	if isWindowsReservedDeviceStem(name) {
		return domi18n.EF(ErrInvalidComponent, domi18n.KeyPathalgReservedName, domi18n.BoundStr("value", name))
	}
	return nil
}

func validateLocalComponentRunes(name string) error {
	for _, r := range name {
		if isForbiddenPathRune(r) {
			return domi18n.EF(ErrInvalidComponent, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "component"))
		}
		if isForbiddenLocalComponentRune(r) {
			return domi18n.EF(ErrInvalidComponent, domi18n.KeyPathalgForbiddenChar, domi18n.BoundStr("value", name), domi18n.Str("char", string(r)))
		}
	}
	return nil
}

func isForbiddenLocalComponentRune(r rune) bool {
	switch r {
	case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
		return true
	default:
		return false
	}
}

// isForbiddenPathRune 判定码点是否为 NUL、ASCII/Unicode 控制字符（Cc）、不可见/Bidi 格式字符（Cf）
// 或 Unicode 行/段分隔符（U+2028/U+2029）。
func isForbiddenPathRune(r rune) bool {
	if r == 0 || r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
		return true
	}
	if r == '\u2028' || r == '\u2029' {
		return true
	}
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

// hasForbiddenPathText 检查字符串是否含非法 UTF-8、NUL、控制字符或 Bidi/Cf 格式字符。
func hasForbiddenPathText(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if isForbiddenPathRune(r) {
			return true
		}
	}
	return false
}

// isWindowsReservedDeviceStem 检测分量首个 '.' 之前的主干（裁剪尾随 ASCII 空格）是否命中 Windows DOS 保留设备名。
func isWindowsReservedDeviceStem(name string) bool {
	stem := name
	if dot := strings.IndexByte(stem, '.'); dot >= 0 {
		stem = stem[:dot]
	}
	stem = strings.TrimRight(stem, " ")
	if len(stem) < 3 {
		return false
	}
	if len(stem) == 3 {
		return equalASCIIFold3(stem, "CON") ||
			equalASCIIFold3(stem, "PRN") ||
			equalASCIIFold3(stem, "AUX") ||
			equalASCIIFold3(stem, "NUL")
	}
	if strings.EqualFold(stem, "CONIN$") || strings.EqualFold(stem, "CONOUT$") {
		return true
	}
	prefix := stem[:3]
	if !equalASCIIFold3(prefix, "COM") && !equalASCIIFold3(prefix, "LPT") {
		return false
	}
	r, size := utf8.DecodeRuneInString(stem[3:])
	if size != len(stem[3:]) {
		return false
	}
	return (r >= '1' && r <= '9') || r == '\u00b9' || r == '\u00b2' || r == '\u00b3'
}

// equalASCIIFold3 使用纯 ASCII 大小写折叠比对 3 字节常量前缀，避免非 ASCII Unicode 折叠误匹配（如 Kelvin 符号）。
func equalASCIIFold3(s, upper string) bool {
	if len(s) != 3 || len(upper) != 3 {
		return false
	}
	for i := range 3 {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c != upper[i] {
			return false
		}
	}
	return true
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func toUpperASCII(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - ('a' - 'A')
	}
	return b
}
