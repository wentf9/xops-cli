package netaddr

import (
	"cmp"
	"encoding"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const (
	maxHostnameLen  = 253
	maxHostLabelLen = 63
	maxIPv6ZoneLen  = 64
)

var (
	_ encoding.TextAppender    = CanonicalHost{}
	_ encoding.TextMarshaler   = CanonicalHost{}
	_ encoding.TextUnmarshaler = (*CanonicalHost)(nil)
)

// HostKind 标识 CanonicalHost 的具体主机类别；零值 HostKindInvalid 严格代表无效未初始化态。
//
//xops:failclosed
type HostKind uint8

const (
	// HostKindInvalid 表示未初始化或校验失败的无效主机类别（失败关闭零值）。
	HostKindInvalid HostKind = iota
	// HostKindIPv4 表示标准点分十进制 IPv4 地址。
	HostKindIPv4
	// HostKindIPv6 表示 RFC 5952 规范化 IPv6 地址（含可选 %zone 与保留原样的 ::ffff:a.b.c.d）。
	HostKindIPv6
	// HostKindDNS 表示 ASCII 小写规范化的 RFC 1123 DNS 主机名。
	HostKindDNS
)

// String 返回 HostKind 的可读名称。
func (k HostKind) String() string {
	switch k {
	case HostKindIPv4:
		return "ipv4"
	case HostKindIPv6:
		return "ipv6"
	case HostKindDNS:
		return "dns"
	default:
		return "invalid"
	}
}

// CanonicalHost 表示经过严格校验与规范化的不可变网络主机（IPv4、IPv6 或 DNS 主机名）。
//
// 关键安全与规范化不变量：
//   - IPv6 经 net/netip.Addr 归一化为 RFC 5952 最小压缩形式，保留合法区段标识（%zone），
//     并故意保留 IPv4-mapped IPv6（如 ::ffff:192.0.2.1）为 HostKindIPv6，绝不静默降级为 IPv4；
//   - DNS 主机名遵循 RFC 1123 并折叠为 ASCII 小写，且末段标签强制包含至少一个 ASCII 字母并拒绝
//     POSIX/WinSock inet_aton 十六进制 IPv4 形式（0x[0-9a-f]+），彻底阻断 "999.999.999.999"、"127.1"、
//     "0177.0.0.1"、"0x7f000001"、"0x7f.0.0.0x1" 等畸形数字伪装主机名绕过 IP 解析；
//   - 严禁静默裁剪首尾空白，任何空白、控制字符或 Unicode 行分隔符一律失败关闭拒绝；
//   - 零值恒无效（IsValid() == false），且 Equal 对无效值恒返回 false。
//
//xops:opaque
//xops:failclosed
type CanonicalHost struct {
	addr     netip.Addr
	hostname string
	kind     HostKind
}

// CanonicalHostFromAddr 从已解析的 netip.Addr 构造规范化 CanonicalHost，并严格校验 IPv6 区段标识。
func CanonicalHostFromAddr(addr netip.Addr) (CanonicalHost, error) {
	if !addr.IsValid() {
		return CanonicalHost{}, domi18n.EF(ErrInvalidHost, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ip"))
	}
	if err := ValidateIPv6Zone(addr.Zone()); err != nil {
		return CanonicalHost{}, domi18n.WrapSentinel(ErrInvalidHost, err)
	}
	if addr.Is4() {
		return CanonicalHost{addr: addr, kind: HostKindIPv4}, nil
	}
	return CanonicalHost{addr: addr, kind: HostKindIPv6}, nil
}

// ParseCanonicalHost 校验并规范化输入主机字符串（支持 IPv4、裸 IPv6、方括号包裹的 [IPv6] 与 RFC 1123 主机名）。
// 方括号仅允许包裹合法 IPv6 字面量（禁止 [192.0.2.1] 或 [example.com]）；拒绝一切空白与控制字符。
func ParseCanonicalHost(raw string) (CanonicalHost, error) {
	if raw == "" {
		return CanonicalHost{}, domi18n.EF(ErrInvalidHost, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "host"))
	}
	if hasForbiddenHostChar(raw) {
		return CanonicalHost{}, domi18n.EF(ErrInvalidHost, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "host"))
	}
	if raw[0] == '[' || raw[len(raw)-1] == ']' {
		return parseBracketedIPv6Host(raw)
	}
	if strings.ContainsAny(raw, "[]") {
		return CanonicalHost{}, domi18n.EF(ErrInvalidHost, domi18n.KeyNetaddrBracketsMalformed, domi18n.BoundStr("value", raw))
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return CanonicalHostFromAddr(addr)
	}
	folded, err := validateAndFoldRFC1123Hostname(raw)
	if err != nil {
		return CanonicalHost{}, domi18n.WrapSentinel(ErrInvalidHost, err)
	}
	return CanonicalHost{hostname: folded, kind: HostKindDNS}, nil
}

func parseBracketedIPv6Host(raw string) (CanonicalHost, error) {
	if len(raw) < 3 || raw[0] != '[' || raw[len(raw)-1] != ']' {
		return CanonicalHost{}, domi18n.EF(ErrInvalidHost, domi18n.KeyNetaddrBracketsMalformed, domi18n.BoundStr("value", raw))
	}
	inner := raw[1 : len(raw)-1]
	if strings.ContainsAny(inner, "[]") {
		return CanonicalHost{}, domi18n.EF(ErrInvalidHost, domi18n.KeyNetaddrBracketsMalformed, domi18n.BoundStr("value", raw))
	}
	addr, err := netip.ParseAddr(inner)
	if err != nil || !addr.Is6() {
		return CanonicalHost{}, domi18n.EF(ErrInvalidHost, domi18n.KeyNetaddrBracketsMalformed, domi18n.BoundStr("value", raw))
	}
	return CanonicalHostFromAddr(addr)
}

// ValidateIPv6Zone 校验任意带区段（%zone）IPv6 地址的区段标识。
// 空串表示无区段（合法）；非空区段采用严格失败关闭 ASCII 白名单：长度 1..64 字节，
// 首字节必须为 [A-Za-z0-9_]，其余字节必须为 [A-Za-z0-9._-] 且不得以 '.' 结尾，
// 从根源阻断 OpenSSH known_hosts 通配/注释元字符（* ? ! #）、%h/命令行选项注入（前导 - 与 shell 字符）
// 及 Unicode 格式/双向控制字符（如 U+200B/U+202E）。
func ValidateIPv6Zone(zone string) error {
	if zone == "" {
		return nil
	}
	if len(zone) > maxIPv6ZoneLen {
		return domi18n.EF(ErrInvalidZone, domi18n.KeyCommonFieldMaxExceeded, domi18n.Str("field", "zone"), domi18n.Int("value", len(zone)), domi18n.Int("max", maxIPv6ZoneLen))
	}
	if !isZoneStartByte(zone[0]) || zone[len(zone)-1] == '.' {
		return domi18n.EF(ErrInvalidZone, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "zone"), domi18n.BoundStr("value", zone))
	}
	for i := 1; i < len(zone); i++ {
		if !isZoneBodyByte(zone[i]) {
			return domi18n.EF(ErrInvalidZone, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "zone"), domi18n.BoundStr("value", zone))
		}
	}
	return nil
}

func isZoneStartByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func isZoneBodyByte(b byte) bool {
	return isZoneStartByte(b) || b == '.' || b == '-'
}

// IsValid 报告 CanonicalHost 是否为有效主机。
func (h CanonicalHost) IsValid() bool {
	return h.kind != HostKindInvalid
}

// IsZero 报告 CanonicalHost 是否为无效零值（配合 encoding/json/v2 omitzero）。
func (h CanonicalHost) IsZero() bool {
	return h.kind == HostKindInvalid
}

// Kind 返回主机类别（无效零值返回 HostKindInvalid）。
func (h CanonicalHost) Kind() HostKind {
	return h.kind
}

// IsIP 报告主机是否为 IPv4 或 IPv6 字面量。
func (h CanonicalHost) IsIP() bool {
	return h.kind == HostKindIPv4 || h.kind == HostKindIPv6
}

// IsIPv4 报告主机是否为纯 IPv4 地址（IPv4-mapped IPv6 返回 false）。
func (h CanonicalHost) IsIPv4() bool {
	return h.kind == HostKindIPv4
}

// IsIPv6 报告主机是否为 IPv6 地址（含 IPv4-mapped IPv6 与带区段地址）。
func (h CanonicalHost) IsIPv6() bool {
	return h.kind == HostKindIPv6
}

// IsDNS 报告主机是否为规范化 RFC 1123 DNS 主机名。
func (h CanonicalHost) IsDNS() bool {
	return h.kind == HostKindDNS
}

// Addr 在主机为 IP 地址时返回底层 netip.Addr 与 true；DNS 主机名或无效零值返回零值与 false。
func (h CanonicalHost) Addr() (netip.Addr, bool) {
	if !h.IsIP() {
		return netip.Addr{}, false
	}
	return h.addr, true
}

// Zone 返回 IPv6 区段标识；无区段、IPv4、DNS 或无效零值返回空串。
func (h CanonicalHost) Zone() string {
	if h.kind != HostKindIPv6 {
		return ""
	}
	return h.addr.Zone()
}

// String 返回规范化无方括号主机文本（如 "192.0.2.1"、"2001:db8::1"、"fe80::1%eth0"、"example.com"）；
// 无效零值返回空串。
func (h CanonicalHost) String() string {
	switch h.kind {
	case HostKindIPv4, HostKindIPv6:
		return h.addr.String()
	case HostKindDNS:
		return h.hostname
	default:
		return ""
	}
}

// Bracketed 返回适合拼接 ":port" 的主机文本：IPv6 自动加方括号 "[...]"，IPv4 与 DNS 原样返回，无效零值返回空串。
func (h CanonicalHost) Bracketed() string {
	switch h.kind {
	case HostKindIPv6:
		return "[" + h.addr.String() + "]"
	case HostKindIPv4:
		return h.addr.String()
	case HostKindDNS:
		return h.hostname
	default:
		return ""
	}
}

// Equal 判断两个 CanonicalHost 是否均有效且完全等价；严格失败关闭，无效零值永不与任何对象相等。
func (h CanonicalHost) Equal(other CanonicalHost) bool {
	if !h.IsValid() || !other.IsValid() {
		return false
	}
	return h.kind == other.kind && h.addr == other.addr && h.hostname == other.hostname
}

// Compare 定义 CanonicalHost 上的确定性全序关系（Invalid < IPv4 < IPv6 < DNS，同类按规范字节/字典序比较）。
func (h CanonicalHost) Compare(other CanonicalHost) int {
	if c := cmp.Compare(h.kind, other.kind); c != 0 {
		return c
	}
	switch h.kind {
	case HostKindIPv4, HostKindIPv6:
		return h.addr.Compare(other.addr)
	case HostKindDNS:
		return cmp.Compare(h.hostname, other.hostname)
	default:
		return 0
	}
}

// AppendText 实现 encoding.TextAppender（值接收者）；对无效零值失败关闭返回 ErrInvalidHost。
func (h CanonicalHost) AppendText(b []byte) ([]byte, error) {
	switch h.kind {
	case HostKindIPv4, HostKindIPv6:
		return h.addr.AppendTo(b), nil
	case HostKindDNS:
		return append(b, h.hostname...), nil
	default:
		return nil, ErrInvalidHost
	}
}

// MarshalText 实现 encoding.TextMarshaler（值接收者），语义与 AppendText(nil) 完全一致。
func (h CanonicalHost) MarshalText() ([]byte, error) {
	return h.AppendText(nil)
}

// UnmarshalText 实现 encoding.TextUnmarshaler，解析并规范化主机文本；失败时重置为零值并失败关闭。
func (h *CanonicalHost) UnmarshalText(text []byte) error {
	if h == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseCanonicalHost(string(text))
	if err != nil {
		*h = CanonicalHost{}
		return err
	}
	*h = parsed
	return nil
}

func hasForbiddenHostChar(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

func validateAndFoldRFC1123Hostname(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > maxHostnameLen {
		return "", domi18n.E(domi18n.KeyNetaddrHostnameInvalid, domi18n.BoundStr("value", raw), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyNetaddrReasonLength)))
	}
	if raw[0] == '.' || raw[len(raw)-1] == '.' {
		return "", domi18n.E(domi18n.KeyNetaddrHostnameInvalid, domi18n.BoundStr("value", raw), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyNetaddrReasonEdgeDot)))
	}

	var b strings.Builder
	b.Grow(len(raw))
	lastLabelHasAlpha := false
	labelStart := 0
	lastFoldedStart := 0
	for i := 0; i <= len(raw); i++ {
		if i < len(raw) && raw[i] != '.' {
			continue
		}
		lastFoldedStart = b.Len()
		hasAlpha, err := appendFoldedLabel(&b, raw[labelStart:i], raw)
		if err != nil {
			return "", err
		}
		lastLabelHasAlpha = hasAlpha
		if i < len(raw) {
			b.WriteByte('.')
		}
		labelStart = i + 1
	}
	folded := b.String()
	if !lastLabelHasAlpha || isHexNumericLabel(folded[lastFoldedStart:]) {
		return "", domi18n.E(domi18n.KeyNetaddrHostnameInvalid, domi18n.BoundStr("value", raw), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyNetaddrReasonNumericTLD)))
	}
	return folded, nil
}

// isHexNumericLabel 判断已折叠为小写的标签是否为 POSIX/WinSock inet_aton 十六进制数值字面量（0x[0-9a-f]+）。
func isHexNumericLabel(foldedLabel string) bool {
	if len(foldedLabel) < 3 || foldedLabel[0] != '0' || foldedLabel[1] != 'x' {
		return false
	}
	for i := 2; i < len(foldedLabel); i++ {
		c := foldedLabel[i]
		isDigit := c >= '0' && c <= '9'
		isHexAlpha := c >= 'a' && c <= 'f'
		if !isDigit && !isHexAlpha {
			return false
		}
	}
	return true
}

func appendFoldedLabel(b *strings.Builder, label, full string) (bool, error) {
	if len(label) == 0 || len(label) > maxHostLabelLen {
		return false, domi18n.E(domi18n.KeyNetaddrHostnameInvalid, domi18n.BoundStr("value", full), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyNetaddrReasonLabelLength)))
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false, domi18n.E(domi18n.KeyNetaddrHostnameInvalid, domi18n.BoundStr("value", full), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyNetaddrReasonEdgeHyphen)))
	}
	hasAlpha := false
	for i := 0; i < len(label); i++ {
		ch := label[i]
		folded, alpha, ok := foldLabelByte(ch)
		if !ok {
			return false, domi18n.E(domi18n.KeyNetaddrHostnameInvalid, domi18n.BoundStr("value", full), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyNetaddrReasonIllegalChar)))
		}
		if alpha {
			hasAlpha = true
		}
		b.WriteByte(folded)
	}
	return hasAlpha, nil
}

func foldLabelByte(c byte) (folded byte, isAlpha, ok bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return c + ('a' - 'A'), true, true
	case c >= 'a' && c <= 'z':
		return c, true, true
	case (c >= '0' && c <= '9') || c == '-':
		return c, false, true
	default:
		return 0, false, false
	}
}
