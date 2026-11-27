package netaddr

import (
	"cmp"
	"encoding"
	"strconv"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

var (
	_ encoding.TextAppender    = HostPort{}
	_ encoding.TextMarshaler   = HostPort{}
	_ encoding.TextUnmarshaler = (*HostPort)(nil)
)

// HostPort 表示协议无关的严格 (CanonicalHost, Port) 网络地址对。
//
// 与 Endpoint 的关键区别：HostPort 不做任何协议默认端口假设（端口必须显式指定于 [1, 65535]），
// 适用于端口转发（-L/-R/-W）、监听地址、代理目标等通用 TCP 场景；
// 零值代表无效状态（IsValid() == false），序列化与 Equal 均严格失败关闭。
//
//xops:opaque
//xops:failclosed
type HostPort struct {
	host CanonicalHost
	port uint16
}

// NewHostPort 校验并构造不可变 HostPort（要求 host 有效且 port 在 [1, 65535] 范围内）。
func NewHostPort(host CanonicalHost, port uint16) (HostPort, error) {
	if !host.IsValid() {
		return HostPort{}, domi18n.WrapSentinel(ErrInvalidHostPort, ErrInvalidHost)
	}
	if port == 0 {
		return HostPort{}, domi18n.WrapS(ErrInvalidHostPort, ErrInvalidPort, domi18n.KeyCommonFieldRange, domi18n.Str("field", "port"), domi18n.Int("value", int(port)), domi18n.Int("min", 1), domi18n.Int("max", 65535))
	}
	return HostPort{host: host, port: port}, nil
}

// ParseHostPort 解析严格的 "<host>:<port>" 或 "[<ipv6>]:<port>" 文本表示。
// 省略端口、端口为 0 或含前导零、未加方括号的 IPv6、空白与控制字符一律失败关闭拒绝。
func ParseHostPort(raw string) (HostPort, error) {
	if raw == "" {
		return HostPort{}, domi18n.EF(ErrInvalidHostPort, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "address"))
	}
	if hasForbiddenHostChar(raw) {
		return HostPort{}, domi18n.EF(ErrInvalidHostPort, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "address"))
	}
	if raw[0] == '[' {
		return parseBracketedHostPort(raw)
	}
	if strings.ContainsAny(raw, "[]") {
		return HostPort{}, domi18n.EF(ErrInvalidHostPort, domi18n.KeyNetaddrBracketsMalformed, domi18n.BoundStr("value", raw))
	}
	if strings.Count(raw, ":") != 1 {
		return HostPort{}, domi18n.EF(ErrInvalidHostPort, domi18n.KeyNetaddrHostPortFormat, domi18n.BoundStr("value", raw))
	}
	hostPart, portPart, _ := strings.Cut(raw, ":")
	return buildHostPort(hostPart, portPart)
}

func parseBracketedHostPort(raw string) (HostPort, error) {
	closeIdx := strings.IndexByte(raw, ']')
	if closeIdx < 2 {
		return HostPort{}, domi18n.EF(ErrInvalidHostPort, domi18n.KeyNetaddrBracketsMalformed, domi18n.BoundStr("value", raw))
	}
	hostPart := raw[:closeIdx+1]
	rest := raw[closeIdx+1:]
	if len(rest) < 2 || rest[0] != ':' {
		return HostPort{}, domi18n.EF(ErrInvalidHostPort, domi18n.KeyNetaddrHostPortFormat, domi18n.BoundStr("value", raw))
	}
	return buildHostPort(hostPart, rest[1:])
}

func buildHostPort(hostPart, portPart string) (HostPort, error) {
	host, err := ParseCanonicalHost(hostPart)
	if err != nil {
		return HostPort{}, domi18n.WrapSentinel(ErrInvalidHostPort, err)
	}
	port, err := parseStrictPort(portPart)
	if err != nil {
		return HostPort{}, domi18n.WrapSentinel(ErrInvalidHostPort, err)
	}
	return HostPort{host: host, port: port}, nil
}

// parseStrictPort 严格解析十进制端口号：仅接受无前导零的纯 ASCII 数字，且值必须落于 [1, 65535]。
// 拒绝 "0"、"022"（阻断八进制歧义）、"+22"、"-1" 与非 ASCII 数字。
func parseStrictPort(raw string) (uint16, error) {
	if raw == "" {
		return 0, domi18n.EF(ErrInvalidPort, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "port"))
	}
	if raw[0] == '0' {
		return 0, domi18n.EF(ErrInvalidPort, domi18n.KeyNetaddrPortFormat, domi18n.BoundStr("value", raw))
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, domi18n.EF(ErrInvalidPort, domi18n.KeyNetaddrPortFormat, domi18n.BoundStr("value", raw))
		}
	}
	v, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || v == 0 {
		return 0, domi18n.EF(ErrInvalidPort, domi18n.KeyNetaddrPortFormat, domi18n.BoundStr("value", raw))
	}
	return uint16(v), nil
}

// IsValid 报告 HostPort 是否持有有效主机与非零端口。
func (hp HostPort) IsValid() bool {
	return hp.host.IsValid() && hp.port != 0
}

// IsZero 报告 HostPort 是否为无效零值（配合 encoding/json/v2 omitzero）。
func (hp HostPort) IsZero() bool {
	return !hp.IsValid()
}

// Host 返回规范化主机值对象。
func (hp HostPort) Host() CanonicalHost {
	return hp.host
}

// Port 返回有效 TCP 端口号（无效零值返回 0）。
func (hp HostPort) Port() uint16 {
	if !hp.IsValid() {
		return 0
	}
	return hp.port
}

// String 返回规范化 "<host>:<port>"（IPv6 自动加方括号）文本；无效零值返回空串。
func (hp HostPort) String() string {
	if !hp.IsValid() {
		return ""
	}
	return hp.host.Bracketed() + ":" + strconv.FormatUint(uint64(hp.port), 10)
}

// Equal 判断两个 HostPort 是否均有效且主机与端口均完全相等；严格失败关闭，无效零值永不相等。
func (hp HostPort) Equal(other HostPort) bool {
	if !hp.IsValid() || !other.IsValid() {
		return false
	}
	return hp.port == other.port && hp.host.Equal(other.host)
}

// Compare 定义 HostPort 上的确定性全序关系（无效零值排在有效值之前，有效值先比主机再比端口）。
func (hp HostPort) Compare(other HostPort) int {
	if !hp.IsValid() && !other.IsValid() {
		return 0
	}
	if !hp.IsValid() {
		return -1
	}
	if !other.IsValid() {
		return 1
	}
	if c := hp.host.Compare(other.host); c != 0 {
		return c
	}
	return cmp.Compare(hp.port, other.port)
}

// AppendText 实现 encoding.TextAppender（值接收者）；对无效零值失败关闭返回 ErrInvalidHostPort。
func (hp HostPort) AppendText(b []byte) ([]byte, error) {
	if !hp.IsValid() {
		return nil, ErrInvalidHostPort
	}
	var err error
	if hp.host.IsIPv6() {
		b = append(b, '[')
		b, err = hp.host.AppendText(b)
		if err != nil {
			return nil, err
		}
		b = append(b, ']')
	} else {
		b, err = hp.host.AppendText(b)
		if err != nil {
			return nil, err
		}
	}
	b = append(b, ':')
	return strconv.AppendUint(b, uint64(hp.port), 10), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者），语义与 AppendText(nil) 完全一致。
func (hp HostPort) MarshalText() ([]byte, error) {
	return hp.AppendText(nil)
}

// UnmarshalText 实现 encoding.TextUnmarshaler，解析严格的 "<host>:<port>"；失败时重置为零值并失败关闭。
func (hp *HostPort) UnmarshalText(text []byte) error {
	if hp == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseHostPort(string(text))
	if err != nil {
		*hp = HostPort{}
		return err
	}
	*hp = parsed
	return nil
}
