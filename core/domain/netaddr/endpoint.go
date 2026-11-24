package netaddr

import (
	"encoding"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var (
	_ encoding.TextAppender    = Endpoint{}
	_ encoding.TextMarshaler   = Endpoint{}
	_ encoding.TextUnmarshaler = (*Endpoint)(nil)
)

// Endpoint 表示强类型规范化 SSH 连接目标端点（绑定规范化主机与 [1, 65535] 端口，见 INV-E2）。
//
// 本类型专供 SSH 拨号计划、OpenSSH Tier-4 策略作用域与 known_hosts 键匹配使用：
//   - 零值恒无效（IsValid() == false）且 Equal / HostEqual 对无效值恒返回 false；
//   - ParseEndpoint 接受省略端口的主机形式（"host"、"[ipv6]"、裸 "2001:db8::1"、"fe80::1%eth0"）
//     并显式补全默认 SSH 端口 22，但严格拒绝显式非法端口（如 ":0"、":022"、":70000"）；
//   - KnownHostsKey 按 OpenSSH 规范格式化：端口 22 输出无方括号主机，非 22 端口输出 "[host]:port"。
//
//xops:opaque
//xops:failclosed
type Endpoint struct {
	addr HostPort
}

// NewEndpoint 使用显式主机与非零端口构造不可变 SSH Endpoint。
func NewEndpoint(host CanonicalHost, port uint16) (Endpoint, error) {
	hp, err := NewHostPort(host, port)
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
	}
	return Endpoint{addr: hp}, nil
}

// NewDefaultEndpoint 使用默认 SSH 端口（22）与已验证主机构造 Endpoint。
func NewDefaultEndpoint(host CanonicalHost) (Endpoint, error) {
	return NewEndpoint(host, DefaultSSHPort)
}

// NewEndpointFromHostPort 将已验证的 HostPort 提升为 SSH Endpoint。
func NewEndpointFromHostPort(hp HostPort) (Endpoint, error) {
	if !hp.IsValid() {
		return Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidEndpoint, ErrInvalidHostPort)
	}
	return Endpoint{addr: hp}, nil
}

// ParseEndpoint 解析 SSH 端点文本为规范化 Endpoint。
// 支持形式："host"、"host:port"、"[ipv6]"、"[ipv6]:port" 以及裸 IPv6 字面量（含 %zone，默认端口 22）；
// 拒绝空白、控制字符、显式端口 0、前导零端口及非 IPv6 方括号包裹。
func ParseEndpoint(raw string) (Endpoint, error) {
	if raw == "" {
		return Endpoint{}, fmt.Errorf("%w: 端点不能为空", ErrInvalidEndpoint)
	}
	if hasForbiddenHostChar(raw) {
		return Endpoint{}, fmt.Errorf("%w: %q 包含空白、控制字符或非法 UTF-8", ErrInvalidEndpoint, raw)
	}
	if raw[0] == '[' {
		return parseBracketedEndpoint(raw)
	}
	if strings.ContainsAny(raw, "[]") {
		return Endpoint{}, fmt.Errorf("%w: %q 包含非预期方括号", ErrInvalidEndpoint, raw)
	}
	return parseUnbracketedEndpoint(raw)
}

func parseBracketedEndpoint(raw string) (Endpoint, error) {
	closeIdx := strings.IndexByte(raw, ']')
	if closeIdx < 2 {
		return Endpoint{}, fmt.Errorf("%w: 畸形方括号端点 %q", ErrInvalidEndpoint, raw)
	}
	hostPart := raw[:closeIdx+1]
	rest := raw[closeIdx+1:]
	if rest == "" {
		host, err := ParseCanonicalHost(hostPart)
		if err != nil {
			return Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
		}
		return NewDefaultEndpoint(host)
	}
	if rest[0] != ':' {
		return Endpoint{}, fmt.Errorf("%w: 端点 %q 方括号后存在非法后缀", ErrInvalidEndpoint, raw)
	}
	hp, err := buildHostPort(hostPart, rest[1:])
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
	}
	return Endpoint{addr: hp}, nil
}

func parseUnbracketedEndpoint(raw string) (Endpoint, error) {
	switch strings.Count(raw, ":") {
	case 0:
		host, err := ParseCanonicalHost(raw)
		if err != nil {
			return Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
		}
		return NewDefaultEndpoint(host)
	case 1:
		hostPart, portPart, _ := strings.Cut(raw, ":")
		hp, err := buildHostPort(hostPart, portPart)
		if err != nil {
			return Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
		}
		return Endpoint{addr: hp}, nil
	default:
		// 含两个及以上冒号且无方括号时，仅允许作为合法裸 IPv6 字面量（默认 SSH 端口 22）。
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is6() {
			return Endpoint{}, fmt.Errorf("%w: %q 既非合法裸 IPv6 也非规范 <host>:<port>", ErrInvalidEndpoint, raw)
		}
		host, err := CanonicalHostFromAddr(addr)
		if err != nil {
			return Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
		}
		return NewDefaultEndpoint(host)
	}
}

// IsValid 报告 Endpoint 是否有效。
func (e Endpoint) IsValid() bool {
	return e.addr.IsValid()
}

// IsZero 报告 Endpoint 是否为无效零值（配合 encoding/json/v2 omitzero）。
func (e Endpoint) IsZero() bool {
	return !e.addr.IsValid()
}

// Host 返回端点的规范化主机。
func (e Endpoint) Host() CanonicalHost {
	return e.addr.Host()
}

// Port 返回端点的 TCP 端口（无效零值返回 0）。
func (e Endpoint) Port() uint16 {
	return e.addr.Port()
}

// HostPort 返回底层不可变 HostPort。
func (e Endpoint) HostPort() HostPort {
	return e.addr
}

// WithPort 返回替换为新非零端口的 Endpoint 副本；若当前端点无效或 port == 0 则失败关闭。
func (e Endpoint) WithPort(port uint16) (Endpoint, error) {
	if !e.IsValid() {
		return Endpoint{}, fmt.Errorf("%w: 禁止修改无效 Endpoint 的端口", ErrInvalidEndpoint)
	}
	return NewEndpoint(e.addr.Host(), port)
}

// String 返回规范化 "<host>:<port>"（IPv6 自动加方括号）文本；无效零值返回空串。
func (e Endpoint) String() string {
	return e.addr.String()
}

// KnownHostsKey 返回符合 OpenSSH known_hosts 规范的主机匹配键：
// 默认端口 22 返回无方括号规范主机；非 22 端口一律返回 "[<host>]:<port>"；无效零值返回空串。
func (e Endpoint) KnownHostsKey() string {
	if !e.IsValid() {
		return ""
	}
	hostStr := e.addr.Host().String()
	if e.addr.Port() == DefaultSSHPort {
		return hostStr
	}
	return "[" + hostStr + "]:" + strconv.FormatUint(uint64(e.addr.Port()), 10)
}

// Equal 严格比对两个 Endpoint 是否均有效且规范化主机与端口均相等（无效零值永不相等）。
func (e Endpoint) Equal(other Endpoint) bool {
	return e.addr.Equal(other.addr)
}

// HostEqual 仅比对两个有效 Endpoint 的规范化主机是否相同（忽略端口；无效零值永不相等）。
//
// 安全警示（INV-E2）：严禁将 HostEqual 用于 Tier-4 OpenSSH 策略作用域、known_hosts 匹配或凭据绑定；
// 凡端口决定安全身份的场景一律必须使用 Equal。HostEqual 仅限显式按主机排除（如批量执行 --exclude）等场景。
func (e Endpoint) HostEqual(other Endpoint) bool {
	if !e.IsValid() || !other.IsValid() {
		return false
	}
	return e.addr.Host().Equal(other.addr.Host())
}

// Compare 定义 Endpoint 上的确定性全序关系（委托底层 HostPort.Compare）。
func (e Endpoint) Compare(other Endpoint) int {
	return e.addr.Compare(other.addr)
}

// AppendText 实现 encoding.TextAppender（值接收者）；对无效零值失败关闭返回 ErrInvalidEndpoint。
func (e Endpoint) AppendText(b []byte) ([]byte, error) {
	if !e.IsValid() {
		return nil, ErrInvalidEndpoint
	}
	return e.addr.AppendText(b)
}

// MarshalText 实现 encoding.TextMarshaler（值接收者），语义与 AppendText(nil) 完全一致。
func (e Endpoint) MarshalText() ([]byte, error) {
	return e.AppendText(nil)
}

// UnmarshalText 实现 encoding.TextUnmarshaler，解析 Endpoint 文本；失败时重置为零值并失败关闭。
func (e *Endpoint) UnmarshalText(text []byte) error {
	if e == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseEndpoint(string(text))
	if err != nil {
		*e = Endpoint{}
		return err
	}
	*e = parsed
	return nil
}
