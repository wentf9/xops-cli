package option

import (
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

// OptionClass、OptionKey 与 StrictHostKeyCheckingMode 为选项元数据与信任模式枚举；零值失败关闭。
type (
	//xops:failclosed
	OptionClass uint8
	//xops:failclosed
	OptionKey string
	//xops:failclosed
	StrictHostKeyCheckingMode uint8
)

const (
	OptionClassInvalid OptionClass = iota
	OptionClassTarget
	OptionClassMux
	OptionClassTransport
	OptionClassAuth
	OptionClassTrust
	OptionClassForward
	OptionClassSession
	OptionClassLocalExec
)
const (
	StrictHostKeyCheckingUnset StrictHostKeyCheckingMode = iota
	StrictHostKeyCheckingYes
	StrictHostKeyCheckingNo
	StrictHostKeyCheckingAsk
	StrictHostKeyCheckingAcceptNew
)
const (
	OptionKeyInvalid         OptionKey = ""
	KeyHostName              OptionKey = "hostname"
	KeyPort                  OptionKey = "port"
	KeyUser                  OptionKey = "user"
	KeyProxyJump             OptionKey = "proxy_jump"
	KeyProxyCommand          OptionKey = "proxy_command"
	KeyControlMaster         OptionKey = "control_master"
	KeyControlPath           OptionKey = "control_path"
	KeyControlPersist        OptionKey = "control_persist"
	KeyConnectTimeout        OptionKey = "connect_timeout"
	KeyServerAliveInterval   OptionKey = "server_alive_interval"
	KeyServerAliveCountMax   OptionKey = "server_alive_count_max"
	KeyCiphers               OptionKey = "ciphers"
	KeyMACs                  OptionKey = "macs"
	KeyKexAlgorithms         OptionKey = "kex_algorithms"
	KeyHostKeyAlgorithms     OptionKey = "host_key_algorithms"
	KeyIdentityFile          OptionKey = "identity_file"
	KeyCertificateFile       OptionKey = "certificate_file"
	KeyIdentitiesOnly        OptionKey = "identities_only"
	KeyBatchMode             OptionKey = "batch_mode"
	KeyStrictHostKeyChecking OptionKey = "strict_host_key_checking"
	KeyUserKnownHostsFile    OptionKey = "user_known_hosts_file"
	KeyForwardAgent          OptionKey = "forward_agent"
	KeySendEnv               OptionKey = "send_env"
	KeyPermitLocalCommand    OptionKey = "permit_local_command"
	KeyLocalCommand          OptionKey = "local_command"
)

// OptionSpec 描述单个已注册 OpenSSH 选项的元数据。
type OptionSpec struct {
	Key              OptionKey   // 规范化 snake_case 键名
	OpenSSHName      string      // 标准 OpenSSH ssh_config(5) 关键字
	Class            OptionClass // 所属安全与功能分类
	WholeLineCommand bool        // 指示值保留整行命令语义
}

func registeredOptionSpecs() [25]OptionSpec {
	return [25]OptionSpec{
		{KeyHostName, "HostName", OptionClassTarget, false}, {KeyPort, "Port", OptionClassTarget, false},
		{KeyUser, "User", OptionClassTarget, false}, {KeyProxyJump, "ProxyJump", OptionClassTarget, false},
		{KeyProxyCommand, "ProxyCommand", OptionClassTarget, true}, {KeyControlMaster, "ControlMaster", OptionClassMux, false},
		{KeyControlPath, "ControlPath", OptionClassMux, false}, {KeyControlPersist, "ControlPersist", OptionClassMux, false},
		{KeyConnectTimeout, "ConnectTimeout", OptionClassTransport, false}, {KeyServerAliveInterval, "ServerAliveInterval", OptionClassTransport, false},
		{KeyServerAliveCountMax, "ServerAliveCountMax", OptionClassTransport, false},
		{KeyCiphers, "Ciphers", OptionClassTransport, false}, {KeyMACs, "MACs", OptionClassTransport, false},
		{KeyKexAlgorithms, "KexAlgorithms", OptionClassTransport, false}, {KeyHostKeyAlgorithms, "HostKeyAlgorithms", OptionClassTransport, false},
		{KeyIdentityFile, "IdentityFile", OptionClassAuth, false}, {KeyCertificateFile, "CertificateFile", OptionClassAuth, false},
		{KeyIdentitiesOnly, "IdentitiesOnly", OptionClassAuth, false}, {KeyBatchMode, "BatchMode", OptionClassAuth, false},
		{KeyStrictHostKeyChecking, "StrictHostKeyChecking", OptionClassTrust, false}, {KeyUserKnownHostsFile, "UserKnownHostsFile", OptionClassTrust, false},
		{KeyForwardAgent, "ForwardAgent", OptionClassForward, false}, {KeySendEnv, "SendEnv", OptionClassSession, false},
		{KeyPermitLocalCommand, "PermitLocalCommand", OptionClassLocalExec, false}, {KeyLocalCommand, "LocalCommand", OptionClassLocalExec, true},
	}
}

// CanonicalOptionKey 与 LookupOptionSpec 提供已注册 OpenSSH 选项的归一化与元数据查询。
func CanonicalOptionKey(raw string) (OptionKey, bool) {
	t := strings.TrimSpace(raw)
	if !hasForbiddenControlChar(raw) && t != "" && len(t) <= 64 {
		for _, spec := range registeredOptionSpecs() {
			if strings.EqualFold(t, spec.OpenSSHName) || strings.EqualFold(t, string(spec.Key)) {
				return spec.Key, true
			}
		}
	}
	return OptionKeyInvalid, false
}
func LookupOptionSpec(key OptionKey) (OptionSpec, bool) {
	for _, spec := range registeredOptionSpecs() {
		if key != OptionKeyInvalid && spec.Key == key {
			return spec, true
		}
	}
	return OptionSpec{}, false
}

// OptionKey 校验与文本编解码方法。
func (k OptionKey) IsValid() bool { _, ok := LookupOptionSpec(k); return ok }
func (k OptionKey) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, string(k), k.IsValid(), ErrUnknownOption)
}
func (k OptionKey) MarshalText() ([]byte, error)  { return k.AppendText(nil) }
func (k *OptionKey) UnmarshalText(t []byte) error { return unmarshalTextVia(k, t, parseOptionKey) }
func parseOptionKey(s string) (OptionKey, error) {
	if key, ok := CanonicalOptionKey(s); ok {
		return key, nil
	}
	return OptionKeyInvalid, domi18n.EF(ErrUnknownOption, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "option"), domi18n.BoundStr("value", s))
}

// ParseStrictHostKeyChecking 解析 StrictHostKeyChecking（yes/no/ask/accept-new），拒绝控制与格式字符。
func ParseStrictHostKeyChecking(raw string) (StrictHostKeyCheckingMode, error) {
	if !hasForbiddenControlChar(raw) {
		if m, ok := map[string]StrictHostKeyCheckingMode{
			"yes": StrictHostKeyCheckingYes, "true": StrictHostKeyCheckingYes,
			"no": StrictHostKeyCheckingNo, "false": StrictHostKeyCheckingNo, "off": StrictHostKeyCheckingNo,
			"ask": StrictHostKeyCheckingAsk, "accept-new": StrictHostKeyCheckingAcceptNew,
		}[strings.ToLower(strings.TrimSpace(raw))]; ok {
			return m, nil
		}
	}
	return StrictHostKeyCheckingUnset, domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "strict_host_key_checking"), domi18n.BoundStr("value", raw))
}
func (m StrictHostKeyCheckingMode) String() string {
	return enumName(uint8(m), "yes", "no", "ask", "accept-new")
}
func (m StrictHostKeyCheckingMode) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, m.String(), m.String() != "", ErrInvalidOption)
}
func (m StrictHostKeyCheckingMode) MarshalText() ([]byte, error) { return m.AppendText(nil) }
func (m *StrictHostKeyCheckingMode) UnmarshalText(text []byte) error {
	return unmarshalTextVia(m, text, ParseStrictHostKeyChecking)
}

type textToken struct {
	raw   string
	valid bool
}

func (t textToken) IsValid() bool  { return t.valid }
func (t textToken) IsZero() bool   { return !t.valid }
func (t textToken) String() string { return t.raw }
func (t textToken) app(b []byte, err error) ([]byte, error) {
	return appendValidText(b, t.raw, t.valid, err)
}

// Username 表示经严格校验的 SSH 用户名值对象；零值恒无效。
//
//xops:opaque
//xops:failclosed
type Username struct{ textToken }

// ParseUsername 校验 SSH 用户名（拒绝空白、控制字符、'.'/'..'、'/'、':'、'['、']'、'@'、前导 '-' 与 Shell 元字符）。
func ParseUsername(raw string) (Username, error) {
	if hasAnySpaceOrControl(raw) || raw == "" || len(raw) > maxTokenLen ||
		raw == "." || raw == ".." || raw[0] == '-' || strings.ContainsAny(raw, "@/:[]"+forbiddenHopShellChars) {
		return Username{}, domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "username"), domi18n.BoundStr("value", raw))
	}
	return Username{textToken{raw, true}}, nil
}
func (u Username) Equal(o Username) bool               { return u.valid && o.valid && u.raw == o.raw }
func (u Username) AppendText(b []byte) ([]byte, error) { return u.app(b, ErrInvalidOption) }
func (u Username) MarshalText() ([]byte, error)        { return u.AppendText(nil) }
func (u *Username) UnmarshalText(t []byte) error       { return unmarshalTextVia(u, t, ParseUsername) }

// HostNameSpec 表示 OpenSSH HostName 指令值（规范字面主机或 %h 模板，字面 '%' 统一按 '%%' 规范化存储）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type HostNameSpec struct{ textToken }

// ParseHostNameSpec 按 OpenSSH 模板语法解析 HostName（仅允许 %% 与 %h；含 %h 时探针校验，字面主机经 % -> %% 规范存储）。
func ParseHostNameSpec(raw string) (HostNameSpec, error) {
	if hasAnySpaceOrControl(raw) || raw == "" || len(raw) > maxTokenLen || raw[0] == '-' {
		return HostNameSpec{}, domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "hostname"), domi18n.BoundStr("value", raw))
	}
	if err := validateTemplateTokens(raw, "%h", false); err != nil {
		return HostNameSpec{}, domi18n.WrapS(ErrInvalidOption, err, domi18n.KeyOptionTemplateInvalid, domi18n.Str("option", "HostName"))
	}
	if strings.Contains(strings.ReplaceAll(raw, "%%", ""), "%h") {
		if _, err := netaddr.ParseCanonicalHost(strings.NewReplacer("%%", "%", "%h", "host").Replace(raw)); err != nil {
			return HostNameSpec{}, domi18n.WrapS(ErrInvalidOption, err, domi18n.KeyOptionTemplateInvalid, domi18n.Str("option", "HostName"))
		}
		return HostNameSpec{textToken{raw, true}}, nil
	}
	ch, err := netaddr.ParseCanonicalHost(strings.ReplaceAll(raw, "%%", "%"))
	if err != nil {
		return HostNameSpec{}, domi18n.WrapSentinel(ErrInvalidOption, err)
	}
	return HostNameSpec{textToken{strings.ReplaceAll(ch.String(), "%", "%%"), true}}, nil
}

// HostNameSpecFromHost 由已校验字面 netaddr.CanonicalHost 构造 HostNameSpec（% -> %% 规范存储，保证带区 IPv6 双射往返）。
func HostNameSpecFromHost(host netaddr.CanonicalHost) (HostNameSpec, error) {
	if !host.IsValid() {
		return HostNameSpec{}, domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "hostname"))
	}
	return HostNameSpec{textToken{strings.ReplaceAll(host.String(), "%", "%%"), true}}, nil
}

// OriginalHostSpec 表示经严格校验的 SSH 原始主机名、IP 或 OpenSSH Host 别名（供 %n 展开与审计留痕）。
// 允许规范 IP（含带区 IPv6）、规范 DNS 及合法非 IP OpenSSH/NodeID 别名（保留大小写，如 "prod_db"、"bastion.01"）；
// 严格拒绝控制/空白/Shell 元字符、保留字 "none"、前导 '-'、尾随 '.' 与畸形数值 SSRF IP 形态；零值恒无效。
//
//xops:opaque
//xops:failclosed
type OriginalHostSpec struct {
	textToken
	canon algebraic.Option[netaddr.CanonicalHost]
}

// ParseOriginalHost 校验并构造原始主机/别名值对象（IP 字面量规范化，非 IP 别名保留大小写）。
func ParseOriginalHost(raw string) (OriginalHostSpec, error) {
	if raw == "" || len(raw) > maxTokenLen || hasAnySpaceOrControl(raw) {
		return OriginalHostSpec{}, domi18n.EF(ErrInvalidEndpoint, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "original_host"), domi18n.BoundStr("value", raw))
	}
	if ch, err := netaddr.ParseCanonicalHost(raw); err == nil && ch.IsIP() {
		return OriginalHostSpec{textToken{ch.String(), true}, algebraic.Some(ch)}, nil
	}
	h, err := parsePlainHostOrAlias(raw, raw, ErrInvalidEndpoint)
	if err != nil {
		return OriginalHostSpec{}, err
	}
	var canon algebraic.Option[netaddr.CanonicalHost]
	if ch, err := netaddr.ParseCanonicalHost(h); err == nil {
		canon = algebraic.Some(ch)
	}
	return OriginalHostSpec{textToken{h, true}, canon}, nil
}

// OriginalHostFromCanonical 由已校验的 netaddr.CanonicalHost 构造 OriginalHostSpec。
func OriginalHostFromCanonical(host netaddr.CanonicalHost) (OriginalHostSpec, error) {
	if !host.IsValid() {
		return OriginalHostSpec{}, ErrInvalidEndpoint
	}
	return OriginalHostSpec{textToken{host.String(), true}, algebraic.Some(host)}, nil
}

// OriginalHostSpec 只读访问器与文本编解码方法。
func (h OriginalHostSpec) Equal(o OriginalHostSpec) bool                { return h.valid && o.valid && h.raw == o.raw }
func (h OriginalHostSpec) CanonicalHost() (netaddr.CanonicalHost, bool) { return h.canon.Get() }
func (h OriginalHostSpec) AppendText(b []byte) ([]byte, error)          { return h.app(b, ErrInvalidEndpoint) }
func (h OriginalHostSpec) MarshalText() ([]byte, error)                 { return h.AppendText(nil) }
func (h *OriginalHostSpec) UnmarshalText(t []byte) error {
	return unmarshalTextVia(h, t, ParseOriginalHost)
}

// ResolveHost 与 ResolveHostFor 基于规范主机或 OpenSSH 别名展开 HostNameSpec 为 netaddr.CanonicalHost。
func (h HostNameSpec) ResolveHost(origHost netaddr.CanonicalHost) (z netaddr.CanonicalHost, err error) {
	orig, err := OriginalHostFromCanonical(origHost)
	if err != nil {
		return z, ErrInvalidOption
	}
	return h.ResolveHostFor(orig)
}
func (h HostNameSpec) ResolveHostFor(origHost OriginalHostSpec) (z netaddr.CanonicalHost, err error) {
	if !h.valid || !origHost.valid {
		return z, ErrInvalidOption
	}
	return netaddr.ParseCanonicalHost(strings.NewReplacer("%%", "%", "%h", origHost.raw).Replace(h.raw))
}
func (h HostNameSpec) Equal(o HostNameSpec) bool           { return h.valid && o.valid && h.raw == o.raw }
func (h HostNameSpec) AppendText(b []byte) ([]byte, error) { return h.app(b, ErrInvalidOption) }
func (h HostNameSpec) MarshalText() ([]byte, error)        { return h.AppendText(nil) }
func (h *HostNameSpec) UnmarshalText(t []byte) error {
	return unmarshalTextVia(h, t, ParseHostNameSpec)
}

func parseStrictPortNumber(raw string) (uint16, error) {
	v, err := parseStrictUint(raw, 1, 16, "port")
	return uint16(v), err
}
func parseNonNegativeUint32(raw string) (uint32, error) {
	v, err := parseStrictUint(raw, 0, 32, "uint32")
	return uint32(v), err
}
func parseStrictUint(raw string, minVal uint64, bits int, label string) (uint64, error) {
	if raw == "" || (raw[0] == '0' && (minVal > 0 || len(raw) > 1)) || !isAllASCIIDigits(raw) {
		return 0, domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", label), domi18n.BoundStr("value", raw))
	}
	v, err := strconv.ParseUint(raw, 10, bits)
	if err != nil || v < minVal {
		return 0, domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", label), domi18n.BoundStr("value", raw))
	}
	return v, nil
}
func isAllASCIIDigits(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

// DefaultCiphers、DefaultMACs、DefaultKexAlgorithms 与 DefaultHostKeyAlgorithms 返回现代安全默认算法列表副本。
func DefaultCiphers() []string {
	return []string{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"}
}
func DefaultMACs() []string {
	return []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512"}
}
func DefaultKexAlgorithms() []string {
	return []string{"mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group14-sha256"}
}
func DefaultHostKeyAlgorithms() []string {
	return []string{"ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256"}
}
