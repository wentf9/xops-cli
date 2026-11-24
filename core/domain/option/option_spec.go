package option

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

// OptionClass、OptionKey 与 StrictHostKeyCheckingMode 为选项元数据与信任模式枚举；零值失败关闭。
//
//xops:failclosed
type OptionClass uint8

//xops:failclosed
type OptionKey string

//xops:failclosed
type StrictHostKeyCheckingMode uint8

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

func registeredOptionSpecs() [24]OptionSpec {
	return [24]OptionSpec{
		{KeyHostName, "HostName", OptionClassTarget, false}, {KeyPort, "Port", OptionClassTarget, false},
		{KeyUser, "User", OptionClassTarget, false}, {KeyProxyJump, "ProxyJump", OptionClassTarget, false},
		{KeyProxyCommand, "ProxyCommand", OptionClassTarget, true}, {KeyControlMaster, "ControlMaster", OptionClassMux, false},
		{KeyControlPath, "ControlPath", OptionClassMux, false}, {KeyControlPersist, "ControlPersist", OptionClassMux, false},
		{KeyConnectTimeout, "ConnectTimeout", OptionClassTransport, false}, {KeyServerAliveInterval, "ServerAliveInterval", OptionClassTransport, false},
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
func (k OptionKey) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *OptionKey) UnmarshalText(text []byte) error {
	return unmarshalTextVia(k, text, parseOptionKey)
}
func parseOptionKey(s string) (OptionKey, error) {
	if key, ok := CanonicalOptionKey(s); ok {
		return key, nil
	}
	return OptionKeyInvalid, fmt.Errorf("%w: %q", ErrUnknownOption, s)
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
	return StrictHostKeyCheckingUnset, fmt.Errorf("%w: 无效 StrictHostKeyChecking %q", ErrInvalidOption, raw)
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

// Username 表示经严格校验的 SSH 用户名值对象；零值恒无效。
//
//xops:opaque
//xops:failclosed
type Username struct {
	raw   string
	valid bool
}

// ParseUsername 校验 SSH 用户名（拒绝空白、控制字符、'.'/'..'、'/'、':'、'['、']'、'@'、前导 '-' 与 Shell 元字符）。
func ParseUsername(raw string) (Username, error) {
	if hasAnySpaceOrControl(raw) || raw == "" || len(raw) > maxTokenLen ||
		raw == "." || raw == ".." || raw[0] == '-' || strings.ContainsAny(raw, "@/:[]"+forbiddenHopShellChars) {
		return Username{}, fmt.Errorf("%w: 无效用户名 %q", ErrInvalidOption, raw)
	}
	return Username{raw, true}, nil
}
func (u Username) IsValid() bool         { return u.valid }
func (u Username) IsZero() bool          { return !u.valid }
func (u Username) String() string        { return u.raw }
func (u Username) Equal(o Username) bool { return u.valid && o.valid && u.raw == o.raw }
func (u Username) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, u.raw, u.valid, ErrInvalidOption)
}
func (u Username) MarshalText() ([]byte, error)     { return u.AppendText(nil) }
func (u *Username) UnmarshalText(text []byte) error { return unmarshalTextVia(u, text, ParseUsername) }

// HostNameSpec 表示 OpenSSH HostName 指令值（规范字面主机或 %h 模板，字面 '%' 统一按 '%%' 规范化存储）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type HostNameSpec struct {
	raw   string
	valid bool
}

// ParseHostNameSpec 按 OpenSSH 模板语法解析 HostName（仅允许 %% 与 %h；含 %h 时探针校验，字面主机经 % -> %% 规范存储）。
func ParseHostNameSpec(raw string) (HostNameSpec, error) {
	if hasAnySpaceOrControl(raw) || raw == "" || len(raw) > maxTokenLen || raw[0] == '-' {
		return HostNameSpec{}, fmt.Errorf("%w: 无效 HostName %q", ErrInvalidOption, raw)
	}
	if err := validateTemplateTokens(raw, "%h", false); err != nil {
		return HostNameSpec{}, fmt.Errorf("%w: HostName 模板非法: %w", ErrInvalidOption, err)
	}
	if strings.Contains(strings.ReplaceAll(raw, "%%", ""), "%h") {
		if _, err := netaddr.ParseCanonicalHost(strings.NewReplacer("%%", "%", "%h", "host").Replace(raw)); err != nil {
			return HostNameSpec{}, fmt.Errorf("%w: HostName 模板校验失败: %w", ErrInvalidOption, err)
		}
		return HostNameSpec{raw, true}, nil
	}
	ch, err := netaddr.ParseCanonicalHost(strings.ReplaceAll(raw, "%%", "%"))
	if err != nil {
		return HostNameSpec{}, fmt.Errorf("%w: %w", ErrInvalidOption, err)
	}
	return HostNameSpec{strings.ReplaceAll(ch.String(), "%", "%%"), true}, nil
}

// HostNameSpecFromHost 由已校验字面 netaddr.CanonicalHost 构造 HostNameSpec（% -> %% 规范存储，保证带区 IPv6 双射往返）。
func HostNameSpecFromHost(host netaddr.CanonicalHost) (HostNameSpec, error) {
	if !host.IsValid() {
		return HostNameSpec{}, fmt.Errorf("%w: 无效 CanonicalHost", ErrInvalidOption)
	}
	return HostNameSpec{strings.ReplaceAll(host.String(), "%", "%%"), true}, nil
}

// ResolveHost 将 HostNameSpec 基于 origHost 展开并校验为规范 netaddr.CanonicalHost。
func (h HostNameSpec) ResolveHost(origHost netaddr.CanonicalHost) (netaddr.CanonicalHost, error) {
	if !h.valid || !origHost.IsValid() {
		var zero netaddr.CanonicalHost
		return zero, ErrInvalidOption
	}
	return netaddr.ParseCanonicalHost(strings.NewReplacer("%%", "%", "%h", origHost.String()).Replace(h.raw))
}
func (h HostNameSpec) IsValid() bool             { return h.valid }
func (h HostNameSpec) IsZero() bool              { return !h.valid }
func (h HostNameSpec) String() string            { return h.raw }
func (h HostNameSpec) Equal(o HostNameSpec) bool { return h.valid && o.valid && h.raw == o.raw }
func (h HostNameSpec) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, h.raw, h.valid, ErrInvalidOption)
}
func (h HostNameSpec) MarshalText() ([]byte, error) { return h.AppendText(nil) }
func (h *HostNameSpec) UnmarshalText(text []byte) error {
	return unmarshalTextVia(h, text, ParseHostNameSpec)
}

func parseStrictPortNumber(raw string) (uint16, error) {
	if raw == "" || raw[0] == '0' || strings.IndexFunc(raw, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, fmt.Errorf("%w: 端口 %q 格式非法", ErrInvalidOption, raw)
	}
	v, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("%w: 端口 %q 超出 [1, 65535]", ErrInvalidOption, raw)
	}
	return uint16(v), nil
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
