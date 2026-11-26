// Package targetparse 提供纯无状态的 SSH 目标字符串解析与 CLI ProxyJump 上游选项投影（INV-D3），
// 供 core/internal/usecase/inventory 在目标解析与多跳跳板展开中复用。
package targetparse

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
)

const maxRawTargetBytes = 512

// ParsedTarget 保存解析 [user@]host[:port] 或 OpenSSH 别名后得到的强类型原始目标要素。
type ParsedTarget struct {
	User     algebraic.Option[option.Username]
	OrigHost option.OriginalHostSpec
	Port     algebraic.Option[uint16]
}

// InlineLayer 将解析得到的行内用户名与端口投影为最高优先级 OptionLayer。
func (p ParsedTarget) InlineLayer() option.OptionLayer {
	layer := option.UnsetOptionLayer()
	if u, ok := p.User.Get(); ok {
		layer = layer.WithUser(u)
	}
	if port, ok := p.Port.Get(); ok {
		layer = layer.WithPort(port)
	}
	return layer
}

// ParseSpec 解析用户传入的目标字符串（支持 [user@]host[:port]、[ipv6][:port]、裸 IPv6 与 OpenSSH 别名），
// 严格拒绝空串、空白、控制/格式字符、多个 '@' 与前导零/越界端口。
func ParseSpec(raw string, invalidErr error) (ParsedTarget, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > maxRawTargetBytes || hasForbiddenTargetChars(raw) || strings.ContainsFunc(trimmed, unicode.IsSpace) {
		return ParsedTarget{}, fmt.Errorf("%w: %q 为空、超长或包含非法空白/控制字符", invalidErr, raw)
	}
	userOpt, hostPart, err := splitTargetUser(trimmed, invalidErr)
	var origHost option.OriginalHostSpec
	var portOpt algebraic.Option[uint16]
	if err == nil {
		origHost, portOpt, err = parseTargetHostPort(hostPart, trimmed, invalidErr)
	}
	return ParsedTarget{User: userOpt, OrigHost: origHost, Port: portOpt}, err
}

// ParseHopSpec 将已校验的 option.HopTarget 转换为统一的 ParsedTarget 供递归跳板解析复用。
func ParseHopSpec(h option.HopTarget, invalidErr error) (pt ParsedTarget, err error) {
	if !h.IsValid() {
		return pt, fmt.Errorf("%w: 无效 ProxyJump HopTarget", invalidErr)
	}
	if h.User() != "" {
		u, uErr := option.ParseUsername(h.User())
		if uErr != nil {
			return pt, fmt.Errorf("%w: 跳板用户名非法: %w", invalidErr, uErr)
		}
		pt.User = algebraic.Some(u)
	}
	if pt.OrigHost, err = option.ParseOriginalHost(h.Host()); err != nil {
		return ParsedTarget{}, fmt.Errorf("%w: 跳板主机 %q 非法: %w", invalidErr, h.Host(), err)
	}
	if p, ok := h.Port(); ok {
		pt.Port = algebraic.Some(p)
	}
	return pt, nil
}

func splitTargetUser(trimmed string, invalidErr error) (algebraic.Option[option.Username], string, error) {
	userPart, hostPart, hasAt := strings.Cut(trimmed, "@")
	if !hasAt {
		return algebraic.None[option.Username](), trimmed, nil
	}
	if userPart == "" || hostPart == "" || strings.ContainsRune(hostPart, '@') {
		return algebraic.None[option.Username](), "", fmt.Errorf("%w: 目标 %q 含空用户/空主机或重复 '@'", invalidErr, trimmed)
	}
	u, err := option.ParseUsername(userPart)
	if err != nil {
		return algebraic.None[option.Username](), "", fmt.Errorf("%w: %w", invalidErr, err)
	}
	return algebraic.Some(u), hostPart, nil
}

func parseIPv6OriginalHost(raw, errMsg string, invalidErr error) (z option.OriginalHostSpec, err error) {
	ch, err := netaddr.ParseCanonicalHost(raw)
	if err != nil || !ch.IsIPv6() {
		return z, fmt.Errorf("%w: %s", invalidErr, errMsg)
	}
	orig, oErr := option.OriginalHostFromCanonical(ch)
	if oErr != nil {
		return z, fmt.Errorf("%w: %w", invalidErr, oErr)
	}
	return orig, nil
}

func parseTargetHostPort(hostPart, full string, invalidErr error) (z option.OriginalHostSpec, nonePort algebraic.Option[uint16], err error) {
	switch {
	case hostPart == "":
		return z, nonePort, fmt.Errorf("%w: 目标 %q 缺少主机段", invalidErr, full)
	case hostPart[0] == '[':
		return parseBracketedTargetHostPort(hostPart, full, invalidErr)
	case strings.ContainsAny(hostPart, "[]"):
		return z, nonePort, fmt.Errorf("%w: 目标 %q 包含非法方括号", invalidErr, full)
	}
	switch strings.Count(hostPart, ":") {
	case 0:
		orig, err := option.ParseOriginalHost(hostPart)
		if err != nil {
			return z, nonePort, fmt.Errorf("%w: %w", invalidErr, err)
		}
		return orig, nonePort, nil
	case 1:
		h, pStr, _ := strings.Cut(hostPart, ":")
		orig, err := option.ParseOriginalHost(h)
		var p uint16
		if err == nil {
			p, err = parseStrictTargetPort(pStr)
		}
		if err != nil {
			return z, nonePort, fmt.Errorf("%w: %w", invalidErr, err)
		}
		return orig, algebraic.Some(p), nil
	default:
		// 含两个及以上冒号时仅接受合法裸 IPv6 字面量（含可选 %zone，不带显式端口）。
		orig, err := parseIPv6OriginalHost(hostPart, fmt.Sprintf("目标 %q 既非合法 IPv6 也非规范 host:port", full), invalidErr)
		return orig, nonePort, err
	}
}

func parseBracketedTargetHostPort(hostPart, full string, invalidErr error) (z option.OriginalHostSpec, nonePort algebraic.Option[uint16], err error) {
	closeIdx := strings.IndexByte(hostPart, ']')
	if closeIdx < 2 {
		return z, nonePort, fmt.Errorf("%w: 目标 %q 方括号畸形", invalidErr, full)
	}
	orig, err := parseIPv6OriginalHost(hostPart[:closeIdx+1], fmt.Sprintf("目标 %q 方括号内必须为合法 IPv6 地址", full), invalidErr)
	if err != nil {
		return z, nonePort, err
	}
	rest := hostPart[closeIdx+1:]
	if rest == "" {
		return orig, nonePort, nil
	}
	if rest[0] != ':' {
		return z, nonePort, fmt.Errorf("%w: 目标 %q 方括号后存在非法后缀", invalidErr, full)
	}
	p, err := parseStrictTargetPort(rest[1:])
	if err != nil {
		return z, nonePort, fmt.Errorf("%w: %w", invalidErr, err)
	}
	return orig, algebraic.Some(p), nil
}

func parseStrictTargetPort(raw string) (uint16, error) {
	if raw == "" || raw[0] == '0' {
		return 0, fmt.Errorf("端口 %q 不能为空或含前导零", raw)
	}
	for i := range len(raw) {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, fmt.Errorf("端口 %q 含非数字字符", raw)
		}
	}
	v, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("端口 %q 超出 [1, 65535] 范围", raw)
	}
	return uint16(v), nil
}

func hasForbiddenTargetChars(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
	})
}

// ExtractCLIJumpPolicy 提取依 INV-D3 须对全部 ProxyJump 上游跳板（含虚拟与临时跳板）生效的
// CLI 安全、非交互、信任库与传输算法覆写，绝不污染目标专用 HostName/Port/User/Proxy/SendEnv/LocalCommand。
func ExtractCLIJumpPolicy(cli option.OptionLayer) option.OptionLayer {
	out := option.UnsetOptionLayer().WithUserKnownHostsFiles(cli.UserKnownHostsFiles()).
		WithCiphers(cli.Ciphers()).WithMACs(cli.MACs()).WithKexAlgorithms(cli.KexAlgorithms()).WithHostKeyAlgorithms(cli.HostKeyAlgorithms())
	if v, ok := cli.BatchMode().Get(); ok {
		out = out.WithBatchMode(v)
	}
	if v, ok := cli.StrictHostKeyChecking().Get(); ok {
		out = out.WithStrictHostKeyChecking(v)
	}
	if v, ok := cli.ConnectTimeout().Get(); ok {
		out = out.WithConnectTimeout(v)
	}
	return out
}

// ExtractCLIJumpAuthFallback 仅提取供临时 AdHoc ProxyJump 跳板兜底复用的 CLI 密钥认证项，
// 避免覆盖 OpenSSH 虚拟跳板在 ~/.ssh/config 中显式绑定的 IdentityFile/CertificateFile/IdentitiesOnly。
func ExtractCLIJumpAuthFallback(cli option.OptionLayer) option.OptionLayer {
	out := option.UnsetOptionLayer().WithIdentityFiles(cli.IdentityFiles()).WithCertificateFiles(cli.CertificateFiles())
	if v, ok := cli.IdentitiesOnly().Get(); ok {
		out = out.WithIdentitiesOnly(v)
	}
	return out
}
