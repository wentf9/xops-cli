package inventory

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

// parsedTarget 保存解析 [user@]host[:port] 或 OpenSSH 别名后得到的强类型原始目标要素。
type parsedTarget struct {
	user     algebraic.Option[option.Username]
	origHost option.OriginalHostSpec
	port     algebraic.Option[uint16]
}

// parseTargetSpec 解析用户传入的目标字符串（支持 [user@]host[:port]、[ipv6][:port]、裸 IPv6 与 OpenSSH 别名），
// 严格拒绝空串、空白、控制/格式字符、多个 '@' 与前导零/越界端口。
func parseTargetSpec(raw string) (parsedTarget, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > maxRawTargetBytes || hasForbiddenTargetChars(raw) || strings.ContainsFunc(trimmed, unicode.IsSpace) {
		return parsedTarget{}, fmt.Errorf("%w: %q 为空、超长或包含非法空白/控制字符", ErrInvalidTarget, raw)
	}
	userOpt, hostPart, err := splitTargetUser(trimmed)
	if err != nil {
		return parsedTarget{}, err
	}
	origHost, portOpt, err := parseTargetHostPort(hostPart, trimmed)
	if err != nil {
		return parsedTarget{}, err
	}
	return parsedTarget{user: userOpt, origHost: origHost, port: portOpt}, nil
}

// parseHopTargetSpec 将已校验的 option.HopTarget 转换为统一的 parsedTarget 供递归跳板解析复用。
func parseHopTargetSpec(h option.HopTarget) (parsedTarget, error) {
	if !h.IsValid() {
		return parsedTarget{}, fmt.Errorf("%w: 无效 ProxyJump HopTarget", ErrInvalidTarget)
	}
	var userOpt algebraic.Option[option.Username]
	if h.User() != "" {
		u, err := option.ParseUsername(h.User())
		if err != nil {
			return parsedTarget{}, fmt.Errorf("%w: 跳板用户名非法: %w", ErrInvalidTarget, err)
		}
		userOpt = algebraic.Some(u)
	}
	origHost, err := option.ParseOriginalHost(h.Host())
	if err != nil {
		return parsedTarget{}, fmt.Errorf("%w: 跳板主机 %q 非法: %w", ErrInvalidTarget, h.Host(), err)
	}
	var portOpt algebraic.Option[uint16]
	if p, ok := h.Port(); ok {
		portOpt = algebraic.Some(p)
	}
	return parsedTarget{user: userOpt, origHost: origHost, port: portOpt}, nil
}

func splitTargetUser(trimmed string) (algebraic.Option[option.Username], string, error) {
	userPart, hostPart, hasAt := strings.Cut(trimmed, "@")
	if !hasAt {
		return algebraic.None[option.Username](), trimmed, nil
	}
	if userPart == "" || hostPart == "" || strings.ContainsRune(hostPart, '@') {
		return algebraic.None[option.Username](), "", fmt.Errorf("%w: 目标 %q 含空用户/空主机或重复 '@'", ErrInvalidTarget, trimmed)
	}
	u, err := option.ParseUsername(userPart)
	if err != nil {
		return algebraic.None[option.Username](), "", fmt.Errorf("%w: %w", ErrInvalidTarget, err)
	}
	return algebraic.Some(u), hostPart, nil
}

func parseTargetHostPort(hostPart, full string) (option.OriginalHostSpec, algebraic.Option[uint16], error) {
	var zeroHost option.OriginalHostSpec
	nonePort := algebraic.None[uint16]()
	if hostPart == "" {
		return zeroHost, nonePort, fmt.Errorf("%w: 目标 %q 缺少主机段", ErrInvalidTarget, full)
	}
	if hostPart[0] == '[' {
		return parseBracketedTargetHostPort(hostPart, full)
	}
	if strings.ContainsAny(hostPart, "[]") {
		return zeroHost, nonePort, fmt.Errorf("%w: 目标 %q 包含非法方括号", ErrInvalidTarget, full)
	}
	switch strings.Count(hostPart, ":") {
	case 0:
		orig, err := option.ParseOriginalHost(hostPart)
		if err != nil {
			return zeroHost, nonePort, fmt.Errorf("%w: %w", ErrInvalidTarget, err)
		}
		return orig, nonePort, nil
	case 1:
		h, pStr, _ := strings.Cut(hostPart, ":")
		orig, err := option.ParseOriginalHost(h)
		if err != nil {
			return zeroHost, nonePort, fmt.Errorf("%w: %w", ErrInvalidTarget, err)
		}
		p, err := parseStrictTargetPort(pStr)
		if err != nil {
			return zeroHost, nonePort, fmt.Errorf("%w: %w", ErrInvalidTarget, err)
		}
		return orig, algebraic.Some(p), nil
	default:
		// 含两个及以上冒号时仅接受合法裸 IPv6 字面量（含可选 %zone，不带显式端口）。
		ch, err := netaddr.ParseCanonicalHost(hostPart)
		if err != nil || !ch.IsIPv6() {
			return zeroHost, nonePort, fmt.Errorf("%w: 目标 %q 既非合法 IPv6 也非规范 host:port", ErrInvalidTarget, full)
		}
		orig, err := option.OriginalHostFromCanonical(ch)
		if err != nil {
			return zeroHost, nonePort, fmt.Errorf("%w: %w", ErrInvalidTarget, err)
		}
		return orig, nonePort, nil
	}
}

func parseBracketedTargetHostPort(hostPart, full string) (option.OriginalHostSpec, algebraic.Option[uint16], error) {
	var zeroHost option.OriginalHostSpec
	nonePort := algebraic.None[uint16]()
	closeIdx := strings.IndexByte(hostPart, ']')
	if closeIdx < 2 {
		return zeroHost, nonePort, fmt.Errorf("%w: 目标 %q 方括号畸形", ErrInvalidTarget, full)
	}
	ch, err := netaddr.ParseCanonicalHost(hostPart[:closeIdx+1])
	if err != nil || !ch.IsIPv6() {
		return zeroHost, nonePort, fmt.Errorf("%w: 目标 %q 方括号内必须为合法 IPv6 地址", ErrInvalidTarget, full)
	}
	orig, err := option.OriginalHostFromCanonical(ch)
	if err != nil {
		return zeroHost, nonePort, fmt.Errorf("%w: %w", ErrInvalidTarget, err)
	}
	rest := hostPart[closeIdx+1:]
	if rest == "" {
		return orig, nonePort, nil
	}
	if rest[0] != ':' {
		return zeroHost, nonePort, fmt.Errorf("%w: 目标 %q 方括号后存在非法后缀", ErrInvalidTarget, full)
	}
	p, err := parseStrictTargetPort(rest[1:])
	if err != nil {
		return zeroHost, nonePort, fmt.Errorf("%w: %w", ErrInvalidTarget, err)
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
	if !utf8.ValidString(s) {
		return true
	}
	return strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
	})
}

func (p parsedTarget) inlineLayer() option.OptionLayer {
	layer := option.UnsetOptionLayer()
	if u, ok := p.user.Get(); ok {
		layer = layer.WithUser(u)
	}
	if port, ok := p.port.Get(); ok {
		layer = layer.WithPort(port)
	}
	return layer
}

// extractCLIJumpPolicy 提取依 INV-D3 须对全部 ProxyJump 上游跳板（含虚拟与临时跳板）生效的
// CLI 安全、非交互、信任库与传输算法覆写，绝不污染目标专用 HostName/Port/User/Proxy/SendEnv/LocalCommand。
func extractCLIJumpPolicy(cli option.OptionLayer) option.OptionLayer {
	out := option.UnsetOptionLayer().
		WithUserKnownHostsFiles(cli.UserKnownHostsFiles()).
		WithCiphers(cli.Ciphers()).
		WithMACs(cli.MACs()).
		WithKexAlgorithms(cli.KexAlgorithms()).
		WithHostKeyAlgorithms(cli.HostKeyAlgorithms())
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

// extractCLIJumpAuthFallback 仅提取供临时 AdHoc ProxyJump 跳板兜底复用的 CLI 密钥认证项，
// 避免覆盖 OpenSSH 虚拟跳板在 ~/.ssh/config 中显式绑定的 IdentityFile/CertificateFile/IdentitiesOnly。
func extractCLIJumpAuthFallback(cli option.OptionLayer) option.OptionLayer {
	out := option.UnsetOptionLayer().
		WithIdentityFiles(cli.IdentityFiles()).
		WithCertificateFiles(cli.CertificateFiles())
	if v, ok := cli.IdentitiesOnly().Get(); ok {
		out = out.WithIdentitiesOnly(v)
	}
	return out
}
