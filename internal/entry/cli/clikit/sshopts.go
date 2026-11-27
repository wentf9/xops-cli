package clikit

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
)

// ApplyCommonSSHShortOption 解析各远程命令共用的 OpenSSH 短选项（-p/-l/-i/-J/-o/-F）。
// 当 flagChar 属于共用选项集时更新 layer/cfgFile 并返回 (true, nil)；否则返回 (false, nil)。
func ApplyCommonSSHShortOption(cur *FlagCursor, flagChar byte, remainder string, layer *option.OptionLayer, cfgFile *string) (bool, error) {
	switch flagChar {
	case 'p', 'l', 'i', 'J', 'o', 'F':
		val, err := cur.ConsumeShortArg(flagChar, remainder)
		if err != nil {
			return false, err
		}
		return true, applySSHValueFlag(flagChar, val, layer, cfgFile)
	default:
		return false, nil
	}
}

func applySSHValueFlag(flagChar byte, val string, layer *option.OptionLayer, cfgFile *string) error {
	switch flagChar {
	case 'p':
		return ApplyOptionKV(layer, "Port", val, "-p")
	case 'l':
		return ApplyOptionKV(layer, "User", val, "-l")
	case 'J':
		return ApplyOptionKV(layer, "ProxyJump", val, "-J")
	case 'i':
		return ApplyIdentityFile(layer, val)
	case 'o':
		return ApplyRawOption(layer, val)
	case 'F':
		return SetConfigFile(cfgFile, val)
	default:
		return fmt.Errorf("%w: 不支持的 SSH 短选项 -%c", ErrUsage, flagChar)
	}
}

// ApplyOptionKV 使用 core/domain/option 严格解析单条 OpenSSH 键值指令并按序折叠入 Tier-1 选项层。
func ApplyOptionKV(layer *option.OptionLayer, key, val, flagLabel string) error {
	parsed, err := option.ParseOptionKV(key, val)
	if err != nil {
		return fmt.Errorf("%w: %s 参数 %q 非法: %w", ErrUsage, flagLabel, val, err)
	}
	*layer = layer.ApplyParsedOption(parsed)
	return nil
}

// ApplyIdentityFile 直接经 option.ParsePathListEntries 构造并累加入 Tier-1，
// 使含空格的跨平台本地密钥路径（如 Windows 用户目录）与 `-i none` 均能免引号安全解析。
func ApplyIdentityFile(layer *option.OptionLayer, val string) error {
	pl, err := option.ParsePathListEntries([]string{val})
	if err != nil {
		return fmt.Errorf("%w: -i 参数 %q 非法: %w", ErrUsage, val, err)
	}
	*layer = layer.Compose(option.UnsetOptionLayer().WithIdentityFiles(pl))
	return nil
}

// ApplyRawOption 严格经 option.ParseOption 解析 `-o Key=Value` 指令并折叠入 Tier-1。
func ApplyRawOption(layer *option.OptionLayer, directive string) error {
	parsed, err := option.ParseOption(directive)
	if err != nil {
		return fmt.Errorf("%w: -o 选项 %q 无效: %w", ErrUsage, directive, err)
	}
	*layer = layer.ApplyParsedOption(parsed)
	return nil
}

// ParseForwardFlagSpec 按 OpenSSH `-L` / `-R` / `-D` 语法解析强类型 engine.ForwardSpec：
//   - `-D`: `[bind_address:]port`（省略 bind_address 默认 127.0.0.1）；
//   - `-L` / `-R`: `[bind_address:]port:host:hostport`、`[bind_address:]port:remote_socket`、
//     `local_socket:host:hostport`、`local_socket:remote_socket`（完整支持方括号 IPv6 与 StreamLocal 混合端点）。
func ParseForwardFlagSpec(dir engine.ForwardDirection, raw string) (spec engine.ForwardSpec, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return spec, fmt.Errorf("%w: 转发规格不能为空", ErrUsage)
	}
	if dir == engine.ForwardDynamic {
		bindAddr, bErr := normalizeTCPBindAddr(trimmed)
		if bErr != nil {
			return spec, bErr
		}
		return engine.NewForwardSpec(engine.ForwardDynamic, bindAddr, "")
	}
	if dir != engine.ForwardLocal && dir != engine.ForwardRemote {
		return spec, fmt.Errorf("%w: 不支持的转发方向 %s", ErrUsage, dir)
	}
	parts, pErr := splitForwardFields(trimmed)
	if pErr != nil {
		return spec, pErr
	}
	return buildLocalOrRemoteForwardSpec(dir, parts, trimmed)
}

func buildLocalOrRemoteForwardSpec(dir engine.ForwardDirection, parts []string, raw string) (spec engine.ForwardSpec, err error) {
	switch len(parts) {
	case 2:
		if isUnixSocketSpec(parts[0]) && isUnixSocketSpec(parts[1]) {
			return engine.NewTypedForwardSpec(dir, engine.ForwardEndpointUnix, parts[0], engine.ForwardEndpointUnix, parts[1])
		}
		if !isUnixSocketSpec(parts[0]) && isUnixSocketSpec(parts[1]) {
			bindAddr, bErr := joinTCPHostPort("127.0.0.1", parts[0], true)
			if bErr != nil {
				return spec, fmt.Errorf("%w: 转发规格 %q 监听端口非法: %w", ErrUsage, raw, bErr)
			}
			return engine.NewTypedForwardSpec(dir, engine.ForwardEndpointTCP, bindAddr, engine.ForwardEndpointUnix, parts[1])
		}
		return spec, fmt.Errorf("%w: 转发规格 %q 缺少目标主机或端口", ErrUsage, raw)
	case 3:
		return parseThreePartForward(dir, parts, raw)
	case 4:
		bindAddr, bErr := joinTCPHostPort(parts[0], parts[1], true)
		if bErr != nil {
			return spec, fmt.Errorf("%w: 转发规格 %q 监听端非法: %w", ErrUsage, raw, bErr)
		}
		targetAddr, tErr := joinTCPHostPort(parts[2], parts[3], false)
		if tErr != nil {
			return spec, fmt.Errorf("%w: 转发规格 %q 目标端非法: %w", ErrUsage, raw, tErr)
		}
		return engine.NewForwardSpec(dir, bindAddr, targetAddr)
	default:
		return spec, fmt.Errorf("%w: 转发规格 %q 分段数非法", ErrUsage, raw)
	}
}

func parseThreePartForward(dir engine.ForwardDirection, parts []string, raw string) (spec engine.ForwardSpec, err error) {
	switch {
	case isUnixSocketSpec(parts[0]):
		targetAddr, tErr := joinTCPHostPort(parts[1], parts[2], false)
		if tErr != nil {
			return spec, fmt.Errorf("%w: 转发规格 %q 目标端非法: %w", ErrUsage, raw, tErr)
		}
		return engine.NewTypedForwardSpec(dir, engine.ForwardEndpointUnix, parts[0], engine.ForwardEndpointTCP, targetAddr)
	case isUnixSocketSpec(parts[2]):
		bindAddr, bErr := joinTCPHostPort(parts[0], parts[1], true)
		if bErr != nil {
			return spec, fmt.Errorf("%w: 转发规格 %q 监听端非法: %w", ErrUsage, raw, bErr)
		}
		return engine.NewTypedForwardSpec(dir, engine.ForwardEndpointTCP, bindAddr, engine.ForwardEndpointUnix, parts[2])
	default:
		bindAddr, bErr := joinTCPHostPort("127.0.0.1", parts[0], true)
		if bErr != nil {
			return spec, fmt.Errorf("%w: 转发规格 %q 监听端口非法: %w", ErrUsage, raw, bErr)
		}
		targetAddr, tErr := joinTCPHostPort(parts[1], parts[2], false)
		if tErr != nil {
			return spec, fmt.Errorf("%w: 转发规格 %q 目标端非法: %w", ErrUsage, raw, tErr)
		}
		return engine.NewForwardSpec(dir, bindAddr, targetAddr)
	}
}

// ParseTUNForwardSpec 解析 OpenSSH `-w local_tun[:remote_tun]` 规格为强类型 ForwardTUN ForwardSpec。
func ParseTUNForwardSpec(mode engine.TUNMode, raw string) (spec engine.ForwardSpec, err error) {
	if !mode.IsValid() {
		mode = engine.TUNModePointToPoint
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return spec, fmt.Errorf("%w: -w TUN 设备规格不能为空", ErrUsage)
	}
	localPart, remotePart, hasRemote := strings.Cut(trimmed, ":")
	if !hasRemote {
		remotePart = "any"
	}
	localUnit, lErr := parseTUNUnit(localPart)
	if lErr != nil {
		return spec, fmt.Errorf("%w: -w 本地设备编号 %q 非法: %w", ErrUsage, localPart, lErr)
	}
	remoteUnit, rErr := parseTUNUnit(remotePart)
	if rErr != nil {
		return spec, fmt.Errorf("%w: -w 远端设备编号 %q 非法: %w", ErrUsage, remotePart, rErr)
	}
	tun, tErr := engine.NewTUNSpec(mode, localUnit, remoteUnit)
	if tErr != nil {
		return spec, fmt.Errorf("%w: %w", ErrUsage, tErr)
	}
	return engine.NewForwardTUNSpec(tun)
}

func parseTUNUnit(raw string) (uint32, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.EqualFold(s, "any") {
		return engine.TUNUnitAny, nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("必须为 any 或非负整数")
	}
	return uint32(v), nil
}

func normalizeTCPBindAddr(raw string) (string, error) {
	parts, err := splitForwardFields(raw)
	if err != nil {
		return "", err
	}
	switch len(parts) {
	case 1:
		return joinTCPHostPort("127.0.0.1", parts[0], true)
	case 2:
		return joinTCPHostPort(parts[0], parts[1], true)
	default:
		return "", fmt.Errorf("%w: 动态转发 -D 参数 %q 必须为 [bind_address:]port", ErrUsage, raw)
	}
}

func joinTCPHostPort(hostRaw, portRaw string, allowZeroPort bool) (string, error) {
	host := strings.TrimSpace(hostRaw)
	switch host {
	case "":
		host = "127.0.0.1"
	case "*":
		host = "0.0.0.0"
	}
	portNum, err := strconv.ParseUint(strings.TrimSpace(portRaw), 10, 16)
	if err != nil || (!allowZeroPort && portNum == 0) {
		return "", fmt.Errorf("端口 %q 非法", portRaw)
	}
	if portNum == 0 {
		ch, err := netaddr.ParseCanonicalHost(host)
		if err != nil {
			return "", err
		}
		if strings.Contains(ch.String(), ":") && !strings.HasPrefix(ch.String(), "[") {
			return "[" + ch.String() + "]:0", nil
		}
		return ch.String() + ":0", nil
	}
	hp, err := netaddr.ParseHostPort(formatHostPortCandidate(host, uint16(portNum)))
	if err != nil {
		return "", err
	}
	return hp.String(), nil
}

func formatHostPortCandidate(host string, port uint16) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func isUnixSocketSpec(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, "~/")
}

// splitForwardFields 按冒号拆分转发规则，尊重方括号 IPv6 字面量（如 [::1]:8080:[::1]:80）。
func splitForwardFields(raw string) ([]string, error) {
	var parts []string
	var cur strings.Builder
	inBracket := false
	for i := range len(raw) {
		ch := raw[i]
		switch ch {
		case '[':
			if inBracket {
				return nil, fmt.Errorf("%w: 转发规格 %q 存在嵌套方括号", ErrUsage, raw)
			}
			inBracket = true
			cur.WriteByte(ch)
		case ']':
			if !inBracket {
				return nil, fmt.Errorf("%w: 转发规格 %q 存在未匹配方括号", ErrUsage, raw)
			}
			inBracket = false
			cur.WriteByte(ch)
		case ':':
			if !inBracket {
				parts = append(parts, cur.String())
				cur.Reset()
				continue
			}
			cur.WriteByte(ch)
		default:
			cur.WriteByte(ch)
		}
	}
	if inBracket {
		return nil, fmt.Errorf("%w: 转发规格 %q 方括号未闭合", ErrUsage, raw)
	}
	parts = append(parts, cur.String())
	return parts, nil
}
