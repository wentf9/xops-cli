package option

import (
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// TokenContext 为 OpenSSH % token 纯字符串展开提供全部显式输入（零 os.Hostname / os/user 隐式访问）。
type TokenContext struct {
	LocalHost    string // 本机完整主机名（%l，%L 取首个 '.' 之前前缀）
	TargetHost   string // 规范化远端目标主机名或 IP（%h）
	Port         uint16 // 目标 SSH 端口（%p，位于 [1, 65535]）
	RemoteUser   string // 远端用户名（%r，空时回退至 LocalUser）
	OriginalHost string // 原始主机或别名（%n，空时回退至 TargetHost）
	LocalUser    string // 本机用户名（%u）
	LocalUID     string // 本机数值 UID（%i）
	HomeDir      string // 本机用户主目录（%d）
	JumpHost     string // 活跃 ProxyJump 末跳无方括号规范主机名（%j，无跳板时为空串）
}

// ComputePercentC 与 ComputeConnectionHash 计算 OpenSSH ssh_config(5) 协议级 %C 40 位小写十六进制 SHA-1 哈希（SHA1(%l%h%p%r%j)）；
// localHost、targetHost、user 必须非空且 port 位于 [1, 65535]，jumpHost 无跳板时可为空串。
func ComputePercentC(localHost, targetHost string, port uint16, user string) (string, error) {
	return ComputeConnectionHash(localHost, targetHost, port, user, "")
}
func ComputeConnectionHash(localHost, targetHost string, port uint16, user, jumpHost string) (string, error) {
	if localHost == "" || targetHost == "" || port == 0 || user == "" {
		return "", domi18n.EF(ErrInvalidPercentInput, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "localHost/targetHost/port/user"))
	}
	for _, s := range [4]string{localHost, targetHost, user, jumpHost} {
		if hasForbiddenControlChar(s) {
			return "", domi18n.EF(ErrInvalidPercentInput, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "percent_input"))
		}
	}
	h := sha1.New()
	for _, part := range [5]string{localHost, targetHost, strconv.FormatUint(uint64(port), 10), user, jumpHost} {
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ExpandTokens 与 ExpandPathTokens 对 OpenSSH 模板执行确定性单遍 % token 展开；
// 非 %j 令牌字段为空均失败关闭，ExpandPathTokens 额外禁止非 %d 令牌注入路径分隔符或目录穿越段。
func ExpandTokens(template string, ctx TokenContext) (string, error) {
	return expandTokensInternal(template, ctx, false)
}
func ExpandPathTokens(template string, ctx TokenContext) (string, error) {
	return expandTokensInternal(template, ctx, true)
}

func expandTokensInternal(template string, ctx TokenContext, pathSafe bool) (string, error) {
	if ctx.Port == 0 || ctx.TargetHost == "" {
		return "", domi18n.EF(ErrInvalidPercentInput, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "port/target_host"))
	}
	for _, s := range [9]string{template, ctx.LocalHost, ctx.TargetHost, ctx.RemoteUser, ctx.OriginalHost, ctx.LocalUser, ctx.LocalUID, ctx.HomeDir, ctx.JumpHost} {
		if hasForbiddenControlChar(s) {
			return "", domi18n.EF(ErrInvalidPercentInput, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "token_context"))
		}
	}
	var b strings.Builder
	b.Grow(len(template) + 32)
	for i := 0; i < len(template); {
		if template[i] != '%' {
			b.WriteByte(template[i])
			i++
			continue
		}
		if i+1 >= len(template) {
			return "", domi18n.EF(ErrInvalidPercentInput, domi18n.KeyOptionTemplateInvalid, domi18n.Str("option", "percent_template"))
		}
		val, err := resolvePercentToken(template[i+1], ctx, pathSafe)
		if err != nil {
			return "", err
		}
		b.WriteString(val)
		i += 2
	}
	return b.String(), nil
}

func resolvePercentToken(tok byte, ctx TokenContext, pathSafe bool) (string, error) {
	switch tok {
	case '%':
		return "%", nil
	case 'p':
		return strconv.FormatUint(uint64(ctx.Port), 10), nil
	case 'd':
		if ctx.HomeDir == "" {
			return "", domi18n.EF(ErrInvalidPercentInput, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "home_dir"))
		}
		return ctx.HomeDir, nil
	case 'C':
		return ComputeConnectionHash(ctx.LocalHost, ctx.TargetHost, ctx.Port, effectiveRemoteUser(ctx), ctx.JumpHost)
	default:
		val, ok := lookupStringPercentToken(tok, ctx)
		if !ok || (tok != 'j' && val == "") {
			return "", domi18n.EF(ErrInvalidPercentInput, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "token"), domi18n.BoundStr("value", "%"+string(tok)))
		}
		if pathSafe && val != "" && (strings.ContainsAny(val, `/\`) || val == "." || strings.Contains(val, "..")) {
			return "", domi18n.EF(ErrInvalidPercentInput, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", val), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyPathalgReasonSepOrTraversal)))
		}
		return val, nil
	}
}

func lookupStringPercentToken(tok byte, ctx TokenContext) (string, bool) {
	shortLocal, _, _ := strings.Cut(ctx.LocalHost, ".")
	orig := ctx.OriginalHost
	if orig == "" {
		orig = ctx.TargetHost
	}
	v, ok := map[byte]string{
		'h': ctx.TargetHost, 'r': effectiveRemoteUser(ctx), 'n': orig,
		'u': ctx.LocalUser, 'l': ctx.LocalHost, 'L': shortLocal, 'i': ctx.LocalUID, 'j': ctx.JumpHost,
	}[tok]
	return v, ok
}
func effectiveRemoteUser(ctx TokenContext) string {
	if ctx.RemoteUser != "" {
		return ctx.RemoteUser
	}
	return ctx.LocalUser
}
