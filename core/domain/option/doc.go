// Package option 提供 XOps v2 纯函数领域核的 OpenSSH 四层选项幺半群、协议级 %C 哈希与唯一纯策略求解器。
//
// 本包恪守 100% 纯数学与零副作用铁律（零 os、零 net、零 context、零 sync/sync/atomic、零反射），
// 并经 archbound 独占获准导入标准库 crypto/sha1 专供 OpenSSH ssh_config(5) %C 连接哈希计算。
//
// 核心代数结构（严格对齐校准后 RFC §3.6）：
//   - (PathList, Compose, Unset)：专用于 IdentityFile/CertificateFile 单指令单路径多行累积的三态路径幺半群；
//   - (KnownHostsList, Compose, Unset)：专用于 UserKnownHostsFile 的独立不透明 FirstWins 幺半群；
//   - (AlgoPolicy, Compose, Unset)：单指令算法算子（exact/+/-（独占通配）/^），跨指令与跨层按 FirstWins 合并；
//   - (ProxyRoute, ComposeProxyRoute, ProxyUnset)：封闭和类型与双槽遮蔽代数（ProxyJump 与 ProxyCommand）；
//   - (ControlPolicy, Compose, Unset)：三槽 FirstWins 直积幺半群（!Path().IsEnabled() 时运行期投影归零）；
//   - (EnvFilter, Compose, Unset)：SendEnv 模式列表与 -PATTERN 通配减法幺半群；
//   - (OptionLayer, Compose, Unset) 与唯一纯求解入口 ResolveEffectivePolicy(origin, endpoint, t1, t2, t3, t4)。
package option

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"strings"
	"unicode"
	"unicode/utf8"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const (
	maxCmdLen      = 4096
	maxTokenLen    = 512
	maxAlgoNameLen = 128
)

// 包级哨兵错误：所有无效输入、未知选项与零值访问均严格失败关闭。
var (
	ErrInvalidOption        = domi18n.Sentinel(domi18n.KeyOptionInvalidOption)
	ErrUnknownOption        = domi18n.Sentinel(domi18n.KeyOptionUnknownOption)
	ErrInvalidOrigin        = domi18n.Sentinel(domi18n.KeyOptionInvalidOrigin)
	ErrInvalidEndpoint      = domi18n.Sentinel(domi18n.KeyOptionInvalidEndpoint)
	ErrInvalidPathList      = domi18n.Sentinel(domi18n.KeyOptionInvalidPathList)
	ErrInvalidAlgoPolicy    = domi18n.Sentinel(domi18n.KeyOptionInvalidAlgoPolicy)
	ErrEmptyAlgorithmList   = domi18n.Sentinel(domi18n.KeyOptionEmptyAlgorithmList)
	ErrInvalidProxyRoute    = domi18n.Sentinel(domi18n.KeyOptionInvalidProxyRoute)
	ErrInvalidControlPolicy = domi18n.Sentinel(domi18n.KeyOptionInvalidControlPolicy)
	ErrInvalidEnvFilter     = domi18n.Sentinel(domi18n.KeyOptionInvalidEnvFilter)
	ErrInvalidPercentInput  = domi18n.Sentinel(domi18n.KeyOptionInvalidPercentInput)
	ErrNilReceiver          = domi18n.Sentinel(domi18n.KeyOptionNilReceiver)
)

// hasForbiddenControlChar 阻断非法 UTF-8、控制字符、行/段分隔符与全部 Unicode Cf 格式/双向/零宽/标签字符。
func hasForbiddenControlChar(s string) bool {
	return !utf8.ValidString(s) || strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
	}) >= 0
}
func hasAnySpaceOrControl(s string) bool {
	return hasForbiddenControlChar(s) || strings.IndexFunc(s, unicode.IsSpace) >= 0
}
func isNoneKeyword(s string) bool { return strings.EqualFold(s, "none") }
func isASCIIAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
func isValidEnvName(name string) bool {
	return len(name) > 0 && len(name) <= maxTokenLen && (name[0] < '0' || name[0] > '9') &&
		strings.IndexFunc(name, func(r rune) bool { return r > 127 || (!isASCIIAlphaNum(byte(r)) && r != '_') }) < 0
}

func hasValidTemplateTokens(raw, allowedPercent string, allowEnv bool) bool {
	for i := 0; i < len(raw); {
		if raw[i] == '%' {
			if i+1 >= len(raw) || strings.IndexByte(allowedPercent, raw[i+1]) < 0 {
				return false
			}
			i += 2
			continue
		}
		if allowEnv && strings.HasPrefix(raw[i:], "${") {
			relEnd := strings.IndexByte(raw[i+2:], '}')
			if relEnd <= 0 || !isValidEnvName(raw[i+2:i+2+relEnd]) {
				return false
			}
			i += relEnd + 3
			continue
		}
		i++
	}
	return true
}
func validateTemplateTokens(raw, allowedPercent string, allowEnv bool) error {
	if !hasValidTemplateTokens(raw, allowedPercent, allowEnv) {
		return ErrInvalidPercentInput
	}
	return nil
}

func enumName(idx uint8, names ...string) string {
	if idx > 0 && int(idx) <= len(names) {
		return names[idx-1]
	}
	return ""
}
func enumNameOr(idx uint8, fallback string, names ...string) string {
	if s := enumName(idx, names...); s != "" {
		return s
	}
	return fallback
}
func foldMonoid[T any](zero T, combine func(T, T) T, items []T) T {
	for _, item := range items {
		zero = combine(zero, item)
	}
	return zero
}
func appendValidText(b []byte, text string, valid bool, err error) ([]byte, error) {
	if !valid {
		return nil, err
	}
	return append(b, text...), nil
}
func unmarshalTextVia[T any](dst *T, text []byte, parse func(string) (T, error)) error {
	if dst == nil {
		return ErrNilReceiver
	}
	v, err := parse(string(text))
	if err != nil {
		var zero T
		*dst = zero
		return err
	}
	*dst = v
	return nil
}
func unmarshalNullableJSON[T, W any](dst *T, dec *jsontext.Decoder, unset func() T, decode func(W) (T, error)) error {
	if dst == nil || dec == nil {
		return ErrNilReceiver
	}
	*dst = unset()
	if dec.PeekKind() == 'n' {
		_, err := dec.ReadToken()
		return err
	}
	var wire W
	err := jsonv2.UnmarshalDecode(dec, &wire)
	if err == nil {
		*dst, err = decode(wire)
	}
	if err != nil {
		*dst = unset()
	}
	return err
}
