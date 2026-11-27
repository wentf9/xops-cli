// Package security 提供 XOps v2 纯函数数学安全内核。
//
// 本包恪守 100% 纯数学与零副作用铁律（零 sync/sync/atomic/context/os/net/reflect/crypto/rand/time.Now）：
//   - 有界安全格：Verdict 交半格、RiskLevel 并半格（零值 RiskUnknown 失败关闭）、
//     GuardrailDecision 封闭和类型及 NodeOverrides 顺序无关格折叠；
//   - 幻影能力封闭类型集：Capability（CapInspect..CapMutate）及序列化枚举 CapabilityKind；
//   - 操作与链路身份、规范绑定与审批信封：TraceID、OperationID、SHA-256 Digest、经 digestcover 静态校验的 OperationBinding 与
//     ApprovalEnvelope，以及双阶段路径规范化升级判定 CanonicalScopeEscalated。
//
// 架构隔离铁律（ADR-008）：运行期能力证明 Authorized[C] 物理独占定义于 core/internal/gate，严禁在本包定义。
package security

import (
	"cmp"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// 本包导出的规范化哨兵错误集合，均由失败关闭路径显式返回以便调用方使用 errors.Is 判定。
var (
	ErrInvalidVerdict          = domi18n.Sentinel(domi18n.KeySecurityInvalidVerdict)
	ErrInvalidRiskLevel        = domi18n.Sentinel(domi18n.KeySecurityInvalidRiskLevel)
	ErrInvalidDecision         = domi18n.Sentinel(domi18n.KeySecurityInvalidDecision)
	ErrInvalidCapability       = domi18n.Sentinel(domi18n.KeySecurityInvalidCapability)
	ErrInvalidGlob             = domi18n.Sentinel(domi18n.KeySecurityInvalidGlob)
	ErrInvalidNodeOverride     = domi18n.Sentinel(domi18n.KeySecurityInvalidNodeOverride)
	ErrInvalidTraceID          = domi18n.Sentinel(domi18n.KeySecurityInvalidTraceID)
	ErrInvalidOperationID      = domi18n.Sentinel(domi18n.KeySecurityInvalidOperationID)
	ErrNilEntropy              = domi18n.Sentinel(domi18n.KeySecurityNilEntropy)
	ErrInvalidDigest           = domi18n.Sentinel(domi18n.KeySecurityInvalidDigest)
	ErrInvalidOperationBinding = domi18n.Sentinel(domi18n.KeySecurityInvalidBinding)
	ErrInvalidApprovalEnvelope = domi18n.Sentinel(domi18n.KeySecurityInvalidEnvelope)
	ErrInvalidScopeSnapshot    = domi18n.Sentinel(domi18n.KeySecurityInvalidScope)
	ErrNilWriter               = domi18n.Sentinel(domi18n.KeySecurityNilWriter)
	ErrNilReceiver             = domi18n.Sentinel(domi18n.KeySecurityNilReceiver)
)

func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}

func optInvalid[T interface{ IsValid() bool }](opt algebraic.Option[T]) bool {
	v, ok := opt.Get()
	return ok && !v.IsValid()
}

func enumName(idx uint8, fallback string, names ...string) string {
	if int(idx) < len(names) {
		return names[idx]
	}
	return fallback
}

func appendValidText(b []byte, valid bool, text string, baseErr error, raw uint8) ([]byte, error) {
	if !valid {
		return nil, domi18n.EF(baseErr, domi18n.KeyCommonValueInvalid, domi18n.Uint64("value", uint64(raw)))
	}
	return append(b, text...), nil
}

func parseEnumByName[T ~uint8](raw string, lo, hi, zero T, nameFn func(T) string, baseErr error) (T, error) {
	for v := lo; v <= hi; v++ {
		if nameFn(v) == raw {
			return v, nil
		}
	}
	return zero, domi18n.EF(baseErr, domi18n.KeyCommonValueInvalid, domi18n.BoundStr("value", raw))
}

func unmarshalTextWithReset[T any](dst *T, zero T, text []byte, parse func(string) (T, error)) error {
	if dst == nil {
		return ErrNilReceiver
	}
	parsed, err := parse(string(text))
	if err != nil {
		*dst = zero
		return err
	}
	*dst = parsed
	return nil
}

// rejectJSONNull 在自定义 UnmarshalJSONFrom 入口显式拦截 JSON null，并透传畸形前缀（如 "nul"）的底层语法错误。
func rejectJSONNull(dec *jsontext.Decoder, baseErr error) (bool, error) {
	if dec.PeekKind() != 'n' {
		return false, nil
	}
	if _, err := dec.ReadToken(); err != nil {
		return true, err
	}
	return true, domi18n.EF(baseErr, domi18n.KeyCommonJSONNullForbidden)
}

// unmarshalJSONWithNullReject 统一实现失败关闭的 JSON/v2 反序列化：重置零值、拦截顶层 null、拒绝未知字段、解码 wire 并构造校验值。
func unmarshalJSONWithNullReject[T, W any](dst *T, dec *jsontext.Decoder, baseErr error, build func(W) (T, error)) error {
	if dst == nil {
		return ErrNilReceiver
	}
	var zero T
	*dst = zero
	if isNull, err := rejectJSONNull(dec, baseErr); isNull {
		return err
	}
	var wire W
	if err := jsonv2.UnmarshalDecode(dec, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	parsed, err := build(wire)
	if err != nil {
		return err
	}
	*dst = parsed
	return nil
}

func equalOpt[T interface{ Equal(T) bool }](a, b algebraic.Option[T]) bool {
	va, oka := a.Get()
	vb, okb := b.Get()
	return oka == okb && (!oka || va.Equal(vb))
}

func sortAndMergeByKey[T any](items []T, key func(T) string, merge func(T, T) T) []T {
	if len(items) == 0 {
		return nil
	}
	slices.SortFunc(items, func(a, b T) int { return cmp.Compare(key(a), key(b)) })
	out := make([]T, 0, len(items))
	for _, item := range items {
		if n := len(out); n > 0 && key(out[n-1]) == key(item) {
			out[n-1] = merge(out[n-1], item)
			continue
		}
		out = append(out, item)
	}
	return out
}

// isValidNodeID 统一校验跨 NodeOverrides、OperationBinding 与 ScopeSnapshot 的节点标识符：
// 允许长度 1..128 字节的有效可打印非空白 UTF-8，严格拒绝空白、控制字符与 Unicode Cf 格式/Bidi 字符。
func isValidNodeID(raw string) bool {
	if len(raw) == 0 || len(raw) > maxOperationIDLen || !utf8.ValidString(raw) {
		return false
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || isForbiddenFormatOrControl(r) {
			return false
		}
	}
	return true
}
