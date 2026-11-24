// Package inventory 提供 XOps v2 纯函数领域核的资产实体模型、封闭认证/来源代数和类型、
// 跨命名空间 Tarjan ProxyJump DAG 环路校验器、5 位置引用检查器与格式无关导入包 ImportBundle。
//
// 本包恪守 100% 纯数学与零副作用铁律（零 os、零 net、零 context、零 sync/sync/atomic、零反射），
// 并严格遵循 ADR-006（100% 零 v1 兼容与迁移代码）。
package inventory

import (
	"encoding/binary"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

const (
	// DefaultMaxJumpDepth 表示默认允许的最大 ProxyJump 跳板深度。
	DefaultMaxJumpDepth   = 16
	maxIDLen              = 128
	maxDescriptionBytes   = 512
	maxKeyPathBytes       = 1024
	maxCommandBytes       = 2048
	maxCommandArgs        = 64
	maxPatternBytes       = 512
	maxAuthCompositeDepth = 4
	maxCertPaths          = 32
	maxTagsOrAliases      = 64
	maxFormatNameLen      = 64
	maxWarningMsgBytes    = 512
)

// 本包导出的规范哨兵错误，所有非法输入、环路、缺失引用与 JSON null 均严格失败关闭。
var (
	ErrInvalidID              = errors.New("inventory: 无效的资产标识符")
	ErrInvalidKeySpec         = errors.New("inventory: 无效的私钥、证书或指纹规格")
	ErrInvalidChallengeRule   = errors.New("inventory: 无效的 keyboard-interactive 质询应答规则")
	ErrInvalidAuthMethod      = errors.New("inventory: 无效的认证方式 AuthMethod")
	ErrAuthCompositeTooDeep   = errors.New("inventory: AuthComposite 嵌套深度超限")
	ErrInvalidNodeOrigin      = errors.New("inventory: 无效的节点来源 NodeOrigin")
	ErrInvalidHost            = errors.New("inventory: 无效的主机实体 Host")
	ErrInvalidIdentity        = errors.New("inventory: 无效的身份实体 Identity")
	ErrInvalidNode            = errors.New("inventory: 无效的节点实体 Node")
	ErrInvalidGraph           = errors.New("inventory: 无效的资产配置图 Graph")
	ErrDuplicateAssetID       = errors.New("inventory: 存在重复的资产标识或别名碰撞")
	ErrMissingAssetRef        = errors.New("inventory: 节点引用了不存在的 Host 或 Identity")
	ErrMissingProxyHop        = errors.New("inventory: ProxyJump 引用了不存在的跳板目标")
	ErrProxyJumpCycle         = errors.New("inventory: 检测到跨命名空间 ProxyJump 环路")
	ErrProxyJumpDepthExceeded = errors.New("inventory: ProxyJump 跳板链深度超过上限")
	ErrUnknownSecretStore     = errors.New("inventory: 凭据引用指向未注册的凭据存储")
	ErrInvalidImportBundle    = errors.New("inventory: 无效的格式无关导入包 ImportBundle")
	ErrNilWriter              = errors.New("inventory: WriteCanonical 或编码目标不能为 nil")
	ErrNilReceiver            = errors.New("inventory: 反序列化目标接收者不能为 nil")
)

type validatable interface{ IsValid() bool }

func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}
func kindIf[T ~uint8](ok bool, yes T) T {
	if ok {
		return yes
	}
	return 0
}

// getValid 先验证 p.IsValid() 后再求值 fn(p)，保证对 nil 指针接收者零解引用且失败关闭。
func getValid[P validatable, T any](p P, fn func(P) T) (zero T) {
	if p.IsValid() {
		return fn(p)
	}
	return zero
}
func equalOptionFunc[T any](a, b algebraic.Option[T], eq func(T, T) bool) bool {
	va, oka := a.Get()
	vb, okb := b.Get()
	return oka == okb && (!oka || eq(va, vb))
}
func mapSliceErr[A, B any](in []A, fn func(A) (B, error)) ([]B, error) {
	out := make([]B, len(in))
	for i, item := range in {
		v, err := fn(item)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
func allMatch[T any](items []T, fn func(T) bool) bool {
	for _, x := range items {
		if !fn(x) {
			return false
		}
	}
	return true
}
func enumName(idx uint8, fallback string, names ...string) string {
	if int(idx) < len(names) {
		return names[idx]
	}
	return fallback
}
func parseEnumByName[T ~uint8](raw string, lo, hi, zero T, nameFn func(T) string, baseErr error) (T, error) {
	if !hasForbiddenText(raw) {
		for norm, v := strings.ToLower(strings.TrimSpace(raw)), lo; v <= hi; v++ {
			if nameFn(v) == norm {
				return v, nil
			}
		}
	}
	return zero, fmt.Errorf("%w: %q", baseErr, raw)
}
func appendValidText(b []byte, valid bool, text string, baseErr error) ([]byte, error) {
	if !valid {
		return nil, baseErr
	}
	return append(b, text...), nil
}
func unmarshalText[T any](dst *T, text []byte, parse func(string) (T, error)) error {
	if dst == nil {
		return ErrNilReceiver
	}
	var zero T
	parsed, err := parse(string(text))
	if err != nil {
		*dst = zero
		return err
	}
	*dst = parsed
	return nil
}
func unmarshalJSON[T, W any](dst *T, dec *jsontext.Decoder, baseErr error, build func(W) (T, error)) error {
	if dst == nil || dec == nil {
		return ErrNilReceiver
	}
	var zero T
	*dst = zero
	if dec.PeekKind() == 'n' {
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		return fmt.Errorf("%w: JSON null 不是有效值", baseErr)
	}
	var wire W
	if err := jsonv2.UnmarshalDecode(dec, &wire); err != nil {
		return err
	}
	parsed, err := build(wire)
	if err == nil {
		*dst = parsed
	}
	return err
}
func unmarshalJSONVal[T, W any](dec *jsontext.Decoder, baseErr error, build func(W) (T, error)) (T, error) {
	var out T
	return out, unmarshalJSON(&out, dec, baseErr, build)
}
func indexUnique[T any, K comparable](raw []T, valid func(T) bool, keyOf func(T) K, cmpKey func(K, K) int, badErr error) ([]T, map[K]bool, error) {
	out, seen := make([]T, len(raw)), make(map[K]bool, len(raw))
	for i, item := range raw {
		if !valid(item) {
			return nil, nil, fmt.Errorf("%w: 第 %d 项无效", badErr, i)
		}
		k := keyOf(item)
		if seen[k] {
			return nil, nil, fmt.Errorf("%w: 重复标识 %v", ErrDuplicateAssetID, k)
		}
		seen[k], out[i] = true, item
	}
	slices.SortFunc(out, func(a, b T) int { return cmpKey(keyOf(a), keyOf(b)) })
	return out, seen, nil
}
func maskFlags(flags ...bool) uint8 {
	var m uint8
	for i, f := range flags {
		if f {
			m |= 1 << i
		}
	}
	return m
}
func isForbiddenRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}
func hasForbiddenText(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, isForbiddenRune)
}
func hasSpaceOrForbidden(s string) bool {
	return hasForbiddenText(s) || strings.ContainsFunc(s, unicode.IsSpace)
}
func sanitizeSingleLine(s string, maxBytes int) (string, error) {
	if len(s) > maxBytes || hasForbiddenText(s) {
		return "", fmt.Errorf("文本超长或包含非法 UTF-8/控制/Cf 字符")
	}
	return s, nil
}

type canonicalEncoder struct {
	w   io.Writer
	err error
}

func (e *canonicalEncoder) writeRaw(p []byte) {
	if e.err == nil && len(p) > 0 {
		_, e.err = e.w.Write(p)
	}
}
func (e *canonicalEncoder) writeUint8(v uint8) { e.writeRaw([]byte{v}) }
func (e *canonicalEncoder) writeUint64(v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	e.writeRaw(buf[:])
}
func (e *canonicalEncoder) writeString(s string) {
	e.writeUint64(uint64(len(s)))
	e.writeRaw([]byte(s))
}
func writeCanonicalStringers[T fmt.Stringer](e *canonicalEncoder, items []T) {
	e.writeUint64(uint64(len(items)))
	for _, x := range items {
		e.writeString(x.String())
	}
}
