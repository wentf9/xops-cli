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
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
	ErrInvalidID              = domi18n.Sentinel(domi18n.KeyInventoryInvalidID)
	ErrInvalidKeySpec         = domi18n.Sentinel(domi18n.KeyInventoryInvalidKeySpec)
	ErrInvalidChallengeRule   = domi18n.Sentinel(domi18n.KeyInventoryInvalidChallengeRule)
	ErrInvalidAuthMethod      = domi18n.Sentinel(domi18n.KeyInventoryInvalidAuthMethod)
	ErrAuthCompositeTooDeep   = domi18n.Sentinel(domi18n.KeyInventoryAuthCompositeTooDeep)
	ErrInvalidNodeOrigin      = domi18n.Sentinel(domi18n.KeyInventoryInvalidNodeOrigin)
	ErrInvalidHost            = domi18n.Sentinel(domi18n.KeyInventoryInvalidHost)
	ErrInvalidIdentity        = domi18n.Sentinel(domi18n.KeyInventoryInvalidIdentity)
	ErrInvalidNode            = domi18n.Sentinel(domi18n.KeyInventoryInvalidNode)
	ErrInvalidGraph           = domi18n.Sentinel(domi18n.KeyInventoryInvalidGraph)
	ErrDuplicateAssetID       = domi18n.Sentinel(domi18n.KeyInventoryDuplicateAssetID)
	ErrMissingAssetRef        = domi18n.Sentinel(domi18n.KeyInventoryMissingAssetRef)
	ErrMissingProxyHop        = domi18n.Sentinel(domi18n.KeyInventoryMissingProxyHop)
	ErrProxyJumpCycle         = domi18n.Sentinel(domi18n.KeyInventoryProxyJumpCycle)
	ErrProxyJumpDepthExceeded = domi18n.Sentinel(domi18n.KeyInventoryProxyJumpDepth)
	ErrUnknownSecretStore     = domi18n.Sentinel(domi18n.KeyInventoryUnknownSecretStore)
	ErrInvalidImportBundle    = domi18n.Sentinel(domi18n.KeyInventoryInvalidImportBundle)
	ErrNilWriter              = domi18n.Sentinel(domi18n.KeyInventoryNilWriter)
	ErrNilReceiver            = domi18n.Sentinel(domi18n.KeyInventoryNilReceiver)
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
	return zero, domi18n.EF(baseErr, domi18n.KeyCommonValueInvalid, domi18n.BoundStr("value", raw))
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
		return domi18n.EF(baseErr, domi18n.KeyCommonJSONNullForbidden)
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
			return nil, nil, domi18n.EF(badErr, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "items"), domi18n.Int("index", i))
		}
		k := keyOf(item)
		if seen[k] {
			return nil, nil, domi18n.EF(ErrDuplicateAssetID, domi18n.KeyCommonDuplicateItem, domi18n.Str("kind", "asset_id"), domi18n.BoundStr("value", fmt.Sprint(k)))
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
		return "", domi18n.E(domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "text"))
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
