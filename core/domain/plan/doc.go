// Package plan 提供 XOps v2 纯函数领域核的 Merkle 链式连接计划与世代句柄模型。
//
// 本包恪守 100% 纯数学与零副作用铁律（零 os、零 net、零 context、零 sync/sync/atomic、零反射）：
//   - HopDigest 与 PlanDigest：不透明 32 字节 SHA-256 摘要值对象（常量时间 Equal + TextAppender）；
//   - TransportPolicySpec 与 HopSpec：冻结每跳连接安全与传输策略投影（零明文凭据），
//     全部经 //xops:canonicalhash 由 xopsvet/digestcover 在编译期静态验证 WriteCanonical 100% 全字段覆盖；
//   - SealedConnectionPlan：不可变多跳 Merkle 链式连接计划，上游任意跳板变动均必然级联刷新全部下游
//     HopDigest 与 PlanDigest，保障连接池缓存隔离与共享堡垒机前缀安全复用（INV-C1 / ADR-009）；
//   - ManagedHandle[K]：按封闭句柄类别 K 参数化的世代句柄（id、gen>=1、planDigest、binding、valid），
//     零值失败关闭，阻断跨类别、陈旧世代或绑定漂移重放。
package plan

import (
	"encoding/binary"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

const (
	maxNodeIDLen   = 128
	maxHandleIDLen = 128
	maxPlanHops    = 32
)

// 本包导出的规范哨兵错误，所有非法字段、篡改摘要、JSON null 及零值访问均严格失败关闭。
var (
	ErrInvalidDigest          = errors.New("plan: 无效的 SHA-256 摘要")
	ErrInvalidTransportPolicy = errors.New("plan: 无效的连接传输策略投影 TransportPolicySpec")
	ErrInvalidHopSpec         = errors.New("plan: 无效的单跳连接规格 HopSpec")
	ErrInvalidConnectionPlan  = errors.New("plan: 无效的 Merkle 连接计划 SealedConnectionPlan")
	ErrTamperedPlanDigest     = errors.New("plan: 编码携带的连接计划或跳板 Merkle 摘要与重算结果不匹配")
	ErrInvalidHandleKind      = errors.New("plan: 无效的句柄类别 HandleKind")
	ErrInvalidHandleID        = errors.New("plan: 无效的句柄标识 HandleID")
	ErrInvalidManagedHandle   = errors.New("plan: 无效的世代托管句柄 ManagedHandle")
	ErrNilEntropy             = errors.New("plan: 熵源 io.Reader 不能为 nil")
	ErrNilWriter              = errors.New("plan: WriteCanonical 或编码目标不能为 nil")
	ErrNilReceiver            = errors.New("plan: 反序列化目标接收者不能为 nil")
)

func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}

func enumName(idx uint8, fallback string, names ...string) string {
	if int(idx) < len(names) {
		return names[idx]
	}
	return fallback
}

func appendValidText(b []byte, valid bool, text string, baseErr error) ([]byte, error) {
	if !valid {
		return nil, baseErr
	}
	return append(b, text...), nil
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

func rejectJSONNull(dec *jsontext.Decoder, baseErr error) (bool, error) {
	if dec.PeekKind() != 'n' {
		return false, nil
	}
	if _, err := dec.ReadToken(); err != nil {
		return true, err
	}
	return true, fmt.Errorf("%w: JSON null 不是有效值", baseErr)
}

func unmarshalJSONWithNullReject[T, W any](dst *T, dec *jsontext.Decoder, baseErr error, build func(W) (T, error)) error {
	if dst == nil || dec == nil {
		return ErrNilReceiver
	}
	var zero T
	*dst = zero
	if isNull, err := rejectJSONNull(dec, baseErr); isNull {
		return err
	}
	var wire W
	if err := jsonv2.UnmarshalDecode(dec, &wire); err != nil {
		return err
	}
	parsed, err := build(wire)
	if err != nil {
		return err
	}
	*dst = parsed
	return nil
}

func isForbiddenRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

func isValidNodeLabel(s string) bool {
	if s == "" || len(s) > maxNodeIDLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || isForbiddenRune(r) {
			return false
		}
	}
	return true
}

func isValidASCIIToken(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

func isLowerHexString(raw string) bool {
	for i := range len(raw) {
		c := raw[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func compareValidity(a, b bool) int { return pickIf(a == b, 0, pickIf(!a, -1, 1)) }

// canonicalEncoder 提供零反射、带显式长度前缀与域分离标签的规范摘要编码器。
type canonicalEncoder struct {
	w   io.Writer
	err error
}

func (e *canonicalEncoder) fail(err error) {
	if err != nil && e.err == nil {
		e.err = err
	}
}

func (e *canonicalEncoder) writeRaw(p []byte) {
	if e.err == nil && len(p) > 0 {
		_, e.err = e.w.Write(p)
	}
}

func (e *canonicalEncoder) writeUint8(v uint8)   { e.writeRaw([]byte{v}) }
func (e *canonicalEncoder) writeBool(v bool)     { e.writeUint8(pickIf[uint8](v, 1, 0)) }
func (e *canonicalEncoder) writeUint32(v uint32) { e.writeUint64(uint64(v)) }
func (e *canonicalEncoder) writeInt64(v int64)   { e.writeUint64(uint64(v)) }
func (e *canonicalEncoder) writeUint64(v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	e.writeRaw(buf[:])
}

func (e *canonicalEncoder) writeBytes(p []byte) {
	e.writeUint64(uint64(len(p)))
	e.writeRaw(p)
}

func (e *canonicalEncoder) writeString(s string) {
	e.writeUint64(uint64(len(s)))
	e.writeRaw([]byte(s))
}

func (e *canonicalEncoder) writeStrings(items []string) {
	e.writeUint64(uint64(len(items)))
	for _, s := range items {
		e.writeString(s)
	}
}
