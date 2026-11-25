package security

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const (
	operationIDEntropyBytes = 16
	maxOperationIDLen       = 128
	sha256DigestPrefix      = "sha256:"
	sha256HexLen            = sha256.Size * 2
)

// TraceID 表示单次请求链路的不可变全局追踪唯一标识，
// 由 core/internal/foundation/trace 别名复用（零拷贝互通），供 core/ports 与 core/events 公开使用；
// 零值恒无效并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type TraceID struct{ value string }

// TraceIDFromBytes 将 16 字节原始熵确定性编码为 32 位小写十六进制 TraceID。
func TraceIDFromBytes(raw [operationIDEntropyBytes]byte) TraceID {
	return TraceID{value: hex.EncodeToString(raw[:])}
}

// NewTraceIDFrom 从调用方显式注入的熵源读取 16 字节并构造 TraceID（零隐式 crypto/rand）。
func NewTraceIDFrom(entropy io.Reader) (TraceID, error) {
	val, err := readHexID(entropy, ErrInvalidTraceID)
	return TraceID{value: val}, err
}

// ParseTraceID 校验并构造 TraceID；仅接受长度 1..128 的可打印非空白 ASCII（0x21..0x7E）。
func ParseTraceID(raw string) (TraceID, error) {
	val, err := parseToken(raw, ErrInvalidTraceID)
	return TraceID{value: val}, err
}

// IsValid、IsZero、String、Equal 与 Compare 实现 TraceID 的失败关闭语义与确定性全序（无效零值永不相等）。
func (id TraceID) IsValid() bool  { return id.value != "" }
func (id TraceID) IsZero() bool   { return id.value == "" }
func (id TraceID) String() string { return id.value }
func (id TraceID) Equal(other TraceID) bool {
	return id.IsValid() && other.IsValid() && id.value == other.value
}
func (id TraceID) Compare(other TraceID) int { return compareToken(id.value, other.value) }

// AppendText、MarshalText 与 UnmarshalText 实现 TraceID 的值接收者文本编解码（零值与非法输入失败关闭）。
func (id TraceID) AppendText(b []byte) ([]byte, error) {
	return appendValidToken(b, id.value, ErrInvalidTraceID)
}
func (id TraceID) MarshalText() ([]byte, error) { return id.AppendText(nil) }
func (id *TraceID) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(id, TraceID{}, text, ParseTraceID)
}

// OperationID 表示单次安全授权、审批挑战与审计闭环的不可变操作唯一标识，
// 由 core/internal/foundation/trace.OpID 别名复用；零值恒无效并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type OperationID struct{ value string }

// OperationIDFromBytes 将 16 字节原始熵确定性编码为 32 位小写十六进制 OperationID。
func OperationIDFromBytes(raw [operationIDEntropyBytes]byte) OperationID {
	return OperationID{value: hex.EncodeToString(raw[:])}
}

// NewOperationIDFrom 从调用方显式注入的熵源读取 16 字节并构造 OperationID（零隐式 crypto/rand）。
func NewOperationIDFrom(entropy io.Reader) (OperationID, error) {
	val, err := readHexID(entropy, ErrInvalidOperationID)
	return OperationID{value: val}, err
}

// ParseOperationID 校验并构造 OperationID；仅接受长度 1..128 的可打印非空白 ASCII（0x21..0x7E）。
func ParseOperationID(raw string) (OperationID, error) {
	val, err := parseToken(raw, ErrInvalidOperationID)
	return OperationID{value: val}, err
}

// IsValid、IsZero、String、Equal 与 Compare 实现 OperationID 的失败关闭语义与确定性全序（无效零值永不相等）。
func (id OperationID) IsValid() bool  { return id.value != "" }
func (id OperationID) IsZero() bool   { return id.value == "" }
func (id OperationID) String() string { return id.value }
func (id OperationID) Equal(other OperationID) bool {
	return id.IsValid() && other.IsValid() && id.value == other.value
}
func (id OperationID) Compare(other OperationID) int { return compareToken(id.value, other.value) }

// AppendText、MarshalText 与 UnmarshalText 实现 OperationID 的值接收者文本编解码（零值与非法输入失败关闭）。
func (id OperationID) AppendText(b []byte) ([]byte, error) {
	return appendValidToken(b, id.value, ErrInvalidOperationID)
}
func (id OperationID) MarshalText() ([]byte, error) { return id.AppendText(nil) }
func (id *OperationID) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(id, OperationID{}, text, ParseOperationID)
}

// Digest 表示规范化的不可变 SHA-256 密码学摘要值对象（"sha256:<64位小写十六进制>"）；
// 零值恒无效，Equal 使用 crypto/subtle.ConstantTimeCompare 抵御时序侧信道。
//
//xops:opaque
//xops:failclosed
type Digest struct {
	sum   [sha256.Size]byte
	valid bool
}

// DigestFromSHA256 将 32 字节 SHA-256 摘要封装为不可变 Digest。
func DigestFromSHA256(sum [sha256.Size]byte) Digest { return Digest{sum: sum, valid: true} }

// DigestBytes 对字节切片计算 SHA-256 并返回不可变 Digest。
func DigestBytes(data []byte) Digest { return DigestFromSHA256(sha256.Sum256(data)) }

// ParseDigest 严格解析规范 SHA-256 摘要文本（"sha256:<64位小写十六进制>"）。
func ParseDigest(raw string) (Digest, error) {
	hexPart, ok := strings.CutPrefix(raw, sha256DigestPrefix)
	if !ok || len(hexPart) != sha256HexLen || !isLowerHexString(hexPart) {
		return Digest{}, fmt.Errorf("%w: %q", ErrInvalidDigest, raw)
	}
	var sum [sha256.Size]byte
	if _, err := hex.Decode(sum[:], []byte(hexPart)); err != nil {
		return Digest{}, fmt.Errorf("%w: %w", ErrInvalidDigest, err)
	}
	return Digest{sum: sum, valid: true}, nil
}

// IsValid、IsZero、Bytes、Hex、String、Equal 与 Compare 实现 Digest 的失败关闭语义、常量时间比对与确定性全序。
func (d Digest) IsValid() bool { return d.valid }
func (d Digest) IsZero() bool  { return !d.valid }
func (d Digest) Bytes() ([sha256.Size]byte, bool) {
	return pickIf(d.valid, d.sum, [sha256.Size]byte{}), d.valid
}
func (d Digest) Hex() string    { return pickIf(d.valid, hex.EncodeToString(d.sum[:]), "") }
func (d Digest) String() string { return pickIf(d.valid, sha256DigestPrefix+d.Hex(), "") }
func (d Digest) Equal(other Digest) bool {
	return d.valid && other.valid && subtle.ConstantTimeCompare(d.sum[:], other.sum[:]) == 1
}
func (d Digest) Compare(other Digest) int {
	if !d.valid || !other.valid {
		return compareValidity(d.valid, other.valid)
	}
	return bytes.Compare(d.sum[:], other.sum[:])
}

// AppendText、MarshalText 与 UnmarshalText 实现 Digest 的值接收者文本编解码（零值与非法输入失败关闭）。
func (d Digest) AppendText(b []byte) ([]byte, error) {
	if !d.valid {
		return nil, ErrInvalidDigest
	}
	return hex.AppendEncode(append(b, sha256DigestPrefix...), d.sum[:]), nil
}
func (d Digest) MarshalText() ([]byte, error) { return d.AppendText(nil) }
func (d *Digest) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(d, Digest{}, text, ParseDigest)
}

func compareValidity(a, b bool) int { return pickIf(a == b, 0, pickIf(!a, -1, 1)) }
func compareToken(a, b string) int {
	if a == "" || b == "" {
		return compareValidity(a != "", b != "")
	}
	return cmp.Compare(a, b)
}
func appendValidToken(b []byte, val string, baseErr error) ([]byte, error) {
	if val == "" {
		return nil, baseErr
	}
	return append(b, val...), nil
}
func parseToken(raw string, baseErr error) (string, error) {
	if !isValidASCIIToken(raw, maxOperationIDLen) {
		return "", fmt.Errorf("%w: %q", baseErr, raw)
	}
	return raw, nil
}
func readHexID(entropy io.Reader, baseErr error) (string, error) {
	raw, err := readExact16Bytes(entropy)
	if err != nil {
		return "", fmt.Errorf("%w: %w", baseErr, err)
	}
	return hex.EncodeToString(raw[:]), nil
}
func readExact16Bytes(entropy io.Reader) ([operationIDEntropyBytes]byte, error) {
	var buf [operationIDEntropyBytes]byte
	if entropy == nil {
		return buf, ErrNilEntropy
	}
	if _, err := io.ReadFull(entropy, buf[:]); err != nil {
		return [operationIDEntropyBytes]byte{}, err
	}
	return buf, nil
}

func isValidASCIIToken(raw string, maxLen int) bool {
	if len(raw) == 0 || len(raw) > maxLen {
		return false
	}
	for i := range len(raw) {
		if raw[i] < 0x21 || raw[i] > 0x7E {
			return false
		}
	}
	return true
}

func isLowerHexString(raw string) bool {
	for i := range len(raw) {
		if c := raw[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
