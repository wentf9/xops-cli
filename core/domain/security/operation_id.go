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

// OperationID 表示单次安全授权、审批挑战与审计闭环的不可变操作唯一标识，
// 格式与 core/internal/foundation/trace.OpID 保持完全一致；零值恒无效并严格失败关闭。
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
	raw, err := readExact16Bytes(entropy)
	if err != nil {
		return OperationID{}, fmt.Errorf("%w: %w", ErrInvalidOperationID, err)
	}
	return OperationIDFromBytes(raw), nil
}

// ParseOperationID 校验并构造 OperationID；仅接受长度 1..128 的可打印非空白 ASCII（0x21..0x7E）。
func ParseOperationID(raw string) (OperationID, error) {
	if !isValidASCIIToken(raw, maxOperationIDLen) {
		return OperationID{}, fmt.Errorf("%w: %q", ErrInvalidOperationID, raw)
	}
	return OperationID{value: raw}, nil
}

// IsValid 报告 OperationID 是否为有效的非零标识。
func (id OperationID) IsValid() bool { return id.value != "" }

// IsZero 报告 OperationID 是否为无效零值。
func (id OperationID) IsZero() bool { return id.value == "" }

// String 返回 OperationID 规范文本；无效零值返回空串。
func (id OperationID) String() string { return id.value }

// Equal 严格比对两个 OperationID 是否均有效且相等（无效零值永不相等）。
func (id OperationID) Equal(other OperationID) bool {
	return id.IsValid() && other.IsValid() && id.value == other.value
}

// Compare 定义 OperationID 上的确定性全序（无效零值排在有效值之前）。
func (id OperationID) Compare(other OperationID) int {
	if !id.IsValid() || !other.IsValid() {
		return compareValidity(id.IsValid(), other.IsValid())
	}
	return cmp.Compare(id.value, other.value)
}

// AppendText 实现 encoding.TextAppender（值接收者）；对无效零值失败关闭。
func (id OperationID) AppendText(b []byte) ([]byte, error) {
	if !id.IsValid() {
		return nil, ErrInvalidOperationID
	}
	return append(b, id.value...), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (id OperationID) MarshalText() ([]byte, error) { return id.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为零值并失败关闭。
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

// IsValid 报告 Digest 是否为有效已初始化摘要。
func (d Digest) IsValid() bool { return d.valid }

// IsZero 报告 Digest 是否为无效零值。
func (d Digest) IsZero() bool { return !d.valid }

// Bytes 返回 32 字节原始摘要副本与有效性标志；无效零值返回全零与 false。
func (d Digest) Bytes() ([sha256.Size]byte, bool) {
	return pickIf(d.valid, d.sum, [sha256.Size]byte{}), d.valid
}

// Hex 返回 64 位小写十六进制摘要正文；无效零值返回空串。
func (d Digest) Hex() string {
	if !d.valid {
		return ""
	}
	return hex.EncodeToString(d.sum[:])
}

// String 返回带算法前缀的规范文本 "sha256:<64hex>"；无效零值返回空串。
func (d Digest) String() string {
	if !d.valid {
		return ""
	}
	return sha256DigestPrefix + d.Hex()
}

// Equal 以常量时间比对两个 Digest 是否均有效且字节完全一致（无效零值永不相等）。
func (d Digest) Equal(other Digest) bool {
	return d.valid && other.valid && subtle.ConstantTimeCompare(d.sum[:], other.sum[:]) == 1
}

// Compare 定义 Digest 上的确定性全序（无效零值排在有效值之前）。
func (d Digest) Compare(other Digest) int {
	if !d.valid || !other.valid {
		return compareValidity(d.valid, other.valid)
	}
	return bytes.Compare(d.sum[:], other.sum[:])
}

// AppendText 实现 encoding.TextAppender（值接收者）；对无效零值失败关闭。
func (d Digest) AppendText(b []byte) ([]byte, error) {
	if !d.valid {
		return nil, ErrInvalidDigest
	}
	return hex.AppendEncode(append(b, sha256DigestPrefix...), d.sum[:]), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (d Digest) MarshalText() ([]byte, error) { return d.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为零值并失败关闭。
func (d *Digest) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(d, Digest{}, text, ParseDigest)
}

func compareValidity(a, b bool) int { return pickIf(a == b, 0, pickIf(!a, -1, 1)) }

func readExact16Bytes(entropy io.Reader) ([16]byte, error) {
	var buf [16]byte
	if entropy == nil {
		return buf, ErrNilEntropy
	}
	if _, err := io.ReadFull(entropy, buf[:]); err != nil {
		return [16]byte{}, err
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
