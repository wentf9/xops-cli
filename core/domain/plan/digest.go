package plan

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	sha256Prefix = "sha256:"
	sha256HexLen = sha256.Size * 2
)

func parseSHA256Bytes(raw string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	hexPart, ok := strings.CutPrefix(raw, sha256Prefix)
	if !ok || len(hexPart) != sha256HexLen || !isLowerHexString(hexPart) {
		return sum, fmt.Errorf("%w: %q", ErrInvalidDigest, raw)
	}
	if _, err := hex.Decode(sum[:], []byte(hexPart)); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %w", ErrInvalidDigest, err)
	}
	return sum, nil
}

// HopDigest 表示多跳 Merkle 连接计划中单跳（含全部上游祖先跳板）的不可变 32 字节 SHA-256 摘要；
// 零值恒无效，Equal 采用常量时间比较，供连接池按跳隔离与共享前缀复用。
//
//xops:opaque
//xops:failclosed
type HopDigest struct {
	sum   [sha256.Size]byte
	valid bool
}

// HopDigestFromSHA256 将 32 字节 SHA-256 摘要封装为不可变 HopDigest。
func HopDigestFromSHA256(sum [sha256.Size]byte) HopDigest { return HopDigest{sum: sum, valid: true} }

// ParseHopDigest 严格解析规范 SHA-256 文本（"sha256:<64位小写十六进制>"）为 HopDigest。
func ParseHopDigest(raw string) (HopDigest, error) {
	sum, err := parseSHA256Bytes(raw)
	if err != nil {
		return HopDigest{}, err
	}
	return HopDigestFromSHA256(sum), nil
}

func (d HopDigest) IsValid() bool { return d.valid }
func (d HopDigest) IsZero() bool  { return !d.valid }
func (d HopDigest) Bytes() ([sha256.Size]byte, bool) {
	return pickIf(d.valid, d.sum, [sha256.Size]byte{}), d.valid
}
func (d HopDigest) Hex() string {
	if !d.valid {
		return ""
	}
	return hex.EncodeToString(d.sum[:])
}
func (d HopDigest) String() string {
	if !d.valid {
		return ""
	}
	return sha256Prefix + d.Hex()
}

// SecurityDigest 将有效 HopDigest 无损投影为 security.Digest；无效零值返回零值 security.Digest。
func (d HopDigest) SecurityDigest() security.Digest {
	if !d.valid {
		var zero security.Digest
		return zero
	}
	return security.DigestFromSHA256(d.sum)
}

// Equal 以常量时间比对两个 HopDigest 是否均有效且字节完全一致（无效零值永不相等）。
func (d HopDigest) Equal(other HopDigest) bool {
	return d.valid && other.valid && subtle.ConstantTimeCompare(d.sum[:], other.sum[:]) == 1
}

// Compare 定义 HopDigest 上的确定性全序关系（无效零值排在有效值之前）。
func (d HopDigest) Compare(other HopDigest) int {
	if !d.valid || !other.valid {
		return compareValidity(d.valid, other.valid)
	}
	return bytes.Compare(d.sum[:], other.sum[:])
}

func (d HopDigest) AppendText(b []byte) ([]byte, error) {
	if !d.valid {
		return nil, ErrInvalidDigest
	}
	return hex.AppendEncode(append(b, sha256Prefix...), d.sum[:]), nil
}
func (d HopDigest) MarshalText() ([]byte, error) { return d.AppendText(nil) }
func (d *HopDigest) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(d, HopDigest{}, text, ParseHopDigest)
}

// PlanDigest 表示整条不可变 SealedConnectionPlan 的顶层 32 字节 Merkle SHA-256 摘要；
// 零值恒无效，Equal 采用常量时间比较，并可无损投影至 security.OperationBinding.PlanDigest。
//
//xops:opaque
//xops:failclosed
type PlanDigest struct {
	sum   [sha256.Size]byte
	valid bool
}

// PlanDigestFromSHA256 将 32 字节 SHA-256 摘要封装为不可变 PlanDigest。
func PlanDigestFromSHA256(sum [sha256.Size]byte) PlanDigest { return PlanDigest{sum: sum, valid: true} }

// ParsePlanDigest 严格解析规范 SHA-256 文本（"sha256:<64位小写十六进制>"）为 PlanDigest。
func ParsePlanDigest(raw string) (PlanDigest, error) {
	sum, err := parseSHA256Bytes(raw)
	if err != nil {
		return PlanDigest{}, err
	}
	return PlanDigestFromSHA256(sum), nil
}

func (d PlanDigest) IsValid() bool { return d.valid }
func (d PlanDigest) IsZero() bool  { return !d.valid }
func (d PlanDigest) Bytes() ([sha256.Size]byte, bool) {
	return pickIf(d.valid, d.sum, [sha256.Size]byte{}), d.valid
}
func (d PlanDigest) Hex() string {
	if !d.valid {
		return ""
	}
	return hex.EncodeToString(d.sum[:])
}
func (d PlanDigest) String() string {
	if !d.valid {
		return ""
	}
	return sha256Prefix + d.Hex()
}

// SecurityDigest 将有效 PlanDigest 无损投影为 security.Digest；无效零值返回零值 security.Digest。
func (d PlanDigest) SecurityDigest() security.Digest {
	if !d.valid {
		var zero security.Digest
		return zero
	}
	return security.DigestFromSHA256(d.sum)
}

// Equal 以常量时间比对两个 PlanDigest 是否均有效且字节完全一致（无效零值永不相等）。
func (d PlanDigest) Equal(other PlanDigest) bool {
	return d.valid && other.valid && subtle.ConstantTimeCompare(d.sum[:], other.sum[:]) == 1
}

// Compare 定义 PlanDigest 上的确定性全序关系（无效零值排在有效值之前）。
func (d PlanDigest) Compare(other PlanDigest) int {
	if !d.valid || !other.valid {
		return compareValidity(d.valid, other.valid)
	}
	return bytes.Compare(d.sum[:], other.sum[:])
}

func (d PlanDigest) AppendText(b []byte) ([]byte, error) {
	if !d.valid {
		return nil, ErrInvalidDigest
	}
	return hex.AppendEncode(append(b, sha256Prefix...), d.sum[:]), nil
}
func (d PlanDigest) MarshalText() ([]byte, error) { return d.AppendText(nil) }
func (d *PlanDigest) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(d, PlanDigest{}, text, ParsePlanDigest)
}
