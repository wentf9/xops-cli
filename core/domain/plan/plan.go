package plan

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

const (
	merkleHopDomainTag  = "xops.plan.merkle_hop.v1"
	sealedPlanDomainTag = "xops.plan.sealed_plan.v1"
	planCanonicalTag    = "xops.plan.sealed_plan_canonical.v1"
)

// SealedConnectionPlan 表示不可变的多跳 Merkle 链式 SSH 连接计划（INV-C1 / ADR-009）：
//   - HopDigest[0] = SHA256(merkleHopDomainTag || 0 || HopSpec[0].WriteCanonical)
//   - HopDigest[i] = SHA256(merkleHopDomainTag || HopDigest[i-1] || HopSpec[i].WriteCanonical)
//   - PlanDigest   = SHA256(sealedPlanDomainTag || len(hops) || HopDigest[n-1])
//
// 任意上游跳板的任一字段变更均必然级联刷新所有下游 HopDigest 与 PlanDigest，而共享完全相同上游前缀的
// 两条计划则天然共享相同前缀 HopDigest；经 //xops:canonicalhash 校验 WriteCanonical 100% 全字段覆盖。
//
//xops:opaque
//xops:failclosed
//xops:canonicalhash
type SealedConnectionPlan struct {
	hops       algebraic.NonEmpty[HopSpec]
	hopDigests algebraic.NonEmpty[HopDigest]
	planDigest PlanDigest
	valid      bool
}

// SealConnectionPlan 便捷封装可变长跳板序列并构造 Merkle 链式 SealedConnectionPlan。
func SealConnectionPlan(hops ...HopSpec) (SealedConnectionPlan, error) {
	ne, err := algebraic.NonEmptyFromSlice(hops)
	if err != nil {
		return SealedConnectionPlan{}, fmt.Errorf("%w: 连接计划至少需要 1 跳", ErrInvalidConnectionPlan)
	}
	return NewSealedConnectionPlan(ne)
}

// NewSealedConnectionPlan 校验全部跳板规格及其连续索引 [0..n-1]，计算 Merkle 跳板摘要链与顶层 PlanDigest。
func NewSealedConnectionPlan(hops algebraic.NonEmpty[HopSpec]) (SealedConnectionPlan, error) {
	if !hops.IsValid() {
		return SealedConnectionPlan{}, fmt.Errorf("%w: hops 不能为空", ErrInvalidConnectionPlan)
	}
	src := hops.Slice()
	if len(src) > maxPlanHops {
		return SealedConnectionPlan{}, fmt.Errorf("%w: 跳板数量 %d 超过上限 %d", ErrInvalidConnectionPlan, len(src), maxPlanHops)
	}
	digests := make([]HopDigest, len(src))
	var prev HopDigest
	for i, hop := range src {
		if !hop.IsValid() {
			return SealedConnectionPlan{}, fmt.Errorf("%w: hops[%d] 无效", ErrInvalidConnectionPlan, i)
		}
		if hop.hopIndex != uint32(i) {
			return SealedConnectionPlan{}, fmt.Errorf("%w: hops[%d].hop_index=%d 与顺序索引不连续", ErrInvalidConnectionPlan, i, hop.hopIndex)
		}
		hd, err := computeMerkleHopDigest(prev, hop)
		if err != nil {
			return SealedConnectionPlan{}, err
		}
		digests[i] = hd
		prev = hd
	}
	neDigests, err := algebraic.NonEmptyFromSlice(digests)
	if err != nil {
		return SealedConnectionPlan{}, fmt.Errorf("%w: %w", ErrInvalidConnectionPlan, err)
	}
	pd, err := computePlanDigest(uint64(len(src)), prev)
	if err != nil {
		return SealedConnectionPlan{}, err
	}
	return SealedConnectionPlan{hops: hops, hopDigests: neDigests, planDigest: pd, valid: true}, nil
}

func computeMerkleHopDigest(parent HopDigest, hop HopSpec) (HopDigest, error) {
	h := sha256.New()
	enc := &canonicalEncoder{w: h}
	enc.writeString(merkleHopDomainTag)
	if sum, ok := parent.Bytes(); ok {
		enc.writeUint8(1)
		enc.writeBytes(sum[:])
	} else {
		enc.writeUint8(0)
	}
	if enc.err != nil {
		return HopDigest{}, enc.err
	}
	if err := hop.WriteCanonical(h); err != nil {
		return HopDigest{}, err
	}
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return HopDigestFromSHA256(out), nil
}

func computePlanDigest(hopCount uint64, leaf HopDigest) (PlanDigest, error) {
	sum, ok := leaf.Bytes()
	if !ok || hopCount == 0 {
		return PlanDigest{}, ErrInvalidConnectionPlan
	}
	h := sha256.New()
	enc := &canonicalEncoder{w: h}
	enc.writeString(sealedPlanDomainTag)
	enc.writeUint64(hopCount)
	enc.writeBytes(sum[:])
	if enc.err != nil {
		return PlanDigest{}, enc.err
	}
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return PlanDigestFromSHA256(out), nil
}

func (p SealedConnectionPlan) IsValid() bool {
	return p.valid && p.hops.IsValid() && p.hopDigests.IsValid() && p.hops.Len() == p.hopDigests.Len() && p.planDigest.IsValid()
}
func (p SealedConnectionPlan) IsZero() bool                      { return !p.IsValid() }
func (p SealedConnectionPlan) Len() int                          { return pickIf(p.IsValid(), p.hops.Len(), 0) }
func (p SealedConnectionPlan) Hops() algebraic.NonEmpty[HopSpec] { return p.hops }
func (p SealedConnectionPlan) HopSlice() []HopSpec               { return pickIf(p.IsValid(), p.hops.Slice(), nil) }
func (p SealedConnectionPlan) HopDigests() []HopDigest {
	return pickIf(p.IsValid(), p.hopDigests.Slice(), nil)
}
func (p SealedConnectionPlan) PlanDigest() PlanDigest {
	return pickIf(p.IsValid(), p.planDigest, PlanDigest{})
}

// HopAt 返回第 index 跳的不可变 HopSpec；越界或计划无效返回 (零值, false)。
func (p SealedConnectionPlan) HopAt(index int) (HopSpec, bool) {
	if !p.IsValid() {
		return HopSpec{}, false
	}
	return p.hops.At(index)
}

// HopDigestAt 返回第 index 跳的 Merkle HopDigest；越界或计划无效返回 (零值, false)。
func (p SealedConnectionPlan) HopDigestAt(index int) (HopDigest, bool) {
	if !p.IsValid() {
		return HopDigest{}, false
	}
	return p.hopDigests.At(index)
}

// Target 返回计划末跳（最终目标主机）规格；无效零值返回 (零值, false)。
func (p SealedConnectionPlan) Target() (HopSpec, bool) {
	if !p.IsValid() {
		return HopSpec{}, false
	}
	return p.hops.At(p.hops.Len() - 1)
}

// Prefix 返回前 count 跳（1 <= count <= Len()）对应的子连接计划，严格保持前缀每跳 HopDigest 完全一致，
// 供连接池多跳拨号逐级缓存并安全复用公共堡垒机前缀。
func (p SealedConnectionPlan) Prefix(count int) (SealedConnectionPlan, error) {
	if !p.IsValid() || count < 1 || count > p.hops.Len() {
		return SealedConnectionPlan{}, fmt.Errorf("%w: 非法前缀长度 %d", ErrInvalidConnectionPlan, count)
	}
	subHops, err := algebraic.NonEmptyFromSlice(p.hops.Slice()[:count])
	if err != nil {
		return SealedConnectionPlan{}, err
	}
	subDigests, err := algebraic.NonEmptyFromSlice(p.hopDigests.Slice()[:count])
	if err != nil {
		return SealedConnectionPlan{}, err
	}
	leaf, ok := subDigests.At(count - 1)
	if !ok {
		return SealedConnectionPlan{}, ErrInvalidConnectionPlan
	}
	pd, err := computePlanDigest(uint64(count), leaf)
	if err != nil {
		return SealedConnectionPlan{}, err
	}
	return SealedConnectionPlan{hops: subHops, hopDigests: subDigests, planDigest: pd, valid: true}, nil
}

// Equal 严格比对两份 SealedConnectionPlan 是否均有效、摘要匹配且全部跳板规格一致。
func (p SealedConnectionPlan) Equal(o SealedConnectionPlan) bool {
	return p.IsValid() && o.IsValid() &&
		p.planDigest.Equal(o.planDigest) &&
		slices.EqualFunc(p.hopDigests.Slice(), o.hopDigests.Slice(), HopDigest.Equal) &&
		slices.EqualFunc(p.hops.Slice(), o.hops.Slice(), HopSpec.Equal)
}

// WriteCanonical 以零反射、长度前缀与域分离方式将 SealedConnectionPlan 全字段写入 w（受 digestcover 校验）。
func (p SealedConnectionPlan) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !p.valid || !p.IsValid() {
		return ErrInvalidConnectionPlan
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(planCanonicalTag)
	hops := p.hops.Slice()
	enc.writeUint64(uint64(len(hops)))
	for _, h := range hops {
		if enc.err == nil {
			enc.fail(h.WriteCanonical(w))
		}
	}
	digests := p.hopDigests.Slice()
	enc.writeUint64(uint64(len(digests)))
	for _, d := range digests {
		sum, ok := d.Bytes()
		if !ok {
			return ErrInvalidConnectionPlan
		}
		enc.writeBytes(sum[:])
	}
	planSum, ok := p.planDigest.Bytes()
	if !ok {
		return ErrInvalidConnectionPlan
	}
	enc.writeBytes(planSum[:])
	return enc.err
}

// CanonicalJSON 使用 Go 1.27 encoding/json/v2 Deterministic(true) 编码确定性 JSON。
func (p SealedConnectionPlan) CanonicalJSON() ([]byte, error) {
	if !p.IsValid() {
		return nil, ErrInvalidConnectionPlan
	}
	return jsonv2.Marshal(p, jsonv2.Deterministic(true))
}

type sealedPlanWire struct {
	Hops       []HopSpec                    `json:"hops"`
	HopDigests []HopDigest                  `json:"hop_digests"`
	PlanDigest algebraic.Option[PlanDigest] `json:"plan_digest"`
}

// MarshalJSONTo 实现 SealedConnectionPlan 的 json/v2 确定性编码。
func (p SealedConnectionPlan) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !p.IsValid() {
		return ErrInvalidConnectionPlan
	}
	return jsonv2.MarshalEncode(enc, sealedPlanWire{
		Hops:       p.hops.Slice(),
		HopDigests: p.hopDigests.Slice(),
		PlanDigest: algebraic.Some(p.planDigest),
	})
}

// UnmarshalJSONFrom 实现 SealedConnectionPlan 的防篡改 json/v2 解码：
// 必须完整携带 hop_digests 与 plan_digest 且与依据 hops 重算的 Merkle 链严格一致，缺失/null/篡改一律失败关闭。
func (p *SealedConnectionPlan) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(p, dec, ErrInvalidConnectionPlan, func(w sealedPlanWire) (SealedConnectionPlan, error) {
		neHops, err := algebraic.NonEmptyFromSlice(w.Hops)
		if err != nil {
			return SealedConnectionPlan{}, fmt.Errorf("%w: %w", ErrInvalidConnectionPlan, err)
		}
		pd, hasPD := w.PlanDigest.Get()
		if !hasPD || len(w.HopDigests) == 0 {
			return SealedConnectionPlan{}, fmt.Errorf("%w: 缺少必需的 hop_digests 或 plan_digest", ErrTamperedPlanDigest)
		}
		rebuilt, err := NewSealedConnectionPlan(neHops)
		if err != nil {
			return SealedConnectionPlan{}, err
		}
		if !slices.EqualFunc(w.HopDigests, rebuilt.hopDigests.Slice(), HopDigest.Equal) {
			return SealedConnectionPlan{}, fmt.Errorf("%w: hop_digests 校验失败", ErrTamperedPlanDigest)
		}
		if !pd.Equal(rebuilt.planDigest) {
			return SealedConnectionPlan{}, fmt.Errorf("%w: plan_digest 校验失败", ErrTamperedPlanDigest)
		}
		return rebuilt, nil
	})
}
