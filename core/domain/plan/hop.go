package plan

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const hopSpecDomainTag = "xops.plan.hop_spec.v1"

// HopSpecInput 是构造不可变 HopSpec 的显式入参规格（仅携带零明文 inventory.AuthMethod，内部派生 AuthKind 与 AuthDigest 防止漂移）。
type HopSpecInput struct {
	HopIndex     uint32
	NodeID       string
	Origin       option.OriginKind
	Endpoint     netaddr.Endpoint
	OriginalHost option.OriginalHostSpec
	Username     option.Username
	Auth         inventory.AuthMethod
	Transport    TransportPolicySpec
}

// HopSpec 表示多跳 SSH 连接计划中单跳的不可变规范规格（零明文、零反射）；
// 直接内嵌不可变 inventory.AuthMethod 并在构造期派生 authKind 与 authDigest 以杜绝三者漂移，
// 经 //xops:canonicalhash 由 xopsvet/digestcover 校验 WriteCanonical 100% 全字段覆盖。
//
//xops:opaque
//xops:failclosed
//xops:canonicalhash
type HopSpec struct {
	hopIndex     uint32
	nodeID       string
	origin       option.OriginKind
	endpoint     netaddr.Endpoint
	originalHost option.OriginalHostSpec
	username     option.Username
	auth         inventory.AuthMethod
	authKind     inventory.AuthMethodKind
	authDigest   security.Digest
	transport    TransportPolicySpec
	valid        bool
}

// AuthMethodDigest 计算 inventory.AuthMethod 的零明文确定性 SHA-256 摘要，供 HopSpec 绑定认证身份。
func AuthMethodDigest(auth inventory.AuthMethod) (security.Digest, error) {
	h := sha256.New()
	if err := inventory.WriteAuthMethodCanonical(h, auth); err != nil {
		var zero security.Digest
		return zero, fmt.Errorf("%w: %w", ErrInvalidHopSpec, err)
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return security.DigestFromSHA256(sum), nil
}

// NewHopSpec 校验全部单跳规格字段并在内部由 Auth 派生 AuthKind 与 AuthDigest，构造不可变 HopSpec。
func NewHopSpec(in HopSpecInput) (HopSpec, error) {
	if err := validateHopSpecInput(in); err != nil {
		return HopSpec{}, err
	}
	digest, err := AuthMethodDigest(in.Auth)
	if err != nil {
		return HopSpec{}, err
	}
	return HopSpec{
		hopIndex: in.HopIndex, nodeID: in.NodeID, origin: in.Origin,
		endpoint: in.Endpoint, originalHost: in.OriginalHost, username: in.Username,
		auth: in.Auth, authKind: in.Auth.Kind(), authDigest: digest, transport: in.Transport, valid: true,
	}, nil
}

// NewHopSpecFromAuth 直接结合已求解 EffectivePolicy 与封闭 AuthMethod 构造不可变 HopSpec。
func NewHopSpecFromAuth(hopIndex uint32, nodeID string, user option.Username, auth inventory.AuthMethod, policy option.EffectivePolicy) (HopSpec, error) {
	if !policy.IsValid() {
		return HopSpec{}, fmt.Errorf("%w: EffectivePolicy 无效", ErrInvalidHopSpec)
	}
	tp, err := TransportPolicyFromEffective(policy)
	if err != nil {
		return HopSpec{}, fmt.Errorf("%w: %w", ErrInvalidHopSpec, err)
	}
	return NewHopSpec(HopSpecInput{
		HopIndex: hopIndex, NodeID: nodeID, Origin: policy.Origin(),
		Endpoint: policy.Endpoint(), OriginalHost: policy.OriginalHost(),
		Username: user, Auth: auth, Transport: tp,
	})
}

func validateHopSpecInput(in HopSpecInput) error {
	switch {
	case !isValidNodeLabel(in.NodeID):
		return fmt.Errorf("%w: 非法 node_id %q", ErrInvalidHopSpec, in.NodeID)
	case !in.Origin.IsValid():
		return fmt.Errorf("%w: 无效 OriginKind", ErrInvalidHopSpec)
	case !in.Endpoint.IsValid() || !in.OriginalHost.IsValid():
		return fmt.Errorf("%w: Endpoint 与 OriginalHost 均须有效", ErrInvalidHopSpec)
	case !in.Username.IsValid():
		return fmt.Errorf("%w: 无效 Username", ErrInvalidHopSpec)
	case in.Auth == nil || !in.Auth.IsValid() || !in.Auth.Kind().IsValid():
		return fmt.Errorf("%w: Auth 必须为有效的非 nil inventory.AuthMethod", ErrInvalidHopSpec)
	case !in.Transport.IsValid():
		return fmt.Errorf("%w: %w", ErrInvalidHopSpec, ErrInvalidTransportPolicy)
	}
	return nil
}

func (h HopSpec) IsValid() bool {
	return h.valid && h.nodeID != "" && h.origin.IsValid() && h.endpoint.IsValid() &&
		h.originalHost.IsValid() && h.username.IsValid() && h.auth != nil && h.auth.IsValid() &&
		h.authKind.IsValid() && h.auth.Kind() == h.authKind && h.authDigest.IsValid() && h.transport.IsValid()
}
func (h HopSpec) IsZero() bool                          { return !h.IsValid() }
func (h HopSpec) HopIndex() uint32                      { return h.hopIndex }
func (h HopSpec) NodeID() string                        { return h.nodeID }
func (h HopSpec) Origin() option.OriginKind             { return h.origin }
func (h HopSpec) Endpoint() netaddr.Endpoint            { return h.endpoint }
func (h HopSpec) OriginalHost() option.OriginalHostSpec { return h.originalHost }
func (h HopSpec) Username() option.Username             { return h.username }
func (h HopSpec) Auth() inventory.AuthMethod            { return pickIf(h.IsValid(), h.auth, nil) }
func (h HopSpec) AuthKind() inventory.AuthMethodKind    { return h.authKind }
func (h HopSpec) AuthDigest() security.Digest           { return h.authDigest }
func (h HopSpec) Transport() TransportPolicySpec        { return h.transport }

// Equal 严格比对两跳规格是否均有效且全部字段完全一致。
func (h HopSpec) Equal(o HopSpec) bool {
	return h.IsValid() && o.IsValid() && h.hopIndex == o.hopIndex && h.nodeID == o.nodeID &&
		h.origin == o.origin && h.endpoint.Equal(o.endpoint) && h.originalHost.Equal(o.originalHost) &&
		h.username.Equal(o.username) && inventory.EqualAuthMethod(h.auth, o.auth) &&
		h.authKind == o.authKind && h.authDigest.Equal(o.authDigest) && h.transport.Equal(o.transport)
}

// WriteCanonical 以零反射、长度前缀与域分离方式将 HopSpec 全部字段写入 w（受 digestcover 校验）。
func (h HopSpec) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !h.valid || !h.IsValid() {
		return ErrInvalidHopSpec
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(hopSpecDomainTag)
	enc.writeUint32(h.hopIndex)
	enc.writeString(h.nodeID)
	enc.writeUint8(uint8(h.origin))
	enc.writeString(h.endpoint.String())
	enc.writeString(h.originalHost.String())
	enc.writeString(h.username.String())
	if enc.err == nil {
		enc.fail(inventory.WriteAuthMethodCanonical(w, h.auth))
	}
	enc.writeUint8(uint8(h.authKind))
	sum, ok := h.authDigest.Bytes()
	if !ok {
		return ErrInvalidHopSpec
	}
	enc.writeBytes(sum[:])
	if enc.err == nil {
		enc.fail(h.transport.WriteCanonical(w))
	}
	return enc.err
}

type authMethodWire struct{ auth inventory.AuthMethod }

func (a authMethodWire) MarshalJSONTo(enc *jsontext.Encoder) error {
	return inventory.MarshalAuthMethodTo(enc, a.auth)
}
func (a *authMethodWire) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	m, err := inventory.UnmarshalAuthMethodFrom(dec)
	if err != nil {
		a.auth = nil
		return err
	}
	a.auth = m
	return nil
}

type hopSpecWire struct {
	HopIndex     algebraic.Option[uint32]                   `json:"hop_index"`
	NodeID       algebraic.Option[string]                   `json:"node_id"`
	Origin       algebraic.Option[option.OriginKind]        `json:"origin"`
	Endpoint     algebraic.Option[netaddr.Endpoint]         `json:"endpoint"`
	OriginalHost algebraic.Option[option.OriginalHostSpec]  `json:"original_host"`
	Username     algebraic.Option[option.Username]          `json:"username"`
	Auth         algebraic.Option[authMethodWire]           `json:"auth"`
	AuthKind     algebraic.Option[inventory.AuthMethodKind] `json:"auth_kind"`
	AuthDigest   algebraic.Option[security.Digest]          `json:"auth_digest"`
	Transport    algebraic.Option[TransportPolicySpec]      `json:"transport"`
}

// MarshalJSONTo 实现 HopSpec 的 json/v2 确定性编码。
func (h HopSpec) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !h.IsValid() {
		return ErrInvalidHopSpec
	}
	return jsonv2.MarshalEncode(enc, hopSpecWire{
		HopIndex: algebraic.Some(h.hopIndex), NodeID: algebraic.Some(h.nodeID),
		Origin: algebraic.Some(h.origin), Endpoint: algebraic.Some(h.endpoint),
		OriginalHost: algebraic.Some(h.originalHost), Username: algebraic.Some(h.username),
		Auth:     algebraic.Some(authMethodWire{h.auth}),
		AuthKind: algebraic.Some(h.authKind), AuthDigest: algebraic.Some(h.authDigest),
		Transport: algebraic.Some(h.transport),
	})
}

// UnmarshalJSONFrom 实现 HopSpec 的失败关闭 json/v2 解码，强制核验 auth 与派生 auth_kind/auth_digest 一致。
func (h *HopSpec) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(h, dec, ErrInvalidHopSpec, func(w hopSpecWire) (HopSpec, error) {
		idx, okIdx := w.HopIndex.Get()
		nid, okN := w.NodeID.Get()
		ori, okO := w.Origin.Get()
		ep, okE := w.Endpoint.Get()
		origHost, okH := w.OriginalHost.Get()
		user, okU := w.Username.Get()
		aw, okA := w.Auth.Get()
		ak, okAK := w.AuthKind.Get()
		ad, okAD := w.AuthDigest.Get()
		tp, okT := w.Transport.Get()
		if !okIdx || !okN || !okO || !okE || !okH || !okU || !okA || !okAK || !okAD || !okT {
			return HopSpec{}, fmt.Errorf("%w: 缺少必需的 HopSpec 字段", ErrInvalidHopSpec)
		}
		rebuilt, err := NewHopSpec(HopSpecInput{idx, nid, ori, ep, origHost, user, aw.auth, tp})
		if err != nil {
			return HopSpec{}, err
		}
		if rebuilt.authKind != ak || !rebuilt.authDigest.Equal(ad) {
			return HopSpec{}, fmt.Errorf("%w: HopSpec auth_kind/auth_digest 与 auth 负载不匹配", ErrTamperedPlanDigest)
		}
		return rebuilt, nil
	})
}
