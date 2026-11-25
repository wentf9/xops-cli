package option

import (
	"fmt"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

// OriginKind 标识目标连接的来源分类（与 inventory.NodeOrigin 语义同构而零循环依赖）；零值 OriginInvalid 失败关闭。
//
//xops:failclosed
type OriginKind uint8

const (
	OriginInvalid        OriginKind = iota // 未初始化/非法来源（零值失败关闭）
	OriginManaged                          // XOps 托管资产节点（按 INV-D2 仅对 t4 执行安全裁剪）
	OriginOpenSSHVirtual                   // ~/.ssh/config 只读虚拟节点（完整应用 t4）
	OriginOpenSSHDerived                   // 纯 OpenSSH Host 派生节点（完整应用 t4）
	OriginAdHoc                            // 临时 user@host 或未持久化派生会话（按 INV-D2 仅对 t4 执行安全裁剪）
)

// ParseOriginKind 解析规范策略来源分类文本，严格拒绝控制与格式字符。
func ParseOriginKind(raw string) (OriginKind, error) {
	if !hasForbiddenControlChar(raw) {
		if v, ok := map[string]OriginKind{
			"managed": OriginManaged, "openssh_virtual": OriginOpenSSHVirtual,
			"openssh_derived": OriginOpenSSHDerived, "ad_hoc": OriginAdHoc,
		}[strings.ToLower(strings.TrimSpace(raw))]; ok {
			return v, nil
		}
	}
	return OriginInvalid, fmt.Errorf("%w: 未知策略来源 %q", ErrInvalidOrigin, raw)
}
func (o OriginKind) IsValid() bool { return o >= OriginManaged && o <= OriginAdHoc }
func (o OriginKind) AllowsFullOpenSSHConfig() bool {
	return o == OriginOpenSSHVirtual || o == OriginOpenSSHDerived
}
func (o OriginKind) String() string {
	return enumName(uint8(o), "managed", "openssh_virtual", "openssh_derived", "ad_hoc")
}
func (o OriginKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, o.String(), o.IsValid(), ErrInvalidOrigin)
}
func (o OriginKind) MarshalText() ([]byte, error) { return o.AppendText(nil) }
func (o *OriginKind) UnmarshalText(text []byte) error {
	return unmarshalTextVia(o, text, ParseOriginKind)
}

// DefaultServerAliveCountMax 是 OpenSSH 默认保活探测最大允许丢失次数。
const DefaultServerAliveCountMax uint32 = 3

// DefaultOptionLayer 返回内置安全默认兜底层（位于四层 t1..t4 之后）。
func DefaultOptionLayer() OptionLayer {
	return UnsetOptionLayer().WithControlPolicy(UnsetControlPolicy().WithMaster(ControlMasterNo)).
		WithServerAliveInterval(algebraic.ZeroDuration()).WithServerAliveCountMax(DefaultServerAliveCountMax).
		WithIdentitiesOnly(false).WithBatchMode(false).
		WithStrictHostKeyChecking(StrictHostKeyCheckingAsk).WithForwardAgent(false).WithPermitLocalCommand(false)
}

// EffectivePolicy 表示经唯一纯求解入口 ResolveEffectivePolicy 计算得到的不可变生效策略快照；零值恒无效。
//
//xops:opaque
//xops:failclosed
type EffectivePolicy struct {
	origin                                     OriginKind
	endpoint                                   netaddr.Endpoint
	originalHost                               OriginalHostSpec
	opts                                       OptionLayer
	ciphers, macs, kexAlgorithms, hostKeyAlgos []string
	valid                                      bool
}

// ResolveEffectivePolicy 是全平面共用的唯一纯四层 OpenSSH 策略求解入口。
// 优先级严格固定为 t1（CLI） > t2（托管节点） > t3（XOps 全局配置） > t4（OpenSSH ~/.ssh/config） + DefaultOptionLayer()；
// 非 OpenSSH 来源按 INV-D2 仅对 t4 裁剪（严格保留 OptionClassMux ∪ OptionClassTransport，完整保留 t1/t2/t3），
// 随后求值端点、对默认集单次应用获胜算法策略并门控 LocalCommand。
func ResolveEffectivePolicy(origin OriginKind, endpoint netaddr.Endpoint, t1, t2, t3, t4 OptionLayer) (EffectivePolicy, error) {
	if !origin.IsValid() {
		return EffectivePolicy{}, ErrInvalidOrigin
	}
	if !endpoint.IsValid() {
		return EffectivePolicy{}, ErrInvalidEndpoint
	}
	origHost := OriginalHostSpec{textToken{endpoint.Host().String(), true}, algebraic.Some(endpoint.Host())}
	return ResolveEffectivePolicyWithOriginalHost(origin, origHost, endpoint.Port(), t1, t2, t3, t4)
}

// ResolveEffectivePolicyWithOriginalHost 支持以经校验的 OpenSSH 别名（如 "prod_db"、"bastion.01"）
// 作为 OriginalHost（保留 %n 语义）执行四层策略求解；最终拨号端点 Endpoint 仍严格校验为 netaddr.Endpoint。
func ResolveEffectivePolicyWithOriginalHost(origin OriginKind, originalHost OriginalHostSpec, defaultPort uint16, t1, t2, t3, t4 OptionLayer) (EffectivePolicy, error) {
	if !origin.IsValid() {
		return EffectivePolicy{}, ErrInvalidOrigin
	}
	if !originalHost.IsValid() || defaultPort == 0 {
		return EffectivePolicy{}, ErrInvalidEndpoint
	}
	for _, layer := range [4]OptionLayer{t1, t2, t3, t4} {
		if err := layer.Validate(); err != nil {
			return EffectivePolicy{}, err
		}
	}
	if !origin.AllowsFullOpenSSHConfig() {
		t4 = t4.FilterForNonOpenSSHOrigin()
	}
	merged := FoldOptionLayers(t1, t2, t3, t4, DefaultOptionLayer())
	if !merged.permitLocalCommand.OrElse(false) {
		merged.localCommand = algebraic.UnsetFirstWins[SanitizedCmd]()
	}
	resolvedEP, err := resolveEffectiveEndpoint(originalHost, defaultPort, merged)
	if err != nil {
		return EffectivePolicy{}, err
	}
	algos, err := applyAlgoPolicies(
		[4]AlgoPolicy{merged.ciphers, merged.macs, merged.kexAlgorithms, merged.hostKeyAlgorithms},
		[4][]string{DefaultCiphers(), DefaultMACs(), DefaultKexAlgorithms(), DefaultHostKeyAlgorithms()},
	)
	if err != nil {
		return EffectivePolicy{}, err
	}
	return EffectivePolicy{origin, resolvedEP, originalHost, merged, algos[0], algos[1], algos[2], algos[3], true}, nil
}

func applyAlgoPolicies(policies [4]AlgoPolicy, defaults [4][]string) ([4][]string, error) {
	var out [4][]string
	for i := range policies {
		var err error
		if out[i], err = policies[i].Apply(defaults[i]); err != nil {
			return out, err
		}
	}
	return out, nil
}
func resolveEffectiveEndpoint(origHost OriginalHostSpec, defaultPort uint16, merged OptionLayer) (netaddr.Endpoint, error) {
	var zero netaddr.Endpoint
	var host netaddr.CanonicalHost
	var err error
	if spec, ok := merged.hostName.Get(); ok {
		host, err = spec.ResolveHostFor(origHost)
	} else {
		host, err = netaddr.ParseCanonicalHost(origHost.String())
	}
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
	}
	ep, err := netaddr.NewEndpoint(host, merged.port.OrElse(defaultPort))
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
	}
	return ep, nil
}

// EffectivePolicy 只读访问器（切片均返回防御性副本，未授权 LocalCommand 恒为 None）。
func (p EffectivePolicy) IsValid() bool                    { return p.valid }
func (p EffectivePolicy) Origin() OriginKind               { return p.origin }
func (p EffectivePolicy) Endpoint() netaddr.Endpoint       { return p.endpoint }
func (p EffectivePolicy) OriginalHost() OriginalHostSpec   { return p.originalHost }
func (p EffectivePolicy) Options() OptionLayer             { return p.opts.clone() }
func (p EffectivePolicy) User() algebraic.Option[Username] { return p.opts.user.ToOption() }
func (p EffectivePolicy) Proxy() ProxyRoute                { return p.opts.Proxy() }
func (p EffectivePolicy) Control() ControlPolicy           { return p.opts.control }
func (p EffectivePolicy) ConnectTimeout() algebraic.Option[algebraic.Duration] {
	return p.opts.connectTimeout.ToOption()
}
func (p EffectivePolicy) ServerAliveInterval() algebraic.Duration {
	return p.opts.serverAliveInterval.OrElse(algebraic.ZeroDuration())
}
func (p EffectivePolicy) ServerAliveCountMax() uint32 {
	if !p.valid {
		return 0
	}
	return p.opts.serverAliveCountMax.OrElse(DefaultServerAliveCountMax)
}
func (p EffectivePolicy) Ciphers() []string           { return slices.Clone(p.ciphers) }
func (p EffectivePolicy) MACs() []string              { return slices.Clone(p.macs) }
func (p EffectivePolicy) KexAlgorithms() []string     { return slices.Clone(p.kexAlgorithms) }
func (p EffectivePolicy) HostKeyAlgorithms() []string { return slices.Clone(p.hostKeyAlgos) }
func (p EffectivePolicy) IdentityFiles() PathList     { return p.opts.identityFiles.clone() }
func (p EffectivePolicy) CertificateFiles() PathList  { return p.opts.certificateFiles.clone() }
func (p EffectivePolicy) IdentitiesOnly() bool        { return p.opts.identitiesOnly.OrElse(false) }
func (p EffectivePolicy) BatchMode() bool             { return p.opts.batchMode.OrElse(false) }
func (p EffectivePolicy) StrictHostKeyChecking() StrictHostKeyCheckingMode {
	return p.opts.strictHostKeyChecking.OrElse(StrictHostKeyCheckingAsk)
}
func (p EffectivePolicy) UserKnownHostsFiles() KnownHostsList {
	return p.opts.userKnownHostsFiles.clone()
}
func (p EffectivePolicy) ForwardAgent() bool       { return p.opts.forwardAgent.OrElse(false) }
func (p EffectivePolicy) SendEnv() EnvFilter       { return p.opts.SendEnv() }
func (p EffectivePolicy) PermitLocalCommand() bool { return p.opts.permitLocalCommand.OrElse(false) }
func (p EffectivePolicy) LocalCommand() algebraic.Option[SanitizedCmd] {
	if !p.PermitLocalCommand() {
		return algebraic.None[SanitizedCmd]()
	}
	return p.opts.localCommand.ToOption()
}

// PercentC 基于已求解策略（Endpoint、生效 User 与活跃 ProxyJump 末跳主机名 %j）计算 OpenSSH %C 哈希。
func (p EffectivePolicy) PercentC(localHost, fallbackUser string) (string, error) {
	if !p.valid {
		return "", ErrInvalidEndpoint
	}
	user := fallbackUser
	if u, ok := p.User().Get(); ok {
		user = u.String()
	}
	jumpHost, err := formatActiveJumpForPercentC(p.Proxy())
	if err != nil {
		return "", err
	}
	return ComputeConnectionHash(localHost, p.endpoint.Host().String(), p.endpoint.Port(), user, jumpHost)
}
func formatActiveJumpForPercentC(route ProxyRoute) (string, error) {
	switch v := route.(type) {
	case nil, *ProxyUnset, *ProxyDisabled, *ProxyCommandSpec:
		return "", nil
	case *ProxyJumpChain:
		if !v.IsValid() {
			return "", ErrInvalidProxyRoute
		}
		hops := v.hops.Slice()
		return hops[len(hops)-1].Host(), nil
	default:
		return "", ErrInvalidProxyRoute
	}
}

// Equal 判断两个有效 EffectivePolicy 是否完全相等（无效零值永不相等）。
func (p EffectivePolicy) Equal(o EffectivePolicy) bool {
	return p.valid && o.valid && p.origin == o.origin &&
		p.endpoint.Equal(o.endpoint) && p.originalHost.Equal(o.originalHost) && p.opts.Equal(o.opts) &&
		slices.Equal(p.ciphers, o.ciphers) && slices.Equal(p.macs, o.macs) &&
		slices.Equal(p.kexAlgorithms, o.kexAlgorithms) && slices.Equal(p.hostKeyAlgos, o.hostKeyAlgos)
}
