package plan

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"io"
	"slices"
	"strings"
	"unicode"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/option"
)

const transportPolicyDomainTag = "xops.plan.transport_policy.v1"

// TransportPolicySpec 是从 option.EffectivePolicy 完整提取的不可变连接传输与安全策略投影；
// 100% 覆盖算法协商、主机密钥信任、身份/证书路径、多路复用、代理与会话选项，
// 并经 //xops:canonicalhash 由 xopsvet/digestcover 在编译期静态验证 WriteCanonical 全字段覆盖。
//
//xops:opaque
//xops:failclosed
//xops:canonicalhash
type TransportPolicySpec struct {
	ciphers               []string
	macs                  []string
	kexAlgorithms         []string
	hostKeyAlgorithms     []string
	strictHostKeyChecking option.StrictHostKeyCheckingMode
	userKnownHostsFiles   option.KnownHostsList
	identityFiles         option.PathList
	certificateFiles      option.PathList
	identitiesOnly        bool
	batchMode             bool
	forwardAgent          bool
	connectTimeout        algebraic.Option[algebraic.Duration]
	serverAliveInterval   algebraic.Duration
	serverAliveCountMax   uint32
	proxyRoute            option.ProxyRoute
	controlPolicy         option.ControlPolicy
	sendEnv               option.EnvFilter
	permitLocalCommand    bool
	localCommand          algebraic.Option[option.SanitizedCmd]
	valid                 bool
}

// TransportPolicyFromEffective 从已求解的有效策略提取不可变 TransportPolicySpec。
func TransportPolicyFromEffective(ep option.EffectivePolicy) (TransportPolicySpec, error) {
	if !ep.IsValid() {
		return TransportPolicySpec{}, domi18n.EF(ErrInvalidTransportPolicy, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "effective_policy"))
	}
	ciphers, macs, kex, hk := ep.Ciphers(), ep.MACs(), ep.KexAlgorithms(), ep.HostKeyAlgorithms()
	if len(ciphers) == 0 || len(macs) == 0 || len(kex) == 0 || len(hk) == 0 {
		return TransportPolicySpec{}, domi18n.EF(ErrInvalidTransportPolicy, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "algorithms"))
	}
	if err := option.ValidateProxyRoute(ep.Proxy()); err != nil {
		return TransportPolicySpec{}, domi18n.WrapSentinel(ErrInvalidTransportPolicy, err)
	}
	return TransportPolicySpec{
		ciphers: ciphers, macs: macs, kexAlgorithms: kex, hostKeyAlgorithms: hk,
		strictHostKeyChecking: ep.StrictHostKeyChecking(),
		userKnownHostsFiles:   ep.UserKnownHostsFiles(),
		identityFiles:         ep.IdentityFiles(),
		certificateFiles:      ep.CertificateFiles(),
		identitiesOnly:        ep.IdentitiesOnly(),
		batchMode:             ep.BatchMode(),
		forwardAgent:          ep.ForwardAgent(),
		connectTimeout:        ep.ConnectTimeout(),
		serverAliveInterval:   ep.ServerAliveInterval(),
		serverAliveCountMax:   ep.ServerAliveCountMax(),
		proxyRoute:            ep.Proxy(),
		controlPolicy:         ep.Control(),
		sendEnv:               ep.SendEnv(),
		permitLocalCommand:    ep.PermitLocalCommand(),
		localCommand:          ep.LocalCommand(),
		valid:                 true,
	}, nil
}

func (t TransportPolicySpec) IsValid() bool {
	return t.valid && len(t.ciphers) > 0 && len(t.macs) > 0 && len(t.kexAlgorithms) > 0 && len(t.hostKeyAlgorithms) > 0
}
func (t TransportPolicySpec) IsZero() bool            { return !t.IsValid() }
func (t TransportPolicySpec) Ciphers() []string       { return slices.Clone(t.ciphers) }
func (t TransportPolicySpec) MACs() []string          { return slices.Clone(t.macs) }
func (t TransportPolicySpec) KexAlgorithms() []string { return slices.Clone(t.kexAlgorithms) }
func (t TransportPolicySpec) HostKeyAlgos() []string  { return slices.Clone(t.hostKeyAlgorithms) }
func (t TransportPolicySpec) StrictHostKeyChecking() option.StrictHostKeyCheckingMode {
	return t.strictHostKeyChecking
}
func (t TransportPolicySpec) UserKnownHostsFiles() option.KnownHostsList {
	return t.userKnownHostsFiles
}
func (t TransportPolicySpec) IdentityFiles() option.PathList    { return t.identityFiles }
func (t TransportPolicySpec) CertificateFiles() option.PathList { return t.certificateFiles }
func (t TransportPolicySpec) IdentitiesOnly() bool              { return t.valid && t.identitiesOnly }
func (t TransportPolicySpec) BatchMode() bool                   { return t.valid && t.batchMode }
func (t TransportPolicySpec) ForwardAgent() bool                { return t.valid && t.forwardAgent }
func (t TransportPolicySpec) ConnectTimeout() algebraic.Option[algebraic.Duration] {
	return t.connectTimeout
}
func (t TransportPolicySpec) ServerAliveInterval() algebraic.Duration { return t.serverAliveInterval }
func (t TransportPolicySpec) ServerAliveCountMax() uint32 {
	return pickIf(t.valid, t.serverAliveCountMax, 0)
}
func (t TransportPolicySpec) ProxyRoute() option.ProxyRoute {
	return option.ComposeProxyRoute(t.proxyRoute, nil)
}
func (t TransportPolicySpec) ControlPolicy() option.ControlPolicy { return t.controlPolicy }
func (t TransportPolicySpec) SendEnv() option.EnvFilter           { return t.sendEnv }
func (t TransportPolicySpec) PermitLocalCommand() bool            { return t.valid && t.permitLocalCommand }
func (t TransportPolicySpec) LocalCommand() algebraic.Option[option.SanitizedCmd] {
	if !t.PermitLocalCommand() {
		return algebraic.None[option.SanitizedCmd]()
	}
	return t.localCommand
}

// Equal 严格比对两份 TransportPolicySpec 是否均有效且全部字段完全一致。
func (t TransportPolicySpec) Equal(o TransportPolicySpec) bool {
	if !t.IsValid() || !o.IsValid() {
		return false
	}
	ctA, okCA := t.connectTimeout.Get()
	ctB, okCB := o.connectTimeout.Get()
	lcA, okLA := t.localCommand.Get()
	lcB, okLB := o.localCommand.Get()
	return slices.Equal(t.ciphers, o.ciphers) && slices.Equal(t.macs, o.macs) &&
		slices.Equal(t.kexAlgorithms, o.kexAlgorithms) && slices.Equal(t.hostKeyAlgorithms, o.hostKeyAlgorithms) &&
		t.strictHostKeyChecking == o.strictHostKeyChecking &&
		t.userKnownHostsFiles.Equal(o.userKnownHostsFiles) &&
		t.identityFiles.Equal(o.identityFiles) && t.certificateFiles.Equal(o.certificateFiles) &&
		t.identitiesOnly == o.identitiesOnly && t.batchMode == o.batchMode && t.forwardAgent == o.forwardAgent &&
		okCA == okCB && (!okCA || ctA.Equal(ctB)) &&
		t.serverAliveInterval.Equal(o.serverAliveInterval) &&
		t.serverAliveCountMax == o.serverAliveCountMax &&
		option.EqualProxyRoute(t.proxyRoute, o.proxyRoute) &&
		t.controlPolicy.Equal(o.controlPolicy) && t.sendEnv.Equal(o.sendEnv) &&
		t.permitLocalCommand == o.permitLocalCommand &&
		okLA == okLB && (!okLA || lcA.Equal(lcB))
}

// WriteCanonical 以零反射、长度前缀与域分离方式写入 TransportPolicySpec 全字段（受 digestcover 校验）。
func (t TransportPolicySpec) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !t.valid || !t.IsValid() {
		return ErrInvalidTransportPolicy
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(transportPolicyDomainTag)
	enc.writeStrings(t.ciphers)
	enc.writeStrings(t.macs)
	enc.writeStrings(t.kexAlgorithms)
	enc.writeStrings(t.hostKeyAlgorithms)
	enc.writeUint8(uint8(t.strictHostKeyChecking))
	writeKnownHostsCanonical(enc, t.userKnownHostsFiles)
	writePathListCanonical(enc, t.identityFiles)
	writePathListCanonical(enc, t.certificateFiles)
	enc.writeBool(t.identitiesOnly)
	enc.writeBool(t.batchMode)
	enc.writeBool(t.forwardAgent)
	writeOptDurationCanonical(enc, t.connectTimeout)
	enc.writeInt64(int64(t.serverAliveInterval.Std()))
	enc.writeUint32(t.serverAliveCountMax)
	enc.fail(writeProxyRouteCanonical(enc, t.proxyRoute))
	writeControlPolicyCanonical(enc, t.controlPolicy)
	writeEnvFilterCanonical(enc, t.sendEnv)
	enc.writeBool(t.permitLocalCommand)
	if lc, ok := t.localCommand.Get(); ok {
		enc.writeUint8(1)
		enc.writeString(lc.String())
	} else {
		enc.writeUint8(0)
	}
	return enc.err
}

func writePathListCanonical(enc *canonicalEncoder, pl option.PathList) {
	enc.writeUint8(uint8(pl.State()))
	enc.writeBool(pl.Terminated())
	enc.writeStrings(pl.RawItems())
}

func writeKnownHostsCanonical(enc *canonicalEncoder, kh option.KnownHostsList) {
	enc.writeUint8(uint8(kh.State()))
	enc.writeStrings(kh.RawItems())
}

func writeOptDurationCanonical(enc *canonicalEncoder, opt algebraic.Option[algebraic.Duration]) {
	if d, ok := opt.Get(); ok {
		enc.writeUint8(1)
		enc.writeInt64(int64(d.Std()))
	} else {
		enc.writeUint8(0)
	}
}

// writeProxyRouteCanonical 先以 option.ValidateProxyRoute 校验，再经 option.MarshalProxyRouteTo
// 输出完整确定性字节流（涵盖 ProxyJumpChain 携带的 shadowed ProxyCommand 槽位），确保与 EqualProxyRoute 严格双射。
func writeProxyRouteCanonical(enc *canonicalEncoder, route option.ProxyRoute) error {
	if route == nil {
		route = option.NewProxyUnset()
	}
	if err := option.ValidateProxyRoute(route); err != nil {
		enc.fail(ErrInvalidTransportPolicy)
		return domi18n.WrapSentinel(ErrInvalidTransportPolicy, err)
	}
	var buf bytes.Buffer
	if err := option.MarshalProxyRouteTo(jsontext.NewEncoder(&buf), route); err != nil {
		enc.fail(ErrInvalidTransportPolicy)
		return domi18n.WrapSentinel(ErrInvalidTransportPolicy, err)
	}
	enc.writeBytes(buf.Bytes())
	return enc.err
}

func writeControlPolicyCanonical(enc *canonicalEncoder, cp option.ControlPolicy) {
	enc.writeUint8(uint8(cp.Master()))
	enc.writeUint8(uint8(cp.Path().Kind()))
	enc.writeString(cp.Path().String())
	enc.writeUint8(uint8(cp.Persist().Kind()))
	if d, ok := cp.Persist().Timeout(); ok {
		enc.writeUint8(1)
		enc.writeInt64(int64(d.Std()))
	} else {
		enc.writeUint8(0)
	}
}

func writeEnvFilterCanonical(enc *canonicalEncoder, ef option.EnvFilter) {
	enc.writeStrings(ef.ClearPatterns())
	enc.writeStrings(ef.Patterns())
}

type proxyRouteWire struct{ route option.ProxyRoute }

func (p proxyRouteWire) IsZero() bool {
	return p.route == nil || option.EqualProxyRoute(p.route, option.NewProxyUnset())
}
func (p proxyRouteWire) MarshalJSONTo(enc *jsontext.Encoder) error {
	return option.MarshalProxyRouteTo(enc, p.route)
}
func (p *proxyRouteWire) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	r, err := option.UnmarshalProxyRouteFrom(dec)
	if err != nil {
		p.route = nil
		return err
	}
	p.route = r
	return nil
}

type transportPolicyWire struct {
	Ciphers               []string                                           `json:"ciphers"`
	MACs                  []string                                           `json:"macs"`
	KexAlgorithms         []string                                           `json:"kex_algorithms"`
	HostKeyAlgorithms     []string                                           `json:"host_key_algorithms"`
	StrictHostKeyChecking algebraic.Option[option.StrictHostKeyCheckingMode] `json:"strict_host_key_checking"`
	UserKnownHostsFiles   option.KnownHostsList                              `json:"user_known_hosts_files,omitzero"`
	IdentityFiles         option.PathList                                    `json:"identity_files,omitzero"`
	CertificateFiles      option.PathList                                    `json:"certificate_files,omitzero"`
	IdentitiesOnly        bool                                               `json:"identities_only,omitzero"`
	BatchMode             bool                                               `json:"batch_mode,omitzero"`
	ForwardAgent          bool                                               `json:"forward_agent,omitzero"`
	ConnectTimeout        algebraic.Option[algebraic.Duration]               `json:"connect_timeout,omitzero"`
	ServerAliveInterval   algebraic.Option[algebraic.Duration]               `json:"server_alive_interval"`
	ServerAliveCountMax   algebraic.Option[uint32]                           `json:"server_alive_count_max"`
	ProxyRoute            proxyRouteWire                                     `json:"proxy_route,omitzero"`
	ControlPolicy         option.ControlPolicy                               `json:"control_policy,omitzero"`
	SendEnv               option.EnvFilter                                   `json:"send_env,omitzero"`
	PermitLocalCommand    bool                                               `json:"permit_local_command,omitzero"`
	LocalCommand          algebraic.Option[option.SanitizedCmd]              `json:"local_command,omitzero"`
}

// MarshalJSONTo 实现 TransportPolicySpec 的 json/v2 确定性编码。
func (t TransportPolicySpec) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !t.IsValid() {
		return ErrInvalidTransportPolicy
	}
	return jsonv2.MarshalEncode(enc, transportPolicyWire{
		Ciphers: t.ciphers, MACs: t.macs, KexAlgorithms: t.kexAlgorithms, HostKeyAlgorithms: t.hostKeyAlgorithms,
		StrictHostKeyChecking: algebraic.Some(t.strictHostKeyChecking), UserKnownHostsFiles: t.userKnownHostsFiles,
		IdentityFiles: t.identityFiles, CertificateFiles: t.certificateFiles,
		IdentitiesOnly: t.identitiesOnly, BatchMode: t.batchMode, ForwardAgent: t.forwardAgent,
		ConnectTimeout: t.connectTimeout, ServerAliveInterval: algebraic.Some(t.serverAliveInterval),
		ServerAliveCountMax: algebraic.Some(t.serverAliveCountMax),
		ProxyRoute:          proxyRouteWire{t.proxyRoute}, ControlPolicy: t.controlPolicy, SendEnv: t.sendEnv,
		PermitLocalCommand: t.permitLocalCommand, LocalCommand: t.localCommand,
	})
}

// UnmarshalJSONFrom 实现 TransportPolicySpec 的失败关闭 json/v2 解码。
func (t *TransportPolicySpec) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(t, dec, ErrInvalidTransportPolicy, decodeTransportPolicyWire)
}

func decodeTransportPolicyWire(w transportPolicyWire) (TransportPolicySpec, error) {
	shkc, okS := w.StrictHostKeyChecking.Get()
	sal, okA := w.ServerAliveInterval.Get()
	sacm, okC := w.ServerAliveCountMax.Get()
	if !okS || !okA || !okC || len(w.Ciphers) == 0 || len(w.MACs) == 0 || len(w.KexAlgorithms) == 0 || len(w.HostKeyAlgorithms) == 0 {
		return TransportPolicySpec{}, domi18n.EF(ErrInvalidTransportPolicy, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "transport_policy"))
	}
	if sal.IsNegative() {
		return TransportPolicySpec{}, domi18n.EF(ErrInvalidTransportPolicy, domi18n.KeyCommonFieldNegative, domi18n.Str("field", "server_alive_interval"))
	}
	if ct, ok := w.ConnectTimeout.Get(); ok && ct.IsNegative() {
		return TransportPolicySpec{}, domi18n.EF(ErrInvalidTransportPolicy, domi18n.KeyCommonFieldNegative, domi18n.Str("field", "connect_timeout"))
	}
	if err := option.ValidateProxyRoute(w.ProxyRoute.route); err != nil {
		return TransportPolicySpec{}, domi18n.WrapSentinel(ErrInvalidTransportPolicy, err)
	}
	lc, err := validateLocalCommandWire(w.PermitLocalCommand, w.LocalCommand)
	if err != nil {
		return TransportPolicySpec{}, err
	}
	for _, list := range [4][]string{w.Ciphers, w.MACs, w.KexAlgorithms, w.HostKeyAlgorithms} {
		if err := validateExactAlgoList(list); err != nil {
			return TransportPolicySpec{}, err
		}
	}
	return TransportPolicySpec{
		ciphers: slices.Clone(w.Ciphers), macs: slices.Clone(w.MACs),
		kexAlgorithms: slices.Clone(w.KexAlgorithms), hostKeyAlgorithms: slices.Clone(w.HostKeyAlgorithms),
		strictHostKeyChecking: shkc, userKnownHostsFiles: w.UserKnownHostsFiles,
		identityFiles: w.IdentityFiles, certificateFiles: w.CertificateFiles,
		identitiesOnly: w.IdentitiesOnly, batchMode: w.BatchMode, forwardAgent: w.ForwardAgent,
		connectTimeout: w.ConnectTimeout, serverAliveInterval: sal, serverAliveCountMax: sacm,
		proxyRoute:    option.ComposeProxyRoute(w.ProxyRoute.route, nil),
		controlPolicy: w.ControlPolicy, sendEnv: w.SendEnv,
		permitLocalCommand: w.PermitLocalCommand, localCommand: lc, valid: true,
	}, nil
}

// validateExactAlgoList 复用 core/domain/option 的唯一规范算法解析器校验解码后的精确算法列表：
// 拒绝空项、逗号、空白、通配符、增删前缀（+/-/^）、非 ASCII 与重复算法名。
func validateExactAlgoList(list []string) error {
	if len(list) == 0 {
		return domi18n.EF(ErrInvalidTransportPolicy, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "algorithms"))
	}
	for _, item := range list {
		if item == "" || strings.ContainsRune(item, ',') || strings.ContainsFunc(item, unicode.IsSpace) {
			return domi18n.EF(ErrInvalidTransportPolicy, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "algorithm"), domi18n.BoundStr("value", item))
		}
	}
	pol, err := option.ParseAlgoPolicy(strings.Join(list, ","))
	if err != nil || !pol.IsExact() || !slices.Equal(pol.Tokens(), list) {
		return domi18n.EF(ErrInvalidTransportPolicy, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "algorithms"))
	}
	return nil
}

func validateLocalCommandWire(permit bool, opt algebraic.Option[option.SanitizedCmd]) (algebraic.Option[option.SanitizedCmd], error) {
	if !permit {
		return algebraic.None[option.SanitizedCmd](), nil
	}
	if c, ok := opt.Get(); ok && !c.IsValid() {
		return algebraic.None[option.SanitizedCmd](), domi18n.EF(ErrInvalidTransportPolicy, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "local_command"))
	}
	return opt, nil
}
