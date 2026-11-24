package option

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

type (
	pathListJSON struct {
		State      string      `json:"state"`
		Items      []PathEntry `json:"items,omitzero"`
		Terminated bool        `json:"terminated,omitzero"`
	}
	algoPolicyJSON struct {
		Op     string   `json:"op"`
		Tokens []string `json:"tokens,omitzero"`
	}
	envFilterJSON struct {
		Clear []string `json:"clear,omitzero"`
		Added []string `json:"added,omitzero"`
	}
	controlPolicyJSON struct {
		Master      string `json:"master,omitzero"`
		Path        string `json:"path,omitzero"`
		LiteralPath bool   `json:"literal_path,omitzero"`
		Persist     string `json:"persist,omitzero"`
	}
	proxyRouteJSON struct {
		Kind        string      `json:"kind"`
		Scope       string      `json:"scope,omitzero"`
		Hops        []HopTarget `json:"hops,omitzero"`
		Command     string      `json:"command,omitzero"`
		ShadowedCmd string      `json:"shadowed_cmd,omitzero"`
		ShadowedOff bool        `json:"shadowed_disabled,omitzero"`
	}
	effectivePolicyJSON struct {
		Origin            OriginKind            `json:"origin"`
		Endpoint          netaddr.Endpoint      `json:"endpoint"`
		OriginalHost      netaddr.CanonicalHost `json:"original_host"`
		Options           OptionLayer           `json:"options"`
		Ciphers           []string              `json:"ciphers"`
		MACs              []string              `json:"macs"`
		KexAlgorithms     []string              `json:"kex_algorithms"`
		HostKeyAlgorithms []string              `json:"host_key_algorithms"`
	}
)

func marshalPathStateJSON(enc *jsontext.Encoder, state PathListState, items []PathEntry, terminated bool) error {
	switch state {
	case PathListUnset:
		return enc.WriteToken(jsontext.Null)
	case PathListDisabled:
		return jsonv2.MarshalEncode(enc, pathListJSON{State: "disabled", Terminated: terminated})
	case PathListSet:
		return jsonv2.MarshalEncode(enc, pathListJSON{"set", items, terminated})
	default:
		return ErrInvalidPathList
	}
}
func decodePathStateWire(w pathListJSON, allowTerminated bool) (PathListState, []PathEntry, error) {
	if !allowTerminated && w.Terminated {
		return PathListUnset, nil, fmt.Errorf("%w: 非法 terminated 标志", ErrInvalidPathList)
	}
	switch {
	case w.State == "unset" && len(w.Items) == 0 && !w.Terminated:
		return PathListUnset, nil, nil
	case w.State == "disabled" && len(w.Items) == 0:
		return PathListDisabled, nil, nil
	case w.State == "set" && len(w.Items) > 0:
		dedup, err := dedupPathEntries(w.Items)
		return PathListSet, dedup, err
	}
	return PathListUnset, nil, fmt.Errorf("%w: 非法状态 %q", ErrInvalidPathList, w.State)
}

// MarshalJSONTo 与 UnmarshalJSONFrom 实现 PathList、KnownHostsList、AlgoPolicy、EnvFilter 与 ControlPolicy 的 json/v2 确定性编解码。
func (p PathList) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalPathStateJSON(enc, p.state, p.items, p.Terminated())
}
func (p *PathList) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalNullableJSON(p, dec, UnsetPathList, func(w pathListJSON) (PathList, error) {
		st, items, err := decodePathStateWire(w, true)
		return PathList{st, items, st == PathListDisabled || w.Terminated}, err
	})
}
func (k KnownHostsList) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalPathStateJSON(enc, k.state, k.items, false)
}
func (k *KnownHostsList) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalNullableJSON(k, dec, UnsetKnownHostsList, func(w pathListJSON) (KnownHostsList, error) {
		st, items, err := decodePathStateWire(w, false)
		return KnownHostsList{st, items}, err
	})
}
func (p AlgoPolicy) MarshalJSONTo(enc *jsontext.Encoder) error {
	if p.op == AlgoOpUnset {
		return enc.WriteToken(jsontext.Null)
	}
	if !p.op.IsSet() {
		return ErrInvalidAlgoPolicy
	}
	return jsonv2.MarshalEncode(enc, algoPolicyJSON{p.op.String(), p.tokens})
}
func (p *AlgoPolicy) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalNullableJSON(p, dec, UnsetAlgoPolicy, decodeAlgoPolicyWire)
}
func (f EnvFilter) MarshalJSONTo(enc *jsontext.Encoder) error {
	if f.IsUnset() {
		return enc.WriteToken(jsontext.Null)
	}
	return jsonv2.MarshalEncode(enc, envFilterJSON{f.clear, f.added})
}
func (f *EnvFilter) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalNullableJSON(f, dec, UnsetEnvFilter, decodeEnvFilterWire)
}
func (c ControlPolicy) MarshalJSONTo(enc *jsontext.Encoder) error {
	if c.IsUnset() {
		return enc.WriteToken(jsontext.Null)
	}
	return jsonv2.MarshalEncode(enc, controlPolicyJSON{c.Master().String(), c.path.String(), c.path.IsLiteral(), c.persist.String()})
}
func (c *ControlPolicy) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalNullableJSON(c, dec, UnsetControlPolicy, decodeControlPolicyWire)
}

func decodeAlgoPolicyWire(w algoPolicyJSON) (AlgoPolicy, error) {
	if w.Op == "unset" && len(w.Tokens) == 0 {
		return UnsetAlgoPolicy(), nil
	}
	op, ok := map[string]AlgoOp{"exact": AlgoOpExact, "append": AlgoOpAppend, "remove": AlgoOpRemove, "prepend": AlgoOpPrepend}[w.Op]
	if !ok || len(w.Tokens) == 0 {
		return UnsetAlgoPolicy(), fmt.Errorf("%w: 非法算子或空令牌 %q", ErrInvalidAlgoPolicy, w.Op)
	}
	tokens, err := validateAlgoSlice(w.Tokens, op == AlgoOpRemove)
	return AlgoPolicy{op: op, tokens: tokens}, err
}
func decodeEnvFilterWire(w envFilterJSON) (EnvFilter, error) {
	var out [2][]string
	for i, src := range [2][]string{w.Clear, w.Added} {
		for _, pat := range src {
			if !isValidEnvPattern(pat) {
				return UnsetEnvFilter(), fmt.Errorf("%w: 非法模式 %q", ErrInvalidEnvFilter, pat)
			}
			out[i] = appendUniqueStrings(out[i], []string{pat})
		}
	}
	slices.Sort(out[0])
	return EnvFilter{nilIfEmpty(out[0]), nilIfEmpty(out[1])}, nil
}
func decodeControlPolicyWire(w controlPolicyJSON) (ControlPolicy, error) {
	if w.LiteralPath && (w.Path == "" || isNoneKeyword(strings.TrimSpace(w.Path))) {
		return UnsetControlPolicy(), fmt.Errorf("%w: literal_path 要求有效字面路径", ErrInvalidControlPolicy)
	}
	m, errM := decodeOpt(w.Master, ParseControlMasterMode)
	p, errP := decodeOpt(w.Path, func(s string) (ControlPathSpec, error) { return parseControlPathInternal(s, w.LiteralPath) })
	per, errPer := decodeOpt(w.Persist, ParseControlPersist)
	for _, err := range [3]error{errM, errP, errPer} {
		if err != nil {
			return UnsetControlPolicy(), err
		}
	}
	return UnsetControlPolicy().WithMaster(m).WithPath(p).WithPersist(per), nil
}
func decodeOpt[T any](raw string, parse func(string) (T, error)) (T, error) {
	if raw != "" {
		return parse(raw)
	}
	var zero T
	return zero, nil
}

// MarshalProxyRouteTo 与 UnmarshalProxyRouteFrom 为封闭接口 ProxyRoute 提供多态 json/v2 确定性编解码（失败严格返回 (nil, err)）。
func MarshalProxyRouteTo(enc *jsontext.Encoder, route ProxyRoute) error {
	if enc == nil {
		return ErrNilReceiver
	}
	pair, ok := toProxyPair(route)
	if !ok {
		return ErrInvalidProxyRoute
	}
	if pair.jumpKind == proxyJumpSlotUnset {
		return enc.WriteToken(jsontext.Null)
	}
	var w proxyRouteJSON
	switch {
	case pair.jumpKind == proxyJumpSlotActive:
		w = proxyRouteJSON{Kind: "jump", Hops: pair.hops.Slice(), ShadowedCmd: pair.cmdVal.String(), ShadowedOff: pair.cmdSlot == proxyCmdSlotDisabled}
	case pair.cmdSlot == proxyCmdSlotActive:
		w = proxyRouteJSON{Kind: "command", Command: pair.cmdVal.String()}
	default:
		w = proxyRouteJSON{Kind: "disabled", Scope: map[bool]string{true: "jump_only", false: "all"}[pair.cmdSlot == proxyCmdSlotUnset]}
	}
	return jsonv2.MarshalEncode(enc, w)
}
func UnmarshalProxyRouteFrom(dec *jsontext.Decoder) (ProxyRoute, error) {
	if dec == nil {
		return nil, ErrNilReceiver
	}
	var field proxyRouteField
	if err := field.UnmarshalJSONFrom(dec); err != nil {
		return nil, err
	}
	return field.route, nil
}

// MarshalJSONTo 为四个具体 ProxyRoute 变体提供值接收者 json/v2 编码（无效零值失败关闭）。
func (u ProxyUnset) MarshalJSONTo(enc *jsontext.Encoder) error { return MarshalProxyRouteTo(enc, &u) }
func (d ProxyDisabled) MarshalJSONTo(enc *jsontext.Encoder) error {
	return MarshalProxyRouteTo(enc, &d)
}
func (j ProxyJumpChain) MarshalJSONTo(enc *jsontext.Encoder) error {
	return MarshalProxyRouteTo(enc, &j)
}
func (c ProxyCommandSpec) MarshalJSONTo(enc *jsontext.Encoder) error {
	return MarshalProxyRouteTo(enc, &c)
}

type proxyRouteField struct{ route ProxyRoute }

func (p proxyRouteField) IsZero() bool { return EqualProxyRoute(p.route, NewProxyUnset()) }
func (p proxyRouteField) MarshalJSONTo(e *jsontext.Encoder) error {
	return MarshalProxyRouteTo(e, p.route)
}
func (p *proxyRouteField) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalNullableJSON(p, d, func() proxyRouteField { return proxyRouteField{NewProxyUnset()} }, decodeProxyRouteWire)
}
func decodeProxyRouteWire(w proxyRouteJSON) (proxyRouteField, error) {
	hasJump := len(w.Hops) > 0 || w.ShadowedCmd != "" || w.ShadowedOff
	switch {
	case w.Kind == "unset" && !hasJump && w.Scope == "" && w.Command == "":
		return proxyRouteField{NewProxyUnset()}, nil
	case w.Kind == "disabled" && !hasJump && w.Command == "":
		if r, ok := map[string]*ProxyDisabled{"jump_only": NewProxyJumpDisabled(), "": NewProxyDisabled(), "all": NewProxyDisabled()}[w.Scope]; ok {
			return proxyRouteField{r}, nil
		}
	case w.Kind == "jump" && w.Scope == "" && w.Command == "":
		r, err := decodeProxyJumpWire(w)
		return proxyRouteField{r}, err
	case w.Kind == "command" && !hasJump && w.Scope == "":
		cmd, err := NewProxySanitizedCmd(w.Command)
		return proxyRouteField{&ProxyCommandSpec{cmd}}, err
	}
	return proxyRouteField{}, fmt.Errorf("%w: 非法编码 %q", ErrInvalidProxyRoute, w.Kind)
}
func decodeProxyJumpWire(w proxyRouteJSON) (ProxyRoute, error) {
	ne, err := algebraic.NonEmptyFromSlice(w.Hops)
	if err != nil {
		return nil, wrapProxyErr(err)
	}
	jc, err := NewProxyJumpChain(ne)
	if err != nil || (w.ShadowedOff && w.ShadowedCmd != "") {
		return nil, ErrInvalidProxyRoute
	}
	if w.ShadowedOff {
		jc.cmdSlot = proxyCmdSlotDisabled
	} else if w.ShadowedCmd != "" {
		if jc.cmdValue, err = NewProxySanitizedCmd(w.ShadowedCmd); err != nil {
			return nil, err
		}
		jc.cmdSlot = proxyCmdSlotActive
	}
	return jc, nil
}

type optionLayerJSON struct {
	HostName              algebraic.FirstWins[HostNameSpec]              `json:"hostname,omitzero"`
	Port                  algebraic.FirstWins[uint16]                    `json:"port,omitzero"`
	User                  algebraic.FirstWins[Username]                  `json:"user,omitzero"`
	Proxy                 proxyRouteField                                `json:"proxy,omitzero"`
	Control               ControlPolicy                                  `json:"control,omitzero"`
	ConnectTimeout        algebraic.FirstWins[algebraic.Duration]        `json:"connect_timeout,omitzero"`
	ServerAliveInterval   algebraic.FirstWins[algebraic.Duration]        `json:"server_alive_interval,omitzero"`
	Ciphers               AlgoPolicy                                     `json:"ciphers,omitzero"`
	MACs                  AlgoPolicy                                     `json:"macs,omitzero"`
	KexAlgorithms         AlgoPolicy                                     `json:"kex_algorithms,omitzero"`
	HostKeyAlgorithms     AlgoPolicy                                     `json:"host_key_algorithms,omitzero"`
	IdentityFiles         PathList                                       `json:"identity_files,omitzero"`
	CertificateFiles      PathList                                       `json:"certificate_files,omitzero"`
	IdentitiesOnly        algebraic.FirstWins[bool]                      `json:"identities_only,omitzero"`
	BatchMode             algebraic.FirstWins[bool]                      `json:"batch_mode,omitzero"`
	StrictHostKeyChecking algebraic.FirstWins[StrictHostKeyCheckingMode] `json:"strict_host_key_checking,omitzero"`
	UserKnownHostsFiles   KnownHostsList                                 `json:"user_known_hosts_files,omitzero"`
	ForwardAgent          algebraic.FirstWins[bool]                      `json:"forward_agent,omitzero"`
	SendEnv               EnvFilter                                      `json:"send_env,omitzero"`
	PermitLocalCommand    algebraic.FirstWins[bool]                      `json:"permit_local_command,omitzero"`
	LocalCommand          algebraic.FirstWins[SanitizedCmd]              `json:"local_command,omitzero"`
}

// MarshalJSONTo 与 UnmarshalJSONFrom 实现 OptionLayer 与 EffectivePolicy 的 encoding/json/v2 确定性编解码。
func (l OptionLayer) MarshalJSONTo(enc *jsontext.Encoder) error {
	if err := l.Validate(); err != nil {
		return err
	}
	return jsonv2.MarshalEncode(enc, optionLayerJSON{
		l.hostName, l.port, l.user, proxyRouteField{l.proxy}, l.control, l.connectTimeout,
		l.serverAliveInterval, l.ciphers, l.macs, l.kexAlgorithms, l.hostKeyAlgorithms,
		l.identityFiles, l.certificateFiles, l.identitiesOnly, l.batchMode,
		l.strictHostKeyChecking, l.userKnownHostsFiles, l.forwardAgent, l.sendEnv,
		l.permitLocalCommand, l.localCommand,
	})
}
func (l *OptionLayer) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalNullableJSON(l, dec, UnsetOptionLayer, func(w optionLayerJSON) (OptionLayer, error) {
		out := OptionLayer{
			w.HostName, w.Port, w.User, w.Proxy.route, w.Control, w.ConnectTimeout,
			w.ServerAliveInterval, w.Ciphers, w.MACs, w.KexAlgorithms, w.HostKeyAlgorithms,
			w.IdentityFiles, w.CertificateFiles, w.IdentitiesOnly, w.BatchMode,
			w.StrictHostKeyChecking, w.UserKnownHostsFiles, w.ForwardAgent, w.SendEnv,
			w.PermitLocalCommand, w.LocalCommand,
		}
		return out, out.Validate()
	})
}
func (p EffectivePolicy) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !p.valid {
		return ErrInvalidOrigin
	}
	return jsonv2.MarshalEncode(enc, effectivePolicyJSON{p.origin, p.endpoint, p.originalHost, p.opts, p.ciphers, p.macs, p.kexAlgorithms, p.hostKeyAlgos})
}
func (p *EffectivePolicy) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if p == nil || dec == nil {
		return ErrNilReceiver
	}
	*p = EffectivePolicy{}
	if dec.PeekKind() == 'n' {
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		return ErrInvalidOrigin
	}
	var w effectivePolicyJSON
	if err := jsonv2.UnmarshalDecode(dec, &w); err != nil {
		return err
	}
	pol, err := decodeEffectivePolicyWire(w)
	if err == nil {
		*p = pol
	}
	return err
}
func decodeEffectivePolicyWire(w effectivePolicyJSON) (EffectivePolicy, error) {
	if !w.Origin.IsValid() {
		return EffectivePolicy{}, ErrInvalidOrigin
	}
	if !w.Endpoint.IsValid() || !w.OriginalHost.IsValid() {
		return EffectivePolicy{}, ErrInvalidEndpoint
	}
	if err := w.Options.Validate(); err != nil {
		return EffectivePolicy{}, err
	}
	var sets [4][]string
	for i, s := range [4][]string{w.Ciphers, w.MACs, w.KexAlgorithms, w.HostKeyAlgorithms} {
		list, err := validateAlgoSlice(s, false)
		if err != nil {
			return EffectivePolicy{}, err
		}
		if len(list) == 0 {
			return EffectivePolicy{}, ErrEmptyAlgorithmList
		}
		sets[i] = list
	}
	opts := w.Options.clone()
	if !opts.permitLocalCommand.OrElse(false) {
		opts.localCommand = algebraic.UnsetFirstWins[SanitizedCmd]()
	}
	return EffectivePolicy{w.Origin, w.Endpoint, w.OriginalHost, opts, sets[0], sets[1], sets[2], sets[3], true}, nil
}
