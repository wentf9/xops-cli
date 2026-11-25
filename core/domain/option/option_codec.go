package option

import (
	"cmp"
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
		Origin            OriginKind       `json:"origin"`
		Endpoint          netaddr.Endpoint `json:"endpoint"`
		OriginalHost      OriginalHostSpec `json:"original_host"`
		Options           OptionLayer      `json:"options"`
		Ciphers           []string         `json:"ciphers"`
		MACs              []string         `json:"macs"`
		KexAlgorithms     []string         `json:"kex_algorithms"`
		HostKeyAlgorithms []string         `json:"host_key_algorithms"`
	}
)

func marshalPathStateJSON(enc *jsontext.Encoder, st PathListState, items []PathEntry, term bool) error {
	return marshalNullOrWire(enc, st == PathListUnset, st == PathListDisabled || st == PathListSet, ErrInvalidPathList,
		pathListJSON{map[bool]string{true: "disabled", false: "set"}[st == PathListDisabled], items, term})
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
func (p PathList) MarshalJSONTo(e *jsontext.Encoder) error {
	return marshalPathStateJSON(e, p.state, p.items, p.Terminated())
}
func (p *PathList) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalNullableJSON(p, d, UnsetPathList, decodePathListWire)
}
func decodePathListWire(w pathListJSON) (PathList, error) {
	st, items, err := decodePathStateWire(w, true)
	return PathList{pathSetBase{st, items}, st == PathListDisabled || w.Terminated}, err
}
func (k KnownHostsList) MarshalJSONTo(e *jsontext.Encoder) error {
	return marshalPathStateJSON(e, k.state, k.items, false)
}
func (k *KnownHostsList) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalNullableJSON(k, d, UnsetKnownHostsList, decodeKnownHostsWire)
}
func decodeKnownHostsWire(w pathListJSON) (KnownHostsList, error) {
	st, items, err := decodePathStateWire(w, false)
	return KnownHostsList{pathSetBase{st, items}}, err
}
func (p AlgoPolicy) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalNullOrWire(enc, p.op == AlgoOpUnset, p.op.IsSet(), ErrInvalidAlgoPolicy, algoPolicyJSON{p.op.String(), p.tokens})
}
func (p *AlgoPolicy) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalNullableJSON(p, d, UnsetAlgoPolicy, decodeAlgoPolicyWire)
}
func (f EnvFilter) MarshalJSONTo(e *jsontext.Encoder) error {
	return marshalNullOrWire(e, f.IsUnset(), true, ErrInvalidEnvFilter, envFilterJSON{f.clear, f.added})
}
func (f *EnvFilter) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalNullableJSON(f, d, UnsetEnvFilter, decodeEnvFilterWire)
}
func (c ControlPolicy) MarshalJSONTo(e *jsontext.Encoder) error {
	return marshalNullOrWire(e, c.IsUnset(), true, ErrInvalidControlPolicy, controlPolicyJSON{c.Master().String(), c.path.String(), c.path.IsLiteral(), c.persist.String()})
}
func (c *ControlPolicy) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalNullableJSON(c, d, UnsetControlPolicy, decodeControlPolicyWire)
}
func marshalNullOrWire[W any](enc *jsontext.Encoder, isNull, valid bool, badErr error, wire W) error {
	if isNull {
		return enc.WriteToken(jsontext.Null)
	}
	if !valid {
		return badErr
	}
	return jsonv2.MarshalEncode(enc, wire)
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
	return UnsetControlPolicy().WithMaster(m).WithPath(p).WithPersist(per), cmp.Or(errM, errP, errPer)
}
func decodeOpt[T any](raw string, parse func(string) (T, error)) (z T, err error) {
	if raw != "" {
		return parse(raw)
	}
	return z, nil
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
	w := proxyRouteJSON{Kind: "disabled", Scope: map[bool]string{true: "jump_only", false: "all"}[pair.cmdSlot == proxyCmdSlotUnset]}
	if pair.jumpKind == proxyJumpSlotActive {
		w = proxyRouteJSON{Kind: "jump", Hops: pair.hops.Slice(), ShadowedCmd: pair.cmdVal.String(), ShadowedOff: pair.cmdSlot == proxyCmdSlotDisabled}
	} else if pair.cmdSlot == proxyCmdSlotActive {
		w = proxyRouteJSON{Kind: "command", Command: pair.cmdVal.String()}
	}
	return jsonv2.MarshalEncode(enc, w)
}
func UnmarshalProxyRouteFrom(dec *jsontext.Decoder) (ProxyRoute, error) {
	if dec == nil {
		return nil, ErrNilReceiver
	}
	var f proxyRouteField
	if err := f.UnmarshalJSONFrom(dec); err != nil {
		return nil, err
	}
	return f.route, nil
}

// MarshalJSONTo 为四个具体 ProxyRoute 变体提供值接收者 json/v2 编码（无效零值失败关闭）。
func (u ProxyUnset) MarshalJSONTo(e *jsontext.Encoder) error       { return MarshalProxyRouteTo(e, &u) }
func (d ProxyDisabled) MarshalJSONTo(e *jsontext.Encoder) error    { return MarshalProxyRouteTo(e, &d) }
func (j ProxyJumpChain) MarshalJSONTo(e *jsontext.Encoder) error   { return MarshalProxyRouteTo(e, &j) }
func (c ProxyCommandSpec) MarshalJSONTo(e *jsontext.Encoder) error { return MarshalProxyRouteTo(e, &c) }

type proxyRouteField struct{ route ProxyRoute }

func unsetPRField() proxyRouteField    { return proxyRouteField{NewProxyUnset()} }
func (p proxyRouteField) IsZero() bool { return EqualProxyRoute(p.route, NewProxyUnset()) }
func (p proxyRouteField) MarshalJSONTo(e *jsontext.Encoder) error {
	return MarshalProxyRouteTo(e, p.route)
}
func (p *proxyRouteField) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalNullableJSON(p, d, unsetPRField, decodeProxyRouteWire)
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
	ServerAliveCountMax   algebraic.FirstWins[uint32]                    `json:"server_alive_count_max,omitzero"`
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
		l.serverAliveInterval, l.serverAliveCountMax, l.ciphers, l.macs, l.kexAlgorithms, l.hostKeyAlgorithms,
		l.identityFiles, l.certificateFiles, l.identitiesOnly, l.batchMode,
		l.strictHostKeyChecking, l.userKnownHostsFiles, l.forwardAgent, l.sendEnv,
		l.permitLocalCommand, l.localCommand,
	})
}
func (l *OptionLayer) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalNullableJSON(l, dec, UnsetOptionLayer, func(w optionLayerJSON) (OptionLayer, error) {
		out := OptionLayer{
			w.HostName, w.Port, w.User, w.Proxy.route, w.Control, w.ConnectTimeout,
			w.ServerAliveInterval, w.ServerAliveCountMax, w.Ciphers, w.MACs, w.KexAlgorithms, w.HostKeyAlgorithms,
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
	if p != nil && dec != nil && dec.PeekKind() == 'n' {
		*p = EffectivePolicy{}
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		return ErrInvalidOrigin
	}
	return unmarshalNullableJSON(p, dec, func() EffectivePolicy { return EffectivePolicy{} }, decodeEffectivePolicyWire)
}
func decodeEffectivePolicyWire(w effectivePolicyJSON) (EffectivePolicy, error) {
	switch {
	case !w.Origin.IsValid():
		return EffectivePolicy{}, ErrInvalidOrigin
	case !w.Endpoint.IsValid() || !w.OriginalHost.IsValid():
		return EffectivePolicy{}, ErrInvalidEndpoint
	case w.Options.Validate() != nil:
		return EffectivePolicy{}, w.Options.Validate()
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
