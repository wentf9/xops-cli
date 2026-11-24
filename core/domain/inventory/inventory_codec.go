package inventory

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

type (
	challengeRuleWire struct {
		Kind               ChallengeRuleKind                    `json:"kind"`
		Name               string                               `json:"name,omitzero"`
		PromptPattern      string                               `json:"prompt_pattern"`
		InstructionPattern string                               `json:"instruction_pattern,omitzero"`
		TOTPSecretRef      algebraic.Option[secret.Ref]         `json:"totp_secret_ref,omitzero"`
		SecretRef          algebraic.Option[secret.Ref]         `json:"secret_ref,omitzero"`
		Command            string                               `json:"command,omitzero"`
		Args               []string                             `json:"args,omitzero"`
		Timeout            algebraic.Option[algebraic.Duration] `json:"timeout,omitzero"`
	}
	authMethodWire struct {
		Kind        AuthMethodKind                         `json:"kind"`
		PasswordRef algebraic.Option[secret.Ref]           `json:"password_ref,omitzero"`
		KeyPaths    []KeyPathSpec                          `json:"key_paths,omitzero"`
		Passphrase  algebraic.Option[KeyPassphraseBinding] `json:"passphrase,omitzero"`
		CertPaths   []CertPathSpec                         `json:"cert_paths,omitzero"`
		AgentSpec   algebraic.Option[AgentSpec]            `json:"agent_spec,omitzero"`
		Rules       []challengeRuleWire                    `json:"rules,omitzero"`
		Methods     []authMethodWire                       `json:"methods,omitzero"`
	}
	nodeOriginWire struct {
		Kind        option.OriginKind        `json:"kind"`
		HostPattern string                   `json:"host_pattern,omitzero"`
		BaseAlias   string                   `json:"base_alias,omitzero"`
		SourceFile  string                   `json:"source_file,omitzero"`
		ParentNode  algebraic.Option[NodeID] `json:"parent_node,omitzero"`
	}
	hostWire struct {
		ID          HostID                  `json:"id"`
		Endpoint    netaddr.Endpoint        `json:"endpoint"`
		Alias       algebraic.Option[Alias] `json:"alias,omitzero"`
		Description string                  `json:"description,omitzero"`
		Tags        []Tag                   `json:"tags,omitzero"`
	}
	identityWire struct {
		ID          IdentityID      `json:"id"`
		User        option.Username `json:"user"`
		Auth        authMethodWire  `json:"auth"`
		Description string          `json:"description,omitzero"`
		Tags        []Tag           `json:"tags,omitzero"`
	}
	nodeWire struct {
		ID                   NodeID                                    `json:"id"`
		HostRef              HostID                                    `json:"host"`
		IdentityRef          IdentityID                                `json:"identity"`
		Aliases              []Alias                                   `json:"aliases,omitzero"`
		Tags                 []Tag                                     `json:"tags,omitzero"`
		Proxy                proxyRouteField                           `json:"proxy,omitzero"`
		Execution            algebraic.Option[execution.LaunchProfile] `json:"execution,omitzero"`
		Options              option.OptionLayer                        `json:"options,omitzero"`
		PrivilegePasswordRef algebraic.Option[secret.Ref]              `json:"privilege_password_ref,omitzero"`
		Origin               nodeOriginWire                            `json:"origin"`
		Description          string                                    `json:"description,omitzero"`
	}
	importWarningWire struct {
		Code    string `json:"code"`
		Subject string `json:"subject,omitzero"`
		Message string `json:"message"`
	}
	importBundleWire struct {
		SourceFormat string          `json:"source_format"`
		Hosts        []Host          `json:"hosts,omitzero"`
		Identities   []Identity      `json:"identities,omitzero"`
		Nodes        []Node          `json:"nodes,omitzero"`
		Warnings     []ImportWarning `json:"warnings,omitzero"`
	}
	proxyRouteField struct{ route option.ProxyRoute }
)

func (p proxyRouteField) IsZero() bool {
	return p.route == nil || option.EqualProxyRoute(p.route, option.NewProxyUnset())
}
func (p proxyRouteField) MarshalJSONTo(e *jsontext.Encoder) error {
	return option.MarshalProxyRouteTo(e, p.route)
}
func (p *proxyRouteField) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	r, err := option.UnmarshalProxyRouteFrom(d)
	p.route = pickIf(err == nil, r, nil)
	return err
}

// MarshalChallengeRuleTo..UnmarshalNodeOriginFrom 为全部封闭和类型提供多态 JSON/v2 确定性编解码。
func MarshalChallengeRuleTo(e *jsontext.Encoder, r ChallengeRule) error {
	return marshalWire(e, r, encodeChallengeRuleWire)
}
func UnmarshalChallengeRuleFrom(d *jsontext.Decoder) (ChallengeRule, error) {
	return unmarshalJSONVal(d, ErrInvalidChallengeRule, decodeChallengeRuleWire)
}
func MarshalAuthMethodTo(e *jsontext.Encoder, a AuthMethod) error {
	return marshalWire(e, a, func(m AuthMethod) (authMethodWire, error) { return encodeAuthMethodWire(m, 1) })
}
func UnmarshalAuthMethodFrom(d *jsontext.Decoder) (AuthMethod, error) {
	return unmarshalJSONVal(d, ErrInvalidAuthMethod, func(w authMethodWire) (AuthMethod, error) { return decodeAuthMethodWire(w, 1) })
}
func MarshalNodeOriginTo(e *jsontext.Encoder, o NodeOrigin) error {
	return marshalWire(e, o, encodeNodeOriginWire)
}
func UnmarshalNodeOriginFrom(d *jsontext.Decoder) (NodeOrigin, error) {
	return unmarshalJSONVal(d, ErrInvalidNodeOrigin, decodeNodeOriginWire)
}
func marshalWire[T, W any](enc *jsontext.Encoder, v T, build func(T) (W, error)) error {
	if enc == nil {
		return ErrNilWriter
	}
	w, err := build(v)
	return marshalValidWire(enc, err == nil, err, w)
}
func marshalValidWire[W any](enc *jsontext.Encoder, valid bool, invalidErr error, wire W) error {
	if !valid {
		return invalidErr
	}
	return jsonv2.MarshalEncode(enc, wire)
}

// MarshalJSONTo 为全部封闭变体提供值接收者 json/v2 编码（零值失败关闭）。
func (r RuleTOTP) MarshalJSONTo(e *jsontext.Encoder) error      { return MarshalChallengeRuleTo(e, &r) }
func (r RuleSecretRef) MarshalJSONTo(e *jsontext.Encoder) error { return MarshalChallengeRuleTo(e, &r) }
func (r RuleCommand) MarshalJSONTo(e *jsontext.Encoder) error   { return MarshalChallengeRuleTo(e, &r) }
func (r RuleLoginPassword) MarshalJSONTo(e *jsontext.Encoder) error {
	return MarshalChallengeRuleTo(e, &r)
}
func (a AuthPassword) MarshalJSONTo(e *jsontext.Encoder) error   { return MarshalAuthMethodTo(e, &a) }
func (a AuthPrivateKey) MarshalJSONTo(e *jsontext.Encoder) error { return MarshalAuthMethodTo(e, &a) }
func (a AuthAgent) MarshalJSONTo(e *jsontext.Encoder) error      { return MarshalAuthMethodTo(e, &a) }
func (a AuthKeyboardInteractive) MarshalJSONTo(e *jsontext.Encoder) error {
	return MarshalAuthMethodTo(e, &a)
}
func (a AuthComposite) MarshalJSONTo(e *jsontext.Encoder) error { return MarshalAuthMethodTo(e, &a) }
func (o OriginManaged) MarshalJSONTo(e *jsontext.Encoder) error { return MarshalNodeOriginTo(e, &o) }
func (o OriginOpenSSHVirtual) MarshalJSONTo(e *jsontext.Encoder) error {
	return MarshalNodeOriginTo(e, &o)
}
func (o OriginOpenSSHDerived) MarshalJSONTo(e *jsontext.Encoder) error {
	return MarshalNodeOriginTo(e, &o)
}
func (o OriginAdHoc) MarshalJSONTo(e *jsontext.Encoder) error { return MarshalNodeOriginTo(e, &o) }

func encodeChallengeRuleWire(r ChallengeRule) (challengeRuleWire, error) {
	if r == nil || !r.IsValid() {
		return challengeRuleWire{}, ErrInvalidChallengeRule
	}
	w := challengeRuleWire{Kind: r.Kind(), Name: r.Name(), PromptPattern: r.PromptPattern(), InstructionPattern: r.InstructionPattern()}
	switch v := r.(type) {
	case *RuleTOTP:
		w.TOTPSecretRef = algebraic.Some(v.totpSecretRef)
	case *RuleSecretRef:
		w.SecretRef = algebraic.Some(v.secretRef)
	case *RuleCommand:
		w.Command, w.Args, w.Timeout = v.command, v.args, v.timeout
	case *RuleLoginPassword:
	default:
		return challengeRuleWire{}, ErrInvalidChallengeRule
	}
	return w, nil
}
func decodeChallengeRuleWire(w challengeRuleWire) (ChallengeRule, error) {
	meta := ChallengeRuleMeta{w.Name, w.PromptPattern, w.InstructionPattern}
	mask := maskFlags(w.TOTPSecretRef.IsSome(), w.SecretRef.IsSome(), w.Command != "" || len(w.Args) > 0 || w.Timeout.IsSome())
	switch w.Kind {
	case ChallengeRuleKindTOTP:
		if ref, ok := w.TOTPSecretRef.Get(); ok && mask == 1 {
			return NewRuleTOTP(meta, ref)
		}
	case ChallengeRuleKindSecretRef:
		if ref, ok := w.SecretRef.Get(); ok && mask == 2 {
			return NewRuleSecretRef(meta, ref)
		}
	case ChallengeRuleKindCommand:
		if mask == 4 && w.Command != "" {
			return NewRuleCommand(meta, w.Command, w.Args, w.Timeout)
		}
	case ChallengeRuleKindLoginPassword:
		if mask == 0 {
			return NewRuleLoginPassword(meta)
		}
	}
	return nil, fmt.Errorf("%w: 质询规则类别或字段组合非法", ErrInvalidChallengeRule)
}
func encodeAuthMethodWire(m AuthMethod, depth int) (authMethodWire, error) {
	if m == nil || !m.IsValid() {
		return authMethodWire{}, ErrInvalidAuthMethod
	}
	if depth > maxAuthCompositeDepth+1 {
		return authMethodWire{}, ErrAuthCompositeTooDeep
	}
	switch v := m.(type) {
	case *AuthPassword:
		return authMethodWire{Kind: AuthMethodKindPassword, PasswordRef: algebraic.Some(v.passwordRef)}, nil
	case *AuthPrivateKey:
		return authMethodWire{Kind: AuthMethodKindPrivateKey, KeyPaths: v.keyPaths.Slice(), Passphrase: v.passphrase, CertPaths: v.certPaths}, nil
	case *AuthAgent:
		return authMethodWire{Kind: AuthMethodKindAgent, AgentSpec: v.spec}, nil
	case *AuthKeyboardInteractive:
		rules, err := mapSliceErr(v.rules.Slice(), encodeChallengeRuleWire)
		return authMethodWire{Kind: AuthMethodKindKeyboardInteractive, Rules: rules}, err
	case *AuthComposite:
		ms, err := mapSliceErr(v.methods.Slice(), func(sub AuthMethod) (authMethodWire, error) { return encodeAuthMethodWire(sub, depth+1) })
		return authMethodWire{Kind: AuthMethodKindComposite, Methods: ms}, err
	default:
		return authMethodWire{}, ErrInvalidAuthMethod
	}
}
func decodeAuthMethodWire(w authMethodWire, depth int) (AuthMethod, error) {
	if depth > maxAuthCompositeDepth+1 {
		return nil, ErrAuthCompositeTooDeep
	}
	mask := maskFlags(w.PasswordRef.IsSome(), len(w.KeyPaths) > 0 || w.Passphrase.IsSome() || len(w.CertPaths) > 0, w.AgentSpec.IsSome(), len(w.Rules) > 0, len(w.Methods) > 0)
	switch w.Kind {
	case AuthMethodKindPassword:
		if ref, ok := w.PasswordRef.Get(); ok && mask == 1 {
			return NewAuthPassword(ref)
		}
	case AuthMethodKindPrivateKey:
		if ne, err := algebraic.NonEmptyFromSlice(w.KeyPaths); err == nil && mask == 2 {
			return NewAuthPrivateKey(ne, w.Passphrase, w.CertPaths)
		}
	case AuthMethodKindAgent:
		if mask&^4 == 0 {
			return NewAuthAgent(w.AgentSpec)
		}
	case AuthMethodKindKeyboardInteractive:
		return decodeAuthList(mask == 8, w.Rules, decodeChallengeRuleWire, NewAuthKeyboardInteractive)
	case AuthMethodKindComposite:
		if depth > maxAuthCompositeDepth {
			return nil, ErrAuthCompositeTooDeep
		}
		return decodeAuthList(mask == 16, w.Methods, func(sub authMethodWire) (AuthMethod, error) { return decodeAuthMethodWire(sub, depth+1) }, NewAuthComposite)
	}
	return nil, fmt.Errorf("%w: 认证类别或字段组合非法", ErrInvalidAuthMethod)
}
func decodeAuthList[W, T any, R AuthMethod](maskOK bool, raw []W, decFn func(W) (T, error), build func(algebraic.NonEmpty[T]) (R, error)) (AuthMethod, error) {
	if !maskOK {
		return nil, fmt.Errorf("%w: 组合认证字段组合非法", ErrInvalidAuthMethod)
	}
	items, err := mapSliceErr(raw, decFn)
	if err != nil {
		return nil, err
	}
	ne, err := algebraic.NonEmptyFromSlice(items)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAuthMethod, err)
	}
	return build(ne)
}
func encodeNodeOriginWire(origin NodeOrigin) (nodeOriginWire, error) {
	if origin == nil || !origin.IsValid() {
		return nodeOriginWire{}, ErrInvalidNodeOrigin
	}
	switch v := origin.(type) {
	case *OriginManaged:
		return nodeOriginWire{Kind: option.OriginManaged}, nil
	case *OriginOpenSSHVirtual:
		return nodeOriginWire{Kind: option.OriginOpenSSHVirtual, HostPattern: v.hostPattern, SourceFile: v.sourceFile}, nil
	case *OriginOpenSSHDerived:
		return nodeOriginWire{Kind: option.OriginOpenSSHDerived, BaseAlias: v.baseAlias, SourceFile: v.sourceFile}, nil
	case *OriginAdHoc:
		return nodeOriginWire{Kind: option.OriginAdHoc, ParentNode: v.parentNode}, nil
	default:
		return nodeOriginWire{}, ErrInvalidNodeOrigin
	}
}
func decodeNodeOriginWire(w nodeOriginWire) (NodeOrigin, error) {
	mask := maskFlags(w.HostPattern != "", w.BaseAlias != "", w.SourceFile != "", w.ParentNode.IsSome())
	switch w.Kind {
	case option.OriginManaged:
		if mask == 0 {
			return NewOriginManaged(), nil
		}
	case option.OriginOpenSSHVirtual:
		if mask&^5 == 0 {
			return NewOriginOpenSSHVirtual(w.HostPattern, w.SourceFile)
		}
	case option.OriginOpenSSHDerived:
		if mask&^6 == 0 {
			return NewOriginOpenSSHDerived(w.BaseAlias, w.SourceFile)
		}
	case option.OriginAdHoc:
		if mask&^8 == 0 {
			return NewOriginAdHoc(w.ParentNode)
		}
	}
	return nil, fmt.Errorf("%w: 节点来源类别或字段组合非法", ErrInvalidNodeOrigin)
}

// Host、Identity、Node、ImportWarning 与 ImportBundle 的 Go 1.27 JSON/v2 确定性编解码方法。
func (h Host) MarshalJSONTo(e *jsontext.Encoder) error {
	return marshalValidWire(e, h.IsValid(), ErrInvalidHost, hostWire{h.id, h.endpoint, h.alias, h.description, h.tags})
}
func (h *Host) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalJSON(h, d, ErrInvalidHost, func(w hostWire) (Host, error) { return NewHost(HostSpec(w)) })
}
func (id Identity) MarshalJSONTo(e *jsontext.Encoder) error {
	if !id.IsValid() {
		return ErrInvalidIdentity
	}
	aw, err := encodeAuthMethodWire(id.auth, 1)
	return marshalValidWire(e, err == nil, err, identityWire{id.id, id.user, aw, id.description, id.tags})
}
func (id *Identity) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalJSON(id, d, ErrInvalidIdentity, func(w identityWire) (Identity, error) {
		auth, err := decodeAuthMethodWire(w.Auth, 1)
		if err != nil {
			return Identity{}, fmt.Errorf("%w: %w", ErrInvalidIdentity, err)
		}
		return NewIdentity(IdentitySpec{w.ID, w.User, auth, w.Description, w.Tags})
	})
}
func (n Node) MarshalJSONTo(e *jsontext.Encoder) error {
	if !n.IsValid() {
		return ErrInvalidNode
	}
	ow, err := encodeNodeOriginWire(n.origin)
	return marshalValidWire(e, err == nil, err, nodeWire{n.id, n.hostRef, n.identityRef, n.aliases, n.tags, proxyRouteField{n.proxy}, n.execution, n.options, n.privilegePasswordRef, ow, n.description})
}
func (n *Node) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalJSON(n, d, ErrInvalidNode, func(w nodeWire) (Node, error) {
		origin, err := decodeNodeOriginWire(w.Origin)
		if err != nil {
			return Node{}, fmt.Errorf("%w: %w", ErrInvalidNode, err)
		}
		return NewNode(NodeSpec{w.ID, w.HostRef, w.IdentityRef, w.Aliases, w.Tags, w.Proxy.route, w.Execution, w.Options, w.PrivilegePasswordRef, origin, w.Description})
	})
}
func (w ImportWarning) MarshalJSONTo(e *jsontext.Encoder) error {
	return marshalValidWire(e, w.IsValid(), ErrInvalidImportBundle, importWarningWire{w.code, w.subject, w.message})
}
func (w *ImportWarning) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalJSON(w, d, ErrInvalidImportBundle, func(wire importWarningWire) (ImportWarning, error) {
		return NewImportWarning(wire.Code, wire.Subject, wire.Message)
	})
}
func (b ImportBundle) MarshalJSONTo(e *jsontext.Encoder) error {
	return marshalValidWire(e, b.IsValid(), ErrInvalidImportBundle, importBundleWire{b.sourceFormat, b.hosts, b.identities, b.nodes, b.warnings})
}
func (b *ImportBundle) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return unmarshalJSON(b, d, ErrInvalidImportBundle, func(w importBundleWire) (ImportBundle, error) { return NewImportBundle(ImportBundleSpec(w)) })
}
