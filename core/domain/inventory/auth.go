package inventory

import (
	"fmt"
	"io"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

const authCanonicalDomainTag = "xops.inventory.auth_method.v1"

// AuthMethodKind 标识 SSH 认证方式判别类别；零值 AuthMethodKindInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type AuthMethodKind uint8

const (
	AuthMethodKindInvalid             AuthMethodKind = iota // 无效认证方式（零值失败关闭）
	AuthMethodKindPassword                                  // 密码凭据引用认证
	AuthMethodKindPrivateKey                                // 私钥与可选证书/绑定口令认证
	AuthMethodKindAgent                                     // SSH Agent 认证
	AuthMethodKindKeyboardInteractive                       // RFC 4256 质询应答认证
	AuthMethodKindComposite                                 // 多因素或有序组合认证
)

// ParseAuthMethodKind 严格解析认证方式类别文本。
func ParseAuthMethodKind(raw string) (AuthMethodKind, error) {
	return parseEnumByName(raw, AuthMethodKindPassword, AuthMethodKindComposite, AuthMethodKindInvalid, AuthMethodKind.String, ErrInvalidAuthMethod)
}
func (k AuthMethodKind) IsValid() bool {
	return k >= AuthMethodKindPassword && k <= AuthMethodKindComposite
}
func (k AuthMethodKind) IsZero() bool { return k == AuthMethodKindInvalid }
func (k AuthMethodKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "password", "private_key", "agent", "keyboard_interactive", "composite")
}
func (k AuthMethodKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidAuthMethod)
}
func (k AuthMethodKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *AuthMethodKind) UnmarshalText(text []byte) error {
	return unmarshalText(k, text, ParseAuthMethodKind)
}

// AuthMethod 是 SSH 认证方式的封闭代数和类型（RFC §3.6）：
// *AuthPassword | *AuthPrivateKey | *AuthAgent | *AuthKeyboardInteractive | *AuthComposite。
//
//xops:failclosed
type AuthMethod interface {
	sealedAuthMethod()
	Kind() AuthMethodKind
	IsValid() bool
}

// AuthPassword、AuthPrivateKey、AuthAgent、AuthKeyboardInteractive 与 AuthComposite 为全部不可变封闭认证变体。
//
//xops:opaque
//xops:failclosed
type AuthPassword struct {
	passwordRef secret.Ref
	valid       bool
}

//xops:opaque
//xops:failclosed
type AuthPrivateKey struct {
	keyPaths   algebraic.NonEmpty[KeyPathSpec]
	passphrase algebraic.Option[KeyPassphraseBinding]
	certPaths  []CertPathSpec
	valid      bool
}

//xops:opaque
//xops:failclosed
type AuthAgent struct {
	spec  algebraic.Option[AgentSpec]
	valid bool
}

//xops:opaque
//xops:failclosed
type AuthKeyboardInteractive struct {
	rules algebraic.NonEmpty[ChallengeRule]
	valid bool
}

//xops:opaque
//xops:failclosed
type AuthComposite struct {
	methods algebraic.NonEmpty[AuthMethod]
	valid   bool
}

func (*AuthPassword) sealedAuthMethod()            {}
func (*AuthPrivateKey) sealedAuthMethod()          {}
func (*AuthAgent) sealedAuthMethod()               {}
func (*AuthKeyboardInteractive) sealedAuthMethod() {}
func (*AuthComposite) sealedAuthMethod()           {}

// NewAuthPassword、NewAuthPrivateKey、NewAuthAgent、NewAuthKeyboardInteractive 与 NewAuthComposite 构造不可变认证方式。
func NewAuthPassword(ref secret.Ref) (*AuthPassword, error) {
	if !ref.IsValid() {
		return nil, fmt.Errorf("%w: AuthPassword 必须绑定有效 secret.Ref", ErrInvalidAuthMethod)
	}
	return &AuthPassword{ref, true}, nil
}
func NewAuthPrivateKey(keyPaths algebraic.NonEmpty[KeyPathSpec], passphrase algebraic.Option[KeyPassphraseBinding], certPaths []CertPathSpec) (*AuthPrivateKey, error) {
	pb, hasPB := passphrase.Get()
	if !keyPaths.IsValid() || slices.ContainsFunc(keyPaths.Slice(), KeyPathSpec.IsZero) ||
		(hasPB && !pb.IsValid()) || len(certPaths) > maxCertPaths || slices.ContainsFunc(certPaths, CertPathSpec.IsZero) {
		return nil, fmt.Errorf("%w: AuthPrivateKey 密钥/口令绑定/证书路径非法", ErrInvalidAuthMethod)
	}
	return &AuthPrivateKey{keyPaths, passphrase, slices.Clone(certPaths), true}, nil
}
func NewAuthAgent(spec algebraic.Option[AgentSpec]) (*AuthAgent, error) {
	if s, ok := spec.Get(); ok && !s.IsValid() {
		return nil, fmt.Errorf("%w: 无效 AgentSpec", ErrInvalidAuthMethod)
	}
	return &AuthAgent{spec, true}, nil
}
func NewAuthKeyboardInteractive(rules algebraic.NonEmpty[ChallengeRule]) (*AuthKeyboardInteractive, error) {
	if !rules.IsValid() {
		return nil, fmt.Errorf("%w: keyboard_interactive 需要至少一条规则", ErrInvalidAuthMethod)
	}
	seen := make(map[string]bool, rules.Len())
	for i, r := range rules.Slice() {
		if r == nil || !r.IsValid() {
			return nil, fmt.Errorf("%w: rules[%d] 无效", ErrInvalidAuthMethod, i)
		}
		if name := r.Name(); name != "" {
			if seen[name] {
				return nil, fmt.Errorf("%w: 重复质询规则名 %q", ErrInvalidChallengeRule, name)
			}
			seen[name] = true
		}
	}
	return &AuthKeyboardInteractive{rules, true}, nil
}
func NewAuthComposite(methods algebraic.NonEmpty[AuthMethod]) (*AuthComposite, error) {
	if !methods.IsValid() {
		return nil, fmt.Errorf("%w: AuthComposite 子列表不能为空", ErrInvalidAuthMethod)
	}
	visiting := make(map[*AuthComposite]bool)
	for _, m := range methods.Slice() {
		if err := validateAuthMethodDepth(m, 2, visiting); err != nil {
			return nil, err
		}
	}
	return &AuthComposite{methods, true}, nil
}

func validateAuthMethodDepth(m AuthMethod, depth int, visiting map[*AuthComposite]bool) error {
	if m == nil || !m.IsValid() {
		return ErrInvalidAuthMethod
	}
	switch v := m.(type) {
	case *AuthPassword, *AuthPrivateKey, *AuthAgent, *AuthKeyboardInteractive:
		return nil
	case *AuthComposite:
		if depth > maxAuthCompositeDepth {
			return fmt.Errorf("%w: 超过最大嵌套深度 %d", ErrAuthCompositeTooDeep, maxAuthCompositeDepth)
		}
		if visiting[v] {
			return fmt.Errorf("%w: 检测到 AuthComposite 循环引用", ErrInvalidAuthMethod)
		}
		visiting[v] = true
		defer delete(visiting, v)
		for _, sub := range v.methods.Slice() {
			if err := validateAuthMethodDepth(sub, depth+1, visiting); err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrInvalidAuthMethod
	}
}

// 五类认证变体的零值与 nil 安全只读访问器（切片返回防御性副本）。
func (a *AuthPassword) IsValid() bool        { return a != nil && a.valid && a.passwordRef.IsValid() }
func (a *AuthPassword) Kind() AuthMethodKind { return kindIf(a.IsValid(), AuthMethodKindPassword) }
func (a *AuthPassword) PasswordRef() secret.Ref {
	return getValid(a, func(v *AuthPassword) secret.Ref { return v.passwordRef })
}
func (a *AuthPrivateKey) IsValid() bool        { return a != nil && a.valid && a.keyPaths.IsValid() }
func (a *AuthPrivateKey) Kind() AuthMethodKind { return kindIf(a.IsValid(), AuthMethodKindPrivateKey) }
func (a *AuthPrivateKey) KeyPaths() algebraic.NonEmpty[KeyPathSpec] {
	return getValid(a, func(v *AuthPrivateKey) algebraic.NonEmpty[KeyPathSpec] { return v.keyPaths })
}
func (a *AuthPrivateKey) Passphrase() algebraic.Option[KeyPassphraseBinding] {
	return getValid(a, func(v *AuthPrivateKey) algebraic.Option[KeyPassphraseBinding] { return v.passphrase })
}
func (a *AuthPrivateKey) CertPaths() []CertPathSpec {
	return getValid(a, func(v *AuthPrivateKey) []CertPathSpec { return slices.Clone(v.certPaths) })
}
func (a *AuthAgent) IsValid() bool        { return a != nil && a.valid }
func (a *AuthAgent) Kind() AuthMethodKind { return kindIf(a.IsValid(), AuthMethodKindAgent) }
func (a *AuthAgent) Spec() algebraic.Option[AgentSpec] {
	return getValid(a, func(v *AuthAgent) algebraic.Option[AgentSpec] { return v.spec })
}
func (a *AuthKeyboardInteractive) IsValid() bool { return a != nil && a.valid && a.rules.IsValid() }
func (a *AuthKeyboardInteractive) Kind() AuthMethodKind {
	return kindIf(a.IsValid(), AuthMethodKindKeyboardInteractive)
}
func (a *AuthKeyboardInteractive) Rules() []ChallengeRule {
	return getValid(a, func(v *AuthKeyboardInteractive) []ChallengeRule { return v.rules.Slice() })
}
func (a *AuthComposite) IsValid() bool        { return a != nil && a.valid && a.methods.IsValid() }
func (a *AuthComposite) Kind() AuthMethodKind { return kindIf(a.IsValid(), AuthMethodKindComposite) }
func (a *AuthComposite) Methods() []AuthMethod {
	return getValid(a, func(v *AuthComposite) []AuthMethod { return v.methods.Slice() })
}

// EqualAuthMethod 严格按值比对两个 AuthMethod 是否均有效且结构完全等价。
func EqualAuthMethod(a, b AuthMethod) bool {
	if a == nil || b == nil || !a.IsValid() || !b.IsValid() {
		return false
	}
	switch va := a.(type) {
	case *AuthPassword:
		vb, ok := b.(*AuthPassword)
		return ok && vb.IsValid() && va.passwordRef.Equal(vb.passwordRef)
	case *AuthPrivateKey:
		vb, ok := b.(*AuthPrivateKey)
		return ok && vb.IsValid() && slices.EqualFunc(va.keyPaths.Slice(), vb.keyPaths.Slice(), KeyPathSpec.Equal) &&
			equalOptionFunc(va.passphrase, vb.passphrase, KeyPassphraseBinding.Equal) &&
			slices.EqualFunc(va.certPaths, vb.certPaths, CertPathSpec.Equal)
	case *AuthAgent:
		vb, ok := b.(*AuthAgent)
		return ok && vb.IsValid() && algebraic.EqualOption(va.spec, vb.spec)
	case *AuthKeyboardInteractive:
		vb, ok := b.(*AuthKeyboardInteractive)
		return ok && vb.IsValid() && slices.EqualFunc(va.rules.Slice(), vb.rules.Slice(), EqualChallengeRule)
	case *AuthComposite:
		vb, ok := b.(*AuthComposite)
		return ok && vb.IsValid() && slices.EqualFunc(va.methods.Slice(), vb.methods.Slice(), EqualAuthMethod)
	default:
		return false
	}
}

// WriteAuthMethodCanonical 以零反射、零明文的方式写入 AuthMethod 规范摘要字节流，供 plan.HopSpec 计算认证摘要。
func WriteAuthMethodCanonical(w io.Writer, m AuthMethod) error {
	if w == nil {
		return ErrNilWriter
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(authCanonicalDomainTag)
	if err := writeAuthMethodNode(enc, m); err != nil {
		return err
	}
	return enc.err
}

func writeAuthMethodNode(enc *canonicalEncoder, m AuthMethod) error {
	if m == nil || !m.IsValid() {
		return ErrInvalidAuthMethod
	}
	enc.writeUint8(uint8(m.Kind()))
	switch v := m.(type) {
	case *AuthPassword:
		enc.writeString(v.passwordRef.String())
	case *AuthPrivateKey:
		writePrivateKeyCanonical(enc, v)
	case *AuthAgent:
		sp, ok := v.spec.Get()
		enc.writeUint8(pickIf[uint8](ok, 1, 0))
		if ok {
			enc.writeString(sp.String())
		}
	case *AuthKeyboardInteractive:
		return writeCanonicalList(enc, v.rules.Slice(), writeChallengeRuleCanonical)
	case *AuthComposite:
		return writeCanonicalList(enc, v.methods.Slice(), writeAuthMethodNode)
	default:
		return ErrInvalidAuthMethod
	}
	return enc.err
}

func writePrivateKeyCanonical(enc *canonicalEncoder, v *AuthPrivateKey) {
	writeCanonicalStringers(enc, v.keyPaths.Slice())
	pb, ok := v.passphrase.Get()
	enc.writeUint8(pickIf[uint8](ok, 1, 0))
	if ok {
		enc.writeString(pb.passphraseRef.String())
		enc.writeString(pb.keyFingerprint.String())
	}
	writeCanonicalStringers(enc, v.certPaths)
}

func writeCanonicalList[T any](enc *canonicalEncoder, items []T, fn func(*canonicalEncoder, T) error) error {
	enc.writeUint64(uint64(len(items)))
	for _, item := range items {
		if err := fn(enc, item); err != nil {
			return err
		}
	}
	return enc.err
}
