package inventory

import (
	"cmp"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/jsontext"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/secret"
)

const (
	forbiddenIDChars     = "@:/\\,;|&$`<>(){}!'\"*?[]"
	sha256FingerprintTag = "SHA256:"
	sha256FingerprintB64 = 43
	maxAgentSpecBytes    = 512
)

func validateAssetIdent(raw string, forbidOpenSSH bool) error {
	if raw == "" || len(raw) > maxIDLen || hasSpaceOrForbidden(raw) || raw == "." || raw == ".." ||
		raw[0] == '-' || strings.EqualFold(raw, "none") || strings.ContainsAny(raw, forbiddenIDChars) {
		return fmt.Errorf("%w: %q 格式非法或使用了保留字", ErrInvalidID, raw)
	}
	if forbidOpenSSH && len(raw) >= 8 && strings.EqualFold(raw[:8], "openssh:") {
		return fmt.Errorf("%w: %q 禁止使用保留前缀 %q", ErrInvalidID, raw, "openssh:")
	}
	return nil
}

func validateKeyFileSpec(raw string) (string, error) {
	t := strings.TrimSpace(raw)
	if t == "" || len(t) > maxKeyPathBytes || hasForbiddenText(raw) || strings.EqualFold(t, "none") ||
		strings.ContainsRune(t, '%') || strings.Contains(t, "${") ||
		(strings.HasPrefix(t, "~") && t != "~" && !strings.HasPrefix(t, "~/") && !strings.HasPrefix(t, `~\`)) {
		return "", fmt.Errorf("%w: 密钥/证书路径 %q 非法", ErrInvalidKeySpec, raw)
	}
	return t, nil
}

type assetIDToken struct{ value string }

func (t assetIDToken) IsValid() bool  { return t.value != "" }
func (t assetIDToken) IsZero() bool   { return t.value == "" }
func (t assetIDToken) String() string { return t.value }
func (t assetIDToken) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, t.value != "", t.value, ErrInvalidID)
}
func (t assetIDToken) MarshalText() ([]byte, error) { return t.AppendText(nil) }

type keyFileToken struct{ raw string }

func (t keyFileToken) IsValid() bool  { return t.raw != "" }
func (t keyFileToken) IsZero() bool   { return t.raw == "" }
func (t keyFileToken) String() string { return t.raw }
func (t keyFileToken) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, t.raw != "", t.raw, ErrInvalidKeySpec)
}
func (t keyFileToken) MarshalText() ([]byte, error) { return t.AppendText(nil) }

func parseIdent[T ~struct{ assetIDToken }](raw string, forbidOpenSSH bool) (T, error) {
	if err := validateAssetIdent(raw, forbidOpenSSH); err != nil {
		var zero T
		return zero, err
	}
	return T(struct{ assetIDToken }{assetIDToken{raw}}), nil
}

func parseKeyFile[T ~struct{ keyFileToken }](raw string) (T, error) {
	c, err := validateKeyFileSpec(raw)
	if err != nil {
		var zero T
		return zero, err
	}
	return T(struct{ keyFileToken }{keyFileToken{c}}), nil
}

// HostID、IdentityID、NodeID、Alias、Tag、KeyPathSpec、CertPathSpec 与 AgentSpec 为强类型不透明值对象（零值失败关闭）。
//
//xops:opaque
//xops:failclosed
type HostID struct{ assetIDToken }

//xops:opaque
//xops:failclosed
type IdentityID struct{ assetIDToken }

//xops:opaque
//xops:failclosed
type NodeID struct{ assetIDToken }

//xops:opaque
//xops:failclosed
type Alias struct{ assetIDToken }

//xops:opaque
//xops:failclosed
type Tag struct{ assetIDToken }

//xops:opaque
//xops:failclosed
type KeyPathSpec struct{ keyFileToken }

//xops:opaque
//xops:failclosed
type CertPathSpec struct{ keyFileToken }

//xops:opaque
//xops:failclosed
type AgentSpec struct{ raw string }

// ParseHostID..ParseAgentSpec 校验并构造强类型资产标识与凭据路径规格（失败返回零值）。
func ParseHostID(raw string) (HostID, error)             { return parseIdent[HostID](raw, true) }
func ParseIdentityID(raw string) (IdentityID, error)     { return parseIdent[IdentityID](raw, true) }
func ParseNodeID(raw string) (NodeID, error)             { return parseIdent[NodeID](raw, true) }
func ParseAlias(raw string) (Alias, error)               { return parseIdent[Alias](raw, true) }
func ParseTag(raw string) (Tag, error)                   { return parseIdent[Tag](raw, false) }
func ParseKeyPathSpec(raw string) (KeyPathSpec, error)   { return parseKeyFile[KeyPathSpec](raw) }
func ParseCertPathSpec(raw string) (CertPathSpec, error) { return parseKeyFile[CertPathSpec](raw) }
func ParseAgentSpec(raw string) (AgentSpec, error) {
	t := strings.TrimSpace(raw)
	if t == "" || len(t) > maxAgentSpecBytes || hasForbiddenText(raw) {
		return AgentSpec{}, fmt.Errorf("%w: 非法 AgentSpec %q", ErrInvalidAuthMethod, raw)
	}
	return AgentSpec{t}, nil
}

// 强类型标识与路径规格的等价比较、全序与文本反序列化方法。
func (id HostID) Equal(o HostID) bool           { return id.IsValid() && o.IsValid() && id.value == o.value }
func (id HostID) Compare(o HostID) int          { return cmp.Compare(id.value, o.value) }
func (id *HostID) UnmarshalText(b []byte) error { return unmarshalText(id, b, ParseHostID) }
func (id IdentityID) Equal(o IdentityID) bool {
	return id.IsValid() && o.IsValid() && id.value == o.value
}
func (id IdentityID) Compare(o IdentityID) int       { return cmp.Compare(id.value, o.value) }
func (id *IdentityID) UnmarshalText(b []byte) error  { return unmarshalText(id, b, ParseIdentityID) }
func (id NodeID) Equal(o NodeID) bool                { return id.IsValid() && o.IsValid() && id.value == o.value }
func (id NodeID) Compare(o NodeID) int               { return cmp.Compare(id.value, o.value) }
func (id *NodeID) UnmarshalText(b []byte) error      { return unmarshalText(id, b, ParseNodeID) }
func (a Alias) Equal(o Alias) bool                   { return a.IsValid() && o.IsValid() && a.value == o.value }
func (a Alias) Compare(o Alias) int                  { return cmp.Compare(a.value, o.value) }
func (a *Alias) UnmarshalText(b []byte) error        { return unmarshalText(a, b, ParseAlias) }
func (t Tag) Equal(o Tag) bool                       { return t.IsValid() && o.IsValid() && t.value == o.value }
func (t Tag) Compare(o Tag) int                      { return cmp.Compare(t.value, o.value) }
func (t *Tag) UnmarshalText(b []byte) error          { return unmarshalText(t, b, ParseTag) }
func (k KeyPathSpec) Equal(o KeyPathSpec) bool       { return k.IsValid() && o.IsValid() && k.raw == o.raw }
func (k KeyPathSpec) Compare(o KeyPathSpec) int      { return cmp.Compare(k.raw, o.raw) }
func (k *KeyPathSpec) UnmarshalText(b []byte) error  { return unmarshalText(k, b, ParseKeyPathSpec) }
func (c CertPathSpec) Equal(o CertPathSpec) bool     { return c.IsValid() && o.IsValid() && c.raw == o.raw }
func (c CertPathSpec) Compare(o CertPathSpec) int    { return cmp.Compare(c.raw, o.raw) }
func (c *CertPathSpec) UnmarshalText(b []byte) error { return unmarshalText(c, b, ParseCertPathSpec) }
func (a AgentSpec) IsValid() bool                    { return a.raw != "" }
func (a AgentSpec) IsZero() bool                     { return a.raw == "" }
func (a AgentSpec) String() string                   { return a.raw }
func (a AgentSpec) Equal(o AgentSpec) bool           { return a.IsValid() && o.IsValid() && a.raw == o.raw }
func (a AgentSpec) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, a.raw != "", a.raw, ErrInvalidAuthMethod)
}
func (a AgentSpec) MarshalText() ([]byte, error)  { return a.AppendText(nil) }
func (a *AgentSpec) UnmarshalText(b []byte) error { return unmarshalText(a, b, ParseAgentSpec) }

// KeyFingerprint 表示经严格校验的 OpenSSH SHA-256 公钥指纹（"SHA256:<43位无填充Base64>"）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type KeyFingerprint struct {
	sum   [sha256.Size]byte
	raw   string
	valid bool
}

// KeyFingerprintFromSHA256 与 ParseKeyFingerprint 构造或解析规范 OpenSSH 公钥指纹。
func KeyFingerprintFromSHA256(sum [sha256.Size]byte) KeyFingerprint {
	return KeyFingerprint{sum, sha256FingerprintTag + base64.RawStdEncoding.EncodeToString(sum[:]), true}
}
func ParseKeyFingerprint(raw string) (KeyFingerprint, error) {
	b64, ok := strings.CutPrefix(raw, sha256FingerprintTag)
	if !ok || hasSpaceOrForbidden(raw) || len(b64) != sha256FingerprintB64 {
		return KeyFingerprint{}, fmt.Errorf("%w: 指纹 %q 非法", ErrInvalidKeySpec, raw)
	}
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(b64)
	if err != nil || len(decoded) != sha256.Size {
		return KeyFingerprint{}, fmt.Errorf("%w: 指纹 Base64 解码失败", ErrInvalidKeySpec)
	}
	var sum [sha256.Size]byte
	copy(sum[:], decoded)
	return KeyFingerprintFromSHA256(sum), nil
}
func (f KeyFingerprint) IsValid() bool  { return f.valid && f.raw != "" }
func (f KeyFingerprint) IsZero() bool   { return !f.IsValid() }
func (f KeyFingerprint) String() string { return pickIf(f.IsValid(), f.raw, "") }
func (f KeyFingerprint) Equal(o KeyFingerprint) bool {
	return f.IsValid() && o.IsValid() && subtle.ConstantTimeCompare(f.sum[:], o.sum[:]) == 1
}
func (f KeyFingerprint) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, f.IsValid(), f.raw, ErrInvalidKeySpec)
}
func (f KeyFingerprint) MarshalText() ([]byte, error) { return f.AppendText(nil) }
func (f *KeyFingerprint) UnmarshalText(b []byte) error {
	return unmarshalText(f, b, ParseKeyFingerprint)
}

// KeyPassphraseBinding 在类型级结构化强制 INV-F1 / RFC §3.6 不变量：私钥口令凭据引用必绑已校验公钥指纹。
//
//xops:opaque
//xops:failclosed
type KeyPassphraseBinding struct {
	passphraseRef  secret.Ref
	keyFingerprint KeyFingerprint
	valid          bool
}

// NewKeyPassphraseBinding 校验口令凭据引用与公钥指纹均有效后构造不可变 KeyPassphraseBinding。
func NewKeyPassphraseBinding(ref secret.Ref, fp KeyFingerprint) (KeyPassphraseBinding, error) {
	if !ref.IsValid() || !fp.IsValid() {
		return KeyPassphraseBinding{}, fmt.Errorf("%w: 私钥口令引用与公钥指纹均必须有效", ErrInvalidKeySpec)
	}
	return KeyPassphraseBinding{ref, fp, true}, nil
}
func (b KeyPassphraseBinding) IsValid() bool {
	return b.valid && b.passphraseRef.IsValid() && b.keyFingerprint.IsValid()
}
func (b KeyPassphraseBinding) IsZero() bool                   { return !b.IsValid() }
func (b KeyPassphraseBinding) PassphraseRef() secret.Ref      { return b.passphraseRef }
func (b KeyPassphraseBinding) KeyFingerprint() KeyFingerprint { return b.keyFingerprint }
func (b KeyPassphraseBinding) Equal(o KeyPassphraseBinding) bool {
	return b.IsValid() && o.IsValid() && b.passphraseRef.Equal(o.passphraseRef) && b.keyFingerprint.Equal(o.keyFingerprint)
}

type passphraseBindingWire struct {
	PassphraseRef  secret.Ref     `json:"passphrase_ref"`
	KeyFingerprint KeyFingerprint `json:"key_fingerprint"`
}

func (b KeyPassphraseBinding) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalValidWire(enc, b.IsValid(), ErrInvalidKeySpec, passphraseBindingWire{b.passphraseRef, b.keyFingerprint})
}
func (b *KeyPassphraseBinding) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSON(b, dec, ErrInvalidKeySpec, func(w passphraseBindingWire) (KeyPassphraseBinding, error) {
		return NewKeyPassphraseBinding(w.PassphraseRef, w.KeyFingerprint)
	})
}
