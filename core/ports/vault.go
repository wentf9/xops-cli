package ports

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

const (
	maxKeyAlgoBytes  = 128
	maxWireBlobBytes = 64 * 1024
	sshfpSHA1Bytes   = 20
	sshfpSHA256Bytes = 32
)

// SecretVault 定义 100% 作用域闭包化的凭据存储出站端口（ADR-011 / RFC §3.2）。
type SecretVault interface {
	// WithSecret 按 ref 读取机密并在同步闭包内借出 *secret.SecretBox；退出前无条件清零。
	//
	//xops:syncclosure
	//xops:borrowed
	WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error
	PutAndVerify(ctx context.Context, ref secret.Ref, box *secret.SecretBox) error
	Delete(ctx context.Context, ref secret.Ref) error
}

// VaultState 表示凭据库生命周期状态；零值 VaultStateInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type VaultState uint8

const (
	VaultStateInvalid       VaultState = iota // 无效状态（零值失败关闭）
	VaultStateUninitialized                   // 尚未初始化凭据库
	VaultStateLocked                          // 已初始化但处于锁定状态
	VaultStateUnlocked                        // 已解锁并可供读写
)

// VaultStatusSpec 是构造不可变 VaultStatus 的显式入参规格。
type VaultStatusSpec struct {
	State       VaultState `json:"state"`
	KnownStores []string   `json:"known_stores,omitzero"`
	Detail      string     `json:"detail,omitzero"`
}

// VaultStatus 描述凭据库当前锁定状态、可用存储后端清单与诊断摘要；零值恒无效。
//
//xops:opaque
//xops:failclosed
type VaultStatus struct {
	state       VaultState
	knownStores []string
	detail      string
	valid       bool
}

// NewVaultStatus 校验状态与存储后端清单并构造规范排序去重的不可变 VaultStatus。
func NewVaultStatus(spec VaultStatusSpec) (VaultStatus, error) {
	if !spec.State.IsValid() || slices.ContainsFunc(spec.KnownStores, func(s string) bool { return !isValidASCIIToken(s, maxPortTokenLen) }) {
		return VaultStatus{}, fmt.Errorf("%w: VaultStatus 状态或凭据存储名非法", ErrInvalidArgument)
	}
	detail, err := sanitizeBoundedText(spec.Detail, maxPortDetailBytes, true, ErrInvalidArgument)
	if err != nil {
		return VaultStatus{}, err
	}
	stores := slices.Clone(spec.KnownStores)
	slices.Sort(stores)
	return VaultStatus{state: spec.State, knownStores: slices.Compact(stores), detail: detail, valid: true}, nil
}
func (s VaultStatus) IsValid() bool         { return s.valid && s.state.IsValid() }
func (s VaultStatus) IsZero() bool          { return !s.IsValid() }
func (s VaultStatus) State() VaultState     { return pickIf(s.IsValid(), s.state, VaultStateInvalid) }
func (s VaultStatus) IsUnlocked() bool      { return s.IsValid() && s.state == VaultStateUnlocked }
func (s VaultStatus) KnownStores() []string { return slices.Clone(s.knownStores) }
func (s VaultStatus) Detail() string        { return s.detail }
func (s VaultStatus) Equal(o VaultStatus) bool {
	return s.IsValid() && o.IsValid() && s.state == o.state && slices.Equal(s.knownStores, o.knownStores) && s.detail == o.detail
}

// VaultControlPort 定义凭据库初始化、解锁、锁定与状态查询出站端口（P3-T1 <-> P4-T4）。
// Init / Unlock 无回调参数，借用的主口令 *secret.SecretBox 由 secretbox Rule 1 与具体实现参数级 //xops:borrowed 共同保证零逃逸。
type VaultControlPort interface {
	// Init 使用借用的主口令 SecretBox 初始化新凭据库；已初始化返回 ErrAlreadyExists。
	Init(ctx context.Context, pass *secret.SecretBox) error
	// Unlock 使用借用的主口令 SecretBox 解锁凭据库；口令错误返回 ErrAuthFailed，未初始化返回 ErrNotFound。
	Unlock(ctx context.Context, pass *secret.SecretBox) error
	Lock(ctx context.Context) error
	Status(ctx context.Context) (VaultStatus, error)
}

// PublicKeyInfoSpec 是构造不可变 PublicKeyInfo 的显式入参规格。
type PublicKeyInfoSpec struct {
	Algorithm   string
	Fingerprint inventory.KeyFingerprint
	WireBlob    []byte
	Comment     string
}

// PublicKeyInfo 表示协议库无关的不可变 SSH 公钥元数据；零值恒无效。
//
//xops:opaque
//xops:failclosed
type PublicKeyInfo struct {
	algorithm, comment string
	fingerprint        inventory.KeyFingerprint
	wireBlob           []byte
	valid              bool
}

// NewPublicKeyInfo 校验算法名、指纹与非空公钥线缆载荷并构造不可变 PublicKeyInfo。
func NewPublicKeyInfo(spec PublicKeyInfoSpec) (PublicKeyInfo, error) {
	if !isValidASCIIToken(spec.Algorithm, maxKeyAlgoBytes) || !spec.Fingerprint.IsValid() || len(spec.WireBlob) == 0 || len(spec.WireBlob) > maxWireBlobBytes {
		return PublicKeyInfo{}, fmt.Errorf("%w: 公钥算法、指纹或 wire 载荷非法", ErrInvalidArgument)
	}
	comment, err := sanitizeBoundedText(spec.Comment, maxPortDetailBytes, true, ErrInvalidArgument)
	if err != nil {
		return PublicKeyInfo{}, err
	}
	return PublicKeyInfo{algorithm: spec.Algorithm, fingerprint: spec.Fingerprint, wireBlob: bytes.Clone(spec.WireBlob), comment: comment, valid: true}, nil
}
func (k PublicKeyInfo) IsValid() bool {
	return k.valid && k.algorithm != "" && k.fingerprint.IsValid() && len(k.wireBlob) > 0
}
func (k PublicKeyInfo) IsZero() bool                          { return !k.IsValid() }
func (k PublicKeyInfo) Algorithm() string                     { return k.algorithm }
func (k PublicKeyInfo) Fingerprint() inventory.KeyFingerprint { return k.fingerprint }
func (k PublicKeyInfo) WireBlob() []byte                      { return bytes.Clone(k.wireBlob) }
func (k PublicKeyInfo) Comment() string                       { return k.comment }
func (k PublicKeyInfo) Equal(o PublicKeyInfo) bool {
	return k.IsValid() && o.IsValid() && k.algorithm == o.algorithm && k.fingerprint.Equal(o.fingerprint) && bytes.Equal(k.wireBlob, o.wireBlob) && k.comment == o.comment
}

// Signature 表示协议库无关的不可变 SSH 数字签名值对象；零值恒无效。
//
//xops:opaque
//xops:failclosed
type Signature struct {
	format string
	blob   []byte
	valid  bool
}

// NewSignature 校验签名算法格式与非空载荷并构造不可变 Signature。
func NewSignature(format string, blob []byte) (Signature, error) {
	if !isValidASCIIToken(format, maxKeyAlgoBytes) || len(blob) == 0 || len(blob) > maxWireBlobBytes {
		return Signature{}, fmt.Errorf("%w: 签名格式或载荷非法", ErrInvalidArgument)
	}
	return Signature{format: format, blob: bytes.Clone(blob), valid: true}, nil
}
func (s Signature) IsValid() bool  { return s.valid && s.format != "" && len(s.blob) > 0 }
func (s Signature) IsZero() bool   { return !s.IsValid() }
func (s Signature) Format() string { return s.format }
func (s Signature) Blob() []byte   { return bytes.Clone(s.blob) }
func (s Signature) Equal(o Signature) bool {
	return s.IsValid() && o.IsValid() && s.format == o.format && bytes.Equal(s.blob, o.blob)
}

// KeySignerPort 定义私钥解析、指纹核验与公钥签名出站端口。
type KeySignerPort interface {
	ListPublicKeys(ctx context.Context, auth inventory.AuthMethod) ([]PublicKeyInfo, error)
	Sign(ctx context.Context, key inventory.KeyFingerprint, algorithm string, data []byte) (Signature, error)
	InspectPrivateKeyFingerprint(ctx context.Context, keyPath inventory.KeyPathSpec, passphrase algebraic.Option[secret.Ref]) (inventory.KeyFingerprint, error)
}

// SSHAgentPort 定义本机 SSH Agent 通道连接、公钥列举与签名出站端口（统一封装 Unix $SSH_AUTH_SOCK 与 Windows 命名管道）。
type SSHAgentPort interface {
	DialAgent(ctx context.Context, spec algebraic.Option[inventory.AgentSpec]) (net.Conn, error)
	ListAgentKeys(ctx context.Context, spec algebraic.Option[inventory.AgentSpec]) ([]PublicKeyInfo, error)
	SignWithAgent(ctx context.Context, spec algebraic.Option[inventory.AgentSpec], key inventory.KeyFingerprint, algorithm string, data []byte) (Signature, error)
}

// SSHFPRecordSpec 是构造不可变 SSHFPRecord 的显式入参规格（RFC 4255 / RFC 6594）。
type SSHFPRecordSpec struct {
	Algorithm, FingerprintType uint8
	Digest                     []byte
	Authenticated              bool // DNSSEC AD 校验标记（零值 false 失败关闭）
}

// SSHFPRecord 表示单条经校验的 DNS SSHFP 记录；零值恒无效且 Authenticated==false。
//
//xops:opaque
//xops:failclosed
type SSHFPRecord struct {
	algorithm, fpType    uint8
	digest               []byte
	authenticated, valid bool
}

// NewSSHFPRecord 校验算法编号、摘要类型（1=SHA-1/20B, 2=SHA-256/32B）与长度并构造不可变记录。
func NewSSHFPRecord(spec SSHFPRecordSpec) (SSHFPRecord, error) {
	wantLen := pickIf(spec.FingerprintType == 1, sshfpSHA1Bytes, pickIf(spec.FingerprintType == 2, sshfpSHA256Bytes, 0))
	if spec.Algorithm == 0 || wantLen == 0 || len(spec.Digest) != wantLen {
		return SSHFPRecord{}, fmt.Errorf("%w: SSHFP 算法/摘要类型或长度非法", ErrInvalidArgument)
	}
	return SSHFPRecord{algorithm: spec.Algorithm, fpType: spec.FingerprintType, digest: bytes.Clone(spec.Digest), authenticated: spec.Authenticated, valid: true}, nil
}
func (r SSHFPRecord) IsValid() bool          { return r.valid && r.algorithm != 0 && len(r.digest) > 0 }
func (r SSHFPRecord) IsZero() bool           { return !r.IsValid() }
func (r SSHFPRecord) Algorithm() uint8       { return pickIf(r.IsValid(), r.algorithm, 0) }
func (r SSHFPRecord) FingerprintType() uint8 { return pickIf(r.IsValid(), r.fpType, 0) }
func (r SSHFPRecord) Digest() []byte         { return bytes.Clone(r.digest) }
func (r SSHFPRecord) Authenticated() bool    { return r.IsValid() && r.authenticated }
func (r SSHFPRecord) Equal(o SSHFPRecord) bool {
	return r.IsValid() && o.IsValid() && r.algorithm == o.algorithm && r.fpType == o.fpType && r.authenticated == o.authenticated && bytes.Equal(r.digest, o.digest)
}

// SSHFPLookupPort 定义 DNS SSHFP 记录只读查询出站端口（由 internal/host/sys 实现并注入 sshnet/hostkey）。
type SSHFPLookupPort interface {
	LookupSSHFP(ctx context.Context, host netaddr.CanonicalHost) ([]SSHFPRecord, error)
}

// HostTrustStatus 表示远端主机密钥核验状态枚举；零值 HostTrustStatusInvalid 恒拒绝。
//
//xops:opaque
//xops:failclosed
type HostTrustStatus uint8

const (
	HostTrustStatusInvalid HostTrustStatus = iota // 无效状态（零值失败关闭）
	HostTrustTrusted                              // 与信任库匹配
	HostTrustUnknown                              // 尚无端点信任记录
	HostTrustMismatch                             // 与既有记录冲突（疑似 MITM）
	HostTrustRevoked                              // 已被显式吊销（@revoked）
)

// HostTrustRequestSpec 是构造不可变 HostTrustRequest 的显式入参规格。
type HostTrustRequestSpec struct {
	Endpoint   netaddr.Endpoint
	Presented  PublicKeyInfo
	Mode       option.StrictHostKeyCheckingMode
	KnownHosts option.KnownHostsList
}

// HostTrustRequest 表示面向 HostTrustPort.VerifyHostKey 的强类型核验请求（INV-E2）。
//
//xops:opaque
//xops:failclosed
type HostTrustRequest struct {
	endpoint   netaddr.Endpoint
	presented  PublicKeyInfo
	mode       option.StrictHostKeyCheckingMode
	knownHosts option.KnownHostsList
	valid      bool
}

// NewHostTrustRequest 校验端点、远端公钥与校验模式并构造不可变 HostTrustRequest。
func NewHostTrustRequest(spec HostTrustRequestSpec) (HostTrustRequest, error) {
	if !spec.Endpoint.IsValid() || !spec.Presented.IsValid() || spec.Mode.String() == "" {
		return HostTrustRequest{}, fmt.Errorf("%w: Endpoint、Presented 公钥与模式均须有效", ErrInvalidArgument)
	}
	return HostTrustRequest{endpoint: spec.Endpoint, presented: spec.Presented, mode: spec.Mode, knownHosts: spec.KnownHosts, valid: true}, nil
}
func (r HostTrustRequest) IsValid() bool {
	return r.valid && r.endpoint.IsValid() && r.presented.IsValid() && r.mode.String() != ""
}
func (r HostTrustRequest) IsZero() bool                           { return !r.IsValid() }
func (r HostTrustRequest) Endpoint() netaddr.Endpoint             { return r.endpoint }
func (r HostTrustRequest) Presented() PublicKeyInfo               { return r.presented }
func (r HostTrustRequest) Mode() option.StrictHostKeyCheckingMode { return r.mode }
func (r HostTrustRequest) KnownHosts() option.KnownHostsList      { return r.knownHosts }

// HostTrustCheckSpec 是构造不可变 HostTrustCheck 的显式入参规格。
type HostTrustCheckSpec struct {
	Status               HostTrustStatus            `json:"status"`
	Endpoint             netaddr.Endpoint           `json:"endpoint"`
	Presented            PublicKeyInfo              `json:"presented"`
	ExpectedFingerprints []inventory.KeyFingerprint `json:"expected_fingerprints,omitzero"`
	Reason               string                     `json:"reason,omitzero"`
}

// HostTrustCheck 表示 HostTrustPort.VerifyHostKey 返回的不可变核验结论；零值恒无效并拒绝信任。
//
//xops:opaque
//xops:failclosed
type HostTrustCheck struct {
	status               HostTrustStatus
	endpoint             netaddr.Endpoint
	presented            PublicKeyInfo
	expectedFingerprints []inventory.KeyFingerprint
	reason               string
	valid                bool
}

// NewHostTrustCheck 校验核验状态、端点、呈递公钥与可选预期指纹列表并构造不可变 HostTrustCheck。
func NewHostTrustCheck(spec HostTrustCheckSpec) (HostTrustCheck, error) {
	if !spec.Status.IsValid() || !spec.Endpoint.IsValid() || !spec.Presented.IsValid() || slices.ContainsFunc(spec.ExpectedFingerprints, inventory.KeyFingerprint.IsZero) {
		return HostTrustCheck{}, fmt.Errorf("%w: HostTrustCheck 缺少有效字段或含无效预期指纹", ErrInvalidArgument)
	}
	reason, err := sanitizeBoundedText(spec.Reason, maxPortDetailBytes, true, ErrInvalidArgument)
	if err != nil {
		return HostTrustCheck{}, err
	}
	return HostTrustCheck{status: spec.Status, endpoint: spec.Endpoint, presented: spec.Presented, expectedFingerprints: slices.Clone(spec.ExpectedFingerprints), reason: reason, valid: true}, nil
}
func (c HostTrustCheck) IsValid() bool {
	return c.valid && c.status.IsValid() && c.endpoint.IsValid() && c.presented.IsValid()
}
func (c HostTrustCheck) IsZero() bool { return !c.IsValid() }
func (c HostTrustCheck) Status() HostTrustStatus {
	return pickIf(c.IsValid(), c.status, HostTrustStatusInvalid)
}
func (c HostTrustCheck) IsTrusted() bool            { return c.IsValid() && c.status == HostTrustTrusted }
func (c HostTrustCheck) Endpoint() netaddr.Endpoint { return c.endpoint }
func (c HostTrustCheck) Presented() PublicKeyInfo   { return c.presented }
func (c HostTrustCheck) Reason() string             { return c.reason }
func (c HostTrustCheck) ExpectedFingerprints() []inventory.KeyFingerprint {
	return slices.Clone(c.expectedFingerprints)
}
func (c HostTrustCheck) Equal(o HostTrustCheck) bool {
	return c.IsValid() && o.IsValid() && c.status == o.status && c.endpoint.Equal(o.endpoint) && c.presented.Equal(o.presented) &&
		slices.EqualFunc(c.expectedFingerprints, o.expectedFingerprints, inventory.KeyFingerprint.Equal) && c.reason == o.reason
}

// HostTrustPort 定义主机密钥信任库（known_hosts / SSHFP）查询、校验与记录出站端口（INV-C5 / INV-E2）。
type HostTrustPort interface {
	PreferredAlgorithms(ctx context.Context, endpoint netaddr.Endpoint, knownHosts option.KnownHostsList) ([]string, error)
	VerifyHostKey(ctx context.Context, req HostTrustRequest) (HostTrustCheck, error)
	RecordHostKey(ctx context.Context, endpoint netaddr.Endpoint, key PublicKeyInfo, knownHosts option.KnownHostsList) error
}
