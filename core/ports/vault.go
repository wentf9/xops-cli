package ports

import (
	"bytes"
	"context"
	"fmt"
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
)

// SecretVault 定义 100% 作用域闭包化的凭据存储出站端口（ADR-011 / RFC §3.2）。
//
// 安全契约：
//   - 彻底废除命令式裸句柄返回；WithSecret 负责解密并在回调退出（含 panic）时无条件 defer box.Wipe()；
//   - WithSecret 仅标注 //xops:syncclosure 与 //xops:borrowed（严禁标注 //xops:secretuse），
//     由 xopsvet/linearlease 静态禁止 *SecretBox 逃逸，同时允许非明文白名单层透传借用。
type SecretVault interface {
	// WithSecret 按引用 ref 读取机密并在同步作用域闭包 fn 内借出 *secret.SecretBox；
	// 条目不存在返回 ErrSecretNotFound，库处于锁定时返回 ErrVaultLocked。
	//
	//xops:syncclosure
	//xops:borrowed
	WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error
	// PutAndVerify 将有效 *secret.SecretBox 原子写入 ref 并执行常量时间回读比对验证（INV-F3）；
	// 回读不一致返回 ErrSecretVerifyFailed，box 无效或已销毁时失败关闭。
	PutAndVerify(ctx context.Context, ref secret.Ref, box *secret.SecretBox) error
	// Delete 删除 ref 对应的机密条目；条目不存在返回 ErrSecretNotFound，库锁定时返回 ErrVaultLocked。
	Delete(ctx context.Context, ref secret.Ref) error
}

// PublicKeyInfoSpec 是构造不可变 PublicKeyInfo 的显式入参规格。
type PublicKeyInfoSpec struct {
	Algorithm   string
	Fingerprint inventory.KeyFingerprint
	WireBlob    []byte
	Comment     string
}

// PublicKeyInfo 表示协议库无关的不可变 SSH 公钥元数据（算法名、SHA-256 指纹与 SSH wire 字节）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type PublicKeyInfo struct {
	algorithm   string
	fingerprint inventory.KeyFingerprint
	wireBlob    []byte
	comment     string
	valid       bool
}

// NewPublicKeyInfo 校验算法名、指纹与非空公钥线缆载荷并构造不可变 PublicKeyInfo。
func NewPublicKeyInfo(spec PublicKeyInfoSpec) (PublicKeyInfo, error) {
	if !isValidASCIIToken(spec.Algorithm, maxKeyAlgoBytes) || !spec.Fingerprint.IsValid() {
		return PublicKeyInfo{}, fmt.Errorf("%w: 公钥算法或指纹无效", ErrInvalidArgument)
	}
	if len(spec.WireBlob) == 0 || len(spec.WireBlob) > maxWireBlobBytes {
		return PublicKeyInfo{}, fmt.Errorf("%w: 公钥 wire 载荷长度 %d 非法", ErrInvalidArgument, len(spec.WireBlob))
	}
	comment, err := sanitizeBoundedText(spec.Comment, maxPortDetailBytes, true, ErrInvalidArgument)
	if err != nil {
		return PublicKeyInfo{}, err
	}
	return PublicKeyInfo{
		algorithm: spec.Algorithm, fingerprint: spec.Fingerprint,
		wireBlob: bytes.Clone(spec.WireBlob), comment: comment, valid: true,
	}, nil
}

// PublicKeyInfo 只读访问器与严格等价比对（返回防御性拷贝）。
func (k PublicKeyInfo) IsValid() bool {
	return k.valid && k.algorithm != "" && k.fingerprint.IsValid() && len(k.wireBlob) > 0
}
func (k PublicKeyInfo) IsZero() bool                          { return !k.IsValid() }
func (k PublicKeyInfo) Algorithm() string                     { return k.algorithm }
func (k PublicKeyInfo) Fingerprint() inventory.KeyFingerprint { return k.fingerprint }
func (k PublicKeyInfo) WireBlob() []byte                      { return bytes.Clone(k.wireBlob) }
func (k PublicKeyInfo) Comment() string                       { return k.comment }
func (k PublicKeyInfo) Equal(o PublicKeyInfo) bool {
	return k.IsValid() && o.IsValid() && k.algorithm == o.algorithm &&
		k.fingerprint.Equal(o.fingerprint) && bytes.Equal(k.wireBlob, o.wireBlob) && k.comment == o.comment
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

// NewSignature 校验签名算法格式与非空签名载荷并构造不可变 Signature。
func NewSignature(format string, blob []byte) (Signature, error) {
	if !isValidASCIIToken(format, maxKeyAlgoBytes) || len(blob) == 0 || len(blob) > maxWireBlobBytes {
		return Signature{}, fmt.Errorf("%w: 签名格式或载荷非法", ErrInvalidArgument)
	}
	return Signature{format: format, blob: bytes.Clone(blob), valid: true}, nil
}

// Signature 只读访问器与严格等价比对。
func (s Signature) IsValid() bool  { return s.valid && s.format != "" && len(s.blob) > 0 }
func (s Signature) IsZero() bool   { return !s.IsValid() }
func (s Signature) Format() string { return s.format }
func (s Signature) Blob() []byte   { return bytes.Clone(s.blob) }
func (s Signature) Equal(o Signature) bool {
	return s.IsValid() && o.IsValid() && s.format == o.format && bytes.Equal(s.blob, o.blob)
}

// KeySignerPort 定义私钥解析、指纹核验与公钥签名出站端口（隔离 golang.org/x/crypto/ssh 签名实现）。
// 真实实现（sshnet/priv）经依赖注入消费 SecretVault 与 OperatorReadFS，避免明文向用例层泄漏。
type KeySignerPort interface {
	// ListPublicKeys 根据非敏感认证规格 auth 列举可用于公钥认证的候选公钥列表。
	ListPublicKeys(ctx context.Context, auth inventory.AuthMethod) ([]PublicKeyInfo, error)
	// Sign 使用指纹为 key 的私钥或 Agent 身份，以指定算法 algorithm 对 data 生成 SSH 数字签名。
	Sign(ctx context.Context, key inventory.KeyFingerprint, algorithm string, data []byte) (Signature, error)
	// InspectPrivateKeyFingerprint 读取私钥文件（必要时经可选 passphrase 引用解密）并返回规范 SHA-256 指纹（INV-F1）。
	InspectPrivateKeyFingerprint(ctx context.Context, keyPath inventory.KeyPathSpec, passphrase algebraic.Option[secret.Ref]) (inventory.KeyFingerprint, error)
}

// HostTrustStatus 表示远端主机密钥核验的失败关闭状态枚举；零值 HostTrustStatusInvalid 恒代表拒绝。
//
//xops:opaque
//xops:failclosed
type HostTrustStatus uint8

const (
	HostTrustStatusInvalid HostTrustStatus = iota // 无效状态（零值失败关闭）
	HostTrustTrusted                              // 远端主机密钥与信任库（known_hosts/SSHFP）匹配
	HostTrustUnknown                              // 信任库中尚无该 (Host, Port) 端点记录
	HostTrustMismatch                             // 远端主机密钥与既有信任记录冲突（疑似 MITM）
	HostTrustRevoked                              // 远端主机密钥已被显式吊销（@revoked）
)

// HostTrustRequestSpec 是构造不可变 HostTrustRequest 的显式入参规格。
type HostTrustRequestSpec struct {
	Endpoint   netaddr.Endpoint
	Presented  PublicKeyInfo
	Mode       option.StrictHostKeyCheckingMode
	KnownHosts option.KnownHostsList
}

// HostTrustRequest 表示面向 HostTrustPort.VerifyHostKey 的强类型核验请求（INV-E2 强制绑定 Endpoint (Host, Port)）。
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
		return HostTrustRequest{}, fmt.Errorf("%w: Endpoint、Presented 公钥与 StrictHostKeyCheckingMode 均须有效", ErrInvalidArgument)
	}
	return HostTrustRequest{
		endpoint: spec.Endpoint, presented: spec.Presented, mode: spec.Mode, knownHosts: spec.KnownHosts, valid: true,
	}, nil
}

// HostTrustRequest 只读访问器。
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
	Status               HostTrustStatus
	Endpoint             netaddr.Endpoint
	Presented            PublicKeyInfo
	ExpectedFingerprints []inventory.KeyFingerprint
	Reason               string
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
	if !spec.Status.IsValid() || !spec.Endpoint.IsValid() || !spec.Presented.IsValid() {
		return HostTrustCheck{}, fmt.Errorf("%w: HostTrustCheck 缺少有效的 status/endpoint/presented", ErrInvalidArgument)
	}
	if slices.ContainsFunc(spec.ExpectedFingerprints, inventory.KeyFingerprint.IsZero) {
		return HostTrustCheck{}, fmt.Errorf("%w: expected_fingerprints 包含无效指纹", ErrInvalidArgument)
	}
	reason, err := sanitizeBoundedText(spec.Reason, maxPortDetailBytes, true, ErrInvalidArgument)
	if err != nil {
		return HostTrustCheck{}, err
	}
	return HostTrustCheck{
		status: spec.Status, endpoint: spec.Endpoint, presented: spec.Presented,
		expectedFingerprints: slices.Clone(spec.ExpectedFingerprints), reason: reason, valid: true,
	}, nil
}

// HostTrustCheck 只读访问器与严格等价比对。
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
	return c.IsValid() && o.IsValid() && c.status == o.status &&
		c.endpoint.Equal(o.endpoint) && c.presented.Equal(o.presented) &&
		slices.EqualFunc(c.expectedFingerprints, o.expectedFingerprints, inventory.KeyFingerprint.Equal) && c.reason == o.reason
}

// HostTrustPort 定义主机密钥信任库（known_hosts / SSHFP）查询、校验与记录出站端口（INV-C5 / INV-E2）。
// 实现方在单次握手中须在共享锁与 O_NOFOLLOW 约束下读取 known_hosts 快照，严格按 Endpoint (Host, Port) 匹配。
type HostTrustPort interface {
	// PreferredAlgorithms 根据信任库中已记录的主机密钥返回建议优先协商的主机密钥算法顺序。
	PreferredAlgorithms(ctx context.Context, endpoint netaddr.Endpoint, knownHosts option.KnownHostsList) ([]string, error)
	// VerifyHostKey 核验服务端呈递公钥并返回结构化 HostTrustCheck。
	VerifyHostKey(ctx context.Context, req HostTrustRequest) (HostTrustCheck, error)
	// RecordHostKey 在经过策略许可或人工确认后，将公钥以旁路锁原子方式持久化写入指定 known_hosts。
	RecordHostKey(ctx context.Context, endpoint netaddr.Endpoint, key PublicKeyInfo, knownHosts option.KnownHostsList) error
}
