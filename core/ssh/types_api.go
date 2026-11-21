package ssh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// SudoMode 定义了 SSH 连接执行命令时的提权方式
type SudoMode string

const (
	SudoModeRoot   SudoMode = "root"
	SudoModeSudo   SudoMode = "sudo"
	SudoModeSudoer SudoMode = "sudoer"
	SudoModeSu     SudoMode = "su"
	SudoModeNone   SudoMode = "none"
	SudoModeAuto   SudoMode = "auto"
)

// AdmittedCertificate binds an admitted user certificate path to its expected
// SHA-256 digest and optional pre-read raw bytes captured at ConnectionPlan admission.
// RawBytes is excluded from JSON serialization so ConnectionKey hashes only
// deterministic metadata (Path/SHA256/Missing/NonRegular).
type AdmittedCertificate struct {
	Path       string `json:",omitempty" digest:"include"`
	SHA256     string `json:",omitempty" digest:"include"`
	Missing    bool   `json:",omitempty" digest:"include"`
	NonRegular bool   `json:",omitempty" digest:"include"`
	RawBytes   []byte `json:"-" digest:"exclude,reason=pre-read certificate bytes already bound by SHA256 metadata"`
}

// AdmittedKeyDigest binds an admitted key file path to its expected SHA-256
// digest captured at ConnectionPlan admission. Private key bytes are never stored.
type AdmittedKeyDigest struct {
	Path       string `json:",omitempty" digest:"include"`
	SHA256     string `json:",omitempty" digest:"include"`
	Missing    bool   `json:",omitempty" digest:"include"`
	NonRegular bool   `json:",omitempty" digest:"include"`
}

func cloneAdmittedCertificates(src []AdmittedCertificate) []AdmittedCertificate {
	if len(src) == 0 {
		return nil
	}
	out := make([]AdmittedCertificate, len(src))
	for i, c := range src {
		c.RawBytes = slices.Clone(c.RawBytes)
		out[i] = c
	}
	return out
}

func cloneAdmittedKeyDigests(src []AdmittedKeyDigest) []AdmittedKeyDigest {
	if len(src) == 0 {
		return nil
	}
	return slices.Clone(src)
}

func equalAdmittedCertificateMeta(a, b AdmittedCertificate) bool {
	return a.Path == b.Path && a.SHA256 == b.SHA256 && a.Missing == b.Missing && a.NonRegular == b.NonRegular
}

func equalAdmittedCertificates(a, b []AdmittedCertificate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalAdmittedCertificateMeta(a[i], b[i]) {
			return false
		}
	}
	return true
}

// ClientConfig 定义建立 SSH 连接所需的各种参数，代替原有的 models.Node/Host/Identity。
type ClientConfig struct {
	KeyRef       string `digest:"include"`
	TrustVersion string `digest:"include"`
	NodeID       string `digest:"include"` // 逻辑标识
	// OriginalHost is the user's original command-line host or alias (%n).
	// Empty falls back to NodeID. It differs from Address (%h) after
	// CanonicalizeHostname rewrites the target.
	OriginalHost  string `digest:"include"`
	CanonicalHost string `digest:"include"`
	Address       string `digest:"include"`
	// BaseHost records the underlying saved host address when a session-level
	// HostName override rewrites Address, allowing SecretResolver snapshot checks
	// to verify both the dialed override host and the underlying saved address
	// without mutable adapter-wide state.
	BaseHost   string   `digest:"include"`
	Port       int      `digest:"include"`
	User       string   `digest:"include"`
	AuthType   string   `digest:"include"` // "password", "key", "agent", "auto"
	Password   string   `digest:"exclude,reason=plaintext secret must never enter cache digest; credential versioning uses KeyRef and AuthUpdateToken"`
	KeyPath    string   `digest:"include"`
	KeyPaths   []string `digest:"include"`
	Passphrase string   `digest:"exclude,reason=plaintext secret must never enter cache digest; credential versioning uses KeyRef and AuthUpdateToken"`
	// AuthUpdateToken conditionally authorizes persistence of discovered
	// authentication values. An empty token makes discovery session-local.
	AuthUpdateToken string   `digest:"include"`
	SudoMode        SudoMode `digest:"include"` // "root", "sudo", "sudoer", "su", "none", "auto"
	SuPwd           string   `digest:"exclude,reason=plaintext secret must never enter cache digest; credential versioning uses SudoUpdateToken"`
	// SudoUpdateToken conditionally authorizes persistence of discovered sudo
	// values. An empty token makes discovery session-local.
	SudoUpdateToken      string `digest:"include"`
	ProxyJump            string `digest:"include"` // 跳板机的 NodeID
	OriginalProxyJump    string `digest:"include"` // 来自 Provider 的原始 ProxyJump 配置（用于目标一致性变更检查）
	HasOriginalProxyJump bool   `digest:"include"` // 是否显式保留了配置态 ProxyJump 快照（区分显式空字符串与未设置）
	// PasswordPromptPattern 自定义密码提示正则（节点级，可选）。
	// 为空时回落到 Connector 的全局配置，再为空则使用内置的多语言默认模式。
	PasswordPromptPattern       string                `digest:"include"`
	EnforceAdmittedCertificates bool                  `json:",omitempty" digest:"include"`
	AdmittedCertificates        []AdmittedCertificate `json:",omitempty" digest:"include"`
	EnforceAdmittedKeyDigests   bool                  `json:",omitempty" digest:"include"`
	AdmittedKeyDigests          []AdmittedKeyDigest   `json:",omitempty" digest:"include"`
	Execution                   *ExecutionConfig      `digest:"include"`
	Options                     *Options              `digest:"include"`
}

// ToConnectionConfig 将 ClientConfig 转换为仅含网络与连接参数的 ConnectionConfig，剥离所有明文密码。
func (c *ClientConfig) ToConnectionConfig() ConnectionConfig {
	if c == nil {
		return ConnectionConfig{}
	}
	origJump := c.OriginalProxyJump
	hasOriginal := c.HasOriginalProxyJump
	if !hasOriginal && origJump == "" {
		origJump = c.ProxyJump
	}
	return ConnectionConfig{
		KeyRef:                      c.KeyRef,
		TrustVersion:                c.TrustVersion,
		NodeID:                      c.NodeID,
		OriginalHost:                c.OriginalHost,
		CanonicalHost:               c.CanonicalHost,
		Address:                     c.Address,
		BaseHost:                    c.BaseHost,
		Port:                        c.Port,
		User:                        c.User,
		AuthType:                    c.AuthType,
		configuredAuthType:          c.AuthType,
		KeyPath:                     c.KeyPath,
		KeyPaths:                    slices.Clone(c.KeyPaths),
		AuthUpdateToken:             c.AuthUpdateToken,
		SudoMode:                    c.SudoMode,
		SudoUpdateToken:             c.SudoUpdateToken,
		ProxyJump:                   c.ProxyJump,
		OriginalProxyJump:           origJump,
		HasOriginalProxyJump:        hasOriginal,
		PasswordPromptPattern:       c.PasswordPromptPattern,
		EnforceAdmittedCertificates: c.EnforceAdmittedCertificates,
		AdmittedCertificates:        cloneAdmittedCertificates(c.AdmittedCertificates),
		EnforceAdmittedKeyDigests:   c.EnforceAdmittedKeyDigests,
		AdmittedKeyDigests:          cloneAdmittedKeyDigests(c.AdmittedKeyDigests),
		Execution:                   c.Execution.Clone(),
		Options:                     c.Options.Clone(),
	}
}

// ConnectionConfig 包含建立连接所需的目标与网络参数，不包含登录或提权明文机密。
type ConnectionConfig struct {
	KeyRef                      string                `digest:"include"`
	TrustVersion                string                `digest:"include"`
	NodeID                      string                `digest:"include"`
	OriginalHost                string                `digest:"include"`
	CanonicalHost               string                `digest:"include"`
	Address                     string                `digest:"include"`
	BaseHost                    string                `json:"base_host,omitempty" digest:"include"`
	Port                        int                   `digest:"include"`
	User                        string                `digest:"include"`
	AuthType                    string                `digest:"include"`
	configuredAuthType          string                `digest:"exclude,reason=handshake baseline copy of AuthType retained only for legacy auto-auth compatibility"`
	KeyPath                     string                `digest:"include"`
	KeyPaths                    []string              `digest:"include"`
	AuthUpdateToken             string                `digest:"include"`
	SudoMode                    SudoMode              `digest:"include"`
	SudoUpdateToken             string                `digest:"include"`
	ProxyJump                   string                `digest:"include"`
	OriginalProxyJump           string                `digest:"include"`
	HasOriginalProxyJump        bool                  `digest:"include"`
	PasswordPromptPattern       string                `digest:"include"`
	EnforceAdmittedCertificates bool                  `json:",omitempty" digest:"include"`
	AdmittedCertificates        []AdmittedCertificate `json:",omitempty" digest:"include"`
	EnforceAdmittedKeyDigests   bool                  `json:",omitempty" digest:"include"`
	AdmittedKeyDigests          []AdmittedKeyDigest   `json:",omitempty" digest:"include"`
	Execution                   *ExecutionConfig      `digest:"include"`
	Options                     *Options              `digest:"include"`
}

// Clone returns a deep copy of ConnectionConfig, isolating mutable Execution and Options pointers.
func (c ConnectionConfig) Clone() ConnectionConfig {
	out := c
	out.KeyPaths = slices.Clone(c.KeyPaths)
	out.AdmittedCertificates = cloneAdmittedCertificates(c.AdmittedCertificates)
	out.AdmittedKeyDigests = cloneAdmittedKeyDigests(c.AdmittedKeyDigests)
	out.Execution = c.Execution.Clone()
	out.Options = c.Options.Clone()
	return out
}

// AuthMaterial 包含单次 SSH 握手所需的敏感认证材料。
type AuthMaterial struct {
	Password   []byte
	Passphrase []byte
}

// Zero 清零敏感字节切片并清空引用。
func (a *AuthMaterial) Zero() {
	if a == nil {
		return
	}
	zeroBytes(a.Password)
	zeroBytes(a.Passphrase)
	a.Password = nil
	a.Passphrase = nil
}

// PrivilegeMaterial 包含单次提权 (sudo/su) 所需的敏感机密材料。
type PrivilegeMaterial struct {
	Password      []byte
	confirmedSave func(context.Context, []byte) error
	deferSave     bool
	verified      bool
}

// Zero 清零敏感字节切片并清空引用。
func (p *PrivilegeMaterial) Zero() {
	if p == nil {
		return
	}
	zeroBytes(p.Password)
	p.Password = nil
	p.confirmedSave = nil
}

// zeroBytes 将切片中的所有敏感字节清零。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ConnectionConfirmer is an optional provider capability invoked immediately
// after SSH authentication, before recording credentials or dispatching user work.
type ConnectionConfirmer interface {
	ConfirmConnection(context.Context, string) error
}

// AuthenticatedConnectionConfirmer optionally inspects an authenticated client
// before enrollment and credential recording. It may run bounded read-only
// probes but must not retain/close the client or execute user commands.
// Implementations own confirmation and may return newly persisted execution
// defaults for this client; nil preserves its frozen defaults.
// ConnectionConfirmer is the fallback.
type AuthenticatedConnectionConfirmer interface {
	ConfirmAuthenticatedConnection(context.Context, string, *Client) (*ExecutionConfig, error)
}

// ConnectionProvider 提供指定节点的底层连接配置。
type ConnectionProvider interface {
	// GetConfig 获取指定 nodeID 的连接配置
	GetConfig(nodeID string) (*ClientConfig, error)
}

// SecretResolver 解析指定节点认证或提权所需机密。
type SecretResolver interface {
	// ResolveSecret 根据机密请求解析并返回机密字节
	ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error)
}

// CredentialRecorder 负责将探测或交互获得的新凭据写回持久化存储。
type CredentialRecorder interface {
	// UpdateAuth 在探测到可用密码或私钥 passphrase 时，写回持久化存储并返回本次提交后的新认证令牌
	UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error)

	// UpdateSudo 在探测到可用提权模式或接收到 su 密码时，写回持久化存储并返回本次提交后的新提权令牌
	UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode SudoMode, suPwd string) (string, error)
}

// ConfigStore 聚合 ConnectionProvider 和 CredentialRecorder 接口。
// Deprecated: 请优先使用拆分后的小接口 ConnectionProvider, SecretResolver, CredentialRecorder。
type ConfigStore interface {
	ConnectionProvider
	CredentialRecorder
}

// SecretKind 标识需要交互输入的机密类型
type SecretKind uint8

const (
	SecretKindUnknown SecretKind = iota
	SecretKindLoginPassword
	SecretKindPrivateKeyPassphrase
	SecretKindSuPassword
	SecretKindSudoPassword
	SecretKindOTP
	SecretKindKeyboardInteractive
)

// ErrSnapshotMismatch 表示连接快照与当前配置版本或目标不匹配
var ErrSnapshotMismatch = errors.New("connection snapshot mismatch")

// SecretRequest 描述向解析器或用户请求机密的上下文信息（严禁携带已有密码）
type SecretRequest struct {
	Kind         SecretKind
	NodeID       string
	User         string
	Host         string
	BaseHost     string
	Port         int
	KeyPath      string
	VersionToken string
	Instruction  string
	Prompt       string
	Echo         bool
	Attempt      int
	NumPrompts   int
}

// SSHFPVerifyStatus summarizes how DNS SSHFP records relate to a presented host key.
type SSHFPVerifyStatus string

const (
	// SSHFPStatusNone means DNS verification was disabled, unavailable, or found no usable SHA-256 record.
	SSHFPStatusNone SSHFPVerifyStatus = ""
	// SSHFPStatusMatchedVerified means a SHA-256 record matched and the resolver set AD=1.
	SSHFPStatusMatchedVerified SSHFPVerifyStatus = "matched_verified"
	// SSHFPStatusMatchedUnverified means a SHA-256 record matched but the answer was not DNSSEC-authenticated.
	SSHFPStatusMatchedUnverified SSHFPVerifyStatus = "matched_unverified"
	// SSHFPStatusMismatch means SHA-256 records exist for the key algorithm but none match.
	SSHFPStatusMismatch SSHFPVerifyStatus = "mismatch"
)

// HostKeyConfirmation 描述主机密钥指纹确认请求
type HostKeyConfirmation struct {
	Hostname      string
	RemoteAddress string
	Algorithm     string
	Fingerprint   string
	// SSHFPStatus reports the DNS SSHFP evaluation when VerifyHostKeyDNS is enabled.
	SSHFPStatus SSHFPVerifyStatus
}

// SecretPrompter 负责提示用户输入敏感凭据（如密码、私钥密码短语等）
type SecretPrompter interface {
	PromptSecret(ctx context.Context, request SecretRequest) (string, error)
}

// HostKeyConfirmer 负责提示用户确认未知的主机密钥
type HostKeyConfirmer interface {
	ConfirmHostKey(ctx context.Context, request HostKeyConfirmation) (bool, error)
}

// InteractionHandler 组合了机密提示与主机密钥确认接口
type InteractionHandler interface {
	SecretPrompter
	HostKeyConfirmer
}

type tokenRefreshKind int

const (
	tokenRefreshKindAuth tokenRefreshKind = iota
	tokenRefreshKindSudo
)

// validateTargetCompatibility 校验新配置的目标属性是否与已建立的连接快照完全一致
func validateTargetCompatibility(cur ConnectionConfig, newCfg *ClientConfig) error {
	if newCfg == nil {
		return fmt.Errorf("%w: target configuration is nil", ErrSnapshotMismatch)
	}
	if newCfg.Address != cur.Address {
		return fmt.Errorf("%w: host address changed (expected %q, got %q)",
			ErrSnapshotMismatch, cur.Address, newCfg.Address)
	}
	if curBase, newBase := strings.TrimSpace(cur.BaseHost), strings.TrimSpace(newCfg.BaseHost); curBase != newBase {
		return fmt.Errorf("%w: base host changed (expected %q, got %q)",
			ErrSnapshotMismatch, curBase, newBase)
	}
	curPort := cur.Port
	if curPort <= 0 {
		curPort = 22
	}
	newPort := newCfg.Port
	if newPort <= 0 {
		newPort = 22
	}
	if newPort != curPort {
		return fmt.Errorf("%w: host port changed (expected %d, got %d)",
			ErrSnapshotMismatch, curPort, newPort)
	}
	if newCfg.User != cur.User {
		return fmt.Errorf("%w: user changed (expected %q, got %q)",
			ErrSnapshotMismatch, cur.User, newCfg.User)
	}
	if curOrig, newOrig := effectiveOriginalHost(cur.OriginalHost, cur.NodeID), effectiveOriginalHost(newCfg.OriginalHost, newCfg.NodeID); curOrig != newOrig {
		return fmt.Errorf("%w: original host changed (expected %q, got %q)",
			ErrSnapshotMismatch, curOrig, newOrig)
	}
	if curCanon, newCanon := strings.TrimSpace(cur.CanonicalHost), strings.TrimSpace(newCfg.CanonicalHost); curCanon != newCanon {
		return fmt.Errorf("%w: canonical host changed (expected %q, got %q)",
			ErrSnapshotMismatch, curCanon, newCanon)
	}
	if newCfg.KeyRef != cur.KeyRef || newCfg.TrustVersion != cur.TrustVersion {
		return fmt.Errorf("%w: key reference or host trust version changed", ErrSnapshotMismatch)
	}
	if newCfg.AuthUpdateToken != cur.AuthUpdateToken {
		return fmt.Errorf("%w: auth update token changed", ErrSnapshotMismatch)
	}
	if err := validateAuthTypeCompatibility(cur, newCfg); err != nil {
		return err
	}
	if newCfg.KeyPath != cur.KeyPath {
		return fmt.Errorf("%w: key path changed (expected %q, got %q)",
			ErrSnapshotMismatch, cur.KeyPath, newCfg.KeyPath)
	}
	if !slices.Equal(newCfg.KeyPaths, cur.KeyPaths) {
		return fmt.Errorf("%w: key paths changed (expected %v, got %v)",
			ErrSnapshotMismatch, cur.KeyPaths, newCfg.KeyPaths)
	}
	if err := validateAdmittedMaterialTargetCompatibility(cur, newCfg); err != nil {
		return err
	}
	if err := validateOptionsTargetCompatibility(cur.Options, newCfg.Options); err != nil {
		return err
	}
	return validateRoutingTargetCompatibility(cur, newCfg)
}

func validateAdmittedMaterialTargetCompatibility(cur ConnectionConfig, newCfg *ClientConfig) error {
	if cur.EnforceAdmittedCertificates != newCfg.EnforceAdmittedCertificates ||
		!equalAdmittedCertificates(cur.AdmittedCertificates, newCfg.AdmittedCertificates) {
		return fmt.Errorf("%w: admitted certificates changed", ErrSnapshotMismatch)
	}
	if cur.EnforceAdmittedKeyDigests != newCfg.EnforceAdmittedKeyDigests ||
		!slices.Equal(cur.AdmittedKeyDigests, newCfg.AdmittedKeyDigests) {
		return fmt.Errorf("%w: admitted key digests changed", ErrSnapshotMismatch)
	}
	return nil
}

func normalizeAuthType(authType string) string {
	return strings.ToLower(strings.TrimSpace(authType))
}

func validateAuthTypeCompatibility(cur ConnectionConfig, newCfg *ClientConfig) error {
	curType := normalizeAuthType(cur.AuthType)
	newType := normalizeAuthType(newCfg.AuthType)
	if curType == newType {
		return nil
	}
	if normalizeAuthType(cur.configuredAuthType) == "auto" && newType == "auto" {
		return nil
	}
	return fmt.Errorf("%w: auth type changed (expected %q, got %q)",
		ErrSnapshotMismatch, cur.AuthType, newCfg.AuthType)
}

func validateOptionsTargetCompatibility(curOpts, newOpts *Options) error {
	if curOpts.StrictHostKeyChecking() != newOpts.StrictHostKeyChecking() ||
		curOpts.UserKnownHostsFile() != newOpts.UserKnownHostsFile() ||
		curOpts.GlobalKnownHostsFile() != newOpts.GlobalKnownHostsFile() ||
		curOpts.VerifyHostKeyDNS() != newOpts.VerifyHostKeyDNS() ||
		curOpts.HashKnownHosts() != newOpts.HashKnownHosts() {
		return fmt.Errorf("%w: host trust options changed", ErrSnapshotMismatch)
	}
	if !slices.Equal(newOpts.IdentityFiles(), curOpts.IdentityFiles()) {
		return fmt.Errorf("%w: identity files changed", ErrSnapshotMismatch)
	}
	if !slices.Equal(newOpts.CertificateFiles(), curOpts.CertificateFiles()) {
		return fmt.Errorf("%w: certificate files changed", ErrSnapshotMismatch)
	}
	if err := validateAuthOptionsTargetCompatibility(curOpts, newOpts); err != nil {
		return err
	}
	if curOpts.Ciphers() != newOpts.Ciphers() ||
		curOpts.MACs() != newOpts.MACs() ||
		curOpts.KexAlgorithms() != newOpts.KexAlgorithms() ||
		curOpts.HostKeyAlgorithms() != newOpts.HostKeyAlgorithms() {
		return fmt.Errorf("%w: transport algorithm options changed", ErrSnapshotMismatch)
	}
	if newOpts.AddressFamily() != curOpts.AddressFamily() {
		return fmt.Errorf("%w: address family changed (expected %q, got %q)",
			ErrSnapshotMismatch, curOpts.AddressFamily(), newOpts.AddressFamily())
	}
	if err := validateTransportAndForwardOptionsTargetCompatibility(curOpts, newOpts); err != nil {
		return err
	}
	return validateCanonicalizeOptionsTargetCompatibility(curOpts, newOpts)
}

func validateTransportAndForwardOptionsTargetCompatibility(curOpts, newOpts *Options) error {
	curTCPKA, curTCPKAOK := curOpts.TCPKeepAlive()
	newTCPKA, newTCPKAOK := newOpts.TCPKeepAlive()
	if curOpts.ServerAliveInterval() != newOpts.ServerAliveInterval() ||
		curOpts.ServerAliveCountMax() != newOpts.ServerAliveCountMax() ||
		curTCPKA != newTCPKA || curTCPKAOK != newTCPKAOK {
		return fmt.Errorf("%w: keepalive options changed", ErrSnapshotMismatch)
	}
	curUnlink, curUnlinkOK := curOpts.StreamLocalBindUnlink()
	newUnlink, newUnlinkOK := newOpts.StreamLocalBindUnlink()
	curMask, curMaskOK := curOpts.StreamLocalBindMask()
	newMask, newMaskOK := newOpts.StreamLocalBindMask()
	if curOpts.ForwardAgent() != newOpts.ForwardAgent() ||
		curOpts.GatewayPortsMode() != newOpts.GatewayPortsMode() ||
		curUnlink != newUnlink || curUnlinkOK != newUnlinkOK ||
		curMask != newMask || curMaskOK != newMaskOK {
		return fmt.Errorf("%w: forwarding options changed", ErrSnapshotMismatch)
	}
	return nil
}

func validateAuthOptionsTargetCompatibility(curOpts, newOpts *Options) error {
	curPub, curPubOK := curOpts.PubkeyAuthentication()
	newPub, newPubOK := newOpts.PubkeyAuthentication()
	if curOpts.IdentityAgent() != newOpts.IdentityAgent() ||
		curOpts.IdentitiesOnly() != newOpts.IdentitiesOnly() ||
		curOpts.BatchMode() != newOpts.BatchMode() ||
		curPub != newPub || curPubOK != newPubOK {
		return fmt.Errorf("%w: publickey or agent authentication options changed", ErrSnapshotMismatch)
	}
	curPwd, curPwdOK := curOpts.PasswordAuthentication()
	newPwd, newPwdOK := newOpts.PasswordAuthentication()
	curKbd, curKbdOK := curOpts.KbdInteractiveAuthentication()
	newKbd, newKbdOK := newOpts.KbdInteractiveAuthentication()
	if curPwd != newPwd || curPwdOK != newPwdOK ||
		curKbd != newKbd || curKbdOK != newKbdOK ||
		!slices.Equal(curOpts.PreferredAuthentications(), newOpts.PreferredAuthentications()) {
		return fmt.Errorf("%w: authentication policy options changed", ErrSnapshotMismatch)
	}
	return nil
}

func validateCanonicalizeOptionsTargetCompatibility(curOpts, newOpts *Options) error {
	curDots, curDotsOK := curOpts.CanonicalizeMaxDots()
	newDots, newDotsOK := newOpts.CanonicalizeMaxDots()
	curFallback, curFallbackOK := curOpts.CanonicalizeFallbackLocal()
	newFallback, newFallbackOK := newOpts.CanonicalizeFallbackLocal()
	if curOpts.CanonicalizeHostname() != newOpts.CanonicalizeHostname() ||
		!slices.Equal(curOpts.CanonicalDomains(), newOpts.CanonicalDomains()) ||
		curDots != newDots || curDotsOK != newDotsOK ||
		curFallback != newFallback || curFallbackOK != newFallbackOK ||
		!slices.Equal(curOpts.CanonicalizePermittedCNAMEs(), newOpts.CanonicalizePermittedCNAMEs()) {
		return fmt.Errorf("%w: hostname canonicalization options changed", ErrSnapshotMismatch)
	}
	return nil
}

func validateRoutingTargetCompatibility(cur ConnectionConfig, newCfg *ClientConfig) error {
	expectedJump := cur.ProxyJump
	if cur.HasOriginalProxyJump {
		expectedJump = cur.OriginalProxyJump
	} else if cur.OriginalProxyJump != "" {
		expectedJump = cur.OriginalProxyJump
	}
	actualJump := newCfg.ProxyJump
	if newCfg.HasOriginalProxyJump {
		actualJump = newCfg.OriginalProxyJump
	} else if newCfg.OriginalProxyJump != "" {
		actualJump = newCfg.OriginalProxyJump
	}
	if actualJump != expectedJump {
		return fmt.Errorf("%w: proxy jump changed (expected %q, got %q)",
			ErrSnapshotMismatch, expectedJump, actualJump)
	}
	if !HasActiveProxyJump(cur.ProxyJump) {
		expectedProxyCmd := cur.Options.ActiveProxyCommand()
		actualProxyCmd := newCfg.Options.ActiveProxyCommand()
		if actualProxyCmd != expectedProxyCmd {
			return fmt.Errorf("%w: proxy command changed (expected %q, got %q)",
				ErrSnapshotMismatch, expectedProxyCmd, actualProxyCmd)
		}
	}
	return nil
}

// effectiveOriginalHost returns the %n value: an explicit OriginalHost, else nodeID.
func effectiveOriginalHost(originalHost, nodeID string) string {
	if trimmed := strings.TrimSpace(originalHost); trimmed != "" {
		return trimmed
	}
	return nodeID
}

// NormalizeTargetContext returns a canonicalized copy of raw using env for
// local-user fallback.
func NormalizeTargetContext(raw TargetContext, env Environment) TargetContext {
	port := raw.Port
	if port <= 0 {
		port = 22
	}
	user := raw.User
	if user == "" {
		user = env.LocalUser
	}
	return TargetContext{
		Host:          cleanHostLiteral(raw.Host),
		Port:          port,
		User:          user,
		OriginalHost:  strings.TrimSpace(raw.OriginalHost),
		CanonicalHost: strings.TrimSpace(raw.CanonicalHost),
		JumpHost:      NormalizeProxyJump(raw.JumpHost),
		KeyPath:       raw.KeyPath,
		Control:       raw.Control,
	}
}

// BuildClientTargetContext builds a canonical TargetContext from nodeName,
// cfg, env, and ctrl. A nil cfg safely falls back to nodeName, default port,
// env.LocalUser, and ctrl.
func BuildClientTargetContext(nodeName string, cfg *ClientConfig, env Environment, ctrl *ControlConfig) TargetContext {
	if cfg == nil {
		return NormalizeTargetContext(TargetContext{
			OriginalHost: nodeName,
			Control:      ctrl,
		}, env)
	}
	originalHost := effectiveOriginalHost(cfg.OriginalHost, cfg.NodeID)
	if strings.TrimSpace(originalHost) == "" {
		originalHost = nodeName
	}
	return NormalizeTargetContext(TargetContext{
		Host:          cfg.Address,
		Port:          cfg.Port,
		User:          cfg.User,
		OriginalHost:  originalHost,
		CanonicalHost: cfg.CanonicalHost,
		JumpHost:      cfg.ProxyJump,
		KeyPath:       cfg.KeyPath,
		Control:       ctrl,
	}, env)
}
