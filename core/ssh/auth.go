package ssh

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func dialAgentConn(ctx context.Context, dialFn func(context.Context, string) (net.Conn, error), socket string) (net.Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ssh-agent dial context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dialFn == nil {
		return nil, errors.New("ssh-agent dialer is not configured")
	}
	return dialFn(ctx, socket)
}

// ResolveIdentityAgent resolves an OpenSSH IdentityAgent specification against env and target.
//   - "none" (case-insensitive) returns ("", true, nil), disabling SSH agent authentication completely.
//   - "" or "SSH_AUTH_SOCK" returns (strings.TrimSpace(env.AgentSocket), false, nil).
//   - "$VAR", "${VAR}", "~", and percent tokens are expanded via env and target.
func ResolveIdentityAgent(spec string, env Environment, target TargetContext) (socket string, disabled bool, err error) {
	trimmed := strings.TrimSpace(spec)
	if strings.EqualFold(trimmed, "none") {
		return "", true, nil
	}
	if trimmed == "" || trimmed == "SSH_AUTH_SOCK" {
		return strings.TrimSpace(env.AgentSocket), false, nil
	}
	expanded, err := expandAgentSocketPath(trimmed, env, target, "IdentityAgent")
	if err != nil {
		return "", false, err
	}
	return expanded, false, nil
}

func expandAgentSocketPath(rawPath string, env Environment, target TargetContext, kind string) (string, error) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return "", fmt.Errorf("invalid %s: value cannot be empty", kind)
	}
	if hasASCIIControlChar(trimmed) {
		return "", fmt.Errorf("invalid %s %q: contains invalid ASCII control character", kind, rawPath)
	}

	if strings.HasPrefix(trimmed, "$") && !strings.HasPrefix(trimmed, "${") {
		varName := trimmed[1:]
		if !isValidEnvIdentifier(varName) {
			return "", fmt.Errorf("invalid environment variable name %q in %s", rawPath, kind)
		}
		val, ok := lookupEnv(env, varName)
		val = strings.TrimSpace(val)
		if !ok || val == "" {
			return "", fmt.Errorf("invalid environment variable expansion: env var $%s has no value", varName)
		}
		if hasASCIIControlChar(val) {
			return "", fmt.Errorf("invalid %s %q: expanded value contains ASCII control character", kind, rawPath)
		}
		return normalizeExpandedAgentSocketPath(val, env), nil
	}

	expanded := trimmed
	if strings.Contains(expanded, "${") {
		var err error
		expanded, err = expandEnvironmentVariables(expanded, env)
		if err != nil {
			return "", err
		}
	}
	if strings.HasPrefix(expanded, "~") {
		if env.HomeDir != "" {
			var err error
			expanded, err = expandTilde(expanded, env.HomeDir)
			if err != nil {
				return "", err
			}
		} else if env.ResolveKeyPath != nil {
			expanded = env.ResolveKeyPath(expanded)
		} else {
			return "", errors.New("cannot expand '~': home directory is not set")
		}
	}
	if strings.Contains(expanded, "%") {
		var err error
		expanded, err = expandPercentTokens(expanded, env, target)
		if err != nil {
			return "", err
		}
	}
	expanded = strings.TrimSpace(expanded)
	if expanded == "" {
		return "", fmt.Errorf("invalid %s %q: expanded path is empty", kind, rawPath)
	}
	if hasASCIIControlChar(expanded) {
		return "", fmt.Errorf("invalid %s %q: expanded value contains ASCII control character", kind, rawPath)
	}
	return normalizeExpandedAgentSocketPath(expanded, env), nil
}

func normalizeExpandedAgentSocketPath(path string, env Environment) string {
	if strings.HasPrefix(path, `\\.\pipe\`) || strings.HasPrefix(path, `//./pipe/`) {
		return path
	}
	path = resolveKeyPath(path, env.ResolveKeyPath)
	if strings.HasPrefix(path, `\\.\pipe\`) || strings.HasPrefix(path, `//./pipe/`) {
		return path
	}
	return filepath.Clean(filepath.FromSlash(path))
}

// AuthMethod 定义获取 SSH 认证方法的接口
type AuthMethod interface {
	GetMethod() (ssh.AuthMethod, error)
}

var _ AuthMethod = (*PasswordAuth)(nil)

// PasswordAuth 实现密码认证
type PasswordAuth struct {
	Password string
}

func (p *PasswordAuth) GetMethod() (ssh.AuthMethod, error) {
	return ssh.Password(p.Password), nil
}

var _ AuthMethod = (*KeyAuth)(nil)

// KeyAuth 实现私钥认证
type KeyAuth struct {
	Path       string
	Passphrase string
}

func (k *KeyAuth) GetMethod() (ssh.AuthMethod, error) {
	keyData, err := os.ReadFile(k.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", k.Path, err)
	}
	var signer ssh.Signer
	if k.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(k.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyData)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return ssh.PublicKeys(signer), nil
}

var _ ssh.Signer = (*lazySigner)(nil)

// autoSecretProvider 统一管理 auto 认证中的机密解析与交互降级
type autoSecretProvider struct {
	lifecycleCtx       context.Context
	nodeID             string
	user               string
	host               string
	port               int
	versionToken       string
	resolver           SecretResolver
	prompter           SecretPrompter
	handshakeTimeout   time.Duration
	interactionTimeout time.Duration
	failClosed         func(error)
	recoveryPrompter   SecretPrompter

	mu          sync.RWMutex
	terminalErr error
}

func (p *autoSecretProvider) markTerminalError(err error) {
	p.mu.Lock()
	if p.terminalErr == nil {
		p.terminalErr = err
	}
	p.mu.Unlock()

	if p.failClosed != nil {
		p.failClosed(err)
	}
}

func (p *autoSecretProvider) terminalError() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.terminalErr
}

func (p *autoSecretProvider) resolveOrPrompt(req SecretRequest) (string, error) {
	return p.resolveOrPromptAttempt(req, false)
}

func (p *autoSecretProvider) resolveOrPromptAttempt(req SecretRequest, retry bool) (string, error) {
	p.mu.RLock()
	if p.terminalErr != nil {
		termErr := p.terminalErr
		p.mu.RUnlock()
		return "", termErr
	}
	p.mu.RUnlock()

	req.NodeID = p.nodeID
	req.User = p.user
	req.Host = p.host
	req.Port = p.port
	req.VersionToken = p.versionToken

	// 1. 若注入了 resolver，优先使用 resolver 解析
	if p.resolver != nil && !retry {
		timeout := p.handshakeTimeout
		if timeout <= 0 {
			timeout = defaultSSHHandshakeTimeout
		}
		baseCtx := p.lifecycleCtx
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		resCtx, cancel := context.WithTimeout(baseCtx, timeout)
		defer cancel()

		secret, err := p.resolver.ResolveSecret(resCtx, req)
		if len(secret) > 0 {
			defer zeroBytes(secret)
		}
		if err == nil && len(secret) > 0 {
			return string(secret), nil
		}
		if err != nil && !errors.Is(err, ErrInteractionRequired) && !reportCredentialFailure(baseCtx, p.recoveryPrompter, "read", err) {
			// 严格传播后端故障！标记整个认证流程终止并触发 FailClosed，禁止任何后续认证方法和交互！
			p.markTerminalError(err)
			return "", fmt.Errorf("resolve secret failed: %w", err)
		}
	}

	p.mu.RLock()
	if p.terminalErr != nil {
		termErr := p.terminalErr
		p.mu.RUnlock()
		return "", termErr
	}
	p.mu.RUnlock()

	// 2. resolver 明确缺失（ErrInteractionRequired 或 nil resolver）时，按规则降级到交互 prompter
	if p.prompter == nil {
		return "", ErrInteractionRequired
	}
	timeout := p.interactionTimeout
	if timeout <= 0 {
		timeout = DefaultInteractionTimeout
	}
	baseCtx := p.lifecycleCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	promptCtx, cancel := context.WithTimeout(baseCtx, timeout)
	defer cancel()

	val, err := p.prompter.PromptSecret(promptCtx, req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			p.markTerminalError(err)
		}
		return "", fmt.Errorf("prompt secret failed: %w", err)
	}
	return val, nil
}

type lazySigner struct {
	pubKey             ssh.PublicKey
	keyPath            string
	keyData            []byte
	secProvider        *autoSecretProvider
	prompter           SecretPrompter
	passphraseCallback func(string, string)
	decryptedSigner    ssh.Signer
	logger             logger.DebugLogger
	mu                 sync.RWMutex
}

func (s *lazySigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *lazySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	signer, err := s.getDecryptedSigner()
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand, data)
}

func (s *lazySigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	signer, err := s.getDecryptedSigner()
	if err != nil {
		return nil, err
	}
	if algoSigner, ok := signer.(ssh.AlgorithmSigner); ok {
		return algoSigner.SignWithAlgorithm(rand, data, algorithm)
	}
	return signer.Sign(rand, data)
}

func (s *lazySigner) getDecryptedSigner() (ssh.Signer, error) {
	s.mu.RLock()
	if s.decryptedSigner != nil {
		signer := s.decryptedSigner
		s.mu.RUnlock()
		return signer, nil
	}
	s.mu.RUnlock()

	provider := s.secProvider
	if provider == nil {
		provider = &autoSecretProvider{prompter: s.prompter}
	}
	decSigner, passphrase, err := provider.decryptPrivateKey(s.keyData, s.keyPath)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.decryptedSigner != nil {
		return s.decryptedSigner, nil
	}
	s.decryptedSigner = decSigner

	// 成功输入密码短语解密后，自动保存公钥到对应文件
	if err := savePublicKey(s.keyPath, decSigner.PublicKey()); err != nil {
		l := s.logger
		if l == nil {
			l = logger.NopLogger
		}
		l.Debugf("save public key for %q failed: %v", s.keyPath, err)
	}

	if s.passphraseCallback != nil {
		s.passphraseCallback(s.keyPath, passphrase)
	}
	return decSigner, nil
}

// savePublicKey 自动将公钥以 authorized_keys 格式保存到对应的 .pub 文件中
func savePublicKey(keyPath string, pubKey ssh.PublicKey) error {
	pubKeyPath := keyPath + ".pub"
	if _, err := os.Stat(pubKeyPath); err == nil {
		// 如果公钥文件已经存在，不需要重复保存
		return nil
	}
	pubBytes := ssh.MarshalAuthorizedKey(pubKey)
	if err := os.WriteFile(pubKeyPath, pubBytes, 0644); err != nil {
		return fmt.Errorf("write public key %q failed: %w", pubKeyPath, err)
	}
	return nil
}

// parseOpenSSHPublicKeyFromEncryptedPrivate 从 OpenSSH 格式的加密私钥中直接提取明文存储的公钥数据
func parseOpenSSHPublicKeyFromEncryptedPrivate(keyData []byte) (ssh.PublicKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return nil, fmt.Errorf("not an openssh private key")
	}

	data := block.Bytes
	const magic = "openssh-key-v1\x00"
	if len(data) < len(magic) || string(data[:len(magic)]) != magic {
		return nil, fmt.Errorf("invalid magic header")
	}
	data = data[len(magic):]

	readString := func() ([]byte, bool) {
		if len(data) < 4 {
			return nil, false
		}
		length := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		data = data[4:]
		if uint32(len(data)) < length {
			return nil, false
		}
		res := data[:length]
		data = data[length:]
		return res, true
	}

	// Read ciphername
	if _, ok := readString(); !ok {
		return nil, fmt.Errorf("failed to read ciphername")
	}
	// Read kdfname
	if _, ok := readString(); !ok {
		return nil, fmt.Errorf("failed to read kdfname")
	}
	// Read kdfopts
	if _, ok := readString(); !ok {
		return nil, fmt.Errorf("failed to read kdfopts")
	}

	// Read num keys (uint32)
	if len(data) < 4 {
		return nil, fmt.Errorf("failed to read num keys")
	}
	numKeys := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	data = data[4:]
	if numKeys < 1 {
		return nil, fmt.Errorf("no keys found")
	}

	// Read first public key
	pubKeyData, ok := readString()
	if !ok {
		return nil, fmt.Errorf("failed to read public key data")
	}

	return ssh.ParsePublicKey(pubKeyData)
}

type certAuthCandidateMethod struct {
	certPath string
	method   ssh.AuthMethod
}

// resolveKeySigners resolves a single private key path into any paired user-certificate
// publickey methods plus its plain publickey fallback method, sharing a single lazySigner
// across both so passphrase decryption happens at most once and only when challenged.
func resolveKeySigners(
	keyPath string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	secProvider *autoSecretProvider,
	passphraseCallback func(string, string),
	l logger.DebugLogger,
) ([]certAuthCandidateMethod, ssh.AuthMethod, error) {
	if l == nil {
		l = logger.NopLogger
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read key data failed: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err == nil {
		certMethods := buildKeyCertCandidateMethods(keyPath, signer.PublicKey(), signer, explicitCerts, hasExplicitCerts, l)
		return certMethods, ssh.PublicKeys(signer), nil
	}

	// 私钥解析失败，可能是因为被密码保护了，也可能格式损坏。
	// 优先尝试免密读取 .pub，或直接从 OpenSSH 私钥中提取明文公钥，以保持 lazy 解密。
	if pubKey := extractUnencryptedPublicKey(keyPath, keyData, hasExplicitCerts, l); pubKey != nil {
		lazy := &lazySigner{
			pubKey:             pubKey,
			keyPath:            keyPath,
			keyData:            keyData,
			secProvider:        secProvider,
			passphraseCallback: passphraseCallback,
			logger:             l,
		}
		certMethods := buildKeyCertCandidateMethods(keyPath, pubKey, lazy, explicitCerts, hasExplicitCerts, l)
		return certMethods, ssh.PublicKeys(lazy), nil
	}

	// 传统 PEM 等格式无法在解密前取得公钥。仍然把解密动作留在 PublicKeysCallback 中，
	// 这样只有轮到这个 candidate 时才会请求 passphrase。
	if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); ok {
		keyDataCopy := keyData
		keyPathCopy := keyPath
		return nil, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			resolvedSigner, passphrase, parseErr := secProvider.decryptPrivateKey(keyDataCopy, keyPathCopy)
			if parseErr != nil {
				return nil, parseErr
			}
			if saveErr := savePublicKey(keyPathCopy, resolvedSigner.PublicKey()); saveErr != nil {
				l.Debugf("save public key for %q failed: %v", keyPathCopy, saveErr)
			}
			if passphraseCallback != nil {
				passphraseCallback(keyPathCopy, passphrase)
			}
			return []ssh.Signer{resolvedSigner}, nil
		}), nil
	}

	return nil, nil, err
}

func buildKeyCertCandidateMethods(
	keyPath string,
	pubKey ssh.PublicKey,
	signer ssh.Signer,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	l logger.DebugLogger,
) []certAuthCandidateMethod {
	matched := matchCertsForKey(keyPath, pubKey, explicitCerts, hasExplicitCerts, l)
	var certMethods []certAuthCandidateMethod
	for _, mc := range matched {
		cs, csErr := newWrappedCertSigner(mc.cert, signer)
		if csErr != nil {
			l.Debugf("Skipping SSH certificate %q for key %q: %v", mc.path, keyPath, csErr)
			continue
		}
		certMethods = append(certMethods, certAuthCandidateMethod{
			certPath: mc.path,
			method:   ssh.PublicKeys(cs),
		})
	}
	return certMethods
}

func extractUnencryptedPublicKey(
	keyPath string,
	keyData []byte,
	hasExplicitCerts bool,
	l logger.DebugLogger,
) ssh.PublicKey {
	pubKeyPath := keyPath + ".pub"
	if pubKeyData, readErr := os.ReadFile(pubKeyPath); readErr == nil {
		pubKey, _, _, _, parseErr := ssh.ParseAuthorizedKey(pubKeyData)
		if parseErr != nil {
			l.Debugf("Failed to parse public key: %s, error: %v", pubKeyPath, parseErr)
		} else if cert, ok := pubKey.(*ssh.Certificate); ok && cert.Key != nil {
			return cert.Key
		} else if pubKey != nil {
			return pubKey
		}
	} else if extractedPubKey, extractErr := parseOpenSSHPublicKeyFromEncryptedPrivate(keyData); extractErr == nil {
		l.Debugf("Extracted public key from OpenSSH private key without passphrase: %s", keyPath)
		if saveErr := savePublicKey(keyPath, extractedPubKey); saveErr != nil {
			l.Debugf("save extracted public key for %q failed: %v", keyPath, saveErr)
		}
		return extractedPubKey
	} else {
		l.Debugf("Failed to extract public key from OpenSSH key: %s, error: %v", keyPath, extractErr)
	}
	if !hasExplicitCerts {
		if sidecar, ok := parseUserCertFile(keyPath+"-cert.pub", true, l); ok {
			return sidecar.cert.Key
		}
	}
	return nil
}

// resolveKeyAuthMethod 将单个私钥路径解析为一个独立的 publickey 认证候选。
// 对能够免密获得公钥的加密私钥继续使用 lazySigner，仅在服务器接受公钥后才请求 passphrase。
func resolveKeyAuthMethod(keyPath string, secProvider *autoSecretProvider, passphraseCallback func(string, string), l logger.DebugLogger) (ssh.AuthMethod, error) {
	_, plainMethod, err := resolveKeySigners(keyPath, nil, true, secProvider, passphraseCallback, l)
	return plainMethod, err
}

// AutoAuthOptions 封装 auto 认证的完整上下文选项。
type AutoAuthOptions struct {
	AgentSocket               string
	DialAgent                 func(ctx context.Context, socket string) (net.Conn, error)
	DefaultKeyPaths           []string
	ResolveKeyPath            func(string) string
	Environment               Environment
	Target                    TargetContext
	LifecycleCtx              context.Context
	NodeID                    string
	User                      string
	Host                      string
	Port                      int
	VersionToken              string
	Resolver                  SecretResolver
	Prompter                  SecretPrompter
	HandshakeTimeout          time.Duration
	InteractionTimeout        time.Duration
	FailClosed                func(error)
	RecoveryPrompter          SecretPrompter
	KeyPath                   string
	KeyPaths                  []string
	FirstCertMethods          []ssh.AuthMethod
	PasswordCallback          func(string)
	PassphraseCallback        func(keyPath, passphrase string)
	CandidateRejectedCallback func(protocol string)
	SSHOptions                *Options
	HostKeyChanged            *atomic.Bool
	Logger                    logger.DebugLogger
	Diagnostics               logger.DiagnosticObserver
}

const (
	autoAuthProtocolPublicKey           = "publickey"
	autoAuthProtocolPassword            = "password"
	autoAuthProtocolKeyboardInteractive = "keyboard-interactive"
)

type autoAuthCandidate struct {
	protocol   string
	label      string
	method     ssh.AuthMethod
	allow      func(*ssh.ClientAuthContext) bool
	onRejected func()
}

type autoAuthPlan struct {
	candidates   []autoAuthCandidate
	authCallback ssh.ClientAuthCallback
	cleanup      func()
}

func observeAuthNegotiation(observer logger.DiagnosticObserver, ctx *ssh.ClientAuthContext, seen *bool) {
	if *seen || ctx == nil || ctx.Metadata == nil || observer == nil {
		return
	}
	*seen = true
	event := authenticationDiagnostic(ctx)
	event.Kind, event.Methods = logger.Negotiated, nil
	event.ClientVersion, event.ServerVersion = string(ctx.Metadata.ClientVersion()), string(ctx.Metadata.ServerVersion())
	a := ctx.Algorithms
	event.KeyExchange, event.HostKey = a.KeyExchange, a.HostKey
	event.ReadCipher, event.WriteCipher = a.Read.Cipher, a.Write.Cipher
	event.ReadMAC, event.WriteMAC = a.Read.MAC, a.Write.MAC
	logger.EmitDiagnostic(observer, event)
}

func authenticationDiagnostic(ctx *ssh.ClientAuthContext) logger.Diagnostic {
	event := logger.Diagnostic{Kind: logger.AuthenticationMethods, Methods: append([]string(nil), ctx.AllowedMethods...)}
	if ctx.Metadata != nil {
		event.User = ctx.Metadata.User()
		if remote := ctx.Metadata.RemoteAddr(); remote != nil {
			event.Host = remote.String()
		}
	}
	return event
}

// newSequentialAuthCallback 按候选顺序驱动认证。
// ClientConfig.Auth 只会尝试同一 RFC 4252 method 的第一个实例，因此 auto 模式必须通过
// AuthCallback 显式推进多个 publickey candidate。
func newSequentialAuthCallback(candidates []autoAuthCandidate, secProvider *autoSecretProvider, l logger.DebugLogger, observers ...logger.DiagnosticObserver) ssh.ClientAuthCallback {
	return newSequentialAuthCallbackWithPolicy(candidates, authPolicy{
		pubkeyAllowed:   true,
		passwordAllowed: true,
		kbAllowed:       true,
	}, secProvider, l, observers...)
}

func newSequentialAuthCallbackWithPolicy(candidates []autoAuthCandidate, policy authPolicy, secProvider *autoSecretProvider, l logger.DebugLogger, observers ...logger.DiagnosticObserver) ssh.ClientAuthCallback {
	if l == nil {
		l = logger.NopLogger
	}

	next := 0
	lastStage := 0
	selected := false
	negotiated := false
	var blockedErr error
	var activeCandidate *autoAuthCandidate
	return func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
		var observer logger.DiagnosticObserver
		if len(observers) > 0 {
			observer = observers[0]
		}
		event := logger.Diagnostic{Kind: logger.AuthenticationMethods}
		if observer != nil {
			observeAuthNegotiation(observer, ctx, &negotiated)
			event = authenticationDiagnostic(ctx)
		}
		logger.EmitDiagnostic(observer, event)
		if secProvider != nil {
			if err := secProvider.terminalError(); err != nil {
				return nil, err
			}
		}

		stage := len(ctx.PartialSuccessMethods)
		if stage > lastStage {
			lastStage = stage
			next = 0
			selected = false
			blockedErr = nil
			activeCandidate = nil
		} else if activeCandidate != nil {
			if activeCandidate.onRejected != nil {
				activeCandidate.onRejected()
			}
			activeCandidate = nil
		}

		for next < len(candidates) {
			candidate := candidates[next]
			next++

			if !slices.Contains(ctx.AllowedMethods, candidate.protocol) || (candidate.allow != nil && !candidate.allow(ctx)) {
				l.Debugf("Skipping SSH auth candidate %q: server allows %v", candidate.label, ctx.AllowedMethods)
				continue
			}
			if err := policy.checkProtocolRuntime(candidate.protocol); err != nil {
				l.Debugf("Skipping SSH auth candidate %q due to runtime policy: %v", candidate.label, err)
				if blockedErr == nil {
					blockedErr = err
				}
				continue
			}

			l.Debugf("Trying SSH auth candidate: %s", candidate.label)
			selected = true
			activeCandidate = &candidate
			event.Kind, event.Method, event.Methods = logger.AuthenticationAttempt, candidate.protocol, nil
			logger.EmitDiagnostic(observer, event)
			return candidate.method, nil
		}

		if !selected {
			if blockedErr != nil {
				return nil, blockedErr
			}
			return nil, fmt.Errorf("server permits SSH authentication methods %v, but no matching local key, agent, password or keyboard-interactive method is available", ctx.AllowedMethods)
		}
		return nil, nil
	}
}

// buildAutoAuthPlan 构建 auto 认证计划。候选优先级为：
// 显式 -i 私钥 -> SSH agent -> 默认私钥 -> password。
func buildAutoAuthPlan(ctx context.Context, opts AutoAuthOptions, first ...ssh.AuthMethod) autoAuthPlan {
	l := opts.Logger
	if l == nil {
		l = logger.NopLogger
	}
	prompter := opts.Prompter
	if prompter == nil {
		prompter = rejectInteraction{}
	}
	lifecycleCtx := opts.LifecycleCtx
	if lifecycleCtx == nil {
		lifecycleCtx = ctx
	}

	secProvider := &autoSecretProvider{
		lifecycleCtx:       lifecycleCtx,
		nodeID:             opts.NodeID,
		user:               opts.User,
		host:               opts.Host,
		port:               opts.Port,
		versionToken:       opts.VersionToken,
		resolver:           opts.Resolver,
		prompter:           prompter,
		handshakeTimeout:   opts.HandshakeTimeout,
		interactionTimeout: opts.InteractionTimeout,
		failClosed:         opts.FailClosed,
		recoveryPrompter:   opts.RecoveryPrompter,
	}

	rejectPublicKey := func() {
		if opts.CandidateRejectedCallback != nil {
			opts.CandidateRejectedCallback(autoAuthProtocolPublicKey)
		}
	}

	policy := newAuthPolicy(opts.SSHOptions, opts.HostKeyChanged)

	var pubkeyCandidates []autoAuthCandidate
	var cleanup func()
	if policy.pubkeyAllowed {
		pubkeyCandidates, cleanup = buildAutoPubkeyCandidates(ctx, opts, first, secProvider, rejectPublicKey, policy.identitiesOnly, l)
	}

	var passwordCandidates []autoAuthCandidate
	if policy.passwordAllowed {
		passwordCandidates = buildAutoPasswordCandidates(opts, secProvider)
	}

	var kbCandidates []autoAuthCandidate
	if policy.kbAllowed {
		kbMethod := buildKeyboardInteractiveAuthMethod(secProvider)
		kbCandidates = append(kbCandidates, autoAuthCandidate{
			protocol: autoAuthProtocolKeyboardInteractive,
			label:    "keyboard-interactive",
			method:   kbMethod,
		})
	}

	candidates := orderAutoAuthCandidates(policy.preferred, pubkeyCandidates, passwordCandidates, kbCandidates)

	return autoAuthPlan{
		candidates:   candidates,
		authCallback: newSequentialAuthCallbackWithPolicy(candidates, policy, secProvider, l, opts.Diagnostics),
		cleanup:      cleanup,
	}
}

func expandIdentityKeyPath(rawPath string, env Environment, target TargetContext, resolve func(string) string) (string, error) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" || strings.EqualFold(trimmed, "none") {
		return "", nil
	}
	path := trimmed
	if strings.Contains(path, "${") {
		var err error
		path, err = expandEnvironmentVariables(path, env)
		if err != nil {
			return "", err
		}
	}
	if strings.HasPrefix(path, "~") {
		if env.HomeDir != "" {
			var err error
			path, err = expandTilde(path, env.HomeDir)
			if err != nil {
				return "", err
			}
		} else if resolve != nil {
			path = resolve(path)
		} else {
			return "", errors.New("cannot expand '~': home directory is not set")
		}
	}
	if strings.Contains(path, "%") {
		var err error
		path, err = expandPercentTokens(path, env, target)
		if err != nil {
			return "", err
		}
	}
	path = resolveKeyPath(path, resolve)
	if path == "" || strings.EqualFold(path, "none") {
		return "", nil
	}
	return filepath.Clean(filepath.FromSlash(path)), nil
}

func collectExplicitKeyCandidates(
	keyPaths []string,
	keyPath string,
	sshOpts *Options,
	env Environment,
	target TargetContext,
	resolve func(string) string,
	l logger.DebugLogger,
) ([]string, bool) {
	if l == nil {
		l = logger.NopLogger
	}
	var rawEntries []string
	rawEntries = append(rawEntries, keyPaths...)
	if strings.TrimSpace(keyPath) != "" {
		rawEntries = append(rawEntries, keyPath)
	}
	rawEntries = append(rawEntries, sshOpts.IdentityFiles()...)

	var paths []string
	seen := make(map[string]struct{}, len(rawEntries))
	hasExplicit := false
	for _, raw := range rawEntries {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		hasExplicit = true
		if strings.EqualFold(trimmed, "none") {
			continue
		}
		expanded, err := expandIdentityKeyPath(trimmed, env, target, resolve)
		if err != nil {
			l.Debugf("Failed to expand identity key path %q: %v", raw, err)
			continue
		}
		if expanded == "" {
			continue
		}
		if _, exists := seen[expanded]; exists {
			continue
		}
		seen[expanded] = struct{}{}
		paths = append(paths, expanded)
	}
	return paths, hasExplicit
}

func extractIdentityPublicKey(keyPath string) ssh.PublicKey {
	if keyPath == "" {
		return nil
	}
	if keyData, err := os.ReadFile(keyPath); err == nil {
		if signer, parseErr := ssh.ParsePrivateKey(keyData); parseErr == nil {
			return signer.PublicKey()
		}
		if pub, _, _, _, parseErr := ssh.ParseAuthorizedKey(keyData); parseErr == nil {
			if cert, ok := pub.(*ssh.Certificate); ok && cert.Key != nil {
				return cert.Key
			}
			return pub
		}
		if pub, parseErr := parseOpenSSHPublicKeyFromEncryptedPrivate(keyData); parseErr == nil {
			return pub
		}
	}
	if pubData, err := os.ReadFile(keyPath + ".pub"); err == nil {
		if pub, _, _, _, parseErr := ssh.ParseAuthorizedKey(pubData); parseErr == nil {
			if cert, ok := pub.(*ssh.Certificate); ok && cert.Key != nil {
				return cert.Key
			}
			return pub
		}
	}
	return nil
}

func effectiveAuthTargetContext(opts AutoAuthOptions) TargetContext {
	target := opts.Target
	if target.Host == "" {
		target.Host = opts.Host
	}
	if target.Port <= 0 {
		target.Port = opts.Port
	}
	if target.User == "" {
		target.User = opts.User
	}
	if target.OriginalHost == "" {
		target.OriginalHost = opts.NodeID
	}
	return target
}

func effectiveAutoAuthAgentSocket(opts AutoAuthOptions, target TargetContext, l logger.DebugLogger) (string, bool) {
	env := opts.Environment
	if env.AgentSocket == "" && opts.AgentSocket != "" {
		env.AgentSocket = opts.AgentSocket
	}
	spec := opts.SSHOptions.IdentityAgent()
	sock, disabled, err := ResolveIdentityAgent(spec, env, target)
	if err != nil {
		l.Debugf("Failed to resolve IdentityAgent %q: %v", spec, err)
		return "", true
	}
	if disabled {
		return "", true
	}
	return sock, false
}

func dialAgentSignersByPubKey(
	ctx context.Context,
	dialFn func(context.Context, string) (net.Conn, error),
	socket string,
	l logger.DebugLogger,
) (map[string]ssh.Signer, func()) {
	if socket == "" {
		return nil, nil
	}
	conn, err := dialAgentConn(ctx, dialFn, socket)
	if err != nil {
		l.Debugf("connect to ssh-agent failed: %v", err)
		return nil, nil
	}
	cleanup := func() { debugCloseResource(l, conn, "ssh agent connection") }
	signers, signersErr := agent.NewClient(conn).Signers()
	if signersErr != nil {
		l.Debugf("list ssh-agent signers failed: %v", signersErr)
		return nil, cleanup
	}
	agentByPub := make(map[string]ssh.Signer, len(signers))
	for _, s := range signers {
		pubKeyBytes := string(s.PublicKey().Marshal())
		if _, exists := agentByPub[pubKeyBytes]; !exists {
			agentByPub[pubKeyBytes] = s
		}
	}
	return agentByPub, cleanup
}

func expandDefaultIdentityPaths(opts AutoAuthOptions, target TargetContext, l logger.DebugLogger) []string {
	var defaults []string
	for _, raw := range opts.DefaultKeyPaths {
		expanded, err := expandIdentityKeyPath(raw, opts.Environment, target, opts.ResolveKeyPath)
		if err != nil {
			l.Debugf("Failed to expand default key path %q: %v", raw, err)
			continue
		}
		if expanded != "" {
			defaults = append(defaults, expanded)
		}
	}
	return defaults
}

func appendExpandedKeyAndCertCandidates(
	certCandidates *[]autoAuthCandidate,
	plainCandidates *[]autoAuthCandidate,
	pairedCertPaths map[string]struct{},
	seenKeyPaths map[string]struct{},
	keyPath string,
	label string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	secProvider *autoSecretProvider,
	passphraseCallback func(string, string),
	rejectPublicKey func(),
	l logger.DebugLogger,
) {
	if keyPath == "" {
		return
	}
	if _, seen := seenKeyPaths[keyPath]; seen {
		return
	}
	seenKeyPaths[keyPath] = struct{}{}

	l.Debugf("Checking SSH key: %s", keyPath)
	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			l.Debugf("Key file does not exist: %s", keyPath)
		} else {
			l.Debugf("Failed to stat key: %s, error: %v", keyPath, err)
		}
		return
	}

	certMethods, plainMethod, err := resolveKeySigners(keyPath, explicitCerts, hasExplicitCerts, secProvider, passphraseCallback, l)
	if err != nil {
		l.Debugf("Failed to resolve key: %s, error: %v", keyPath, err)
		return
	}

	for _, cm := range certMethods {
		if pairedCertPaths != nil {
			pairedCertPaths[cm.certPath] = struct{}{}
		}
		*certCandidates = append(*certCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      label + " (cert): " + cm.certPath,
			method:     cm.method,
			onRejected: rejectPublicKey,
		})
	}
	*plainCandidates = append(*plainCandidates, autoAuthCandidate{
		protocol:   autoAuthProtocolPublicKey,
		label:      label + ": " + keyPath,
		method:     plainMethod,
		onRejected: rejectPublicKey,
	})
}

func buildAutoPubkeyCandidates(
	ctx context.Context,
	opts AutoAuthOptions,
	first []ssh.AuthMethod,
	secProvider *autoSecretProvider,
	rejectPublicKey func(),
	identitiesOnly bool,
	l logger.DebugLogger,
) ([]autoAuthCandidate, func()) {
	var certCandidates []autoAuthCandidate
	var plainCandidates []autoAuthCandidate
	var cleanup func()
	for _, method := range opts.FirstCertMethods {
		certCandidates = append(certCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      "explicit signer (cert)",
			method:     method,
			onRejected: rejectPublicKey,
		})
	}
	for _, method := range first {
		plainCandidates = append(plainCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      "explicit signer",
			method:     method,
			onRejected: rejectPublicKey,
		})
	}
	seenKeyPaths := make(map[string]struct{})
	pairedCertPaths := make(map[string]struct{})
	target := effectiveAuthTargetContext(opts)
	dialAgentFn := opts.DialAgent
	if dialAgentFn == nil {
		dialAgentFn = opts.Environment.DialAgent
	}

	explicitPaths, hasExplicit := collectExplicitKeyCandidates(
		opts.KeyPaths,
		opts.KeyPath,
		opts.SSHOptions,
		opts.Environment,
		target,
		opts.ResolveKeyPath,
		l,
	)
	explicitCerts, hasExplicitCerts := collectExplicitUserCerts(
		opts.SSHOptions,
		opts.Environment,
		target,
		opts.ResolveKeyPath,
		l,
	)
	agentSocket, agentDisabled := effectiveAutoAuthAgentSocket(opts, target, l)
	hasExplicitIdentity := len(first) > 0 || hasExplicit

	if identitiesOnly {
		return buildIdentitiesOnlyPubkeyCandidates(
			ctx,
			opts,
			target,
			dialAgentFn,
			agentSocket,
			agentDisabled,
			explicitPaths,
			explicitCerts,
			hasExplicitCerts,
			hasExplicitIdentity,
			certCandidates,
			plainCandidates,
			pairedCertPaths,
			seenKeyPaths,
			secProvider,
			rejectPublicKey,
			l,
		)
	}

	// 显式身份必须优先于任何自动发现来源。
	for _, keyPath := range explicitPaths {
		appendExpandedKeyAndCertCandidates(
			&certCandidates, &plainCandidates, pairedCertPaths, seenKeyPaths,
			keyPath, "explicit key", explicitCerts, hasExplicitCerts,
			secProvider, opts.PassphraseCallback, rejectPublicKey, l,
		)
	}

	if !agentDisabled && agentSocket != "" {
		conn, err := dialAgentConn(ctx, dialAgentFn, agentSocket)
		if err == nil {
			agentClient := agent.NewClient(conn)
			if len(explicitCerts) > 0 {
				if signers, signersErr := agentClient.Signers(); signersErr == nil {
					agentByPub := make(map[string]ssh.Signer, len(signers))
					for _, s := range signers {
						pubRaw := string(s.PublicKey().Marshal())
						if _, exists := agentByPub[pubRaw]; !exists {
							agentByPub[pubRaw] = s
						}
					}
					for _, ec := range explicitCerts {
						if _, already := pairedCertPaths[ec.path]; already {
							continue
						}
						if s, ok := agentByPub[ec.keyRaw]; ok {
							if cs, csErr := newWrappedCertSigner(ec.cert, s); csErr == nil {
								pairedCertPaths[ec.path] = struct{}{}
								certCandidates = append(certCandidates, autoAuthCandidate{
									protocol:   autoAuthProtocolPublicKey,
									label:      "ssh-agent (cert): " + ec.path,
									method:     ssh.PublicKeys(cs),
									onRejected: rejectPublicKey,
								})
							}
						}
					}
				}
			}
			plainCandidates = append(plainCandidates, autoAuthCandidate{
				protocol: autoAuthProtocolPublicKey,
				label:    "ssh-agent",
				method:   ssh.PublicKeysCallback(agentClient.Signers),
			})
			cleanup = func() { debugCloseResource(l, conn, "ssh agent connection") }
		} else {
			l.Debugf("connect to ssh-agent failed: %v", err)
		}
	}

	for _, keyPath := range expandDefaultIdentityPaths(opts, target, l) {
		appendExpandedKeyAndCertCandidates(
			&certCandidates, &plainCandidates, pairedCertPaths, seenKeyPaths,
			keyPath, "default key", explicitCerts, hasExplicitCerts,
			secProvider, opts.PassphraseCallback, rejectPublicKey, l,
		)
	}
	return append(certCandidates, plainCandidates...), cleanup
}

func buildIdentitiesOnlyPubkeyCandidates(
	ctx context.Context,
	opts AutoAuthOptions,
	target TargetContext,
	dialAgentFn func(context.Context, string) (net.Conn, error),
	agentSocket string,
	agentDisabled bool,
	explicitPaths []string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	hasExplicitIdentity bool,
	certCandidates []autoAuthCandidate,
	plainCandidates []autoAuthCandidate,
	pairedCertPaths map[string]struct{},
	seenKeyPaths map[string]struct{},
	secProvider *autoSecretProvider,
	rejectPublicKey func(),
	l logger.DebugLogger,
) ([]autoAuthCandidate, func()) {
	candidatePaths := explicitPaths
	candidateLabel := "explicit key"
	if !hasExplicitIdentity {
		candidatePaths = expandDefaultIdentityPaths(opts, target, l)
		candidateLabel = "default key"
	}

	var agentByPub map[string]ssh.Signer
	var cleanup func()
	if !agentDisabled && agentSocket != "" && (len(candidatePaths) > 0 || len(explicitCerts) > 0) {
		agentByPub, cleanup = dialAgentSignersByPubKey(ctx, dialAgentFn, agentSocket, l)
	}

	for _, keyPath := range candidatePaths {
		if pub := extractIdentityPublicKey(keyPath); len(agentByPub) > 0 && pub != nil {
			if signer, ok := agentByPub[string(pub.Marshal())]; ok {
				if _, seen := seenKeyPaths[keyPath]; !seen {
					seenKeyPaths[keyPath] = struct{}{}
					matched := matchCertsForKey(keyPath, pub, explicitCerts, hasExplicitCerts, l)
					for _, mc := range matched {
						if cs, csErr := newWrappedCertSigner(mc.cert, signer); csErr == nil {
							pairedCertPaths[mc.path] = struct{}{}
							certCandidates = append(certCandidates, autoAuthCandidate{
								protocol:   autoAuthProtocolPublicKey,
								label:      candidateLabel + " (ssh-agent cert): " + mc.path,
								method:     ssh.PublicKeys(cs),
								onRejected: rejectPublicKey,
							})
						}
					}
					plainCandidates = append(plainCandidates, autoAuthCandidate{
						protocol:   autoAuthProtocolPublicKey,
						label:      candidateLabel + " (ssh-agent): " + keyPath,
						method:     ssh.PublicKeys(signer),
						onRejected: rejectPublicKey,
					})
				}
				continue
			}
		}
		appendExpandedKeyAndCertCandidates(
			&certCandidates, &plainCandidates, pairedCertPaths, seenKeyPaths,
			keyPath, candidateLabel, explicitCerts, hasExplicitCerts,
			secProvider, opts.PassphraseCallback, rejectPublicKey, l,
		)
	}

	if len(agentByPub) > 0 && len(explicitCerts) > 0 {
		for _, ec := range explicitCerts {
			if _, already := pairedCertPaths[ec.path]; already {
				continue
			}
			if signer, ok := agentByPub[ec.keyRaw]; ok {
				if cs, csErr := newWrappedCertSigner(ec.cert, signer); csErr == nil {
					pairedCertPaths[ec.path] = struct{}{}
					certCandidates = append(certCandidates, autoAuthCandidate{
						protocol:   autoAuthProtocolPublicKey,
						label:      "ssh-agent (cert): " + ec.path,
						method:     ssh.PublicKeys(cs),
						onRejected: rejectPublicKey,
					})
				}
			}
		}
	}

	return append(certCandidates, plainCandidates...), cleanup
}

func buildAutoPasswordCandidates(opts AutoAuthOptions, secProvider *autoSecretProvider) []autoAuthCandidate {
	passwordAttempts := 0
	passwordMethod := ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		retry := passwordAttempts > 0 && opts.RecoveryPrompter != nil
		passwordAttempts++
		password, err := secProvider.resolveOrPromptAttempt(SecretRequest{
			Kind: SecretKindLoginPassword,
		}, retry)
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		if opts.PasswordCallback != nil {
			opts.PasswordCallback(password)
		}
		return password, nil
	}), 3)

	return []autoAuthCandidate{{
		protocol: autoAuthProtocolPassword,
		label:    "password",
		method:   passwordMethod,
		onRejected: func() {
			if opts.CandidateRejectedCallback != nil {
				opts.CandidateRejectedCallback(autoAuthProtocolPassword)
			}
		},
	}}
}

type authPolicy struct {
	pubkeyAllowed   bool
	passwordAllowed bool
	kbAllowed       bool
	identitiesOnly  bool
	preferred       []string
	hostKeyChanged  *atomic.Bool
}

func newAuthPolicy(sshOpts *Options, hostKeyChanged *atomic.Bool) authPolicy {
	pubkeyAllowed, passwordAllowed, kbAllowed, identitiesOnly, preferred := resolveAutoAuthPolicy(sshOpts)
	return authPolicy{
		pubkeyAllowed:   pubkeyAllowed,
		passwordAllowed: passwordAllowed,
		kbAllowed:       kbAllowed,
		identitiesOnly:  identitiesOnly,
		preferred:       preferred,
		hostKeyChanged:  hostKeyChanged,
	}
}

func (p authPolicy) checkProtocolRuntime(protocol string) error {
	switch protocol {
	case autoAuthProtocolPassword, autoAuthProtocolKeyboardInteractive:
		if p.hostKeyChanged != nil && p.hostKeyChanged.Load() {
			return fmt.Errorf("%w: %s authentication disabled because remote host key has changed", ErrHostKeyMismatch, protocol)
		}
	}
	return nil
}

func resolveAutoAuthPolicy(sshOpts *Options) (pubkeyAllowed, passwordAllowed, kbAllowed, identitiesOnly bool, preferred []string) {
	pubkeyAllowed = true
	passwordAllowed = true
	kbAllowed = true
	if sshOpts == nil {
		return
	}
	if v, ok := sshOpts.PubkeyAuthentication(); ok {
		pubkeyAllowed = v
	}
	if v, ok := sshOpts.PasswordAuthentication(); ok {
		passwordAllowed = v
	}
	if v, ok := sshOpts.KbdInteractiveAuthentication(); ok {
		kbAllowed = v
	}
	identitiesOnly = sshOpts.IdentitiesOnly()
	preferred = sshOpts.PreferredAuthentications()
	if len(preferred) > 0 {
		if !slices.Contains(preferred, autoAuthProtocolPublicKey) {
			pubkeyAllowed = false
		}
		if !slices.Contains(preferred, autoAuthProtocolPassword) {
			passwordAllowed = false
		}
		if !slices.Contains(preferred, autoAuthProtocolKeyboardInteractive) {
			kbAllowed = false
		}
	}
	return
}

func orderAutoAuthCandidates(preferred []string, pubkey, password, kb []autoAuthCandidate) []autoAuthCandidate {
	if len(preferred) == 0 {
		var all []autoAuthCandidate
		all = append(all, pubkey...)
		all = append(all, password...)
		all = append(all, kb...)
		return all
	}
	var ordered []autoAuthCandidate
	for _, proto := range preferred {
		switch proto {
		case autoAuthProtocolPublicKey:
			ordered = append(ordered, pubkey...)
		case autoAuthProtocolPassword:
			ordered = append(ordered, password...)
		case autoAuthProtocolKeyboardInteractive:
			ordered = append(ordered, kb...)
		}
	}
	return ordered
}

func (p *autoSecretProvider) decryptPrivateKey(data []byte, path string) (ssh.Signer, string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		passphrase, err := p.resolveOrPromptAttempt(SecretRequest{Kind: SecretKindPrivateKeyPassphrase, KeyPath: path}, attempt > 0)
		if err != nil {
			return nil, "", fmt.Errorf("read private key passphrase: %w", err)
		}
		material := []byte(passphrase)
		signer, err := ssh.ParsePrivateKeyWithPassphrase(data, material)
		zeroBytes(material)
		if err == nil {
			return signer, passphrase, nil
		}
		if p.recoveryPrompter == nil || !errors.Is(err, x509.IncorrectPasswordError) || attempt == 2 {
			return nil, "", fmt.Errorf("decrypt private key: %w", err)
		}
	}
	return nil, "", ErrInteractionRequired
}
