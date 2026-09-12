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
	"slices"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const sshAgentDialTimeout = 5 * time.Second

func dialSSHAgent(ctx context.Context, socket string) (net.Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ssh-agent dial context is nil")
	}
	dialer := net.Dialer{Timeout: sshAgentDialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("dial ssh-agent socket %q failed: %w", socket, err)
	}
	return conn, nil
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

// resolveKeyAuthMethod 将单个私钥路径解析为一个独立的 publickey 认证候选。
// 对能够免密获得公钥的加密私钥继续使用 lazySigner，仅在服务器接受公钥后才请求 passphrase。
func resolveKeyAuthMethod(keyPath string, secProvider *autoSecretProvider, passphraseCallback func(string, string), l logger.DebugLogger) (ssh.AuthMethod, error) {
	if l == nil {
		l = logger.NopLogger
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key data failed: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err == nil {
		return ssh.PublicKeys(signer), nil
	}

	// 私钥解析失败，可能是因为被密码保护了，也可能格式损坏。
	// 优先尝试免密读取 .pub，或直接从 OpenSSH 私钥中提取明文公钥，以保持 lazy 解密。
	var pubKey ssh.PublicKey
	pubKeyPath := keyPath + ".pub"
	if pubKeyData, readErr := os.ReadFile(pubKeyPath); readErr == nil {
		var parseErr error
		pubKey, _, _, _, parseErr = ssh.ParseAuthorizedKey(pubKeyData)
		if parseErr != nil {
			l.Debugf("Failed to parse public key: %s, error: %v", pubKeyPath, parseErr)
			pubKey = nil
		}
	} else {
		if extractedPubKey, extractErr := parseOpenSSHPublicKeyFromEncryptedPrivate(keyData); extractErr == nil {
			pubKey = extractedPubKey
			l.Debugf("Extracted public key from OpenSSH private key without passphrase: %s", keyPath)
			if saveErr := savePublicKey(keyPath, pubKey); saveErr != nil {
				l.Debugf("save extracted public key for %q failed: %v", keyPath, saveErr)
			}
		} else {
			l.Debugf("Failed to extract public key from OpenSSH key: %s, error: %v", keyPath, extractErr)
		}
	}

	if pubKey != nil {
		lazy := &lazySigner{
			pubKey:             pubKey,
			keyPath:            keyPath,
			keyData:            keyData,
			secProvider:        secProvider,
			passphraseCallback: passphraseCallback,
			logger:             l,
		}
		return ssh.PublicKeys(lazy), nil
	}

	// 传统 PEM 等格式无法在解密前取得公钥。仍然把解密动作留在 PublicKeysCallback 中，
	// 这样只有轮到这个 candidate 时才会请求 passphrase。
	if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); ok {
		keyDataCopy := keyData
		keyPathCopy := keyPath
		return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
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

	return nil, err
}

// AutoAuthOptions 封装 auto 认证的完整上下文选项。
type AutoAuthOptions struct {
	LifecycleCtx       context.Context
	NodeID             string
	User               string
	Host               string
	Port               int
	VersionToken       string
	Resolver           SecretResolver
	Prompter           SecretPrompter
	HandshakeTimeout   time.Duration
	InteractionTimeout time.Duration
	FailClosed         func(error)
	RecoveryPrompter   SecretPrompter
	KeyPath            string
	PasswordCallback   func(string)
	PassphraseCallback func(keyPath, passphrase string)
	Logger             logger.DebugLogger
}

const (
	autoAuthProtocolPublicKey = "publickey"
	autoAuthProtocolPassword  = "password"
)

type autoAuthCandidate struct {
	protocol string
	label    string
	method   ssh.AuthMethod
}

type autoAuthPlan struct {
	candidates   []autoAuthCandidate
	authCallback ssh.ClientAuthCallback
	cleanup      func()
}

// newSequentialAuthCallback 按候选顺序驱动认证。
// ClientConfig.Auth 只会尝试同一 RFC 4252 method 的第一个实例，因此 auto 模式必须通过
// AuthCallback 显式推进多个 publickey candidate。
func newSequentialAuthCallback(candidates []autoAuthCandidate, secProvider *autoSecretProvider, l logger.DebugLogger) ssh.ClientAuthCallback {
	if l == nil {
		l = logger.NopLogger
	}

	next := 0
	selected := false
	return func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
		if secProvider != nil {
			if err := secProvider.terminalError(); err != nil {
				return nil, err
			}
		}

		for next < len(candidates) {
			candidate := candidates[next]
			next++

			if !slices.Contains(ctx.AllowedMethods, candidate.protocol) {
				l.Debugf("Skipping SSH auth candidate %q: server allows %v", candidate.label, ctx.AllowedMethods)
				continue
			}

			l.Debugf("Trying SSH auth candidate: %s", candidate.label)
			selected = true
			return candidate.method, nil
		}

		if !selected {
			return nil, fmt.Errorf("server permits SSH authentication methods %v, but no matching local key, agent or password method is available", ctx.AllowedMethods)
		}
		return nil, nil
	}
}

// buildAutoAuthPlan 构建 auto 认证计划。候选优先级为：
// 显式 -i 私钥 -> SSH agent -> 默认私钥 -> password。
func buildAutoAuthPlan(ctx context.Context, opts AutoAuthOptions) autoAuthPlan {
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

	var candidates []autoAuthCandidate
	var cleanup func()
	seenKeyPaths := make(map[string]struct{})

	addKey := func(path, label string) {
		keyPath := expandHomeDir(path)
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

		method, err := resolveKeyAuthMethod(keyPath, secProvider, opts.PassphraseCallback, l)
		if err != nil {
			l.Debugf("Failed to resolve key: %s, error: %v", keyPath, err)
			return
		}

		candidates = append(candidates, autoAuthCandidate{
			protocol: autoAuthProtocolPublicKey,
			label:    label + ": " + keyPath,
			method:   method,
		})
	}

	// 显式身份必须优先于任何自动发现来源。
	if opts.KeyPath != "" {
		addKey(opts.KeyPath, "explicit key")
	}

	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		conn, err := dialSSHAgent(ctx, socket)
		if err == nil {
			agentClient := agent.NewClient(conn)
			candidates = append(candidates, autoAuthCandidate{
				protocol: autoAuthProtocolPublicKey,
				label:    "ssh-agent",
				method:   ssh.PublicKeysCallback(agentClient.Signers),
			})
			cleanup = func() { debugCloseResource(l, conn, "ssh agent connection") }
		} else {
			l.Debugf("connect to ssh-agent failed: %v", err)
		}
	}

	for _, path := range []string{
		"~/.ssh/id_ed25519",
		"~/.ssh/id_ecdsa",
		"~/.ssh/id_rsa",
		"~/.ssh/id_dsa",
	} {
		addKey(path, "default key")
	}

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

	candidates = append(candidates, autoAuthCandidate{
		protocol: autoAuthProtocolPassword,
		label:    "password",
		method:   passwordMethod,
	})

	return autoAuthPlan{
		candidates:   candidates,
		authCallback: newSequentialAuthCallback(candidates, secProvider, l),
		cleanup:      cleanup,
	}
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
