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

// boundedAgentClient wraps an ssh-agent connection so every protocol operation
// (List, Signers, Sign, SignWithFlags) is bounded by opTimeout and immediately
// interrupted when either ctx or lifecycleCtx is canceled. Deadlines are armed
// before each RPC and cleared afterward so idle intervals (such as interactive
// host-key prompts) never expire a healthy agent connection prematurely.
type boundedAgentClient struct {
	mu           sync.Mutex
	conn         net.Conn
	raw          agent.ExtendedAgent
	ctx          context.Context
	lifecycleCtx context.Context
	opTimeout    time.Duration
	timedOut     atomic.Bool
	closeOnce    sync.Once
	closeErr     error
	stopCtx      func() bool
	stopLife     func() bool
}

func dialBoundedAgentClient(
	ctx context.Context,
	lifecycleCtx context.Context,
	dialFn func(context.Context, string) (net.Conn, error),
	socket string,
	timeout time.Duration,
	l logger.DebugLogger,
) (*boundedAgentClient, func(), error) {
	if l == nil {
		l = logger.NopLogger
	}
	if ctx == nil {
		return nil, nil, fmt.Errorf("ssh-agent dial context is nil")
	}
	if socket == "" {
		return nil, nil, ErrAgentNotAvailable
	}
	opTimeout := timeout
	if opTimeout <= 0 {
		opTimeout = defaultSSHHandshakeTimeout
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, opTimeout)
	var stopDialLife func() bool
	if lifecycleCtx != nil && lifecycleCtx != ctx {
		stopDialLife = context.AfterFunc(lifecycleCtx, dialCancel)
	}
	conn, err := dialAgentConn(dialCtx, dialFn, socket)
	if stopDialLife != nil {
		stopDialLife()
	}
	dialCancel()
	if err != nil {
		return nil, nil, err
	}

	b := &boundedAgentClient{
		conn:         conn,
		raw:          agent.NewClient(struct{ io.ReadWriter }{conn}),
		ctx:          ctx,
		lifecycleCtx: lifecycleCtx,
		opTimeout:    opTimeout,
	}
	b.stopCtx = context.AfterFunc(ctx, func() { _ = b.closeConn() })
	if lifecycleCtx != nil && lifecycleCtx != ctx {
		b.stopLife = context.AfterFunc(lifecycleCtx, func() { _ = b.closeConn() })
	}

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if b.stopCtx != nil {
				b.stopCtx()
			}
			if b.stopLife != nil {
				b.stopLife()
			}
			b.closeOnce.Do(func() {
				debugCloseResource(l, conn, "ssh agent connection")
			})
		})
	}
	return b, cleanup, nil
}

func (b *boundedAgentClient) closeConn() error {
	b.closeOnce.Do(func() {
		b.closeErr = b.conn.Close()
	})
	return b.closeErr
}

func (b *boundedAgentClient) contextErr() error {
	if b.ctx != nil {
		if err := context.Cause(b.ctx); err != nil {
			return err
		}
	}
	if b.lifecycleCtx != nil && b.lifecycleCtx != b.ctx {
		if err := context.Cause(b.lifecycleCtx); err != nil {
			return err
		}
	}
	return nil
}

func isAgentDeadlineError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "i/o timeout")
}

func runBoundedAgentOp[T any](b *boundedAgentClient, op string, fn func() (T, error)) (T, error) {
	var zero T
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.contextErr(); err != nil {
		return zero, err
	}
	deadline := time.Now().Add(b.opTimeout)
	if err := b.conn.SetDeadline(deadline); err != nil && !isIgnorableDeadlineError(err) {
		return zero, fmt.Errorf("set ssh-agent %s deadline: %w", op, err)
	}
	watchdog := time.AfterFunc(b.opTimeout, func() {
		b.timedOut.Store(true)
		_ = b.closeConn()
	})
	defer watchdog.Stop()
	res, err := fn()
	stopped := watchdog.Stop()
	if stopped && err == nil {
		if clearErr := b.conn.SetDeadline(time.Time{}); clearErr != nil && !isIgnorableDeadlineError(clearErr) {
			return zero, fmt.Errorf("clear ssh-agent %s deadline: %w", op, clearErr)
		}
		return res, nil
	}
	if ctxErr := b.contextErr(); ctxErr != nil {
		return zero, fmt.Errorf("ssh-agent %s canceled: %w", op, errors.Join(err, ctxErr))
	}
	if b.timedOut.Load() || !stopped || isAgentDeadlineError(err) {
		return zero, fmt.Errorf("ssh-agent %s timed out after %s: %w", op, b.opTimeout, errors.Join(err, context.DeadlineExceeded))
	}
	return zero, err
}

func (b *boundedAgentClient) List() ([]*agent.Key, error) {
	return runBoundedAgentOp(b, "list", b.raw.List)
}

func (b *boundedAgentClient) Signers() ([]ssh.Signer, error) {
	signers, err := runBoundedAgentOp(b, "signers", b.raw.Signers)
	if err != nil {
		return nil, err
	}
	wrapped := make([]ssh.Signer, 0, len(signers))
	for _, s := range signers {
		if s == nil {
			continue
		}
		wrapped = append(wrapped, wrapBoundedAgentSigner(b, s))
	}
	return wrapped, nil
}

type boundedAgentSigner struct {
	client *boundedAgentClient
	inner  ssh.Signer
	pub    ssh.PublicKey
}

var _ ssh.AlgorithmSigner = (*boundedAgentSigner)(nil)

type boundedMultiAlgoAgentSigner struct {
	boundedAgentSigner
	multi ssh.MultiAlgorithmSigner
}

var _ ssh.MultiAlgorithmSigner = (*boundedMultiAlgoAgentSigner)(nil)

func (s *boundedMultiAlgoAgentSigner) Algorithms() []string {
	return s.multi.Algorithms()
}

func wrapBoundedAgentSigner(b *boundedAgentClient, s ssh.Signer) ssh.Signer {
	base := boundedAgentSigner{
		client: b,
		inner:  s,
		pub:    s.PublicKey(),
	}
	if mas, ok := s.(ssh.MultiAlgorithmSigner); ok {
		return &boundedMultiAlgoAgentSigner{
			boundedAgentSigner: base,
			multi:              mas,
		}
	}
	return &base
}

func (s *boundedAgentSigner) PublicKey() ssh.PublicKey {
	return s.pub
}

func (s *boundedAgentSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return runBoundedAgentOp(s.client, "sign", func() (*ssh.Signature, error) {
		return s.inner.Sign(rand, data)
	})
}

func (s *boundedAgentSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	return runBoundedAgentOp(s.client, "sign", func() (*ssh.Signature, error) {
		if algoSigner, ok := s.inner.(ssh.AlgorithmSigner); ok {
			return algoSigner.SignWithAlgorithm(rand, data, algorithm)
		}
		return s.inner.Sign(rand, data)
	})
}

// offeredPubKeyTracker deduplicates ssh-agent and default-key signers whose
// public key has already been offered by an earlier explicit candidate.
type offeredPubKeyTracker struct {
	mu           sync.Mutex
	staticPubs   map[string]struct{}
	lazySigners  map[string][]*lazySigner
	agentOffered map[string]struct{}
}

func newOfferedPubKeyTracker() *offeredPubKeyTracker {
	return &offeredPubKeyTracker{
		staticPubs:   make(map[string]struct{}),
		lazySigners:  make(map[string][]*lazySigner),
		agentOffered: make(map[string]struct{}),
	}
}

func (t *offeredPubKeyTracker) recordStatic(pub ssh.PublicKey) {
	if t == nil || pub == nil {
		return
	}
	raw := string(pub.Marshal())
	t.mu.Lock()
	t.staticPubs[raw] = struct{}{}
	t.mu.Unlock()
}

func (t *offeredPubKeyTracker) recordLazy(ls *lazySigner) {
	if ls == nil {
		return
	}
	t.recordLazyKey(ls.pubKey, ls)
}

func (t *offeredPubKeyTracker) recordLazyKey(pub ssh.PublicKey, ls *lazySigner) {
	if t == nil || ls == nil || pub == nil {
		return
	}
	raw := string(pub.Marshal())
	t.mu.Lock()
	t.lazySigners[raw] = append(t.lazySigners[raw], ls)
	t.mu.Unlock()
}

func (t *offeredPubKeyTracker) wasOfferedBeforeAgent(pubRaw string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.staticPubs[pubRaw]; ok {
		return true
	}
	for _, ls := range t.lazySigners[pubRaw] {
		// If decryption was never attempted (server rejected PK_OK probe) or
		// decryption succeeded, the public key has already been evaluated by
		// the server. Only when local decryption failed (e.g. BatchMode with
		// key unlocked in ssh-agent) should ssh-agent still try signing with it.
		if !ls.decryptFailed.Load() {
			return true
		}
	}
	return false
}

func (t *offeredPubKeyTracker) wasOfferedByAgentOrStatic(pubRaw string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.staticPubs[pubRaw]; ok {
		return true
	}
	if _, ok := t.agentOffered[pubRaw]; ok {
		return true
	}
	for _, ls := range t.lazySigners[pubRaw] {
		if !ls.decryptFailed.Load() {
			return true
		}
	}
	return false
}

func (t *offeredPubKeyTracker) filterAgentSigners(signersFn func() ([]ssh.Signer, error)) func() ([]ssh.Signer, error) {
	return func() ([]ssh.Signer, error) {
		signers, err := signersFn()
		if err != nil {
			return nil, err
		}
		filtered := make([]ssh.Signer, 0, len(signers))
		seenInAgent := make(map[string]struct{}, len(signers))
		for _, s := range signers {
			if s == nil {
				continue
			}
			pubRaw := string(s.PublicKey().Marshal())
			if _, dup := seenInAgent[pubRaw]; dup {
				continue
			}
			seenInAgent[pubRaw] = struct{}{}
			if t.wasOfferedBeforeAgent(pubRaw) {
				continue
			}
			if t != nil {
				t.mu.Lock()
				t.agentOffered[pubRaw] = struct{}{}
				t.mu.Unlock()
			}
			filtered = append(filtered, s)
		}
		return filtered, nil
	}
}

// ResolveIdentityAgent resolves an OpenSSH IdentityAgent specification against env and target.
//   - "none" (case-insensitive) returns ("", true, nil), disabling SSH agent authentication completely.
//   - "" or "SSH_AUTH_SOCK" returns (strings.TrimSpace(env.AgentSocket), false, nil).
//   - "$VAR", "${VAR}", "~", and percent tokens are expanded via env and target.
func ResolveIdentityAgent(spec string, env Environment, target TargetContext) (socket string, disabled bool, err error) {
	if hasControlOrLineSepChar(spec) {
		return "", false, fmt.Errorf("invalid IdentityAgent %q: contains invalid ASCII control character", spec)
	}
	trimmed := strings.TrimSpace(spec)
	if strings.EqualFold(trimmed, "none") {
		return "", true, nil
	}
	if trimmed == "" || trimmed == "SSH_AUTH_SOCK" {
		if hasControlOrLineSepChar(env.AgentSocket) {
			return "", false, fmt.Errorf("invalid SSH_AUTH_SOCK %q: contains invalid ASCII control character", env.AgentSocket)
		}
		trimmedEnv := strings.TrimSpace(env.AgentSocket)
		if trimmedEnv == "" {
			return "", false, nil
		}
		return normalizeExpandedAgentSocketPath(trimmedEnv, env), false, nil
	}
	expanded, err := expandAgentSocketPath(trimmed, env, target, "IdentityAgent")
	if err != nil {
		return "", false, err
	}
	return expanded, false, nil
}

func expandAgentSocketPath(rawPath string, env Environment, target TargetContext, kind string) (string, error) {
	if hasControlOrLineSepChar(rawPath) {
		return "", fmt.Errorf("invalid %s %q: contains invalid ASCII control character", kind, rawPath)
	}
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return "", fmt.Errorf("invalid %s: value cannot be empty", kind)
	}

	if strings.HasPrefix(trimmed, "$") && !strings.HasPrefix(trimmed, "${") {
		varName := trimmed[1:]
		if !isValidEnvIdentifier(varName) {
			return "", fmt.Errorf("invalid environment variable name %q in %s", rawPath, kind)
		}
		val, ok := lookupEnv(env, varName)
		if !ok {
			return "", fmt.Errorf("invalid environment variable expansion: env var $%s has no value", varName)
		}
		if hasControlOrLineSepChar(val) {
			return "", fmt.Errorf("invalid %s %q: expanded value contains ASCII control character", kind, rawPath)
		}
		val = strings.TrimSpace(val)
		if val == "" {
			return "", fmt.Errorf("invalid environment variable expansion: env var $%s has no value", varName)
		}
		return normalizeExpandedAgentSocketPathWithTilde(val, env, false), nil
	}

	expanded, err := expandPathTokensSinglePass(trimmed, env, target, pathExpandOptions{
		kind:          kind,
		tildeFallback: env.ResolveKeyPath,
		expandTilde:   true,
	})
	if err != nil {
		return "", err
	}
	if hasControlOrLineSepChar(expanded) {
		return "", fmt.Errorf("invalid %s %q: expanded value contains ASCII control character", kind, rawPath)
	}
	expanded = strings.TrimSpace(expanded)
	if expanded == "" {
		return "", fmt.Errorf("invalid %s %q: expanded path is empty", kind, rawPath)
	}
	return normalizeExpandedAgentSocketPathWithTilde(expanded, env, false), nil
}

func isAgentPathSlash(c byte) bool {
	return c == '\\' || c == '/'
}

func normalizeWindowsNamedPipePath(path string) (string, bool) {
	const prefixLen = len(`\\.\pipe\`)
	if len(path) < prefixLen {
		return "", false
	}
	if !isAgentPathSlash(path[0]) || !isAgentPathSlash(path[1]) ||
		(path[2] != '.' && path[2] != '?') || !isAgentPathSlash(path[3]) ||
		!strings.EqualFold(path[4:8], "pipe") || !isAgentPathSlash(path[8]) {
		return "", false
	}
	rest := strings.ReplaceAll(path[prefixLen:], "/", `\`)
	for strings.Contains(rest, `\\`) {
		rest = strings.ReplaceAll(rest, `\\`, `\`)
	}
	rest = strings.TrimPrefix(rest, `\`)
	if path[2] == '?' {
		return `\\?\pipe\` + rest, true
	}
	return `\\.\pipe\` + rest, true
}

func normalizeExpandedAgentSocketPath(path string, env Environment) string {
	return normalizeExpandedAgentSocketPathWithTilde(path, env, true)
}

func normalizeExpandedAgentSocketPathWithTilde(path string, env Environment, expandTildeViaResolver bool) string {
	if pipePath, ok := normalizeWindowsNamedPipePath(path); ok {
		return pipePath
	}
	if expandTildeViaResolver || !strings.HasPrefix(path, "~") {
		path = resolveKeyPath(path, env.ResolveKeyPath)
	}
	if pipePath, ok := normalizeWindowsNamedPipePath(path); ok {
		return pipePath
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
	keyData, err := readBoundedRegularFile(k.Path, maxKeyFileBytes)
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
	baseHost           string
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
	req.BaseHost = p.baseHost
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
	decryptFailed      atomic.Bool
	skipSavePublicKey  bool
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
		s.decryptFailed.Store(true)
		return nil, err
	}
	s.decryptFailed.Store(false)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.decryptedSigner != nil {
		return s.decryptedSigner, nil
	}
	s.decryptedSigner = decSigner

	// 成功输入密码短语解密后，自动保存公钥到对应文件（严格准入模式下不写入新文件）
	if !s.skipSavePublicKey {
		if err := savePublicKey(s.keyPath, decSigner.PublicKey()); err != nil {
			l := s.logger
			if l == nil {
				l = logger.NopLogger
			}
			l.Debugf("save public key for %q failed: %v", s.keyPath, err)
		}
	}

	if s.passphraseCallback != nil {
		s.passphraseCallback(s.keyPath, passphrase)
	}
	return decSigner, nil
}

// savePublicKey 自动将公钥以 authorized_keys 格式保存到对应的 .pub 文件中
func savePublicKey(keyPath string, pubKey ssh.PublicKey) error {
	if pubKey == nil {
		return errors.New("public key is nil")
	}
	pubKeyPath := keyPath + ".pub"
	if info, err := os.Lstat(pubKeyPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse to write public key %q: path is a symlink", pubKeyPath)
		}
		// 如果公钥文件已经存在，不需要重复保存
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat public key %q failed: %w", pubKeyPath, err)
	}
	f, err := os.OpenFile(pubKeyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if info, lerr := os.Lstat(pubKeyPath); lerr == nil && info.Mode().IsRegular() {
				return nil
			}
		}
		return fmt.Errorf("create public key %q failed: %w", pubKeyPath, err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(pubKey)
	_, writeErr := f.Write(pubBytes)
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(pubKeyPath)
		return fmt.Errorf("write public key %q failed: %w", pubKeyPath, errors.Join(writeErr, closeErr))
	}
	if closeErr != nil {
		return fmt.Errorf("close public key %q failed: %w", pubKeyPath, closeErr)
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
	certPub  ssh.PublicKey
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
	tracker *offeredPubKeyTracker,
	postAgent bool,
	l logger.DebugLogger,
) ([]certAuthCandidateMethod, ssh.AuthMethod, error) {
	certMethods, plainMethod, _, err := resolveKeySignersWithPolicy(
		keyPath, explicitCerts, hasExplicitCerts, secProvider, passphraseCallback, tracker, postAgent, nil, true, l,
	)
	return certMethods, plainMethod, err
}

func resolveKeySignersWithPolicy(
	keyPath string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	secProvider *autoSecretProvider,
	passphraseCallback func(string, string),
	tracker *offeredPubKeyTracker,
	postAgent bool,
	policy *admittedMaterialPolicy,
	explicit bool,
	l logger.DebugLogger,
) ([]certAuthCandidateMethod, ssh.AuthMethod, bool, error) {
	if l == nil {
		l = logger.NopLogger
	}
	keyData, absentAllowed, err := policy.readKeyFile(keyPath, explicit)
	if err != nil {
		return nil, nil, false, fmt.Errorf("read key data failed: %w", err)
	}
	if absentAllowed {
		return nil, nil, true, nil
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err == nil {
		pub := signer.PublicKey()
		pubRaw := string(pub.Marshal())
		certMethods := buildKeyCertCandidateMethods(keyPath, pub, signer, explicitCerts, hasExplicitCerts, tracker, policy, l)
		if tracker != nil && tracker.wasOfferedBeforeAgent(pubRaw) {
			return certMethods, nil, false, nil
		}
		if postAgent && tracker != nil {
			return certMethods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
				if tracker.wasOfferedByAgentOrStatic(pubRaw) {
					return nil, nil
				}
				tracker.recordStatic(pub)
				return []ssh.Signer{signer}, nil
			}), false, nil
		}
		tracker.recordStatic(pub)
		return certMethods, ssh.PublicKeys(signer), false, nil
	}

	passErr, isEncrypted := isEncryptedPrivateKeyError(keyPath, err)
	if !isEncrypted {
		return nil, nil, false, err
	}
	certMethods, plainMethod, err := resolveEncryptedKeySigners(keyPath, keyData, passErr, explicitCerts, hasExplicitCerts, secProvider, tracker, postAgent, passphraseCallback, policy, l)
	return certMethods, plainMethod, false, err
}

func resolveEncryptedKeySigners(
	keyPath string,
	keyData []byte,
	passErr *ssh.PassphraseMissingError,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	secProvider *autoSecretProvider,
	tracker *offeredPubKeyTracker,
	postAgent bool,
	passphraseCallback func(string, string),
	policy *admittedMaterialPolicy,
	l logger.DebugLogger,
) ([]certAuthCandidateMethod, ssh.AuthMethod, error) {
	if passErr != nil && passErr.PublicKey != nil {
		switch passErr.PublicKey.Type() {
		case ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
			return nil, nil, fmt.Errorf("encrypted FIDO/U2F security-key stubs (%s) require ssh-agent", passErr.PublicKey.Type())
		}
	}

	skipSave := policy != nil && policy.enforceKeys

	// 私钥被密码保护。优先尝试免密读取 .pub、从 OpenSSH 私钥中提取明文公钥、或读取同目录 -cert.pub（并可回退到 PassphraseMissingError 自带公钥），以保持 lazy 解密。
	pubKey := extractUnencryptedPublicKey(keyPath, keyData, hasExplicitCerts, policy, l)
	if pubKey == nil && passErr != nil {
		pubKey = passErr.PublicKey
	}
	if pubKey != nil {
		lazy := &lazySigner{
			pubKey:             pubKey,
			keyPath:            keyPath,
			keyData:            keyData,
			secProvider:        secProvider,
			passphraseCallback: passphraseCallback,
			skipSavePublicKey:  skipSave,
			logger:             l,
		}
		pubRaw := string(pubKey.Marshal())
		certMethods := buildKeyCertCandidateMethods(keyPath, pubKey, lazy, explicitCerts, hasExplicitCerts, tracker, policy, l)
		if !postAgent && tracker != nil && tracker.wasOfferedBeforeAgent(pubRaw) {
			return certMethods, nil, nil
		}
		if postAgent && tracker != nil {
			return certMethods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
				if tracker.wasOfferedByAgentOrStatic(pubRaw) {
					return nil, nil
				}
				tracker.recordLazy(lazy)
				return []ssh.Signer{lazy}, nil
			}), nil
		}
		tracker.recordLazy(lazy)
		return certMethods, ssh.PublicKeys(lazy), nil
	}

	// 传统 PEM 等格式无法在解密前取得公钥。仍然把解密动作留在 PublicKeysCallback 中，
	// 这样只有轮到这个 candidate 时才会请求 passphrase。
	keyDataCopy := keyData
	keyPathCopy := keyPath
	return nil, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		resolvedSigner, passphrase, parseErr := secProvider.decryptPrivateKey(keyDataCopy, keyPathCopy)
		if parseErr != nil {
			return nil, parseErr
		}
		if !skipSave {
			if saveErr := savePublicKey(keyPathCopy, resolvedSigner.PublicKey()); saveErr != nil {
				l.Debugf("save public key for %q failed: %v", keyPathCopy, saveErr)
			}
		}
		if passphraseCallback != nil {
			passphraseCallback(keyPathCopy, passphrase)
		}
		if tracker != nil && tracker.wasOfferedByAgentOrStatic(string(resolvedSigner.PublicKey().Marshal())) {
			return nil, nil
		}
		tracker.recordStatic(resolvedSigner.PublicKey())
		return []ssh.Signer{resolvedSigner}, nil
	}), nil
}

func isEncryptedPrivateKeyError(keyPath string, parseErr error) (*ssh.PassphraseMissingError, bool) {
	if strings.HasSuffix(strings.ToLower(keyPath), ".pub") {
		return nil, false
	}
	passErr, ok := errors.AsType[*ssh.PassphraseMissingError](parseErr)
	return passErr, ok
}

func buildKeyCertCandidateMethods(
	keyPath string,
	pubKey ssh.PublicKey,
	signer ssh.Signer,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	tracker *offeredPubKeyTracker,
	policy *admittedMaterialPolicy,
	l logger.DebugLogger,
) []certAuthCandidateMethod {
	matched := matchCertsForKey(keyPath, pubKey, explicitCerts, hasExplicitCerts, l, policy)
	var certMethods []certAuthCandidateMethod
	for _, mc := range matched {
		if tracker != nil && tracker.wasOfferedBeforeAgent(string(mc.cert.Marshal())) {
			continue
		}
		cs, csErr := newWrappedCertSigner(mc.cert, signer)
		if csErr != nil {
			l.Debugf("Skipping SSH certificate %q for key %q: %v", mc.path, keyPath, csErr)
			continue
		}
		if lazy, ok := signer.(*lazySigner); ok {
			tracker.recordLazyKey(mc.cert, lazy)
		} else {
			tracker.recordStatic(mc.cert)
		}
		certMethods = append(certMethods, certAuthCandidateMethod{
			certPath: mc.path,
			certPub:  mc.cert,
			method:   ssh.PublicKeys(cs),
		})
	}
	return certMethods
}

func extractUnencryptedPublicKey(
	keyPath string,
	keyData []byte,
	hasExplicitCerts bool,
	policy *admittedMaterialPolicy,
	l logger.DebugLogger,
) ssh.PublicKey {
	pubKeyPath := keyPath + ".pub"
	if pubKeyData, ok := policy.readOptionalAdmittedPubFile(pubKeyPath); ok {
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
		if policy == nil || !policy.enforceKeys {
			if saveErr := savePublicKey(keyPath, extractedPubKey); saveErr != nil {
				l.Debugf("save extracted public key for %q failed: %v", keyPath, saveErr)
			}
		}
		return extractedPubKey
	} else {
		l.Debugf("Failed to extract public key from OpenSSH key: %s, error: %v", keyPath, extractErr)
	}
	if !hasExplicitCerts {
		if sidecar, ok := parseUserCertFile(sidecarCertPath(keyPath), true, l, policy); ok {
			return sidecar.cert.Key
		}
	}
	return nil
}

// resolveKeyAuthMethod 将单个私钥路径解析为一个独立的 publickey 认证候选。
// 对能够免密获得公钥的加密私钥继续使用 lazySigner，仅在服务器接受公钥后才请求 passphrase。
func resolveKeyAuthMethod(keyPath string, secProvider *autoSecretProvider, passphraseCallback func(string, string), l logger.DebugLogger) (ssh.AuthMethod, error) {
	_, plainMethod, err := resolveKeySigners(keyPath, nil, true, secProvider, passphraseCallback, nil, false, l)
	return plainMethod, err
}

// AutoAuthOptions 封装 auto 认证的完整上下文选项。
type AutoAuthOptions struct {
	AgentSocket                 string
	DialAgent                   func(ctx context.Context, socket string) (net.Conn, error)
	DefaultKeyPaths             []string
	ResolveKeyPath              func(string) string
	Environment                 Environment
	Target                      TargetContext
	LifecycleCtx                context.Context
	NodeID                      string
	User                        string
	Host                        string
	BaseHost                    string
	Port                        int
	VersionToken                string
	Resolver                    SecretResolver
	Prompter                    SecretPrompter
	HandshakeTimeout            time.Duration
	InteractionTimeout          time.Duration
	FailClosed                  func(error)
	RecoveryPrompter            SecretPrompter
	KeyPath                     string
	KeyPaths                    []string
	ExcludeKeyPath              string
	FirstCertMethods            []ssh.AuthMethod
	FirstCertPaths              []string
	FirstPublicKeys             []ssh.PublicKey
	PasswordCallback            func(string)
	PassphraseCallback          func(keyPath, passphrase string)
	CandidateRejectedCallback   func(protocol string)
	SSHOptions                  *Options
	EnforceAdmittedCertificates bool
	AdmittedCertificates        []AdmittedCertificate
	EnforceAdmittedKeyDigests   bool
	AdmittedKeyDigests          []AdmittedKeyDigest
	HostKeyChanged              *atomic.Bool
	Logger                      logger.DebugLogger
	Diagnostics                 logger.DiagnosticObserver
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
	err          error
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
		baseHost:           opts.BaseHost,
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
		var pubkeyErr error
		pubkeyCandidates, cleanup, pubkeyErr = buildAutoPubkeyCandidates(ctx, opts, first, secProvider, rejectPublicKey, policy.identitiesOnly, l)
		if pubkeyErr != nil {
			if cleanup != nil {
				cleanup()
			}
			return autoAuthPlan{
				authCallback: func(*ssh.ClientAuthContext) (ssh.AuthMethod, error) {
					return nil, pubkeyErr
				},
				err: pubkeyErr,
			}
		}
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

// ExpandIdentityPath expands an IdentityFile or CertificateFile path in a single
// pass using env and target, enforcing control-character rejection, post-expansion
// trimming, single-pass tilde handling, and fail-closed error semantics.
// Returns "", nil for empty or "none" values.
func ExpandIdentityPath(rawPath string, env Environment, target TargetContext) (string, error) {
	return expandIdentityKeyPath(rawPath, env, target, env.ResolveKeyPath)
}

func expandIdentityKeyPath(rawPath string, env Environment, target TargetContext, resolve func(string) string) (string, error) {
	if hasControlOrLineSepChar(rawPath) {
		return "", fmt.Errorf("invalid key path %q: contains invalid control character", rawPath)
	}
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" || IsNoneValue(trimmed) {
		return "", nil
	}
	path, err := expandPathTokensSinglePass(trimmed, env, target, pathExpandOptions{
		kind:          "IdentityFile",
		tildeFallback: resolve,
		expandTilde:   true,
	})
	if err != nil {
		return "", err
	}
	if hasControlOrLineSepChar(path) {
		return "", fmt.Errorf("invalid key path %q: expanded value contains invalid control character", rawPath)
	}
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "~") {
		path = resolveKeyPath(path, resolve)
	}
	if path == "" || IsNoneValue(path) {
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
		if hasControlOrLineSepChar(raw) {
			l.Debugf("Failed to expand identity key path %q: contains invalid control character", raw)
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		hasExplicit = true
		if IsNoneValue(trimmed) {
			break
		}
		expanded, err := expandIdentityKeyPath(raw, env, target, resolve)
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

func extractIdentityPublicKeyWithPolicy(keyPath string, policy *admittedMaterialPolicy, explicit bool) (ssh.PublicKey, error) {
	if keyPath == "" {
		return nil, nil
	}
	keyData, absentAllowed, err := policy.readKeyFile(keyPath, explicit)
	if err != nil && policy != nil && policy.enforceKeys {
		return nil, err
	}
	if err == nil && !absentAllowed {
		if signer, parseErr := ssh.ParsePrivateKey(keyData); parseErr == nil {
			return signer.PublicKey(), nil
		}
		if pub, _, _, _, parseErr := ssh.ParseAuthorizedKey(keyData); parseErr == nil {
			if cert, ok := pub.(*ssh.Certificate); ok && cert.Key != nil {
				return cert.Key, nil
			}
			return pub, nil
		}
		if pub, parseErr := parseOpenSSHPublicKeyFromEncryptedPrivate(keyData); parseErr == nil {
			return pub, nil
		}
	}
	if !strings.HasSuffix(keyPath, ".pub") {
		if pubData, ok := policy.readOptionalAdmittedPubFile(keyPath + ".pub"); ok {
			if pub, _, _, _, parseErr := ssh.ParseAuthorizedKey(pubData); parseErr == nil {
				if cert, ok := pub.(*ssh.Certificate); ok && cert.Key != nil {
					return cert.Key, nil
				}
				return pub, nil
			}
		}
	}
	if sidecar, ok := parseUserCertFile(sidecarCertPath(keyPath), true, nil, policy); ok {
		return sidecar.cert.Key, nil
	}
	return nil, nil
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

func indexAgentSignersByPubKey(signers []ssh.Signer) map[string]ssh.Signer {
	agentByPub := make(map[string]ssh.Signer, len(signers))
	for _, s := range signers {
		if s == nil {
			continue
		}
		pubKeyBytes := string(s.PublicKey().Marshal())
		if _, exists := agentByPub[pubKeyBytes]; !exists {
			agentByPub[pubKeyBytes] = s
		}
	}
	for _, s := range signers {
		if s == nil {
			continue
		}
		if cert, ok := extractCertFromPublicKey(s.PublicKey()); ok {
			plainRaw := string(cert.Key.Marshal())
			if _, exists := agentByPub[plainRaw]; !exists {
				agentByPub[plainRaw] = s
			}
		}
	}
	return agentByPub
}

func isUnencryptedPrivateKeyFile(keyPath string, policies ...*admittedMaterialPolicy) bool {
	if keyPath == "" {
		return false
	}
	policy := firstAdmittedPolicy(policies)
	data, absentAllowed, err := policy.readKeyFile(keyPath, true)
	if err != nil || absentAllowed {
		return false
	}
	_, err = ssh.ParsePrivateKey(data)
	return err == nil
}

func hasSidecarCertFile(keyPath string, policies ...*admittedMaterialPolicy) bool {
	certPath := sidecarCertPath(keyPath)
	if certPath == "" {
		return false
	}
	if policy := firstAdmittedPolicy(policies); policy != nil && policy.enforceCerts {
		entry, ok := policy.lookupCert(certPath)
		return ok && !entry.Missing && !entry.NonRegular
	}
	st, err := os.Stat(certPath)
	return err == nil && st.Mode().IsRegular()
}

func dialAgentSignersByPubKey(
	ctx context.Context,
	lifecycleCtx context.Context,
	dialFn func(context.Context, string) (net.Conn, error),
	socket string,
	timeout time.Duration,
	l logger.DebugLogger,
) (map[string]ssh.Signer, func()) {
	if l == nil {
		l = logger.NopLogger
	}
	if socket == "" {
		return nil, nil
	}
	agentClient, cleanup, err := dialBoundedAgentClient(ctx, lifecycleCtx, dialFn, socket, timeout, l)
	if err != nil {
		l.Debugf("connect to ssh-agent failed: %v", err)
		return nil, nil
	}
	signers, signersErr := agentClient.Signers()
	if signersErr != nil {
		l.Debugf("list ssh-agent signers failed: %v", signersErr)
		cleanup()
		return nil, nil
	}
	return indexAgentSignersByPubKey(signers), cleanup
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
	tracker *offeredPubKeyTracker,
	postAgent bool,
	policy *admittedMaterialPolicy,
	explicit bool,
	l logger.DebugLogger,
) (bool, error) {
	if keyPath == "" {
		return false, nil
	}
	if _, seen := seenKeyPaths[keyPath]; seen {
		return false, nil
	}
	seenKeyPaths[keyPath] = struct{}{}

	if postAgent && tracker != nil {
		pub, pubErr := extractIdentityPublicKeyWithPolicy(keyPath, policy, explicit)
		if pubErr != nil && policy != nil && policy.enforceKeys && errors.Is(pubErr, ErrSnapshotMismatch) {
			return false, pubErr
		}
		if pub != nil && tracker.wasOfferedBeforeAgent(string(pub.Marshal())) {
			l.Debugf("Skipping duplicate SSH key already offered earlier: %s", keyPath)
			return false, nil
		}
	}

	l.Debugf("Checking SSH key: %s", keyPath)
	if policy == nil || !policy.enforceKeys {
		if !statKeyFileExists(keyPath, l) {
			return false, nil
		}
	}

	certMethods, plainMethod, absentAllowed, err := resolveKeySignersWithPolicy(
		keyPath, explicitCerts, hasExplicitCerts, secProvider, passphraseCallback, tracker, postAgent, policy, explicit, l,
	)
	if err != nil {
		if policy != nil && policy.enforceKeys && errors.Is(err, ErrSnapshotMismatch) {
			return false, err
		}
		l.Debugf("Failed to resolve key: %s, error: %v", keyPath, err)
		return false, nil
	}
	if absentAllowed {
		return false, nil
	}

	appendResolvedKeyAuthCandidates(certCandidates, plainCandidates, pairedCertPaths, keyPath, label, certMethods, plainMethod, rejectPublicKey)
	return true, nil
}

func statKeyFileExists(keyPath string, l logger.DebugLogger) bool {
	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			l.Debugf("Key file does not exist: %s", keyPath)
		} else {
			l.Debugf("Failed to stat key: %s, error: %v", keyPath, err)
		}
		return false
	}
	return true
}

func appendResolvedKeyAuthCandidates(
	certCandidates *[]autoAuthCandidate,
	plainCandidates *[]autoAuthCandidate,
	pairedCertPaths map[string]struct{},
	keyPath string,
	label string,
	certMethods []certAuthCandidateMethod,
	plainMethod ssh.AuthMethod,
	rejectPublicKey func(),
) {
	for _, cm := range certMethods {
		if pairedCertPaths != nil {
			if _, already := pairedCertPaths[cm.certPath]; already {
				continue
			}
			pairedCertPaths[cm.certPath] = struct{}{}
		}
		*certCandidates = append(*certCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      label + " (cert): " + cm.certPath,
			method:     cm.method,
			onRejected: rejectPublicKey,
		})
	}
	if plainMethod != nil {
		*plainCandidates = append(*plainCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      label + ": " + keyPath,
			method:     plainMethod,
			onRejected: rejectPublicKey,
		})
	}
}

func appendAgentMatchedKeyPath(
	certCandidates *[]autoAuthCandidate,
	plainCandidates *[]autoAuthCandidate,
	pairedCertPaths map[string]struct{},
	agentByPub map[string]ssh.Signer,
	keyPath string,
	label string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	rejectPublicKey func(),
	tracker *offeredPubKeyTracker,
	policy *admittedMaterialPolicy,
	explicit bool,
	l logger.DebugLogger,
) (bool, error) {
	if len(agentByPub) == 0 {
		return false, nil
	}
	pub, err := extractIdentityPublicKeyWithPolicy(keyPath, policy, explicit)
	if err != nil && policy != nil && policy.enforceKeys && errors.Is(err, ErrSnapshotMismatch) {
		return false, err
	}
	if pub == nil {
		return false, nil
	}
	signer, ok := agentByPub[string(pub.Marshal())]
	if !ok {
		return false, nil
	}
	matched := matchCertsForKey(keyPath, pub, explicitCerts, hasExplicitCerts, l, policy)
	for _, mc := range matched {
		if pairedCertPaths != nil {
			if _, already := pairedCertPaths[mc.path]; already {
				continue
			}
		}
		if tracker != nil && tracker.wasOfferedBeforeAgent(string(mc.cert.Marshal())) {
			continue
		}
		if cs, csErr := newWrappedCertSigner(mc.cert, signer); csErr == nil {
			if pairedCertPaths != nil {
				pairedCertPaths[mc.path] = struct{}{}
			}
			tracker.recordStatic(mc.cert)
			*certCandidates = append(*certCandidates, autoAuthCandidate{
				protocol:   autoAuthProtocolPublicKey,
				label:      label + " (ssh-agent cert): " + mc.path,
				method:     ssh.PublicKeys(cs),
				onRejected: rejectPublicKey,
			})
		}
	}
	if tracker != nil && tracker.wasOfferedBeforeAgent(string(pub.Marshal())) {
		return true, nil
	}
	tracker.recordStatic(pub)
	*plainCandidates = append(*plainCandidates, autoAuthCandidate{
		protocol:   autoAuthProtocolPublicKey,
		label:      label + " (ssh-agent): " + keyPath,
		method:     ssh.PublicKeys(adaptPlainKeySigner(signer, pub)),
		onRejected: rejectPublicKey,
	})
	return true, nil
}

func appendAgentCertsForKeyPath(
	certCandidates *[]autoAuthCandidate,
	pairedCertPaths map[string]struct{},
	agentByPub map[string]ssh.Signer,
	keyPath string,
	label string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	rejectPublicKey func(),
	tracker *offeredPubKeyTracker,
	policy *admittedMaterialPolicy,
	explicit bool,
	l logger.DebugLogger,
) error {
	if len(agentByPub) == 0 || keyPath == "" {
		return nil
	}
	pub, err := extractIdentityPublicKeyWithPolicy(keyPath, policy, explicit)
	if err != nil && policy != nil && policy.enforceKeys && errors.Is(err, ErrSnapshotMismatch) {
		return err
	}
	if pub == nil {
		return nil
	}
	signer, ok := agentByPub[string(pub.Marshal())]
	if !ok {
		return nil
	}
	for _, mc := range matchCertsForKey(keyPath, pub, explicitCerts, hasExplicitCerts, l, policy) {
		if pairedCertPaths != nil {
			if _, already := pairedCertPaths[mc.path]; already {
				continue
			}
		}
		if tracker != nil && tracker.wasOfferedBeforeAgent(string(mc.cert.Marshal())) {
			continue
		}
		cs, csErr := newWrappedCertSigner(mc.cert, signer)
		if csErr != nil {
			continue
		}
		if pairedCertPaths != nil {
			pairedCertPaths[mc.path] = struct{}{}
		}
		tracker.recordStatic(mc.cert)
		*certCandidates = append(*certCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      label + " (ssh-agent cert): " + mc.path,
			method:     ssh.PublicKeys(cs),
			onRejected: rejectPublicKey,
		})
	}
	return nil
}

func appendUnpairedExplicitCertsFromAgent(
	certCandidates *[]autoAuthCandidate,
	pairedCertPaths map[string]struct{},
	agentByPub map[string]ssh.Signer,
	explicitCerts []loadedUserCert,
	labelPrefix string,
	rejectPublicKey func(),
	tracker *offeredPubKeyTracker,
) {
	if len(agentByPub) == 0 || len(explicitCerts) == 0 {
		return
	}
	for _, ec := range explicitCerts {
		if pairedCertPaths != nil {
			if _, already := pairedCertPaths[ec.path]; already {
				continue
			}
		}
		if tracker != nil && tracker.wasOfferedBeforeAgent(string(ec.cert.Marshal())) {
			continue
		}
		signer, ok := agentByPub[ec.keyRaw]
		if !ok {
			continue
		}
		cs, csErr := newWrappedCertSigner(ec.cert, signer)
		if csErr != nil {
			continue
		}
		if pairedCertPaths != nil {
			pairedCertPaths[ec.path] = struct{}{}
		}
		tracker.recordStatic(ec.cert)
		*certCandidates = append(*certCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      labelPrefix + ec.path,
			method:     ssh.PublicKeys(cs),
			onRejected: rejectPublicKey,
		})
	}
}

func initAutoFirstCandidates(
	opts AutoAuthOptions,
	first []ssh.AuthMethod,
	rejectPublicKey func(),
	tracker *offeredPubKeyTracker,
) (certCandidates, plainCandidates []autoAuthCandidate, pairedCertPaths map[string]struct{}) {
	for _, pub := range opts.FirstPublicKeys {
		tracker.recordStatic(pub)
	}
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
	pairedCertPaths = make(map[string]struct{}, len(opts.FirstCertPaths))
	for _, certPath := range opts.FirstCertPaths {
		if certPath != "" {
			pairedCertPaths[certPath] = struct{}{}
		}
	}
	return certCandidates, plainCandidates, pairedCertPaths
}

func buildAutoPubkeyCandidates(
	ctx context.Context,
	opts AutoAuthOptions,
	first []ssh.AuthMethod,
	secProvider *autoSecretProvider,
	rejectPublicKey func(),
	identitiesOnly bool,
	l logger.DebugLogger,
) ([]autoAuthCandidate, func(), error) {
	var cleanup func()
	tracker := newOfferedPubKeyTracker()
	certCandidates, plainCandidates, pairedCertPaths := initAutoFirstCandidates(opts, first, rejectPublicKey, tracker)
	seenKeyPaths := make(map[string]struct{})
	target := effectiveAuthTargetContext(opts)
	materialPolicy := newAdmittedMaterialPolicy(
		opts.EnforceAdmittedCertificates,
		opts.AdmittedCertificates,
		opts.EnforceAdmittedKeyDigests,
		opts.AdmittedKeyDigests,
	)
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
	if opts.ExcludeKeyPath != "" {
		explicitPaths = filterSourcedKeyPath(explicitPaths, opts.ExcludeKeyPath, opts.Environment, target, opts.ResolveKeyPath)
	}
	explicitCerts, hasExplicitCerts := collectExplicitUserCerts(
		opts.SSHOptions,
		opts.Environment,
		target,
		opts.ResolveKeyPath,
		l,
		materialPolicy,
	)
	agentSocket, agentDisabled := effectiveAutoAuthAgentSocket(opts, target, l)
	hasExplicitIdentity := len(first) > 0 || len(opts.FirstCertMethods) > 0 || hasExplicit

	if identitiesOnly {
		return buildIdentitiesOnlyPubkeyCandidatesWithPolicy(
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
			tracker,
			materialPolicy,
			l,
		)
	}

	defaultPaths := expandDefaultIdentityPaths(opts, target, l)
	agentByPub, agentSignersFn, hasAgent, cleanup := openAutoAuthAgent(
		ctx, opts, dialAgentFn, agentSocket, agentDisabled,
		explicitPaths, defaultPaths, explicitCerts, hasExplicitCerts, materialPolicy, l,
	)

	// 显式身份必须优先于任何自动发现来源；对加密/缺失/.pub 显式路径优先复用 ssh-agent 中已解锁的私钥。
	for _, keyPath := range explicitPaths {
		if err := appendExplicitAutoKeyPath(
			&certCandidates, &plainCandidates, pairedCertPaths, seenKeyPaths, agentByPub,
			keyPath, explicitCerts, hasExplicitCerts, secProvider, opts.PassphraseCallback,
			rejectPublicKey, tracker, materialPolicy, l,
		); err != nil {
			return nil, cleanup, err
		}
	}

	appendUnpairedExplicitCertsFromAgent(&certCandidates, pairedCertPaths, agentByPub, explicitCerts, "ssh-agent (cert): ", rejectPublicKey, tracker)

	for _, keyPath := range defaultPaths {
		if _, seen := seenKeyPaths[keyPath]; seen {
			continue
		}
		if err := appendAgentCertsForKeyPath(
			&certCandidates, pairedCertPaths, agentByPub,
			keyPath, "default key", explicitCerts, hasExplicitCerts,
			rejectPublicKey, tracker, materialPolicy, false, l,
		); err != nil {
			return nil, cleanup, err
		}
	}

	if hasAgent {
		plainCandidates = append(plainCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      "ssh-agent",
			method:     ssh.PublicKeysCallback(tracker.filterAgentSigners(agentSignersFn)),
			onRejected: rejectPublicKey,
		})
	}

	for _, keyPath := range defaultPaths {
		if _, err := appendExpandedKeyAndCertCandidates(
			&certCandidates, &plainCandidates, pairedCertPaths, seenKeyPaths,
			keyPath, "default key", explicitCerts, hasExplicitCerts,
			secProvider, opts.PassphraseCallback, rejectPublicKey, tracker, hasAgent, materialPolicy, false, l,
		); err != nil {
			return nil, cleanup, err
		}
	}
	return append(certCandidates, plainCandidates...), cleanup, nil
}

func openAutoAuthAgent(
	ctx context.Context,
	opts AutoAuthOptions,
	dialAgentFn func(context.Context, string) (net.Conn, error),
	agentSocket string,
	agentDisabled bool,
	explicitPaths []string,
	defaultPaths []string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	materialPolicy *admittedMaterialPolicy,
	l logger.DebugLogger,
) (map[string]ssh.Signer, func() ([]ssh.Signer, error), bool, func()) {
	if agentDisabled || agentSocket == "" {
		return nil, nil, false, nil
	}
	ac, acCleanup, err := dialBoundedAgentClient(ctx, opts.LifecycleCtx, dialAgentFn, agentSocket, opts.HandshakeTimeout, l)
	if err != nil {
		l.Debugf("connect to ssh-agent failed: %v", err)
		return nil, nil, false, nil
	}
	var agentByPub map[string]ssh.Signer
	agentSignersFn := ac.Signers
	if shouldPreloadAgentSigners(explicitPaths, defaultPaths, explicitCerts, hasExplicitCerts, materialPolicy) {
		if signers, signersErr := ac.Signers(); signersErr != nil {
			l.Debugf("list ssh-agent signers failed: %v", signersErr)
		} else {
			agentByPub = indexAgentSignersByPubKey(signers)
			agentSignersFn = func() ([]ssh.Signer, error) { return signers, nil }
		}
	}
	return agentByPub, agentSignersFn, true, acCleanup
}

func appendExplicitAutoKeyPath(
	certCandidates *[]autoAuthCandidate,
	plainCandidates *[]autoAuthCandidate,
	pairedCertPaths map[string]struct{},
	seenKeyPaths map[string]struct{},
	agentByPub map[string]ssh.Signer,
	keyPath string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	secProvider *autoSecretProvider,
	passphraseCallback func(string, string),
	rejectPublicKey func(),
	tracker *offeredPubKeyTracker,
	materialPolicy *admittedMaterialPolicy,
	l logger.DebugLogger,
) error {
	if !isUnencryptedPrivateKeyFile(keyPath, materialPolicy) {
		if _, seen := seenKeyPaths[keyPath]; !seen {
			matched, matchErr := appendAgentMatchedKeyPath(
				certCandidates, plainCandidates, pairedCertPaths, agentByPub,
				keyPath, "explicit key", explicitCerts, hasExplicitCerts,
				rejectPublicKey, tracker, materialPolicy, true, l,
			)
			if matchErr != nil {
				return matchErr
			}
			if matched {
				seenKeyPaths[keyPath] = struct{}{}
				return nil
			}
		}
	}
	_, err := appendExpandedKeyAndCertCandidates(
		certCandidates, plainCandidates, pairedCertPaths, seenKeyPaths,
		keyPath, "explicit key", explicitCerts, hasExplicitCerts,
		secProvider, passphraseCallback, rejectPublicKey, tracker, false, materialPolicy, true, l,
	)
	return err
}

func shouldPreloadAgentSigners(
	explicitPaths []string,
	defaultPaths []string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	policies ...*admittedMaterialPolicy,
) bool {
	if len(explicitCerts) > 0 {
		return true
	}
	policy := firstAdmittedPolicy(policies)
	for _, p := range explicitPaths {
		if !isUnencryptedPrivateKeyFile(p, policy) {
			return true
		}
	}
	if !hasExplicitCerts {
		for _, p := range defaultPaths {
			if hasSidecarCertFile(p, policy) {
				return true
			}
		}
	}
	return false
}

func hasUnpairedExplicitCerts(explicitCerts []loadedUserCert, pairedCertPaths map[string]struct{}) bool {
	for _, ec := range explicitCerts {
		if _, paired := pairedCertPaths[ec.path]; !paired {
			return true
		}
	}
	return false
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
	tracker *offeredPubKeyTracker,
	l logger.DebugLogger,
) ([]autoAuthCandidate, func()) {
	candidates, cleanup, _ := buildIdentitiesOnlyPubkeyCandidatesWithPolicy(
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
		tracker,
		nil,
		l,
	)
	return candidates, cleanup
}

func buildIdentitiesOnlyPubkeyCandidatesWithPolicy(
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
	tracker *offeredPubKeyTracker,
	materialPolicy *admittedMaterialPolicy,
	l logger.DebugLogger,
) ([]autoAuthCandidate, func(), error) {
	candidatePaths := explicitPaths
	candidateLabel := "explicit key"
	explicit := true
	if !hasExplicitIdentity {
		candidatePaths = expandDefaultIdentityPaths(opts, target, l)
		candidateLabel = "default key"
		explicit = false
	}

	var agentByPub map[string]ssh.Signer
	var cleanup func()
	if !agentDisabled && agentSocket != "" && (len(candidatePaths) > 0 || hasUnpairedExplicitCerts(explicitCerts, pairedCertPaths)) {
		agentByPub, cleanup = dialAgentSignersByPubKey(ctx, opts.LifecycleCtx, dialAgentFn, agentSocket, opts.HandshakeTimeout, l)
	}

	for _, keyPath := range candidatePaths {
		if _, seen := seenKeyPaths[keyPath]; seen {
			continue
		}
		matched, matchErr := appendAgentMatchedKeyPath(
			&certCandidates, &plainCandidates, pairedCertPaths, agentByPub,
			keyPath, candidateLabel, explicitCerts, hasExplicitCerts,
			rejectPublicKey, tracker, materialPolicy, explicit, l,
		)
		if matchErr != nil {
			return nil, cleanup, matchErr
		}
		if matched {
			seenKeyPaths[keyPath] = struct{}{}
			continue
		}
		if _, err := appendExpandedKeyAndCertCandidates(
			&certCandidates, &plainCandidates, pairedCertPaths, seenKeyPaths,
			keyPath, candidateLabel, explicitCerts, hasExplicitCerts,
			secProvider, opts.PassphraseCallback, rejectPublicKey, tracker, false, materialPolicy, explicit, l,
		); err != nil {
			return nil, cleanup, err
		}
	}

	appendUnpairedExplicitCertsFromAgent(&certCandidates, pairedCertPaths, agentByPub, explicitCerts, "ssh-agent (cert): ", rejectPublicKey, tracker)

	return append(certCandidates, plainCandidates...), cleanup, nil
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
