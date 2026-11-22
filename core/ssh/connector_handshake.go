package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	"golang.org/x/crypto/ssh"
)

// dialPolicy holds an immutable, normalized, secret-free connection snapshot
// captured once at the entry of a dial/handshake attempt.
type dialPolicy struct {
	nodeID                      string
	address                     string
	baseHost                    string
	port                        int
	user                        string
	authType                    string
	keyPath                     string
	keyPaths                    []string
	keyRef                      string
	authUpdateToken             string
	sudoMode                    SudoMode
	sudoUpdateToken             string
	proxyJump                   string
	originalHost                string
	canonicalHost               string
	originalProxyJump           string
	hasOriginalProxyJump        bool
	trustVersion                string
	passwordPromptPattern       string
	enforceAdmittedCertificates bool
	admittedCertificates        []AdmittedCertificate
	enforceAdmittedKeyDigests   bool
	admittedKeyDigests          []AdmittedKeyDigest
	execution                   *ExecutionConfig
	options                     *Options
	control                     *ControlConfig
}

func freezeDialPolicy(cfg *ClientConfig) dialPolicy {
	if cfg == nil {
		return dialPolicy{port: int(DefaultSSHPort)}
	}
	norm := NewClientConfig(*cfg)
	origJump := norm.OriginalProxyJump
	hasOriginalJump := norm.HasOriginalProxyJump
	if !hasOriginalJump && origJump == "" {
		origJump = norm.ProxyJump
	}
	return dialPolicy{
		nodeID:                      norm.NodeID,
		address:                     norm.Address,
		baseHost:                    norm.BaseHost,
		port:                        norm.Port,
		user:                        norm.User,
		authType:                    norm.AuthType,
		keyPath:                     norm.KeyPath,
		keyPaths:                    norm.KeyPaths,
		keyRef:                      norm.KeyRef,
		authUpdateToken:             norm.AuthUpdateToken,
		sudoMode:                    norm.SudoMode,
		sudoUpdateToken:             norm.SudoUpdateToken,
		proxyJump:                   NormalizeProxyJump(norm.ProxyJump),
		originalHost:                norm.OriginalHost,
		canonicalHost:               norm.CanonicalHost,
		originalProxyJump:           origJump,
		hasOriginalProxyJump:        hasOriginalJump,
		trustVersion:                norm.TrustVersion,
		passwordPromptPattern:       norm.PasswordPromptPattern,
		enforceAdmittedCertificates: norm.EnforceAdmittedCertificates,
		admittedCertificates:        norm.AdmittedCertificates,
		enforceAdmittedKeyDigests:   norm.EnforceAdmittedKeyDigests,
		admittedKeyDigests:          norm.AdmittedKeyDigests,
		execution:                   norm.Execution,
		options:                     norm.Options,
		control:                     norm.Control,
	}
}

func (p dialPolicy) readOnlyConfig() *ClientConfig {
	return NewClientConfig(ClientConfig{
		NodeID:                      p.nodeID,
		Address:                     p.address,
		BaseHost:                    p.baseHost,
		Port:                        p.port,
		User:                        p.user,
		AuthType:                    p.authType,
		KeyPath:                     p.keyPath,
		KeyPaths:                    p.keyPaths,
		KeyRef:                      p.keyRef,
		AuthUpdateToken:             p.authUpdateToken,
		SudoMode:                    p.sudoMode,
		SudoUpdateToken:             p.sudoUpdateToken,
		ProxyJump:                   p.proxyJump,
		OriginalHost:                p.originalHost,
		CanonicalHost:               p.canonicalHost,
		OriginalProxyJump:           p.originalProxyJump,
		HasOriginalProxyJump:        p.hasOriginalProxyJump,
		TrustVersion:                p.trustVersion,
		PasswordPromptPattern:       p.passwordPromptPattern,
		EnforceAdmittedCertificates: p.enforceAdmittedCertificates,
		AdmittedCertificates:        p.admittedCertificates,
		EnforceAdmittedKeyDigests:   p.enforceAdmittedKeyDigests,
		AdmittedKeyDigests:          p.admittedKeyDigests,
		Execution:                   p.execution,
		Options:                     p.options,
		Control:                     p.control,
	})
}

func (p dialPolicy) toConnectionConfig() ConnectionConfig {
	return ConnectionConfig{
		KeyRef:                      p.keyRef,
		TrustVersion:                p.trustVersion,
		NodeID:                      p.nodeID,
		OriginalHost:                p.originalHost,
		CanonicalHost:               p.canonicalHost,
		Address:                     p.address,
		BaseHost:                    p.baseHost,
		Port:                        p.port,
		User:                        p.user,
		AuthType:                    p.authType,
		configuredAuthType:          p.authType,
		KeyPath:                     p.keyPath,
		KeyPaths:                    slices.Clone(p.keyPaths),
		AuthUpdateToken:             p.authUpdateToken,
		SudoMode:                    p.sudoMode,
		SudoUpdateToken:             p.sudoUpdateToken,
		ProxyJump:                   p.proxyJump,
		OriginalProxyJump:           p.originalProxyJump,
		HasOriginalProxyJump:        p.hasOriginalProxyJump,
		PasswordPromptPattern:       p.passwordPromptPattern,
		EnforceAdmittedCertificates: p.enforceAdmittedCertificates,
		AdmittedCertificates:        cloneAdmittedCertificates(p.admittedCertificates),
		EnforceAdmittedKeyDigests:   p.enforceAdmittedKeyDigests,
		AdmittedKeyDigests:          cloneAdmittedKeyDigests(p.admittedKeyDigests),
		Execution:                   p.execution.Clone(),
		Options:                     p.options.Clone(),
		Control:                     normalizeControlConfig(p.control),
	}
}

func (p dialPolicy) targetContext(env Environment) TargetContext {
	user := p.user
	if user == "" {
		user = env.LocalUser
	}
	return TargetContext{
		Host:         cleanHostLiteral(p.address),
		Port:         p.port,
		User:         user,
		OriginalHost: effectiveOriginalHost(p.originalHost, p.nodeID),
		JumpHost:     p.proxyJump,
	}
}

type authOutcome struct {
	discovered bool
	password   string
	passphrase string
	keyPath    string
	authType   string
}

// handshakeAttempt isolates mutable per-attempt secrets and discovered
// authentication choices away from the caller's ClientConfig and frozen
// dialPolicy, and zeros its own backing buffers via scrub().
type handshakeAttempt struct {
	mu                 sync.Mutex
	baselineAuthType   string
	initialPassword    []byte
	initialPassphrase  []byte
	initialSuPwd       []byte
	compatPassword     []byte
	resolvedPassword   []byte
	resolvedPassphrase []byte
	discoveredKeyPath  string
	selectedAuthType   string
	discovered         bool
	onDiscovered       func()
}

func newHandshakeAttempt(cfg *ClientConfig, onDiscovered func()) *handshakeAttempt {
	if cfg == nil {
		return &handshakeAttempt{onDiscovered: onDiscovered}
	}
	return &handshakeAttempt{
		baselineAuthType:  cfg.AuthType,
		initialPassword:   []byte(cfg.Password),
		initialPassphrase: []byte(cfg.Passphrase),
		initialSuPwd:      []byte(cfg.SuPwd),
		compatPassword:    []byte(cfg.Password),
		onDiscovered:      onDiscovered,
	}
}

func (a *handshakeAttempt) consumeInitialPassword() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.initialPassword) == 0 {
		return ""
	}
	pwd := string(a.initialPassword)
	zeroBytes(a.initialPassword)
	a.initialPassword = nil
	return pwd
}

func (a *handshakeAttempt) consumeInitialPassphrase() []byte {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.initialPassphrase) == 0 {
		return nil
	}
	out := slices.Clone(a.initialPassphrase)
	zeroBytes(a.initialPassphrase)
	a.initialPassphrase = nil
	return out
}

func (a *handshakeAttempt) effectiveCompatPassword() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.resolvedPassword) > 0 {
		return string(a.resolvedPassword)
	}
	return string(a.compatPassword)
}

func (a *handshakeAttempt) compatSuPwd() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return string(a.initialSuPwd)
}

func (a *handshakeAttempt) recordPassword(password string, clearPassphrase bool) {
	if a == nil {
		return
	}
	a.mu.Lock()
	zeroBytes(a.resolvedPassword)
	a.resolvedPassword = []byte(password)
	zeroBytes(a.compatPassword)
	a.compatPassword = []byte(password)
	if clearPassphrase {
		zeroBytes(a.resolvedPassphrase)
		a.resolvedPassphrase = nil
		a.discoveredKeyPath = ""
	}
	if len(a.resolvedPassphrase) == 0 {
		a.selectedAuthType = "password"
	}
	a.discovered = true
	cb := a.onDiscovered
	a.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (a *handshakeAttempt) recordPassphrase(keyPath, passphrase string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	zeroBytes(a.resolvedPassword)
	a.resolvedPassword = nil
	zeroBytes(a.compatPassword)
	a.compatPassword = nil
	zeroBytes(a.resolvedPassphrase)
	a.resolvedPassphrase = []byte(passphrase)
	a.discoveredKeyPath = keyPath
	a.selectedAuthType = "key"
	a.discovered = true
	cb := a.onDiscovered
	a.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (a *handshakeAttempt) rejectCandidate(protocol string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch protocol {
	case autoAuthProtocolPublicKey:
		zeroBytes(a.resolvedPassphrase)
		a.resolvedPassphrase = nil
		a.discoveredKeyPath = ""
		if len(a.resolvedPassword) == 0 {
			a.selectedAuthType = a.baselineAuthType
		}
	case autoAuthProtocolPassword:
		zeroBytes(a.resolvedPassword)
		a.resolvedPassword = nil
		zeroBytes(a.compatPassword)
		a.compatPassword = nil
		if len(a.resolvedPassphrase) == 0 {
			a.selectedAuthType = a.baselineAuthType
		}
	}
}

func (a *handshakeAttempt) outcome() authOutcome {
	if a == nil {
		return authOutcome{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return authOutcome{
		discovered: a.discovered,
		password:   string(a.resolvedPassword),
		passphrase: string(a.resolvedPassphrase),
		keyPath:    a.discoveredKeyPath,
		authType:   a.selectedAuthType,
	}
}

func (a *handshakeAttempt) scrub() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	zeroBytes(a.initialPassword)
	a.initialPassword = nil
	zeroBytes(a.initialPassphrase)
	a.initialPassphrase = nil
	zeroBytes(a.initialSuPwd)
	a.initialSuPwd = nil
	zeroBytes(a.compatPassword)
	a.compatPassword = nil
	zeroBytes(a.resolvedPassword)
	a.resolvedPassword = nil
	zeroBytes(a.resolvedPassphrase)
	a.resolvedPassphrase = nil
	a.discoveredKeyPath = ""
	a.selectedAuthType = ""
	a.discovered = false
}

func (c *Connector) recordAuthUpdate(ctx context.Context, nodeName string, cfg *ClientConfig, rootConn net.Conn) (string, error) {
	if cfg == nil {
		return "", nil
	}
	policy := freezeDialPolicy(cfg)
	outcome := authOutcome{
		password:   cfg.Password,
		passphrase: cfg.Passphrase,
		keyPath:    cfg.KeyPath,
		authType:   cfg.AuthType,
	}
	return c.recordAuthUpdateOutcome(ctx, nodeName, policy, outcome, policy.keyPath, rootConn)
}

func (c *Connector) recordAuthUpdateOutcome(
	ctx context.Context,
	nodeName string,
	policy dialPolicy,
	outcome authOutcome,
	recordKeyPath string,
	rootConn net.Conn,
) (string, error) {
	if (outcome.password == "" && outcome.passphrase == "") || policy.authUpdateToken == "" {
		return policy.authUpdateToken, nil
	}
	if recordKeyPath == "" {
		recordKeyPath = policy.keyPath
	}
	committedToken, err := c.credentialRecorder.UpdateAuth(ctx, nodeName, policy.authUpdateToken, outcome.password, recordKeyPath, outcome.passphrase)
	if err != nil {
		if reportCredentialFailure(ctx, c.getNodeSecretPrompter(policy.readOnlyConfig()), "save", err) {
			return "", errCredentialNotSaved
		}
		if closeErr := rootConn.Close(); closeErr != nil {
			return "", fmt.Errorf("failed to update authentication for node '%s': %w; close unpublished SSH client failed: %w", nodeName, err, closeErr)
		}
		return "", fmt.Errorf("failed to update authentication for node '%s': %w", nodeName, err)
	}
	return committedToken, nil
}

func shouldRecordDiscoveredAuth(outcome authOutcome, oldAuthToken string) bool {
	if !outcome.discovered || oldAuthToken == "" {
		return false
	}
	return outcome.password != "" || outcome.passphrase != ""
}

func (c *Connector) recordAndSyncAuthAfterHandshake(
	ctx context.Context,
	nodeName string,
	policy dialPolicy,
	outcome authOutcome,
	rootConn net.Conn,
) (ConnectionConfig, *ClientConfig, error) {
	oldAuthToken := policy.authUpdateToken
	discoveredKeyPath := ""
	if outcome.passphrase != "" && outcome.keyPath != "" {
		discoveredKeyPath = outcome.keyPath
	}

	hasAuthUpdate := shouldRecordDiscoveredAuth(outcome, oldAuthToken)
	var committedAuthToken string
	recordingFailed := false
	if hasAuthUpdate {
		recordKeyPath := policy.keyPath
		if discoveredKeyPath != "" {
			recordKeyPath = discoveredKeyPath
		}
		var err error
		committedAuthToken, err = c.recordAuthUpdateOutcome(ctx, nodeName, policy, outcome, recordKeyPath, rootConn)
		if errors.Is(err, errCredentialNotSaved) {
			recordingFailed = true
			hasAuthUpdate = false
		} else if err != nil {
			return ConnectionConfig{}, nil, err
		}
	}

	finalConnCfg := policy.toConnectionConfig()
	if outcome.authType != "" {
		finalConnCfg.AuthType = outcome.authType
	}

	reloadedCfg, err := c.syncRecordedConnection(
		nodeName, &finalConnCfg, oldAuthToken, committedAuthToken, hasAuthUpdate, recordingFailed,
		policy.keyPath, policy.keyPaths, discoveredKeyPath, rootConn,
	)
	if err != nil {
		return ConnectionConfig{}, nil, err
	}

	if recordingFailed {
		finalConnCfg.AuthUpdateToken = ""
		finalConnCfg.SudoUpdateToken = ""
	}
	return finalConnCfg, reloadedCfg, nil
}

func (c *Connector) initializeConnection(ctx context.Context, planNode connectionPlanNode, dialer Dialer, expectParent *PooledClient) (_ *Client, retErr error) {
	nodeName := planNode.name
	policy := freezeDialPolicy(planNode.cfg)
	attempt := newHandshakeAttempt(planNode.cfg, nil)
	defer attempt.scrub()

	roPolicy := policy.readOnlyConfig()
	coordinator := newHandshakeCoordinator(ctx, c.getNodeHandshakeTimeout(roPolicy))
	defer coordinator.Close()

	var initialHandshakeDone atomic.Bool
	authentication := newAuthenticationTrace(c.diagnostics, nodeName)
	sshConfig, cleanup, err := c.buildSSHConfigWithState(ctx, policy, attempt, coordinator, &initialHandshakeDone, authentication)
	if err != nil {
		return nil, fmt.Errorf("failed to build ssh config for '%s': %w", nodeName, err)
	}
	if cleanup != nil {
		cleanup = sync.OnceValue(cleanup)
		defer func() { retErr = errors.Join(retErr, cleanup()) }()
	}

	// 共享任务不继承任一调用者的 deadline，由 coordinator 统一施加有界超时并在交互时暂停；
	// 这同时约束直连和 ProxyJump 的通道建立，避免共享任务无限占用 singleflight。
	rawClient, rootConn, err := c.dialAndHandshake(coordinator.Context(), nodeName, policy, dialer, sshConfig, coordinator, authentication)
	if err != nil {
		return nil, fmt.Errorf("failed to dial and handshake: %w", err)
	}
	initialHandshakeDone.Store(true)
	if cleanup != nil {
		if err := cleanup(); err != nil {
			return nil, errors.Join(fmt.Errorf("release SSH authentication material: %w", err), closeResource(rawClient, "SSH client after authentication cleanup"), closeResource(rootConn, "SSH transport after authentication cleanup"))
		}
	}
	transportRoot := rootConn
	if proxy, ok := dialer.(*SSHProxyDialer); ok && proxy.RootConn != nil {
		transportRoot = proxy.RootConn
	}
	pooled := &PooledClient{
		SSHClient: rawClient,
		RootConn:  transportRoot,
		hopConn:   rootConn,
		parentKey: planNode.parentDigest,
		pool:      c.pool,
	}
	client := c.wrapAuthenticatedClient(policy, attempt, pooled)
	outcome := attempt.outcome()
	if err := checkInitializedTransport(nodeName, policy, outcome, rootConn, client); err != nil {
		return nil, err
	}

	finalConnCfg, reloadedCfg, err := c.recordAndSyncAuthAfterHandshake(ctx, nodeName, policy, outcome, rootConn)
	if err != nil {
		return nil, err
	}
	attempt.scrub()

	if err := checkInitializedTransport(nodeName, policy, outcome, rootConn, client); err != nil {
		return nil, err
	}
	client.cfgMu.Lock()
	client.connCfg = finalConnCfg
	client.cfgMu.Unlock()

	var publishedCfg *ClientConfig
	if reloadedCfg != nil {
		publishedCfg = NewClientConfig(*reloadedCfg)
		if planNode.cfg != nil {
			publishedCfg.ProxyJump = planNode.cfg.ProxyJump
		}
	} else if planNode.cfg != nil {
		publishedCfg = NewClientConfig(*planNode.cfg)
	}

	pooled.probeMu.Lock()
	pooled.Snapshot = finalConnCfg.Clone()
	pooled.hasSnapshot = true
	pooled.publishedCfg = publishedCfg
	pooled.probeMu.Unlock()

	hopKey := planNode.hopDigest()
	if publishedCfg != nil {
		hopKey = DigestClientConfig(publishedCfg, planNode.parentDigest)
	}
	if _, err := c.publishPooled(hopKey, pooled, expectParent, roPolicy); err != nil {
		if errors.Is(err, errStaleParentGeneration) {
			return nil, fmt.Errorf("rebuild proxy chain for '%s': %w", nodeName, errors.Join(errProxyTransportClosed, err))
		}
		return nil, err
	}
	// Start multiplexing master if configured. Pass rootConn (this hop's own
	// connection, not the bastion's transportRoot) as RootConn so shutting down
	// a jump-target master over a healthy bastion never closes the underlying
	// bastion TCP connection, while passing transportRoot as PhysicalRootConn
	// so bounded shutdown can escalate if the bastion is write-wedged.
	c.maybeStartMasterListener(planNode, finalConnCfg.KeyPath, rawClient, rootConn, transportRoot, pooled)
	return client, nil
}

func checkInitializedTransport(nodeID string, policy dialPolicy, outcome authOutcome, hopConn net.Conn, client *Client) error {
	if err := client.transportError(); err != nil {
		authType := outcome.authType
		if authType == "" {
			authType = policy.authType
		}
		connectionErr := &ConnectionError{
			NodeID:   nodeID,
			Address:  policy.address,
			Port:     policy.port,
			AuthType: authType,
			Err:      fmt.Errorf("SSH transport closed during initialization: %w", err),
		}
		var rawClient *ssh.Client
		if client != nil {
			rawClient = client.sshClient
		}
		return errors.Join(connectionErr, interruptSSHTransport(hopConn, rawClient))
	}
	return nil
}

func (c *Connector) syncRecordedConnection(
	nodeName string,
	connCfg *ConnectionConfig,
	oldAuthToken string,
	committedAuthToken string,
	hasAuthUpdate bool,
	recordingFailed bool,
	originalKeyPath string,
	originalKeyPaths []string,
	discoveredKeyPath string,
	rootConn net.Conn,
) (*ClientConfig, error) {
	if c.provider == nil {
		if hasAuthUpdate && discoveredKeyPath != "" && committedAuthToken != oldAuthToken {
			connCfg.KeyPath = discoveredKeyPath
		}
		return nil, nil
	}
	newCfg, err := c.reloadConfigAfterRecording(nodeName, hasAuthUpdate, rootConn)
	if err != nil || newCfg == nil {
		return nil, err
	}

	expected := *connCfg
	expected.KeyPath = originalKeyPath
	expected.KeyPaths = slices.Clone(originalKeyPaths)
	if hasAuthUpdate {
		if err := applyCommittedAuthMetadata(connCfg, newCfg, nodeName, committedAuthToken, rootConn); err != nil {
			return nil, err
		}
		expected.AuthUpdateToken = connCfg.AuthUpdateToken
	} else if recordingFailed {
		// Uncertain durability write: caller clears AuthUpdateToken/SudoUpdateToken
		// immediately after syncRecordedConnection, so allow an advanced token here
		// while still validating all host, trust, auth-type, and option fields.
		expected.AuthUpdateToken = newCfg.AuthUpdateToken
	}
	mayHavePersistedKey := discoveredKeyPath != "" && ((hasAuthUpdate && committedAuthToken != "" && committedAuthToken != oldAuthToken) || recordingFailed)
	if mayHavePersistedKey && isCompatibleRecordedKeyProjection(originalKeyPath, originalKeyPaths, discoveredKeyPath, newCfg.KeyPath, newCfg.KeyPaths) {
		expected.KeyPath = newCfg.KeyPath
		expected.KeyPaths = slices.Clone(newCfg.KeyPaths)
	}

	// [P1] 校验完整连接目标是否仍然与当前已建立的连接一致
	if err := checkTargetDigestCompatibility(expected, newCfg); err != nil {
		return nil, closeRootConnWithError(rootConn, fmt.Sprintf("incompatible target update for node %q during connection setup", nodeName), err)
	}

	connCfg.KeyPath = newCfg.KeyPath
	connCfg.KeyPaths = slices.Clone(newCfg.KeyPaths)
	return newCfg, nil
}

func (c *Connector) reloadConfigAfterRecording(nodeName string, hasAuthUpdate bool, rootConn net.Conn) (*ClientConfig, error) {
	newCfg, err := c.provider.GetConfig(nodeName)
	if err != nil {
		if hasAuthUpdate {
			return nil, closeRootConnWithError(rootConn, fmt.Sprintf("reload config for node %q after auth update failed", nodeName), err)
		}
		return nil, closeRootConnWithError(rootConn, fmt.Sprintf("reload config for node %q failed", nodeName), err)
	}
	if newCfg == nil {
		if hasAuthUpdate {
			return nil, closeRootConnWithError(rootConn, fmt.Sprintf("reload config for node %q after auth update failed", nodeName), ErrSnapshotMismatch)
		}
		return nil, nil
	}
	norm := NewClientConfig(*newCfg)
	norm.Control = normalizeControlConfig(c.resolveControl(nodeName, norm))
	return norm, nil
}

func applyCommittedAuthMetadata(connCfg *ConnectionConfig, newCfg *ClientConfig, nodeName, committedAuthToken string, rootConn net.Conn) error {
	// [P1] 校验刷新版本与本次写回的对应关系：必须严格等于本次事务实际提交的版本，拒绝采纳后续无关更新，且允许幂等未变
	if committedAuthToken != "" && newCfg.AuthUpdateToken != committedAuthToken {
		mismatchErr := fmt.Errorf("%w: auth version mismatch after update for node %q (expected %q, got %q)",
			ErrSnapshotMismatch, nodeName, committedAuthToken, newCfg.AuthUpdateToken)
		if closeErr := rootConn.Close(); closeErr != nil {
			return fmt.Errorf("%w; close unpublished SSH client failed: %w", mismatchErr, closeErr)
		}
		return mismatchErr
	}
	connCfg.AuthUpdateToken = newCfg.AuthUpdateToken
	if newCfg.HasOriginalProxyJump {
		connCfg.OriginalProxyJump = newCfg.OriginalProxyJump
		connCfg.HasOriginalProxyJump = true
	} else if newCfg.OriginalProxyJump != "" {
		connCfg.OriginalProxyJump = newCfg.OriginalProxyJump
	}
	return nil
}

func closeRootConnWithError(rootConn net.Conn, contextMsg string, cause error) error {
	if closeErr := rootConn.Close(); closeErr != nil {
		return fmt.Errorf("%s: %w; close unpublished SSH client failed: %w", contextMsg, cause, closeErr)
	}
	return fmt.Errorf("%s: %w", contextMsg, cause)
}

func isCompatibleRecordedKeyProjection(origKeyPath string, origKeyPaths []string, discoveredKeyPath, newKeyPath string, newKeyPaths []string) bool {
	if newKeyPath != origKeyPath && newKeyPath != discoveredKeyPath {
		return false
	}
	if slices.Equal(newKeyPaths, origKeyPaths) {
		return true
	}
	if countKeyOccurrences(newKeyPaths, discoveredKeyPath) != 1 {
		return false
	}
	remNew := filterOutKeyPath(newKeyPaths, discoveredKeyPath)
	remOrig := filterOutKeyPath(origKeyPaths, discoveredKeyPath)
	if slices.Equal(remNew, remOrig) {
		return true
	}
	return len(remOrig) == len(remNew)+1 && isSingleDeletionSubsequence(remNew, remOrig)
}

func countKeyOccurrences(paths []string, target string) int {
	count := 0
	for _, p := range paths {
		if p == target {
			count++
		}
	}
	return count
}

func filterOutKeyPath(paths []string, target string) []string {
	var out []string
	for _, p := range paths {
		if p != target {
			out = append(out, p)
		}
	}
	return out
}

func isSingleDeletionSubsequence(shorter, longer []string) bool {
	if len(longer) != len(shorter)+1 {
		return false
	}
	i, j := 0, 0
	skipped := false
	for i < len(shorter) && j < len(longer) {
		if shorter[i] == longer[j] {
			i++
			j++
			continue
		}
		if skipped {
			return false
		}
		skipped = true
		j++
	}
	return i == len(shorter)
}

func (c *Connector) initHandshakeDeadline(ctx context.Context, conn net.Conn, nodeName string, timeout time.Duration, coordinator *handshakeCoordinator) error {
	if coordinator != nil {
		if err := coordinator.SetConn(conn); err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				return fmt.Errorf("%w; close connection after deadline setup failed: %w", err, closeErr)
			}
			return err
		}
		return nil
	}
	return setInitialHandshakeDeadline(ctx, conn, nodeName, timeout)
}

func handshakeCancelError(ctx context.Context, coordinator *handshakeCoordinator, nodeName string) error {
	if coordinator != nil && (coordinator.Context().Err() != nil || coordinator.Err() != nil) {
		cause := coordinator.Err()
		if cause == nil {
			cause = coordinator.Context().Err()
		}
		return fmt.Errorf("ssh handshake canceled for '%s': %w", nodeName, cause)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("ssh handshake canceled for '%s': %w", nodeName, ctx.Err())
	}
	return nil
}

func isHandshakeTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "i/o timeout")
}

func (c *Connector) handleHandshakeFailure(ctx context.Context, coordinator *handshakeCoordinator, nodeName string, conn net.Conn, handshakeErr error) error {
	closeErr := conn.Close()
	if isHandshakeTimeoutError(handshakeErr) && coordinator != nil {
		coordinator.FailClosed(context.DeadlineExceeded)
	}
	if cancelErr := handshakeCancelError(ctx, coordinator, nodeName); cancelErr != nil {
		return combineSSHOperationErrors(cancelErr, wrapCloseError(closeErr, "close canceled SSH handshake connection"))
	}
	if isHandshakeTimeoutError(handshakeErr) {
		timeoutErr := fmt.Errorf("ssh handshake timeout for '%s': %w", nodeName, errors.Join(&HandshakeError{NodeID: nodeName, Err: handshakeErr}, context.DeadlineExceeded))
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return fmt.Errorf("%w; close failed SSH handshake connection: %w", timeoutErr, closeErr)
		}
		return timeoutErr
	}
	if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return fmt.Errorf(
			"ssh handshake failed for '%s': %w; close failed SSH handshake connection: %w",
			nodeName,
			&HandshakeError{NodeID: nodeName, Err: handshakeErr},
			closeErr,
		)
	}
	return &HandshakeError{NodeID: nodeName, Err: handshakeErr}
}

func (c *Connector) resolveHandshakeDialer(nodeName string, policy dialPolicy, dialer Dialer) (Dialer, bool, bool) {
	if dialer == nil && policy.proxyJump == "" && policy.options.ActiveProxyCommand() != "" {
		roCfg := policy.readOnlyConfig()
		dialer = &proxyCommandDialer{
			connector: c,
			planNode:  connectionPlanNode{name: nodeName, cfg: roCfg},
		}
	}
	roCfg := policy.readOnlyConfig()
	if dialer == nil {
		dialer = c.baseDialer
	}
	if dialer == nil {
		dialer = c.directDialerFor(roCfg)
	}
	_, isJump := dialer.(*SSHProxyDialer)
	_, isProxyCmd := dialer.(*proxyCommandDialer)
	return dialer, isJump, isProxyCmd
}

func (c *Connector) dialAndHandshake(ctx context.Context, nodeName string, policy dialPolicy, dialer Dialer, sshConfig *ssh.ClientConfig, coordinator *handshakeCoordinator, authentication *authenticationTrace) (*ssh.Client, net.Conn, error) {
	var isJump, isProxyCmd bool
	dialer, isJump, isProxyCmd = c.resolveHandshakeDialer(nodeName, policy, dialer)
	targetAddr := joinHostPort(policy.address, policy.port)
	event := logger.Diagnostic{Kind: logger.Connecting, NodeID: nodeName, Host: policy.address, User: policy.user, Port: policy.port, Proxied: isJump || isProxyCmd}
	logger.EmitDiagnostic(c.diagnostics, event)
	conn, err := dialer.DialContext(ctx, policy.options.DialNetwork(), targetAddr)
	if err != nil {
		event.Kind = logger.HandshakeFailed
		logger.EmitDiagnostic(c.diagnostics, event)
		if isHandshakeTimeoutError(err) && coordinator != nil {
			coordinator.FailClosed(context.DeadlineExceeded)
		}
		dialErr := err
		if cancelErr := handshakeCancelError(ctx, coordinator, nodeName); cancelErr != nil {
			dialErr = fmt.Errorf("%w: %w", cancelErr, err)
		} else if isHandshakeTimeoutError(err) {
			dialErr = fmt.Errorf("%w: %w", context.DeadlineExceeded, err)
		}
		return nil, nil, &ConnectionError{
			NodeID:   nodeName,
			Address:  policy.address,
			Port:     policy.port,
			AuthType: policy.authType,
			Err:      dialErr,
		}
	}
	event.Kind = logger.Connected
	logger.EmitDiagnostic(c.diagnostics, event)
	if !isJump {
		conn = &physicalSSHConn{Conn: conn}
	}
	roCfg := policy.readOnlyConfig()
	if err := c.initHandshakeDeadline(ctx, conn, nodeName, c.getNodeHandshakeTimeout(roCfg), coordinator); err != nil {
		return nil, nil, err
	}
	stopCancelClose := context.AfterFunc(ctx, func() {
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			c.getLogger().Debugf("close SSH handshake connection after cancellation failed: %v", closeErr)
		}
	})

	// 建立 SSH 会话
	// 使用 NewClientConn 接管底层的 conn
	activity := &sshActivityConn{Conn: conn, startedAt: time.Now()}
	ncc, chans, reqs, err := ssh.NewClientConn(activity, targetAddr, sshConfig)
	if err != nil {
		stopCancelClose()
		event.Kind = logger.HandshakeFailed
		logger.EmitDiagnostic(c.diagnostics, event)
		return nil, nil, c.handleHandshakeFailure(ctx, coordinator, nodeName, conn, err)
	}
	stoppedCancelClose := stopCancelClose()
	if ctx.Err() != nil || !stoppedCancelClose {
		closeErr := abortUnclaimedSSHConn(ncc, chans, reqs)
		cancelErr := handshakeCancelError(ctx, coordinator, nodeName)
		if cancelErr == nil {
			cancelErr = fmt.Errorf("ssh handshake canceled for '%s': %w", nodeName, context.Canceled)
		}
		return nil, nil, combineSSHOperationErrors(cancelErr, wrapCloseError(closeErr, "close canceled SSH connection"))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		if !strings.Contains(err.Error(), "deadline not supported") {
			if closeErr := abortUnclaimedSSHConn(ncc, chans, reqs); closeErr != nil {
				return nil, nil, fmt.Errorf(
					"clear SSH connection deadline for '%s' failed: %w; close SSH connection after clearing deadline failed: %w",
					nodeName,
					err,
					closeErr,
				)
			}
			return nil, nil, fmt.Errorf("clear SSH connection deadline for '%s' failed: %w", nodeName, err)
		}
	}

	c.observeAuthenticated(ncc, event, authentication)
	return ssh.NewClient(&activitySSHConn{Conn: ncc, activity: activity}, chans, reqs), conn, nil
}

func (c *Connector) observeAuthenticated(ncc ssh.Conn, event logger.Diagnostic, authentication *authenticationTrace) {
	if c.diagnostics == nil {
		return
	}
	event.Kind = logger.Authenticated
	event.Methods = authentication.successfulMethods()
	if len(event.Methods) > 0 {
		event.Method = event.Methods[len(event.Methods)-1]
	}
	event.ClientVersion, event.ServerVersion = string(ncc.ClientVersion()), string(ncc.ServerVersion())
	if metadata, ok := ncc.(ssh.AlgorithmsConnMetadata); ok {
		algorithms := metadata.Algorithms()
		event.KeyExchange, event.HostKey = algorithms.KeyExchange, algorithms.HostKey
		event.ReadCipher, event.WriteCipher = algorithms.Read.Cipher, algorithms.Write.Cipher
		event.ReadMAC, event.WriteMAC = algorithms.Read.MAC, algorithms.Write.MAC
	}
	logger.EmitDiagnostic(c.diagnostics, event)
}

func (c *Connector) resolvePasswordAuth(cfg *ClientConfig) (ssh.AuthMethod, error) {
	policy := freezeDialPolicy(cfg)
	attempt := newHandshakeAttempt(cfg, nil)
	defer attempt.scrub()
	return c.resolvePasswordAuthWithPolicy(policy, attempt)
}

func (c *Connector) resolvePasswordAuthWithPolicy(policy dialPolicy, attempt *handshakeAttempt) (ssh.AuthMethod, error) {
	pwd := attempt.consumeInitialPassword()
	if pwd == "" {
		secret, err := c.resolveSecret(policy.readOnlyConfig(), SecretRequest{
			Kind:         SecretKindLoginPassword,
			NodeID:       policy.nodeID,
			User:         policy.user,
			Host:         policy.address,
			BaseHost:     policy.baseHost,
			Port:         policy.port,
			VersionToken: policy.authUpdateToken,
		})
		if len(secret) > 0 {
			defer zeroBytes(secret)
		}
		if err == nil && len(secret) > 0 {
			pwd = string(secret)
		} else if err != nil && !errors.Is(err, ErrInteractionRequired) {
			return nil, fmt.Errorf("resolve login password failed: %w", err)
		}
	}
	if pwd == "" {
		return nil, ErrPasswordRequired
	}
	return ssh.Password(pwd), nil
}

func (c *Connector) authTargetContext(cfg *ClientConfig) TargetContext {
	if cfg == nil {
		return TargetContext{}
	}
	port := cfg.Port
	if port <= 0 {
		port = 22
	}
	user := cfg.User
	if user == "" {
		user = c.environment.LocalUser
	}
	return TargetContext{
		Host:         cleanHostLiteral(cfg.Address),
		Port:         port,
		User:         user,
		OriginalHost: effectiveOriginalHost(cfg.OriginalHost, cfg.NodeID),
		JumpHost:     NormalizeProxyJump(cfg.ProxyJump),
	}
}

func (c *Connector) explicitKeyPaths(cfg *ClientConfig) ([]string, bool) {
	if cfg == nil {
		return nil, false
	}
	return collectExplicitKeyCandidates(
		cfg.KeyPaths,
		cfg.KeyPath,
		cfg.Options,
		c.environment,
		c.authTargetContext(cfg),
		c.environment.ResolveKeyPath,
		c.getLogger(),
	)
}

func (c *Connector) resolveConfigAgentSocket(cfg *ClientConfig) (string, error) {
	var spec string
	if cfg != nil {
		spec = cfg.Options.IdentityAgent()
	}
	sock, disabled, err := ResolveIdentityAgent(spec, c.environment, c.authTargetContext(cfg))
	if err != nil {
		return "", err
	}
	if disabled || sock == "" {
		return "", ErrAgentNotAvailable
	}
	return sock, nil
}

func (c *Connector) resolveAgentAuth(ctx context.Context, authCtx context.Context, cfg *ClientConfig) ([]autoAuthCandidate, ssh.AuthMethod, func(), error) {
	socket, err := c.resolveConfigAgentSocket(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	agentClient, cleanup, err := dialBoundedAgentClient(ctx, authCtx, c.environment.DialAgent, socket, c.getNodeHandshakeTimeout(cfg), c.getLogger())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to connect to ssh-agent: %w", err)
	}

	var sshOpts *Options
	if cfg != nil {
		sshOpts = cfg.Options
	}
	materialPolicy := newAdmittedMaterialPolicyFromConfig(cfg)
	explicitCerts, _ := collectExplicitUserCerts(
		sshOpts,
		c.environment,
		c.authTargetContext(cfg),
		c.environment.ResolveKeyPath,
		c.getLogger(),
		materialPolicy,
	)
	if len(explicitCerts) > 0 {
		signers, signersErr := agentClient.Signers()
		if signersErr != nil {
			cleanup()
			return nil, nil, nil, fmt.Errorf("list ssh-agent signers: %w", signersErr)
		}
		tracker := newOfferedPubKeyTracker()
		agentByPub := indexAgentSignersByPubKey(signers)
		var certCandidates []autoAuthCandidate
		pairedCertPaths := make(map[string]struct{}, len(explicitCerts))
		appendUnpairedExplicitCertsFromAgent(&certCandidates, pairedCertPaths, agentByPub, explicitCerts, "ssh-agent (cert): ", nil, tracker)
		if len(certCandidates) > 0 {
			cachedSigners := func() ([]ssh.Signer, error) { return signers, nil }
			certCandidates = append(certCandidates, autoAuthCandidate{
				protocol: autoAuthProtocolPublicKey,
				label:    "ssh-agent",
				method:   ssh.PublicKeysCallback(tracker.filterAgentSigners(cachedSigners)),
			})
			return certCandidates, nil, cleanup, nil
		}
		return nil, ssh.PublicKeys(signers...), cleanup, nil
	}
	return nil, ssh.PublicKeysCallback(agentClient.Signers), cleanup, nil
}

func (c *Connector) resolveFilteredAgentAuth(ctx context.Context, authCtx context.Context, cfg *ClientConfig, explicitPaths []string) ([]autoAuthCandidate, func(), error) {
	socket, err := c.resolveConfigAgentSocket(cfg)
	if err != nil {
		return nil, nil, err
	}
	agentClient, cleanup, err := dialBoundedAgentClient(ctx, authCtx, c.environment.DialAgent, socket, c.getNodeHandshakeTimeout(cfg), c.getLogger())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to ssh-agent: %w", err)
	}
	signers, err := agentClient.Signers()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("list ssh-agent signers: %w", err)
	}
	agentByPub := indexAgentSignersByPubKey(signers)

	var sshOpts *Options
	if cfg != nil {
		sshOpts = cfg.Options
	}
	materialPolicy := newAdmittedMaterialPolicyFromConfig(cfg)
	explicitCerts, hasExplicitCerts := collectExplicitUserCerts(
		sshOpts,
		c.environment,
		c.authTargetContext(cfg),
		c.environment.ResolveKeyPath,
		c.getLogger(),
		materialPolicy,
	)

	var certCandidates []autoAuthCandidate
	var plainCandidates []autoAuthCandidate
	pairedCertPaths := make(map[string]struct{})
	tracker := newOfferedPubKeyTracker()

	for _, keyPath := range explicitPaths {
		if _, matchErr := appendAgentMatchedKeyPath(
			&certCandidates, &plainCandidates, pairedCertPaths, agentByPub,
			keyPath, "explicit key", explicitCerts, hasExplicitCerts,
			nil, tracker, materialPolicy, true, c.getLogger(),
		); matchErr != nil {
			cleanup()
			return nil, nil, matchErr
		}
	}
	appendUnpairedExplicitCertsFromAgent(&certCandidates, pairedCertPaths, agentByPub, explicitCerts, "ssh-agent (IdentitiesOnly cert): ", nil, tracker)

	candidates := append(certCandidates, plainCandidates...)
	if len(candidates) == 0 {
		cleanup()
		return nil, nil, errors.New("no ssh-agent identity matches explicit identity files under IdentitiesOnly=yes")
	}
	return candidates, cleanup, nil
}

func (c *Connector) appendMFACallbackCandidate(
	policy authPolicy,
	secProvider *autoSecretProvider,
	candidates []autoAuthCandidate,
) []autoAuthCandidate {
	if policy.kbAllowed && secProvider != nil {
		candidates = append(candidates, autoAuthCandidate{
			protocol: autoAuthProtocolKeyboardInteractive,
			label:    "keyboard-interactive",
			method:   buildKeyboardInteractiveAuthMethod(secProvider),
			allow: func(ctx *ssh.ClientAuthContext) bool {
				return len(ctx.PartialSuccessMethods) > 0
			},
		})
	}
	return candidates
}

type multiKeySecretPrompter struct {
	passphrasePrompter SecretPrompter
	otherPrompter      SecretPrompter
}

func (p multiKeySecretPrompter) PromptSecret(ctx context.Context, req SecretRequest) (string, error) {
	target := p.otherPrompter
	if req.Kind == SecretKindPrivateKeyPassphrase {
		target = p.passphrasePrompter
	}
	if target == nil {
		return "", ErrInteractionRequired
	}
	return target.PromptSecret(ctx, req)
}

type multiKeyCandidateState struct {
	certCandidates  []autoAuthCandidate
	plainCandidates []autoAuthCandidate
	pairedCertPaths map[string]struct{}
	tracker         *offeredPubKeyTracker
}

func newMultiKeyCandidateState(sourced *sourcedKeyBundle, rejectPublicKey func()) *multiKeyCandidateState {
	st := &multiKeyCandidateState{
		pairedCertPaths: make(map[string]struct{}),
		tracker:         newOfferedPubKeyTracker(),
	}
	if sourced == nil {
		return st
	}
	if sourced.pubKey != nil {
		st.tracker.recordStatic(sourced.pubKey)
	}
	for _, cm := range sourced.certMethods {
		if _, already := st.pairedCertPaths[cm.certPath]; already {
			continue
		}
		st.pairedCertPaths[cm.certPath] = struct{}{}
		if cm.certPub != nil {
			st.tracker.recordStatic(cm.certPub)
		}
		st.certCandidates = append(st.certCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      "explicit signer (cert): " + cm.certPath,
			method:     cm.method,
			onRejected: rejectPublicKey,
		})
	}
	if sourced.plainMethod != nil {
		st.plainCandidates = append(st.plainCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      "explicit signer",
			method:     sourced.plainMethod,
			onRejected: rejectPublicKey,
		})
	}
	return st
}

func (c *Connector) buildMultiKeyAuth(
	ctx context.Context,
	authCtx context.Context,
	cfg *ClientConfig,
	attempt *handshakeAttempt,
	explicitPaths []string,
	sourced *sourcedKeyBundle,
	policy authPolicy,
	prompter SecretPrompter,
	coordinator *handshakeCoordinator,
	observer logger.DiagnosticObserver,
) (ssh.ClientAuthCallback, func() error, error) {
	l := c.getLogger()
	materialPolicy := newAdmittedMaterialPolicyFromConfig(cfg)
	explicitCerts, hasExplicitCerts := collectExplicitUserCerts(
		cfg.Options,
		c.environment,
		c.authTargetContext(cfg),
		c.environment.ResolveKeyPath,
		l,
		materialPolicy,
	)
	if sourced == nil && len(explicitPaths) == 0 && len(explicitCerts) == 0 {
		return nil, nil, ErrKeyPathRequired
	}
	var failClosed func(error)
	if coordinator != nil {
		failClosed = coordinator.FailClosed
	}
	basePrompter := c.getNodeSecretPrompter(cfg)
	recovery := credentialRecoveryPrompter(basePrompter)
	var activePrompter SecretPrompter = rejectInteraction{}
	if recovery != nil {
		activePrompter = prompter
	}
	resolver := &initialKeySecretResolver{value: attempt.consumeInitialPassphrase(), next: c.secretResolver}
	cleanup := func() error {
		resolver.mu.Lock()
		zeroBytes(resolver.value)
		resolver.value = nil
		resolver.mu.Unlock()
		return sourced.close()
	}
	handshakeTimeout := c.getNodeHandshakeTimeout(cfg)
	provider := &autoSecretProvider{
		lifecycleCtx:       authCtx,
		nodeID:             cfg.NodeID,
		user:               cfg.User,
		host:               cfg.Address,
		baseHost:           cfg.BaseHost,
		port:               cfg.Port,
		versionToken:       cfg.AuthUpdateToken,
		resolver:           resolver,
		prompter:           multiKeySecretPrompter{passphrasePrompter: activePrompter, otherPrompter: prompter},
		recoveryPrompter:   recovery,
		handshakeTimeout:   handshakeTimeout,
		interactionTimeout: c.interactionTimeout,
		failClosed:         failClosed,
	}

	rejectPublicKey := func() {
		attempt.rejectCandidate(autoAuthProtocolPublicKey)
	}
	state := newMultiKeyCandidateState(sourced, rejectPublicKey)
	passphraseCb := newMultiKeyPassphraseCallback(attempt, recovery != nil)
	var candidates []autoAuthCandidate
	var firstErr error
	var fatalErr error
	if policy.identitiesOnly {
		candidates, firstErr, fatalErr = c.buildIdentitiesOnlyMultiKeyCandidates(
			ctx, authCtx, cfg, state, explicitPaths, explicitCerts, hasExplicitCerts,
			provider, passphraseCb, rejectPublicKey, handshakeTimeout, &cleanup, materialPolicy, l,
		)
	} else {
		candidates, firstErr, fatalErr = c.buildAgentFallbackMultiKeyCandidates(
			ctx, authCtx, cfg, state, explicitPaths, explicitCerts, hasExplicitCerts,
			provider, passphraseCb, rejectPublicKey, &cleanup, materialPolicy, l,
		)
	}
	if fatalErr != nil {
		closeErr := cleanup()
		return nil, nil, errors.Join(fatalErr, closeErr)
	}
	if len(candidates) == 0 {
		closeErr := cleanup()
		if firstErr != nil {
			return nil, nil, errors.Join(firstErr, closeErr)
		}
		if policy.identitiesOnly && len(explicitCerts) > 0 {
			return nil, nil, errors.Join(errors.New("no ssh-agent or file identity matches explicit CertificateFile under IdentitiesOnly=yes"), closeErr)
		}
		return nil, nil, errors.Join(ErrKeyPathRequired, closeErr)
	}
	candidates = c.appendMFACallbackCandidate(policy, provider, candidates)
	return newSequentialAuthCallbackWithPolicy(candidates, policy, provider, l, observer), cleanup, nil
}

func (c *Connector) buildIdentitiesOnlyMultiKeyCandidates(
	ctx context.Context,
	authCtx context.Context,
	cfg *ClientConfig,
	state *multiKeyCandidateState,
	explicitPaths []string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	provider *autoSecretProvider,
	passphraseCb func(string, string),
	rejectPublicKey func(),
	handshakeTimeout time.Duration,
	cleanup *func() error,
	materialPolicy *admittedMaterialPolicy,
	l logger.DebugLogger,
) ([]autoAuthCandidate, error, error) {
	var agentByPub map[string]ssh.Signer
	if len(explicitPaths) > 0 || hasUnpairedExplicitCerts(explicitCerts, state.pairedCertPaths) {
		if socket, sockErr := c.resolveConfigAgentSocket(cfg); sockErr == nil {
			var agentCleanup func()
			agentByPub, agentCleanup = dialAgentSignersByPubKey(ctx, authCtx, c.environment.DialAgent, socket, handshakeTimeout, l)
			if agentCleanup != nil {
				prevCleanup := *cleanup
				*cleanup = func() error {
					agentCleanup()
					return prevCleanup()
				}
			}
		}
	}

	var firstErr error
	for _, keyPath := range explicitPaths {
		matched, matchErr := appendAgentMatchedKeyPath(
			&state.certCandidates, &state.plainCandidates, state.pairedCertPaths, agentByPub,
			keyPath, "explicit key", explicitCerts, hasExplicitCerts,
			rejectPublicKey, state.tracker, materialPolicy, true, l,
		)
		if matchErr != nil {
			return nil, nil, matchErr
		}
		if matched {
			continue
		}
		certMethods, plainMethod, absentAllowed, err := resolveKeySignersWithPolicy(
			keyPath, explicitCerts, hasExplicitCerts, provider, passphraseCb, state.tracker, false, materialPolicy, true, l,
		)
		if err != nil {
			if materialPolicy != nil && materialPolicy.enforceKeys && errors.Is(err, ErrSnapshotMismatch) {
				return nil, nil, err
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if absentAllowed {
			continue
		}
		appendResolvedMultiKeyCandidate(keyPath, certMethods, plainMethod, rejectPublicKey, state.pairedCertPaths, &state.certCandidates, &state.plainCandidates)
	}

	appendUnpairedExplicitCertsFromAgent(&state.certCandidates, state.pairedCertPaths, agentByPub, explicitCerts, "ssh-agent (IdentitiesOnly cert): ", rejectPublicKey, state.tracker)
	return append(state.certCandidates, state.plainCandidates...), firstErr, nil
}

func (c *Connector) buildAgentFallbackMultiKeyCandidates(
	ctx context.Context,
	authCtx context.Context,
	cfg *ClientConfig,
	state *multiKeyCandidateState,
	explicitPaths []string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	provider *autoSecretProvider,
	passphraseCb func(string, string),
	rejectPublicKey func(),
	cleanup *func() error,
	materialPolicy *admittedMaterialPolicy,
	l logger.DebugLogger,
) ([]autoAuthCandidate, error, error) {
	agentClient, agentByPub, agentSignersFn := c.openMultiKeyFallbackAgent(
		ctx, authCtx, cfg, explicitPaths, explicitCerts, hasExplicitCerts, cleanup, materialPolicy, l,
	)

	var firstErr error
	for _, keyPath := range explicitPaths {
		if v, _ := isUnencryptedPrivateKeyFile(keyPath, materialPolicy); !v.Allowed() {
			matched, matchErr := appendAgentMatchedKeyPath(
				&state.certCandidates, &state.plainCandidates, state.pairedCertPaths, agentByPub,
				keyPath, "explicit key", explicitCerts, hasExplicitCerts,
				rejectPublicKey, state.tracker, materialPolicy, true, l,
			)
			if matchErr != nil {
				return nil, nil, matchErr
			}
			if matched {
				continue
			}
		}
		certMethods, plainMethod, absentAllowed, err := resolveKeySignersWithPolicy(
			keyPath, explicitCerts, hasExplicitCerts, provider, passphraseCb, state.tracker, false, materialPolicy, true, l,
		)
		if err != nil {
			if materialPolicy != nil && materialPolicy.enforceKeys && errors.Is(err, ErrSnapshotMismatch) {
				return nil, nil, err
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if absentAllowed {
			continue
		}
		appendResolvedMultiKeyCandidate(keyPath, certMethods, plainMethod, rejectPublicKey, state.pairedCertPaths, &state.certCandidates, &state.plainCandidates)
	}

	appendUnpairedExplicitCertsFromAgent(&state.certCandidates, state.pairedCertPaths, agentByPub, explicitCerts, "ssh-agent (cert): ", rejectPublicKey, state.tracker)
	if agentClient != nil {
		state.plainCandidates = append(state.plainCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      "ssh-agent",
			method:     ssh.PublicKeysCallback(state.tracker.filterAgentSigners(agentSignersFn)),
			onRejected: rejectPublicKey,
		})
	}
	return append(state.certCandidates, state.plainCandidates...), firstErr, nil
}

func (c *Connector) openMultiKeyFallbackAgent(
	ctx context.Context,
	authCtx context.Context,
	cfg *ClientConfig,
	explicitPaths []string,
	explicitCerts []loadedUserCert,
	hasExplicitCerts bool,
	cleanup *func() error,
	materialPolicy *admittedMaterialPolicy,
	l logger.DebugLogger,
) (*boundedAgentClient, map[string]ssh.Signer, func() ([]ssh.Signer, error)) {
	socket, err := c.resolveConfigAgentSocket(cfg)
	if err != nil {
		return nil, nil, nil
	}
	agentClient, agentCleanup, err := dialBoundedAgentClient(ctx, authCtx, c.environment.DialAgent, socket, c.getNodeHandshakeTimeout(cfg), l)
	if err != nil {
		l.Debugf("ssh-agent fallback unavailable: %v", err)
		return nil, nil, nil
	}
	prevCleanup := *cleanup
	*cleanup = func() error {
		agentCleanup()
		if prevCleanup != nil {
			return prevCleanup()
		}
		return nil
	}
	signersFn := agentClient.Signers
	var agentByPub map[string]ssh.Signer
	if shouldPreloadAgentSigners(explicitPaths, nil, explicitCerts, hasExplicitCerts, materialPolicy) {
		if signers, signersErr := agentClient.Signers(); signersErr != nil {
			l.Debugf("list ssh-agent signers failed: %v", signersErr)
		} else {
			agentByPub = indexAgentSignersByPubKey(signers)
			signersFn = func() ([]ssh.Signer, error) { return signers, nil }
		}
	}
	return agentClient, agentByPub, signersFn
}

func appendResolvedMultiKeyCandidate(
	keyPath string,
	certMethods []certAuthCandidateMethod,
	plainMethod ssh.AuthMethod,
	rejectPublicKey func(),
	pairedCertPaths map[string]struct{},
	certCandidates *[]autoAuthCandidate,
	plainCandidates *[]autoAuthCandidate,
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
			label:      "explicit key (cert): " + cm.certPath,
			method:     cm.method,
			onRejected: rejectPublicKey,
		})
	}
	if plainMethod != nil {
		*plainCandidates = append(*plainCandidates, autoAuthCandidate{
			protocol:   autoAuthProtocolPublicKey,
			label:      "explicit key: " + keyPath,
			method:     plainMethod,
			onRejected: rejectPublicKey,
		})
	}
}

func newMultiKeyPassphraseCallback(attempt *handshakeAttempt, allowRecord bool) func(string, string) {
	return func(path, passphrase string) {
		if allowRecord && passphrase != "" {
			attempt.recordPassphrase(path, passphrase)
		}
	}
}

// buildSSHConfig 根据 Identity 模型构建 ssh.ClientConfig，保持调用方 *ClientConfig 只读。
func (c *Connector) buildSSHConfig(ctx context.Context, cfg *ClientConfig, coordinator *handshakeCoordinator, onAuthDiscovered func(), authentication *authenticationTrace) (*ssh.ClientConfig, func() error, error) {
	policy := freezeDialPolicy(cfg)
	attempt := newHandshakeAttempt(cfg, onAuthDiscovered)
	sshCfg, cleanup, err := c.buildSSHConfigWithState(ctx, policy, attempt, coordinator, nil, authentication)
	if err != nil {
		attempt.scrub()
		return nil, nil, err
	}
	return sshCfg, func() error {
		attempt.scrub()
		if cleanup != nil {
			return cleanup()
		}
		return nil
	}, nil
}

//nolint:gocyclo // buildSSHConfigWithState coordinates multiple authentication strategies, host key verification, and diagnostics.
func (c *Connector) buildSSHConfigWithState(ctx context.Context, dialPolicy dialPolicy, attempt *handshakeAttempt, coordinator *handshakeCoordinator, initialHandshakeDone *atomic.Bool, authentication *authenticationTrace) (*ssh.ClientConfig, func() error, error) {
	cfg := dialPolicy.readOnlyConfig()
	observer := c.diagnostics
	if authentication != nil {
		observer = authentication
	}
	var cleanup func() error
	var authCallback ssh.ClientAuthCallback
	authMethods := []ssh.AuthMethod{}

	basePrompter := c.getNodeSecretPrompter(cfg)
	prompter := basePrompter
	authCtx := c.lifecycleCtx
	if coordinator != nil {
		authCtx = coordinator.Context()
		prompter = &coordinatingPrompter{
			prompter:    basePrompter,
			coordinator: coordinator,
		}
	}

	hostKeyChanged := &atomic.Bool{}
	policy := newAuthPolicy(dialPolicy.options, hostKeyChanged)
	pubkeyAllowed, passwordAllowed, kbAllowed := policy.pubkeyAllowed, policy.passwordAllowed, policy.kbAllowed

	// 根据 AuthType 处理不同的认证方式
	switch dialPolicy.authType {
	case "auto":
		var failClosed func(error)
		if coordinator != nil {
			failClosed = coordinator.FailClosed
		}
		plan, release, err := c.buildOwnedAutoAuth(ctx, cfg, AutoAuthOptions{
			AgentSocket:                 c.environment.AgentSocket,
			DialAgent:                   c.environment.DialAgent,
			DefaultKeyPaths:             c.environment.DefaultKeyPaths,
			ResolveKeyPath:              c.environment.ResolveKeyPath,
			Environment:                 c.environment,
			Target:                      dialPolicy.targetContext(c.environment),
			LifecycleCtx:                authCtx,
			NodeID:                      dialPolicy.nodeID,
			User:                        dialPolicy.user,
			Host:                        dialPolicy.address,
			BaseHost:                    dialPolicy.baseHost,
			Port:                        dialPolicy.port,
			VersionToken:                dialPolicy.authUpdateToken,
			Resolver:                    c.secretResolver,
			Prompter:                    prompter,
			HandshakeTimeout:            c.getNodeHandshakeTimeout(cfg),
			InteractionTimeout:          c.interactionTimeout,
			FailClosed:                  failClosed,
			RecoveryPrompter:            credentialRecoveryPrompter(basePrompter),
			KeyPath:                     dialPolicy.keyPath,
			KeyPaths:                    slices.Clone(dialPolicy.keyPaths),
			SSHOptions:                  dialPolicy.options.Clone(),
			EnforceAdmittedCertificates: dialPolicy.enforceAdmittedCertificates,
			AdmittedCertificates:        cloneAdmittedCertificates(dialPolicy.admittedCertificates),
			EnforceAdmittedKeyDigests:   dialPolicy.enforceAdmittedKeyDigests,
			AdmittedKeyDigests:          cloneAdmittedKeyDigests(dialPolicy.admittedKeyDigests),
			HostKeyChanged:              hostKeyChanged,
			PasswordCallback: func(s string) {
				if s != "" {
					// Preserve any passphrase recorded during an earlier key PartialSuccess in MFA.
					attempt.recordPassword(s, false)
				}
			},
			PassphraseCallback: func(keyPath, passphrase string) {
				if passphrase != "" {
					// Clear untried password material so key authentication never persists password secrets.
					attempt.recordPassphrase(keyPath, passphrase)
				}
			},
			CandidateRejectedCallback: func(protocol string) {
				attempt.rejectCandidate(protocol)
			},
			Logger:      c.getLogger(),
			Diagnostics: observer,
		})
		if err != nil {
			return nil, nil, err
		}
		authCallback = plan.authCallback
		cleanup = release

	case "keyboard-interactive", "otp":
		if !kbAllowed {
			return nil, nil, errors.New("keyboard-interactive authentication disabled by SSH options")
		}
		authCallback = c.buildKeyboardInteractiveAuth(authCtx, dialPolicy, attempt, policy, prompter, coordinator, observer)

	case "password":
		if !passwordAllowed {
			return nil, nil, errors.New("password authentication disabled by SSH options")
		}
		if credentialRecoveryPrompter(basePrompter) != nil {
			authMethods = append(authMethods, c.recoverablePasswordAuth(authCtx, dialPolicy, attempt, prompter))
			break
		}
		method, err := c.resolvePasswordAuthWithPolicy(dialPolicy, attempt)
		if err != nil {
			return nil, nil, err
		}
		authMethods = append(authMethods, method)

	case "key":
		if !pubkeyAllowed {
			return nil, nil, errors.New("publickey authentication disabled by SSH options")
		}
		if dialPolicy.keyRef != "" && c.keySource == nil {
			return nil, nil, errors.New("referenced SSH key requires an explicit key source")
		}
		explicitPaths, _ := c.explicitKeyPaths(cfg)
		var sourced *sourcedKeyBundle
		if c.keySource != nil {
			bundle, err := c.sourcedKeyMethods(authCtx, cfg)
			if err != nil {
				if dialPolicy.keyRef != "" || dialPolicy.keyPath != "" || !errors.Is(err, ErrKeyNotFound) {
					return nil, nil, err
				}
			} else {
				sourced = bundle
				if dialPolicy.keyPath != "" {
					explicitPaths = filterSourcedKeyPath(
						explicitPaths,
						dialPolicy.keyPath,
						c.environment,
						c.authTargetContext(cfg),
						c.environment.ResolveKeyPath,
					)
				}
			}
		}
		effectivePolicy := policy
		if sourced != nil || dialPolicy.keyRef != "" {
			effectivePolicy.identitiesOnly = true
		}
		cb, release, err := c.buildMultiKeyAuth(ctx, authCtx, cfg, attempt, explicitPaths, sourced, effectivePolicy, prompter, coordinator, observer)
		if err != nil {
			return nil, nil, err
		}
		authCallback = cb
		cleanup = release

	case "agent":
		if !pubkeyAllowed {
			return nil, nil, errors.New("publickey authentication disabled by SSH options")
		}
		if policy.identitiesOnly {
			explicitPaths, _ := c.explicitKeyPaths(cfg)
			explicitCerts, _ := collectExplicitUserCerts(
				cfg.Options,
				c.environment,
				c.authTargetContext(cfg),
				c.environment.ResolveKeyPath,
				c.getLogger(),
				newAdmittedMaterialPolicyFromConfig(cfg),
			)
			if len(explicitPaths) == 0 && len(explicitCerts) == 0 {
				return nil, nil, errors.New("ssh-agent authentication disabled by IdentitiesOnly=yes")
			}
			candidates, agentCleanup, err := c.resolveFilteredAgentAuth(ctx, authCtx, cfg, explicitPaths)
			if err != nil {
				return nil, nil, err
			}
			secProvider := c.newAutoSecretProvider(authCtx, cfg, prompter, coordinator)
			candidates = c.appendMFACallbackCandidate(policy, secProvider, candidates)
			authCallback = newSequentialAuthCallbackWithPolicy(candidates, policy, secProvider, c.getLogger(), observer)
			cleanup = legacyAuthCleanup(agentCleanup)
			break
		}
		candidates, method, agentCleanup, err := c.resolveAgentAuth(ctx, authCtx, cfg)
		if err != nil {
			return nil, nil, err
		}
		cleanup = legacyAuthCleanup(agentCleanup)
		if len(candidates) > 0 {
			secProvider := c.newAutoSecretProvider(authCtx, cfg, prompter, coordinator)
			candidates = c.appendMFACallbackCandidate(policy, secProvider, candidates)
			authCallback = newSequentialAuthCallbackWithPolicy(candidates, policy, secProvider, c.getLogger(), observer)
			break
		}
		authMethods = append(authMethods, method)

	default:
		return nil, nil, fmt.Errorf("unsupported auth type: %s", dialPolicy.authType)
	}

	if authCallback == nil && len(authMethods) == 1 {
		authCallback = c.buildSingleMethodTransitionCallback(authCtx, cfg, policy, prompter, coordinator, observer)
	}

	hostKeyCallback, hostKeyAlgorithms, err := c.getHostKeyOptionsWithState(ctx, coordinator, cfg, hostKeyChanged, initialHandshakeDone)
	if err != nil {
		if cleanup != nil {
			err = errors.Join(err, cleanup())
		}
		return nil, nil, err
	}

	cryptoCfg, err := buildTransportCryptoConfig(dialPolicy.options)
	if err != nil {
		if cleanup != nil {
			err = errors.Join(err, cleanup())
		}
		return nil, nil, err
	}

	var clientTimeout time.Duration
	if coordinator == nil {
		clientTimeout = 15 * time.Second
	}

	clientConfig := &ssh.ClientConfig{
		Config:            cryptoCfg,
		User:              dialPolicy.user,
		Auth:              authMethods,
		AuthCallback:      authCallback,
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout:           clientTimeout,
	}
	c.observeSSHConfig(cfg, clientConfig, observer)
	clientConfig.AuthCallback = authentication.wrap(clientConfig.AuthCallback)
	return clientConfig, cleanup, nil
}

func buildTransportCryptoConfig(opts *Options) (ssh.Config, error) {
	var cryptoCfg ssh.Config
	if opts == nil {
		return cryptoCfg, nil
	}
	if ciphers := opts.Ciphers(); ciphers != "" {
		list, err := ResolveAlgorithmList(ciphers, ssh.SupportedAlgorithms().Ciphers)
		if err != nil {
			return cryptoCfg, fmt.Errorf("resolve Ciphers option: %w", err)
		}
		cryptoCfg.Ciphers = list
	}
	if macs := opts.MACs(); macs != "" {
		list, err := ResolveAlgorithmList(macs, ssh.SupportedAlgorithms().MACs)
		if err != nil {
			return cryptoCfg, fmt.Errorf("resolve MACs option: %w", err)
		}
		cryptoCfg.MACs = list
	}
	if kex := opts.KexAlgorithms(); kex != "" {
		list, err := ResolveAlgorithmList(kex, ssh.SupportedAlgorithms().KeyExchanges)
		if err != nil {
			return cryptoCfg, fmt.Errorf("resolve KexAlgorithms option: %w", err)
		}
		cryptoCfg.KeyExchanges = list
	}
	return cryptoCfg, nil
}

// observeSSHConfig adds diagnostics without changing fallback selection or trust results.
func (c *Connector) observeSSHConfig(cfg *ClientConfig, clientConfig *ssh.ClientConfig, observer logger.DiagnosticObserver) {
	if observer == nil {
		return
	}
	verify := clientConfig.HostKeyCallback
	clientConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := verify(hostname, remote, key)
		logger.EmitDiagnostic(observer, logger.Diagnostic{Kind: logger.HostKeyChecked, NodeID: cfg.NodeID, HostKey: key.Type(), Fingerprint: ssh.FingerprintSHA256(key), Accepted: err == nil})
		return err
	}
}

func (c *Connector) newAutoSecretProvider(authCtx context.Context, cfg *ClientConfig, prompter SecretPrompter, coordinator *handshakeCoordinator) *autoSecretProvider {
	var failClosed func(error)
	if coordinator != nil {
		failClosed = coordinator.FailClosed
	}
	basePrompter := c.getNodeSecretPrompter(cfg)
	return &autoSecretProvider{
		lifecycleCtx:       authCtx,
		nodeID:             cfg.NodeID,
		user:               cfg.User,
		host:               cfg.Address,
		baseHost:           cfg.BaseHost,
		port:               cfg.Port,
		versionToken:       cfg.AuthUpdateToken,
		resolver:           c.secretResolver,
		prompter:           prompter,
		handshakeTimeout:   c.getNodeHandshakeTimeout(cfg),
		interactionTimeout: c.interactionTimeout,
		failClosed:         failClosed,
		recoveryPrompter:   credentialRecoveryPrompter(basePrompter),
	}
}

func (c *Connector) buildKeyboardInteractiveAuth(authCtx context.Context, dialPolicy dialPolicy, attempt *handshakeAttempt, policy authPolicy, prompter SecretPrompter, coordinator *handshakeCoordinator, observer logger.DiagnosticObserver) ssh.ClientAuthCallback {
	cfg := dialPolicy.readOnlyConfig()
	secProvider := c.newAutoSecretProvider(authCtx, cfg, prompter, coordinator)
	kbMethod := buildKeyboardInteractiveAuthMethod(secProvider)
	candidates := []autoAuthCandidate{
		{
			protocol: autoAuthProtocolKeyboardInteractive,
			label:    dialPolicy.authType,
			method:   kbMethod,
		},
	}
	if policy.passwordAllowed {
		passwordAttempts := 0
		passwordMethod := ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
			retry := passwordAttempts > 0
			if retry && secProvider.recoveryPrompter == nil {
				return "", ErrInteractionRequired
			}
			passwordAttempts++
			if !retry {
				if pwd := attempt.consumeInitialPassword(); pwd != "" {
					return pwd, nil
				}
			}
			password, err := secProvider.resolveOrPromptAttempt(SecretRequest{
				Kind: SecretKindLoginPassword,
			}, retry)
			if err != nil {
				return "", fmt.Errorf("failed to read password: %w", err)
			}
			return password, nil
		}), 3)
		candidates = append(candidates, autoAuthCandidate{
			protocol: autoAuthProtocolPassword,
			label:    "password",
			method:   passwordMethod,
			allow: func(ctx *ssh.ClientAuthContext) bool {
				// Only coordinate with password in explicit keyboard-interactive/otp mode
				// when multi-stage MFA is in progress or when the initial stage did not
				// offer keyboard-interactive (e.g., password -> keyboard-interactive MFA).
				return len(ctx.PartialSuccessMethods) > 0 || !slices.Contains(ctx.TriedMethods, autoAuthProtocolKeyboardInteractive)
			},
		})
	}
	return newSequentialAuthCallbackWithPolicy(candidates, policy, secProvider, c.getLogger(), observer)
}

func (c *Connector) buildSingleMethodTransitionCallback(authCtx context.Context, cfg *ClientConfig, policy authPolicy, prompter SecretPrompter, coordinator *handshakeCoordinator, observer logger.DiagnosticObserver) ssh.ClientAuthCallback {
	secProvider := c.newAutoSecretProvider(authCtx, cfg, prompter, coordinator)
	var kbMethod ssh.AuthMethod
	if policy.kbAllowed {
		kbMethod = buildKeyboardInteractiveAuthMethod(secProvider)
	}
	protocol := "publickey"
	if cfg.AuthType == "password" {
		protocol = "password"
	}
	negotiated := false
	lastStage := 0
	kbTriedInStage := false
	return func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
		if observer != nil {
			observeAuthNegotiation(observer, ctx, &negotiated)
			event := authenticationDiagnostic(ctx)
			logger.EmitDiagnostic(observer, event)
		}
		if secProvider != nil {
			if err := secProvider.terminalError(); err != nil {
				return nil, err
			}
		}
		stage := len(ctx.PartialSuccessMethods)
		if stage > lastStage {
			lastStage = stage
			kbTriedInStage = false
		}
		// When single-method auth achieves partial success, transition to keyboard-interactive once per stage if allowed by server and policy
		if stage > 0 && policy.kbAllowed && !kbTriedInStage && slices.Contains(ctx.AllowedMethods, autoAuthProtocolKeyboardInteractive) {
			if err := policy.checkProtocolRuntime(autoAuthProtocolKeyboardInteractive); err != nil {
				return nil, err
			}
			kbTriedInStage = true
			if observer != nil {
				event := authenticationDiagnostic(ctx)
				event.Kind, event.Method, event.Methods = logger.AuthenticationAttempt, autoAuthProtocolKeyboardInteractive, nil
				logger.EmitDiagnostic(observer, event)
			}
			c.getLogger().Debugf("Transitioning to keyboard-interactive after partial success: %v", ctx.PartialSuccessMethods)
			return kbMethod, nil
		}
		if stage == 0 {
			if err := policy.checkProtocolRuntime(protocol); err != nil {
				return nil, err
			}
			if observer != nil && slices.Contains(ctx.AllowedMethods, protocol) && !slices.Contains(ctx.TriedMethods, protocol) {
				event := authenticationDiagnostic(ctx)
				event.Kind, event.Method, event.Methods = logger.AuthenticationAttempt, protocol, nil
				logger.EmitDiagnostic(observer, event)
			}
		}
		return nil, nil
	}
}

func buildKeyAuthMethod(cfg *ClientConfig, extraPassphrase []byte, resolver ...func(string) string) (ssh.AuthMethod, error) {
	var resolve func(string) string
	if len(resolver) != 0 {
		resolve = resolver[0]
	}
	// Copy passphrase material into an owned slice and wipe all exits without mutating cfg.
	var passBytes []byte
	if len(extraPassphrase) > 0 {
		passBytes = extraPassphrase
	} else if cfg != nil && cfg.Passphrase != "" {
		passBytes = []byte(cfg.Passphrase)
	}
	if len(passBytes) > 0 {
		defer zeroBytes(passBytes)
	}

	if cfg == nil || cfg.KeyPath == "" {
		return nil, ErrKeyPathRequired
	}
	resolvedPath := resolveKeyPath(cfg.KeyPath, resolve)
	materialPolicy := newAdmittedMaterialPolicyFromConfig(cfg)
	keyBytes, absentAllowed, err := materialPolicy.readKeyFile(resolvedPath, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	if absentAllowed {
		return nil, fmt.Errorf("failed to read key file: %w", os.ErrNotExist)
	}

	var signer ssh.Signer
	if len(passBytes) > 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, passBytes)
	} else {
		signer, err = ssh.ParsePrivateKey(keyBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return ssh.PublicKeys(signer), nil
}

func (c *Connector) syncConnectionAfterRecording(node string, policy dialPolicy, outcome authOutcome, token string, updated, failed bool, rootConn net.Conn) (ConnectionConfig, error) {
	connCfg := policy.toConnectionConfig()
	discoveredKeyPath := ""
	if outcome.keyPath != "" && outcome.keyPath != policy.keyPath {
		discoveredKeyPath = outcome.keyPath
	}
	if _, err := c.syncRecordedConnection(
		node, &connCfg, policy.authUpdateToken, token, updated, failed,
		policy.keyPath, policy.keyPaths, discoveredKeyPath, rootConn,
	); err != nil {
		return ConnectionConfig{}, err
	}
	return connCfg, nil
}
