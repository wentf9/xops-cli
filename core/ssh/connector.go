package ssh

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
	logger "github.com/wentf9/xops-cli/core/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"
)

// Connector 负责创建 SSH 连接
type Connector struct {
	environment      Environment
	hostKeyVerifier  HostKeyVerifier
	keySource        KeySource
	plans            map[string]*planEntry
	allPlans         map[*planEntry]struct{}
	retiredPlans     map[string]struct{}
	disablePlanCache bool
	provider         ConnectionProvider
	controlProvider  ControlProvider
	sessionConfirmer SessionConfirmer
	// masters tracks the multiplexing masters this connector started so CloseAll
	// releases the control socket and SSH transport it owns. Guarded by lifecycleMu.
	masters            map[*MuxServer]*masterOwnership
	masterOrder        []*MuxServer
	secretResolver     SecretResolver
	credentialRecorder CredentialRecorder
	secretPrompter     SecretPrompter
	hostKeyConfirmer   HostKeyConfirmer
	interactionTimeout time.Duration
	handshakeTimeout   time.Duration
	baseDialer         Dialer
	// pool stores live and retired *PooledClient instances keyed solely by Merkle
	// HopDigest, owning CAS parent-generation checks and per-client keepalives.
	pool *connPool
	// singleflight group keyed by HopDigest.String() to coalesce identical hops.
	sf singleflight.Group
	// 自动接受新的主机密钥
	AcceptNewHostKey atomic.Bool
	// PasswordPromptPattern 全局级自定义密码提示正则（可选）。
	// 当节点的 ClientConfig.PasswordPromptPattern 为空时，使用此值；
	// su 在两者均为空时使用 DefaultPasswordPromptPattern；sudo 回退仅接受有效显式配置。
	PasswordPromptPattern string
	// lifecycleMu 与 connectWG 共同保证 CloseAll 和共享建连任务的生命周期有序：
	// closed 置位后不再允许新任务登记或连接发布，CloseAll 等待所有已登记任务返回。
	lifecycleMu     sync.Mutex
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	closed          bool
	closeDone       chan struct{}
	closeErr        error
	connectWG       sync.WaitGroup

	// kaMu protects keepAliveCfg (connector-wide keepalive enable/disable).
	// Lock ordering: connPool.mu -> kaMu -> PooledClient.kaMu; lifecycleMu -> kaMu.
	kaMu sync.Mutex
	// keepAliveCfg 为 nil 表示未启用周期心跳（CLI 短生命周期命令默认不启用）
	keepAliveCfg *keepAliveConfig
	// keepAliveWG covers the config watcher and all PooledClient-owned keepalive goroutines.
	keepAliveWG sync.WaitGroup
	logger      logger.DebugLogger
	diagnostics logger.DiagnosticObserver
}

// keepAliveConfig 描述 Connector 级心跳配置（见 EnableKeepAlive）
type keepAliveConfig struct {
	ctx               context.Context // 根心跳 ctx，取消后级联终止所有非节点级心跳
	cancel            context.CancelFunc
	interval, timeout time.Duration
}

// ErrConnectorClosed 表示 Connector 已执行 CloseAll，不能再建立或返回连接。
var ErrConnectorClosed = errors.New("ssh connector is closed")

// ErrInteractionRequired 表示需要交互式输入但在非交互模式下被拒绝。
var ErrInteractionRequired = errors.New("ssh interaction required")

// rejectInteraction 是默认的 fail-closed 交互实现。
type rejectInteraction struct{}

func (rejectInteraction) PromptSecret(context.Context, SecretRequest) (string, error) {
	return "", ErrInteractionRequired
}

func (rejectInteraction) ConfirmHostKey(context.Context, HostKeyConfirmation) (bool, error) {
	return false, ErrInteractionRequired
}

// rejectSecretResolver 是默认的 fail-closed 机密解析实现。
type rejectSecretResolver struct{}

func (rejectSecretResolver) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return nil, ErrInteractionRequired
}

// nopCredentialRecorder 是默认的空操作凭据记录实现。
type nopCredentialRecorder struct{}

func (nopCredentialRecorder) UpdateAuth(ctx context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", err
		}
	}
	return authUpdateToken, nil
}

func (nopCredentialRecorder) UpdateSudo(ctx context.Context, nodeID, sudoUpdateToken string, mode SudoMode, suPwd string) (string, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", err
		}
	}
	return sudoUpdateToken, nil
}

const (
	defaultSSHHandshakeTimeout = 10 * time.Second
	DefaultInteractionTimeout  = 2 * time.Minute
)

// NewConnector 创建一个新的 Connector，支持 Functional Options。
// 支持接收 ConnectionProvider 或兼容的 ConfigStore。
func NewConnector(provider ConnectionProvider, opts ...Option) *Connector {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	c := &Connector{
		provider:           provider,
		secretResolver:     rejectSecretResolver{},
		credentialRecorder: nopCredentialRecorder{},
		secretPrompter:     rejectInteraction{},
		hostKeyConfirmer:   rejectInteraction{},
		interactionTimeout: DefaultInteractionTimeout,
		pool:               newConnPool(),
		lifecycleCtx:       lifecycleCtx,
		lifecycleCancel:    lifecycleCancel,
		closeDone:          make(chan struct{}),
		logger:             logger.NopLogger,
	}
	if resolver, ok := provider.(SecretResolver); ok {
		c.secretResolver = resolver
	}
	if recorder, ok := provider.(CredentialRecorder); ok {
		c.credentialRecorder = recorder
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

func (c *Connector) interactionContext(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := c.interactionTimeout
	if timeout <= 0 {
		timeout = DefaultInteractionTimeout
	}
	if parent == nil {
		parent = c.lifecycleCtx
	}
	return context.WithTimeout(parent, timeout)
}

func (c *Connector) getLogger() logger.DebugLogger {
	if c != nil && c.logger != nil {
		return c.logger
	}
	return logger.NopLogger
}

// WithControlProvider configures the ControlProvider for multiplexing.
func WithControlProvider(provider ControlProvider) Option {
	return func(c *Connector) {
		c.controlProvider = provider
	}
}

// SessionConfirmer authorizes connection-sharing requests on an ask/autoask
// master. Implementations must honor ctx, return promptly, and fail closed.
type SessionConfirmer interface {
	ConfirmSession(ctx context.Context, action string) (bool, error)
}

// WithSessionConfirmer injects the confirmation source used by ask/autoask
// masters. Without one, every request against such a master is rejected.
func WithSessionConfirmer(confirmer SessionConfirmer) Option {
	if nilCapability(confirmer) {
		confirmer = nil
	}
	return func(c *Connector) {
		c.sessionConfirmer = confirmer
	}
}

type connectionPlanNode struct {
	name         string
	digest       HopDigest
	parentDigest HopDigest
	cfg          *ClientConfig
	control      *ControlConfig
}

func assignPlanDigests(plan []connectionPlanNode) {
	parent := ZeroHopDigest
	for i := len(plan) - 1; i >= 0; i-- {
		plan[i].parentDigest = parent
		plan[i].digest = DigestClientConfig(plan[i].cfg, parent)
		parent = plan[i].digest
	}
}

func (n connectionPlanNode) hopDigest() HopDigest {
	if !n.digest.IsZero() {
		return n.digest
	}
	return DigestClientConfig(n.cfg, n.parentDigest)
}

var errProxyTransportClosed = errors.New("proxy transport generation is closed")

// errJumpChainRequired reports that a jump-chained target was neither cached nor
// reachable through an active control master, so its jump chain has to be built
// before the target itself can be connected.
var errJumpChainRequired = errors.New("connection requires its proxy jump chain")

// Connect 根据节点名称建立 SSH 连接。
// ProxyJump 链会先完整解析并检测环，再从最底层跳板机开始逐层建立连接。
func (c *Connector) Connect(ctx context.Context, nodeName string) (*Client, error) {
	if ctx == nil {
		return nil, fmt.Errorf("connect context is nil")
	}
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}

	plan, err := c.resolveConnectionPlan(ctx, nodeName)
	if err != nil {
		return nil, err
	}

	// A downstream probe or stale parent generation can invalidate a hop already
	// visited in this plan. Restart outside singleflight, so no node task waits
	// recursively for another node task. Bound restarts even under repeated loss.
	rebuildLimit := len(plan) - 1
	for rebuilds := 0; ; rebuilds++ {
		client, err := c.connectPlan(ctx, plan)
		if !errors.Is(err, errProxyTransportClosed) || rebuilds >= rebuildLimit {
			return client, err
		}
		// Successful handshakes clear session secrets and may update credential
		// tokens. Resolve a fresh plan rather than reusing mutated configs.
		plan, err = c.resolveConnectionPlan(ctx, nodeName)
		if err != nil {
			return nil, err
		}
	}
}

func isClientTransportClosed(client *Client) bool {
	if client == nil {
		return true
	}
	return isRootConnClosed(client.rootConn)
}

// probeCachedIntermediateHops probes any cached intermediate hops (index > 0)
// in reuse-only mode so dead cached bastions are evicted before attempting to
// reuse or attach to plan[0]'s ControlMaster. A dead intermediate hop returns
// errJumpChainRequired after eviction and does NOT abort the fast-path; only
// fatal/cancellation/security errors abort immediately.
func (c *Connector) probeCachedIntermediateHops(ctx context.Context, plan []connectionPlanNode, snapshot []*PooledClient) error {
	for index := len(plan) - 1; index > 0; index-- {
		if snapshot[index] == nil {
			continue
		}
		if _, err := c.connectPlannedNode(ctx, plan[index], nil, nil, true); err != nil {
			if errors.Is(err, errJumpChainRequired) {
				continue
			}
			return err
		}
	}
	return nil
}

// validateCachedChain probes every hop of a cached chain approved by
// canReuseCachedChain, verifying that parent/child RootConn generations remain
// consistent across probes.
func (c *Connector) validateCachedChain(ctx context.Context, plan []connectionPlanNode, snapshot []*PooledClient) (*Client, error) {
	if snapshot[0] != nil && snapshot[0].ControlSocketPath != "" {
		// ControlMaster-attached target: still probe any cached intermediate hops
		// so a dead bastion is evicted, then validate or re-attach the target proxy.
		if err := c.probeCachedIntermediateHops(ctx, plan, snapshot); err != nil {
			return nil, err
		}
		return c.connectPlannedNode(ctx, plan[0], nil, nil, true)
	}

	var prevClient *Client
	for index := len(plan) - 1; index >= 0; index-- {
		var expectParent *PooledClient
		if prevClient != nil {
			expectParent = prevClient.pooled
		}
		hopClient, err := c.connectPlannedNode(ctx, plan[index], nil, expectParent, true)
		if err != nil {
			return nil, err
		}
		if expectParent != nil && !isConsistentParentChildTransport(expectParent, hopClient.pooled) {
			if hopClient.pooled != nil {
				c.pool.Retire(plan[index].hopDigest(), hopClient.pooled)
			}
			return nil, errJumpChainRequired
		}
		prevClient = hopClient
	}
	return prevClient, nil
}

// tryAttachTargetControlMaster attempts to attach a jump-chained target to an
// already-running ControlMaster socket on disk without dialing or
// re-authenticating to its bastion.
func (c *Connector) tryAttachTargetControlMaster(ctx context.Context, plan []connectionPlanNode, snapshot []*PooledClient) (*Client, error) {
	if err := c.probeCachedIntermediateHops(ctx, plan, snapshot); err != nil {
		return nil, err
	}
	return c.connectPlannedNode(ctx, plan[0], nil, nil, true)
}

func (c *Connector) reanchorPlanNodeParent(planNode *connectionPlanNode, expectParent *PooledClient) {
	if expectParent == nil {
		return
	}
	parentDigest := c.pool.DigestOf(expectParent)
	if parentDigest.IsZero() || parentDigest == planNode.parentDigest {
		return
	}
	planNode.parentDigest = parentDigest
	planNode.digest = DigestClientConfig(planNode.cfg, planNode.parentDigest)
}

func isPooledTargetUnusable(target *PooledClient) bool {
	return target == nil || target.SSHClient == nil || isRootConnClosed(target.RootConn)
}

func (c *Connector) tryReuseMultiHopPlan(ctx context.Context, plan []connectionPlanNode) (*Client, bool, error) {
	snapshot := c.pool.SnapshotChain(plan)
	if canReuseCachedChain(plan, snapshot) {
		alreadyTriedTargetMux := snapshot[0] != nil && snapshot[0].ControlSocketPath != ""
		reused, err := c.validateCachedChain(ctx, plan, snapshot)
		if err == nil {
			return reused, true, nil
		}
		if !errors.Is(err, errJumpChainRequired) {
			return nil, true, err
		}
		if alreadyTriedTargetMux {
			return nil, false, nil
		}
		// A cached in-memory jump chain was evicted/retired during validation;
		// refresh the snapshot and fall through to check for an independent
		// live ControlMaster on plan[0] before dialing the jump chain.
		snapshot = c.pool.SnapshotChain(plan)
	}
	if !isPooledTargetUnusable(snapshot[0]) {
		return nil, false, nil
	}
	hasSocket, sockErr := c.hasControlSocket(plan[0])
	if sockErr != nil {
		c.getLogger().Debugf("mux: skip target control master probe for node %s: %v", plan[0].name, sockErr)
		return nil, false, nil
	}
	if !hasSocket {
		return nil, false, nil
	}
	reused, err := c.tryAttachTargetControlMaster(ctx, plan, snapshot)
	if err == nil && reused != nil {
		return reused, true, nil
	}
	if err != nil && !errors.Is(err, errJumpChainRequired) {
		return nil, true, err
	}
	return nil, false, nil
}

func (c *Connector) connectPlan(ctx context.Context, plan []connectionPlanNode) (*Client, error) {
	// For multi-hop plans, reuse a fully cached chain (or attach to an active
	// target ControlMaster) before dialing intermediate hops. The reuse predicate
	// is pure: every hop's Merkle HopDigest must hit and parent/child RootConn
	// generations must match.
	if len(plan) > 1 {
		if reused, handled, err := c.tryReuseMultiHopPlan(ctx, plan); handled {
			return reused, err
		}
	}

	var connected *Client
	for index := len(plan) - 1; index >= 0; index-- {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("connect node '%s' canceled: %w", plan[0].name, err)
		}

		planNode := plan[index]
		var (
			dialer       Dialer
			expectParent *PooledClient
		)
		switch {
		case planNode.cfg.ProxyJump != "":
			if connected == nil {
				return nil, fmt.Errorf("resolved proxy jump '%s' for node '%s' has no client", planNode.cfg.ProxyJump, planNode.name)
			}
			dialer = &SSHProxyDialer{
				Client:        connected.sshClient,
				RootConn:      connected.rootConn,
				abortUpstream: c.upstreamAbortFunc(connected.pooled, connected.rootConn),
			}
			expectParent = connected.pooled
			c.reanchorPlanNodeParent(&planNode, expectParent)
		case planNode.cfg.Options.ActiveProxyCommand() != "":
			dialer = &proxyCommandDialer{connector: c, planNode: planNode}
		case c.baseDialer != nil:
			dialer = c.baseDialer
		default:
			dialer = c.directDialerFor(planNode.cfg)
		}

		var err error
		connected, err = c.connectPlannedNode(ctx, planNode, dialer, expectParent, false)
		if err != nil {
			return nil, err
		}
	}
	return connected, nil
}

func (c *Connector) getNodeHandshakeTimeout(cfg *ClientConfig) time.Duration {
	if cfg != nil && cfg.Options != nil {
		if ct := cfg.Options.ConnectTimeout(); ct > 0 {
			return ct
		}
	}
	if c.handshakeTimeout > 0 {
		return c.handshakeTimeout
	}
	return defaultSSHHandshakeTimeout
}

func (c *Connector) getNodeSecretPrompter(cfg *ClientConfig) SecretPrompter {
	if cfg != nil && cfg.Options != nil && cfg.Options.BatchMode() {
		return rejectInteraction{}
	}
	return c.secretPrompter
}

func (c *Connector) directDialerFor(cfg *ClientConfig) Dialer {
	d := &net.Dialer{Timeout: c.getNodeHandshakeTimeout(cfg)}
	if cfg != nil && cfg.Options != nil {
		if tcpKA, ok := cfg.Options.TCPKeepAlive(); ok && !tcpKA {
			d.KeepAlive = -1
		}
	}
	return d
}

func (c *Connector) getInteractionTimeout() time.Duration {
	if c.interactionTimeout > 0 {
		return c.interactionTimeout
	}
	return DefaultInteractionTimeout
}

func (c *Connector) ensureOpen() error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed {
		return ErrConnectorClosed
	}
	return nil
}

func (c *Connector) resolveConnectionPlan(ctx context.Context, nodeName string) ([]connectionPlanNode, error) {
	plan := make([]connectionPlanNode, 0, 2)
	positions := make(map[string]int)
	current := nodeName
	var remainingJumps []string
	for current != "" {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("resolve proxy jump chain for node '%s' canceled: %w", nodeName, err)
		}
		if cycleStart, ok := positions[current]; ok {
			path := make([]string, 0, len(plan)-cycleStart+1)
			for _, item := range plan[cycleStart:] {
				path = append(path, item.name)
			}
			path = append(path, current)
			return nil, &ProxyCycleError{NodeID: current, Path: path}
		}

		cfg, err := c.provider.GetConfig(current)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch config for node '%s': %w", current, err)
		}
		if cfg == nil {
			return nil, fmt.Errorf("config for node '%s' is nil", current)
		}
		nodeCfg := NewClientConfig(*cfg)
		if !nodeCfg.HasOriginalProxyJump {
			nodeCfg.OriginalProxyJump = nodeCfg.ProxyJump
			nodeCfg.HasOriginalProxyJump = true
		}

		var activeJumps []string
		if len(remainingJumps) > 0 {
			activeJumps = remainingJumps
		} else {
			activeJumps = splitProxyJumpChain(nodeCfg.ProxyJump)
		}
		nodeCfg.ProxyJump = strings.Join(activeJumps, ",")
		ctrl := c.resolveControl(current, nodeCfg)
		nodeCfg.Control = normalizeControlConfig(ctrl)
		positions[current] = len(plan)
		plan = append(plan, connectionPlanNode{name: current, cfg: nodeCfg, control: ctrl})

		if len(activeJumps) > 0 {
			current = activeJumps[len(activeJumps)-1]
			remainingJumps = activeJumps[:len(activeJumps)-1]
		} else {
			current = ""
			remainingJumps = nil
		}
	}
	assignPlanDigests(plan)
	return plan, nil
}

// expectedPeerUID is the identity a control socket endpoint must run as. It
// mirrors StartMuxServer so a client and the master it talks to agree even when
// the host injects a UID that differs from the effective one (containers).
func (c *Connector) expectedPeerUID() uint32 {
	return expectedPeerUIDFromEnvironment(c.environment)
}

func (c *Connector) resolveControl(nodeName string, cfg *ClientConfig) *ControlConfig {
	return resolveControlConfig(c.controlProvider, c.provider, nodeName, cfg, c.getLogger())
}

func resolveControlConfig(
	controlProvider ControlProvider,
	provider ConnectionProvider,
	nodeName string,
	cfg *ClientConfig,
	l logger.DebugLogger,
) *ControlConfig {
	if controlProvider != nil {
		if ctrl, err := controlProvider.GetControlConfig(nodeName); err == nil && ctrl != nil {
			return ctrl
		}
		return nil
	}
	if cp, ok := provider.(ControlProvider); ok {
		if ctrl, err := cp.GetControlConfig(nodeName); err == nil && ctrl != nil {
			return ctrl
		}
		return nil
	}
	if cfg != nil && cfg.Control != nil {
		return cfg.Control.Clone()
	}
	if cfg != nil && cfg.Options != nil {
		if ctrl, err := cfg.Options.ValidatedControlConfig(); err == nil {
			return ctrl
		} else if l != nil {
			l.Debugf("ssh: ignoring invalid effective control options for %q: %v", nodeName, err)
		}
	}
	return nil
}

func splitProxyJumpChain(proxyJump string) []string {
	var jumps []string
	for jump := range strings.SplitSeq(proxyJump, ",") {
		jump = strings.TrimSpace(jump)
		if jump != "" && !strings.EqualFold(jump, "none") {
			jumps = append(jumps, jump)
		}
	}
	return jumps
}

// connectPlannedNode runs the cache/multiplex/connect decision for one node in a
// shared task keyed by its Merkle HopDigest. reuseOnly stops before dialing so a
// cached hop or control master can be validated without dialing.
func (c *Connector) connectPlannedNode(ctx context.Context, planNode connectionPlanNode, dialer Dialer, expectParent *PooledClient, reuseOnly bool) (*Client, error) {
	sfKey := planNode.hopDigest().String()
	for {
		// 缓存复检、失效驱逐和重建位于同一个共享任务内。任务仅绑定 Connector 生命周期，
		// 单个调用者取消只停止等待，不会关闭连接池中由其他调用者共享的连接。
		resultCh := c.sf.DoChan(sfKey, func() (any, error) {
			sharedCtx, finish, err := c.beginSharedConnect()
			if err != nil {
				return nil, err
			}
			defer finish()
			return c.connectNode(sharedCtx, planNode, dialer, expectParent, reuseOnly)
		})

		client, err := c.awaitPlannedNode(ctx, planNode.name, resultCh)
		if err != nil && !reuseOnly && errors.Is(err, errJumpChainRequired) {
			// This call joined another caller's reuse-only task, so the target was
			// reported as not reusable. The task is finished; asking again runs the
			// full chain.
			continue
		}
		return client, err
	}
}

func (c *Connector) awaitPlannedNode(ctx context.Context, nodeName string, resultCh <-chan singleflight.Result) (*Client, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("connect node '%s' canceled: %w", nodeName, ctx.Err())
	case <-c.lifecycleCtx.Done():
		return nil, ErrConnectorClosed
	case result := <-resultCh:
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("connect node '%s' canceled: %w", nodeName, err)
		}
		if result.Err != nil {
			return nil, result.Err
		}
		client, ok := result.Val.(*Client)
		if !ok || client == nil {
			return nil, fmt.Errorf("shared connect for node '%s' returned invalid client", nodeName)
		}
		return client, nil
	}
}

func (c *Connector) beginSharedConnect() (context.Context, func(), error) {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed {
		return nil, nil, ErrConnectorClosed
	}
	c.connectWG.Add(1)
	return c.lifecycleCtx, c.connectWG.Done, nil
}

func (c *Connector) connectNode(ctx context.Context, planNode connectionPlanNode, dialer Dialer, expectParent *PooledClient, reuseOnly bool) (*Client, error) {
	nodeName := planNode.name
	hopKey := planNode.hopDigest()
	var probeErr error
	if cachedClient, ok := c.pool.Get(hopKey); ok {
		switch {
		case expectParent != nil && !isConsistentParentChildTransport(expectParent, cachedClient):
			c.pool.Retire(hopKey, cachedClient)
		case cachedClient.SSHClient == nil || isRootConnClosed(cachedClient.RootConn):
			c.pool.Evict(hopKey, cachedClient, true)
		case cachedClient.SSHClient.Conn == nil:
			logger.EmitDiagnostic(c.diagnostics, logger.Diagnostic{Kind: logger.ConnectionReused, NodeID: nodeName})
			return c.wrapCachedClient(planNode.cfg, cachedClient), nil
		default:
			if err := c.probeCachedClient(ctx, cachedClient); err == nil {
				logger.EmitDiagnostic(c.diagnostics, logger.Diagnostic{Kind: logger.ConnectionReused, NodeID: nodeName})
				return c.wrapCachedClient(planNode.cfg, cachedClient), nil
			} else {
				probeErr = err
				c.pool.Evict(hopKey, cachedClient, true)
				if ctx.Err() != nil {
					return nil, fmt.Errorf("probe cached SSH connection for node '%s' failed: %w", nodeName, ctx.Err())
				}
			}
		}
	}

	if proxy, ok := dialer.(*SSHProxyDialer); ok && proxy.transportClosed() {
		return nil, fmt.Errorf("rebuild proxy chain for '%s': %w", nodeName, errors.Join(errProxyTransportClosed, probeErr))
	}

	// Multiplexing Check:
	if client, err := c.tryConnectMultiplex(ctx, planNode); err != nil {
		return nil, err
	} else if client != nil {
		return client, nil
	}

	if reuseOnly {
		return nil, errJumpChainRequired
	}

	client, err := c.initializeConnection(ctx, planNode, dialer, expectParent)
	// Another caller can invalidate the same root after the check above.
	// When this dialer's own proxyChanConn escalated to abort a wedged/blackholed
	// upstream bastion during handshake or post-handshake cleanup, surface the
	// failure directly instead of silently doubling ConnectTimeout.
	if proxy, ok := dialer.(*SSHProxyDialer); err != nil && ok && proxy.transportClosed() && !proxy.abortedBySelf() && ctx.Err() == nil {
		return nil, fmt.Errorf("rebuild proxy chain for '%s': %w", nodeName, errors.Join(errProxyTransportClosed, err))
	}
	return client, err
}

func (c *Connector) wrapCachedClient(cfg *ClientConfig, cachedClient *PooledClient) *Client {
	return c.wrapPoolClientWithResolver(cfg, cachedClient, c.secretResolver)
}

func (c *Connector) wrapAuthenticatedClient(policy dialPolicy, attempt *handshakeAttempt, pooled *PooledClient) *Client {
	roCfg := policy.readOnlyConfig()
	resolver := c.secretResolver
	if resolver == nil {
		if pwd, suPwd := attempt.effectiveCompatPassword(), attempt.compatSuPwd(); pwd != "" || suPwd != "" {
			resolver = &compatSecretResolver{
				password: pwd,
				suPwd:    suPwd,
			}
		}
	}
	return c.wrapPoolClientWithResolver(roCfg, pooled, resolver)
}

func (c *Connector) wrapPoolClientWithResolver(cfg *ClientConfig, cachedClient *PooledClient, resolver SecretResolver) *Client {
	client := c.configureClient(newClientWithComponents(
		cachedClient.SSHClient,
		cachedClient.RootConn,
		cfg,
		c.provider,
		resolver,
		c.getNodeSecretPrompter(cfg),
		c.credentialRecorder,
		c.PasswordPromptPattern,
		c.getNodeHandshakeTimeout(cfg),
		c.getInteractionTimeout(),
		c.getLogger(),
	))
	client.pooled = cachedClient
	client.controlProvider = c.controlProvider
	cachedClient.probeMu.Lock()
	if cachedClient.probeCache == nil {
		cachedClient.probeCache = &executionProbeCache{}
	}
	client.probeCache = cachedClient.probeCache
	cachedClient.probeMu.Unlock()
	client.muxSocketPath = cachedClient.ControlSocketPath
	client.muxExpectedUID = cachedClient.ControlExpectedUID
	return client
}

// Cache revalidation is a finite acquisition step, unlike background liveness
// monitoring. Bound its total duration even while channel data keeps arriving:
// the shared task outlives individual callers and must release its singleflight
// entry without waiting for Connector.CloseAll.
func (c *Connector) probeCachedClient(ctx context.Context, client *PooledClient) error {
	timeout := c.keepAliveProbeTimeout()
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var beforeClose func() func()
	if c.pool != nil {
		beforeClose = func() func() {
			batch := c.pool.detachForEvict(ZeroHopDigest, client, true)
			return batch.closeDescendantsAndRelease
		}
	}
	hopScopedClose := client.isJumpChild()
	var fallbackInterrupt func() error
	if hopScopedClose {
		fallbackInterrupt = func() error {
			var batch *evictionBatch
			if c.pool != nil {
				root := client
				for root.parent != nil {
					root = root.parent
				}
				batch = c.pool.detachForEvict(ZeroHopDigest, root, true)
			}
			// Abort RootConn BEFORE closing multiplexed child channels so a
			// write-wedged bastion cannot deadlock descendant teardown.
			err := client.interrupt()
			if batch != nil {
				_ = batch.dead.closeSelf()
				batch.closeDescendantsAndRelease()
			}
			return err
		}
	}
	return probeWithContexts(probeCtx, probeCtx, client.SSHClient, timeout, client.closeHopTransport, fallbackInterrupt, beforeClose, hopScopedClose, nil)
}

func (c *Connector) keepAliveProbeTimeout() time.Duration {
	c.kaMu.Lock()
	defer c.kaMu.Unlock()
	if c.keepAliveCfg != nil {
		return c.keepAliveCfg.timeout
	}
	return DefaultKeepAliveTimeout
}

// EvictClient removes client's underlying pooled entry from the active pool and
// closes its own transport (plus any evicted same-generation descendants)
// without tearing down healthy upstream ancestors. Callers invoke this when
// post-connect confirmation or enrollment validation rejects a newly returned
// client.
func (c *Connector) EvictClient(client *Client) error {
	if c == nil || client == nil {
		return nil
	}
	if client.pooled != nil && c.pool != nil {
		c.pool.EvictByClient(client.pooled)
		return nil
	}
	return client.Interrupt()
}

func (c *Connector) resolveSecret(cfg *ClientConfig, req SecretRequest) ([]byte, error) {
	if c.secretResolver == nil {
		return nil, ErrInteractionRequired
	}
	timeout := c.getNodeHandshakeTimeout(cfg)
	if timeout <= 0 {
		timeout = defaultSSHHandshakeTimeout
	}
	ctx, cancel := context.WithTimeout(c.lifecycleCtx, timeout)
	defer cancel()

	return c.secretResolver.ResolveSecret(ctx, req)
}

func (c *Connector) buildTargetContext(planNode connectionPlanNode) TargetContext {
	return BuildClientTargetContext(planNode.name, planNode.cfg, c.environment, planNode.control)
}

func isFatalMultiplexSecurityError(err error) bool {
	return errors.Is(err, ErrUnauthorizedPeer) ||
		errors.Is(err, ErrControlTargetMismatch) ||
		errors.Is(err, ErrControlProxyRejected)
}

func (c *Connector) verifyMuxMasterTarget(muxClient *MuxClient, expandedPath string, target TargetContext) error {
	if muxClient == nil {
		return nil
	}
	masterTarget, ok := muxClient.Extension(muxTargetExtensionName)
	if !ok || (masterTarget != "" && target.MatchesMasterTarget(masterTarget)) {
		return nil
	}
	return fmt.Errorf("%w: control socket %q is connected to %s, cannot reuse for %s",
		ErrControlTargetMismatch,
		expandedPath,
		FormatTargetIdentity(masterTarget),
		FormatTargetIdentity(target.CanonicalTargetIdentity()),
	)
}

// warnOrDebugf logs a warning via optional Warnf(string, ...any) capability on
// DebugLogger when warn is true, falling back to Debugf with a "warning: " prefix.
func (c *Connector) warnOrDebugf(warn bool, format string, args ...any) {
	l := c.getLogger()
	if warn {
		if warner, ok := l.(interface{ Warnf(string, ...any) }); ok {
			warner.Warnf(format, args...)
			return
		}
		l.Debugf("warning: "+format, args...)
		return
	}
	l.Debugf(format, args...)
}

func isMultiplexControlEnabled(target TargetContext) bool {
	return target.Control.IsEnabled() && target.Host != ""
}

func isMasterListenerMode(mode ControlMasterMode) bool {
	return mode == ControlMasterYes || mode == ControlMasterAuto || mode == ControlMasterAsk || mode == ControlMasterAutoAsk
}

func (c *Connector) tryConnectMultiplex(ctx context.Context, planNode connectionPlanNode) (*Client, error) {
	target := c.buildTargetContext(planNode)
	if !isMultiplexControlEnabled(target) {
		return nil, nil // Multiplexing disabled
	}
	ctrl := target.Control

	explicitMaster := (ctrl.Master == ControlMasterYes || ctrl.Master == ControlMasterAsk) && !ctrl.AllowReuse

	// 1. Expand ControlPath tokens (or validate literal pre-expanded path)
	expandedPath, err := ctrl.ResolvePath(c.environment, target)
	if err != nil {
		c.warnOrDebugf(explicitMaster, "mux: expand control path %q failed: %v; continuing without connection sharing", ctrl.Path, err)
		return nil, nil
	}
	if strings.TrimSpace(expandedPath) == "" || IsNoneValue(expandedPath) {
		return nil, nil
	}
	if err := ValidateControlPath(expandedPath); err != nil {
		c.warnOrDebugf(explicitMaster, "mux: control path %q validation failed: %v; continuing without connection sharing", expandedPath, err)
		return nil, nil
	}

	// 2. Check if socket file exists on disk and capture initial file identity
	origFi, statErr := os.Lstat(expandedPath)
	if statErr != nil || !isControlSocketFileInfo(origFi) {
		c.getLogger().Debugf("mux: socket %q does not exist or is not a socket", expandedPath)
		return nil, nil
	}

	// 3. Socket file exists: probe master health via AliveCheck
	client, probeDone, probeErr := c.probeActiveMuxMaster(ctx, planNode, expandedPath, target, origFi, explicitMaster, ctrl.Master)
	if probeDone || probeErr != nil {
		return client, probeErr
	}

	return nil, nil
}

func (c *Connector) probeActiveMuxMaster(ctx context.Context, planNode connectionPlanNode, expandedPath string, target TargetContext, origFi os.FileInfo, explicitMaster bool, masterMode ControlMasterMode) (*Client, bool, error) {
	probeTimeout := c.getNodeHandshakeTimeout(planNode.cfg)
	if probeTimeout > 2*time.Second {
		probeTimeout = 2 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	muxClient, dialErr := DialMuxClient(probeCtx, expandedPath, WithExpectedPeerUID(c.expectedPeerUID()))
	if dialErr == nil {
		if targetErr := c.verifyMuxMasterTarget(muxClient, expandedPath, target); targetErr != nil {
			_ = muxClient.Close()
			if explicitMaster {
				c.warnOrDebugf(true, "mux: active master on %q belongs to a different target (%v); not attaching in %s mode", expandedPath, targetErr, masterMode)
				return nil, true, nil
			}
			return nil, true, targetErr
		}

		serverPID, checkErr := muxClient.AliveCheck(probeCtx)
		_ = muxClient.Close()

		if checkErr == nil {
			// -M means "become the master". Attaching to an existing master would
			// silently demote the request, so the caller falls back to its own
			// connection; the later bind reports the conflict.
			if explicitMaster {
				c.getLogger().Debugf("mux: master already running on %q (pid=%d); not attaching in %s mode", expandedPath, serverPID, masterMode)
				return nil, true, nil
			}
			c.getLogger().Debugf("mux: active master running on %q (pid=%d) for node %s", expandedPath, serverPID, planNode.name)
			client, proxyErr := c.tryDialAndPublishProxy(ctx, planNode, expandedPath, target)
			if proxyErr == nil {
				return client, true, nil
			}
			dialErr = proxyErr
		} else {
			dialErr = checkErr
		}
	}

	// 4. Handle stale socket safely without clobbering newly started masters. Every
	// active master mode must be able to replace a socket left by a crash,
	// including the direct-bind fallback used on Windows. A slow/timed-out master
	// is NOT unlinked (matches OpenSSH: only ECONNREFUSED indicates a dead listener),
	// and ControlMaster=no never unlinks sockets it will not replace.
	if dialErr != nil {
		if isFatalMultiplexSecurityError(dialErr) {
			return nil, true, dialErr
		}
		canReplaceStale := masterMode != "" && masterMode != ControlMasterNo
		if isConnectionRefused(dialErr) && canReplaceStale {
			c.getLogger().Debugf("mux: stale socket detected on %q: %v", expandedPath, dialErr)
			client, err := c.handleStaleControlSocket(ctx, planNode, expandedPath, target, origFi)
			return client, true, err
		}
		c.getLogger().Debugf("mux: error connecting to master on %q: %v", expandedPath, dialErr)
	}
	return nil, false, nil
}

func (c *Connector) dialAndPublishProxy(ctx context.Context, planNode connectionPlanNode, expandedPath string, target TargetContext) (*Client, error) {
	client, err := c.tryDialAndPublishProxy(ctx, planNode, expandedPath, target)
	if err != nil {
		if isFatalMultiplexSecurityError(err) {
			return nil, err
		}
		c.getLogger().Debugf("mux: proxy dial on %q failed: %v; falling back to direct connection", expandedPath, err)
		return nil, nil
	}
	return client, nil
}

func (c *Connector) tryDialAndPublishProxy(ctx context.Context, planNode connectionPlanNode, expandedPath string, target TargetContext) (*Client, error) {
	dialTimeout := max(c.getNodeHandshakeTimeout(planNode.cfg), c.getInteractionTimeout())
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	rawClient, proxyConn, proxyErr := DialControlProxy(dialCtx, expandedPath, target, WithExpectedPeerUID(c.expectedPeerUID()))
	if proxyErr != nil {
		return nil, proxyErr
	}

	rootConn := proxyConn.RawConn()
	var publishedCfg *ClientConfig
	if planNode.cfg != nil {
		publishedCfg = NewClientConfig(*planNode.cfg)
	}
	pooled := &PooledClient{
		SSHClient:          rawClient,
		RootConn:           rootConn,
		hopConn:            rootConn,
		parentKey:          planNode.parentDigest,
		pool:               c.pool,
		publishedCfg:       publishedCfg,
		ControlSocketPath:  expandedPath,
		ControlExpectedUID: c.expectedPeerUID(),
		Snapshot:           planNode.cfg.ToConnectionConfig(),
		hasSnapshot:        true,
	}
	hopKey := planNode.hopDigest()
	if _, err := c.publishPooled(hopKey, pooled, nil, planNode.cfg); err != nil {
		_ = proxyConn.Close()
		return nil, err
	}
	logger.EmitDiagnostic(c.diagnostics, logger.Diagnostic{
		Kind:   logger.ConnectionReused,
		NodeID: planNode.name,
		Host:   planNode.cfg.Address,
		User:   planNode.cfg.User,
		Port:   planNode.cfg.Port,
	})
	return c.wrapCachedClient(planNode.cfg, pooled), nil
}

func (c *Connector) handleStaleControlSocket(ctx context.Context, planNode connectionPlanNode, expandedPath string, target TargetContext, origFi os.FileInfo) (*Client, error) {
	ctrl := target.Control
	explicitMaster := ctrl != nil && (ctrl.Master == ControlMasterYes || ctrl.Master == ControlMasterAsk) && !ctrl.AllowReuse

	outcome, pruneErr := fsx.PruneStaleSocket(expandedPath, origFi, func() bool {
		return fsx.ProbeStaleUnixSocket(expandedPath, 100*time.Millisecond)
	})
	if pruneErr != nil {
		c.getLogger().Debugf("mux: prune stale control socket %q failed: %v", expandedPath, pruneErr)
		return nil, nil
	}

	switch outcome {
	case fsx.StaleSocketReplaced:
		return c.probeLiveSocketBeforeUnlink(ctx, planNode, expandedPath, target, explicitMaster, 2*time.Second)
	case fsx.StaleSocketLive:
		if client, err, handled := c.tryAttachReactivatedSocket(ctx, planNode, expandedPath, target, explicitMaster); handled {
			return client, err
		}
	case fsx.StaleSocketRemoved:
		c.getLogger().Debugf("mux: unlinked verified stale control socket %q", expandedPath)
	case fsx.StaleSocketAlreadyGone:
		c.getLogger().Debugf("mux: stale socket %q already unlinked by another process", expandedPath)
	}
	return nil, nil
}

func (c *Connector) probeLiveSocketBeforeUnlink(
	ctx context.Context,
	planNode connectionPlanNode,
	expandedPath string,
	target TargetContext,
	explicitMaster bool,
	timeout time.Duration,
) (*Client, error) {
	c.getLogger().Debugf("mux: control socket %q was replaced by another process; probing new master", expandedPath)
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	muxCli, probeErr := DialMuxClient(probeCtx, expandedPath, WithExpectedPeerUID(c.expectedPeerUID()))
	if probeErr != nil {
		if isFatalMultiplexSecurityError(probeErr) {
			return nil, probeErr
		}
		return nil, nil
	}
	if targetErr := c.verifyMuxMasterTarget(muxCli, expandedPath, target); targetErr != nil {
		_ = muxCli.Close()
		if explicitMaster {
			return nil, nil
		}
		return nil, targetErr
	}
	if _, checkErr := muxCli.AliveCheck(probeCtx); checkErr == nil {
		_ = muxCli.Close()
		if explicitMaster {
			return nil, nil
		}
		return c.dialAndPublishProxy(ctx, planNode, expandedPath, target)
	}
	_ = muxCli.Close()
	// Replaced socket belongs to another process; never unlink
	return nil, nil
}

func (c *Connector) tryAttachReactivatedSocket(
	ctx context.Context,
	planNode connectionPlanNode,
	expandedPath string,
	target TargetContext,
	explicitMaster bool,
) (*Client, error, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	muxCli, probeErr := DialMuxClient(probeCtx, expandedPath, WithExpectedPeerUID(c.expectedPeerUID()))
	if probeErr != nil {
		if isFatalMultiplexSecurityError(probeErr) {
			return nil, probeErr, true
		}
		return nil, nil, false
	}
	if targetErr := c.verifyMuxMasterTarget(muxCli, expandedPath, target); targetErr != nil {
		_ = muxCli.Close()
		if explicitMaster {
			return nil, nil, true
		}
		return nil, targetErr, true
	}
	if _, checkErr := muxCli.AliveCheck(probeCtx); checkErr == nil {
		_ = muxCli.Close()
		if explicitMaster {
			return nil, nil, true
		}
		client, err := c.dialAndPublishProxy(ctx, planNode, expandedPath, target)
		return client, err, true
	}
	_ = muxCli.Close()
	return nil, nil, false
}

func (c *Connector) upstreamAbortFunc(parentPooled *PooledClient, rootConn net.Conn) func(self net.Conn) error {
	return func(self net.Conn) error {
		var skipHop *proxyChanConn
		if pc, ok := self.(*proxyChanConn); ok {
			skipHop = pc
		}
		return c.pool.detachAndAbortRoot(parentPooled, rootConn, nil, skipHop)
	}
}

func (c *Connector) hasControlSocket(planNode connectionPlanNode) (bool, error) {
	target := c.buildTargetContext(planNode)
	if !isMultiplexControlEnabled(target) {
		return false, nil
	}
	expandedPath, err := target.Control.ResolvePath(c.environment, target)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(expandedPath) == "" || IsNoneValue(expandedPath) {
		return false, nil
	}
	if err := ValidateControlPath(expandedPath); err != nil {
		return false, err
	}
	fi, err := os.Lstat(expandedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return isControlSocketFileInfo(fi), nil
}

func (c *Connector) buildMuxMasterOptions(planNode connectionPlanNode, target TargetContext, expandedPath string, rootConn, physicalRoot net.Conn) MuxMasterOptions {
	opts := MuxMasterOptions{
		Path:                  expandedPath,
		Target:                target,
		Environment:           c.environment,
		RootConn:              rootConn,
		PhysicalRootConn:      physicalRoot,
		InitialActiveSessions: 1,
		ConfirmSession:        c.confirmSessionCallback(planNode.name, planNode.cfg),
		DialAgent:             c.environment.DialAgent,
		Logger:                c.getLogger(),
	}
	if planNode.cfg == nil || planNode.cfg.Options == nil {
		return opts
	}
	cfgOpts := planNode.cfg.Options
	opts.GatewayPorts = cfgOpts.EffectiveGatewayPorts()
	opts.GatewayPortsMode = cfgOpts.GatewayPortsMode()
	opts.DialNetwork = cfgOpts.DialNetwork()
	opts.StreamLocalBindUnlink = cfgOpts.EffectiveStreamLocalBindUnlink()
	if mask, ok := cfgOpts.StreamLocalBindMask(); ok {
		opts.StreamLocalBindMask = mask
		opts.HasStreamLocalBindMask = true
	}
	if sock, enabled, fwdErr := ResolveForwardAgent(
		cfgOpts.ForwardAgent(),
		cfgOpts.IdentityAgent(),
		c.environment,
		target,
	); fwdErr == nil && enabled && sock != "" && c.environment.DialAgent != nil {
		opts.AllowAgentForward = true
		opts.AgentSocket = sock
	}
	return opts
}

func (c *Connector) masterBeforeTransportClose(pooled *PooledClient, evicted *atomic.Bool) func() func() {
	if c.pool == nil || pooled == nil {
		return nil
	}
	return func() func() {
		evicted.Store(true)
		batch := c.pool.detachForEvict(ZeroHopDigest, pooled, true)
		return batch.closeDescendantsAndRelease
	}
}

func (c *Connector) maybeStartMasterListener(planNode connectionPlanNode, resolvedKeyPath string, rawClient *ssh.Client, rootConn, transportRoot net.Conn, pooled *PooledClient) {
	physicalRoot := transportRoot
	if physicalRoot == nil {
		physicalRoot = rootConn
	}
	target := c.buildTargetContext(planNode)
	if resolvedKeyPath != "" {
		target.KeyPath = resolvedKeyPath
	}
	if !isMultiplexControlEnabled(target) {
		return
	}
	ctrl := target.Control
	if !isMasterListenerMode(ctrl.Master) {
		return
	}

	expandedPath, err := ctrl.ResolvePath(c.environment, target)
	if err != nil || strings.TrimSpace(expandedPath) == "" || IsNoneValue(expandedPath) || ValidateControlPath(expandedPath) != nil {
		return
	}

	var evicted atomic.Bool
	masterOpts := c.buildMuxMasterOptions(planNode, target, expandedPath, rootConn, physicalRoot)
	server, err := startMuxServer(context.Background(), rawClient, masterOpts, c.masterBeforeTransportClose(pooled, &evicted))
	if err != nil {
		// A concurrent master already owns this path (or the bind was rejected).
		// OpenSSH reports the conflict and continues without sharing.
		explicitMaster := (ctrl.Master == ControlMasterYes || ctrl.Master == ControlMasterAsk) && !ctrl.AllowReuse
		c.warnOrDebugf(explicitMaster, "mux: start master server on %q failed: %v; continuing without connection sharing", expandedPath, err)
		return
	}
	c.trackMasterWithPooled(server, planNode.name, pooled, &evicted)
}

// masterOwnership records this connector's hold on a master it started.
// A connector that keeps using a transport is a live session for that master:
// without the reference a bounded ControlPersist idle timer, or another client
// disconnecting, would tear down a transport still in use by this process.
type masterOwnership struct {
	nodeID            string
	foregroundSession bool
	releaseExtra      func()
}

func isMuxServerClosed(srv *MuxServer) bool {
	if srv == nil {
		return true
	}
	waitCh := srv.Wait()
	if waitCh == nil {
		return false
	}
	select {
	case <-waitCh:
		return true
	default:
		return false
	}
}

func (c *Connector) pruneClosedMastersLocked() {
	if len(c.masterOrder) == 0 && len(c.masters) == 0 {
		return
	}
	for srv := range c.masters {
		if isMuxServerClosed(srv) {
			delete(c.masters, srv)
		}
	}
	n := 0
	for _, srv := range c.masterOrder {
		if srv == nil {
			continue
		}
		if _, ok := c.masters[srv]; ok && !isMuxServerClosed(srv) {
			c.masterOrder[n] = srv
			n++
		}
	}
	clear(c.masterOrder[n:])
	c.masterOrder = c.masterOrder[:n]
}

func (c *Connector) watchMasterShutdown(lifecycleCtx context.Context, waitCh <-chan struct{}, pooled *PooledClient, evicted *atomic.Bool) {
	if waitCh == nil {
		return
	}
	go func() {
		if lifecycleCtx != nil {
			select {
			case <-waitCh:
			case <-lifecycleCtx.Done():
				return
			}
		} else {
			<-waitCh
		}
		c.lifecycleMu.Lock()
		closed := c.closed
		if !closed {
			c.pruneClosedMastersLocked()
		}
		c.lifecycleMu.Unlock()
		// Never hold lifecycleMu across connPool.mu or transport teardown.
		// Normally beforeTransportClose already evicted pooled synchronously
		// inside closeTransportBounded(); this fallback covers masters whose
		// Wait() channel closed without running closeTransportBounded().
		if !closed && c.pool != nil && pooled != nil && (evicted == nil || !evicted.Swap(true)) {
			c.pool.EvictByClient(pooled)
		}
	}()
}

// trackMaster records an owned master so CloseAll can release it. A connector
// that is already closed shuts the master down immediately.
func (c *Connector) trackMaster(server *MuxServer, nodeIDs ...string) {
	var nodeID string
	if len(nodeIDs) > 0 {
		nodeID = nodeIDs[0]
	}
	c.trackMasterWithPooled(server, nodeID, nil, nil)
}

func (c *Connector) trackMasterWithPooled(server *MuxServer, nodeID string, pooled *PooledClient, evicted *atomic.Bool) {
	if server == nil {
		return
	}
	c.lifecycleMu.Lock()
	if c.closed {
		c.lifecycleMu.Unlock()
		_ = server.Shutdown()
		return
	}
	c.pruneClosedMastersLocked()
	if isMuxServerClosed(server) {
		c.lifecycleMu.Unlock()
		if c.pool != nil && pooled != nil && (evicted == nil || !evicted.Swap(true)) {
			c.pool.EvictByClient(pooled)
		}
		return
	}
	if c.masters == nil {
		c.masters = make(map[*MuxServer]*masterOwnership)
	}
	_, exists := c.masters[server]
	if !exists {
		c.masterOrder = append(c.masterOrder, server)
	}
	c.masters[server] = &masterOwnership{
		nodeID:            nodeID,
		foregroundSession: true,
	}
	lifecycleCtx := c.lifecycleCtx
	c.lifecycleMu.Unlock()

	if pooled != nil {
		pooled.setEvictHook(server.evictFromPool)
	}
	if !exists {
		c.watchMasterShutdown(lifecycleCtx, server.Wait(), pooled, evicted)
	}
}

// ReleaseMaster drops this connector's active-session reference to a master it
// started, without stopping the master. A ControlPersist handoff needs exactly
// that: the connector keeps its transport counted so the idle timer cannot kill
// a live session, but the detached daemon that inherits the socket must be able
// to take the master over. It reports whether this connector owned server; the
// master stays owned, so CloseAll still stops it if no handoff happens.
func (c *Connector) ReleaseMaster(server *MuxServer) bool {
	if c == nil || server == nil {
		return false
	}
	c.lifecycleMu.Lock()
	c.pruneClosedMastersLocked()
	ownership := c.masters[server]
	release := ownership != nil && ownership.foregroundSession
	var relFn func()
	if release {
		ownership.foregroundSession = false
		relFn = ownership.releaseExtra
		ownership.releaseExtra = nil
	}
	c.lifecycleMu.Unlock()
	if release {
		if relFn != nil {
			relFn()
		} else {
			server.RemoveForegroundSession()
		}
	}
	return ownership != nil
}

// AcquireMaster restores this connector's active-session reference on a master
// it owns after a handoff reservation was rolled back.
func (c *Connector) AcquireMaster(server *MuxServer) bool {
	if c == nil || server == nil {
		return false
	}
	c.lifecycleMu.Lock()
	if c.closed {
		c.lifecycleMu.Unlock()
		return false
	}
	c.pruneClosedMastersLocked()
	ownership := c.masters[server]
	if ownership == nil {
		c.lifecycleMu.Unlock()
		return false
	}
	if ownership.foregroundSession {
		c.lifecycleMu.Unlock()
		return true
	}
	c.lifecycleMu.Unlock()

	rel, ok := server.AcquireForegroundSession()
	if !ok {
		return false
	}

	c.lifecycleMu.Lock()
	c.pruneClosedMastersLocked()
	ownership = c.masters[server]
	if c.closed || ownership == nil || ownership.foregroundSession {
		alreadyHeld := !c.closed && ownership != nil && ownership.foregroundSession
		c.lifecycleMu.Unlock()
		rel()
		return alreadyHeld
	}
	ownership.foregroundSession = true
	ownership.releaseExtra = rel
	c.lifecycleMu.Unlock()
	return true
}

// OwnsMaster reports whether server was started by this connector.
func (c *Connector) OwnsMaster(server *MuxServer) bool {
	if c == nil || server == nil {
		return false
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.pruneClosedMastersLocked()
	_, ok := c.masters[server]
	return ok
}

// HasMasterSession reports whether this connector still holds its initial
// active-session reference on server.
func (c *Connector) HasMasterSession(server *MuxServer) bool {
	if c == nil || server == nil {
		return false
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.pruneClosedMastersLocked()
	ownership := c.masters[server]
	return ownership != nil && ownership.foregroundSession
}

// MasterNodeID returns the logical node identifier recorded when this connector
// started server, or "" if server is nil or not owned by this connector.
func (c *Connector) MasterNodeID(server *MuxServer) string {
	if c == nil || server == nil {
		return ""
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.pruneClosedMastersLocked()
	ownership := c.masters[server]
	if ownership == nil {
		return ""
	}
	return ownership.nodeID
}

// Masters returns a snapshot of the multiplexing masters this connector started
// in deterministic creation order (outermost jump master to innermost target).
func (c *Connector) Masters() []*MuxServer {
	if c == nil {
		return nil
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.pruneClosedMastersLocked()
	masters := make([]*MuxServer, 0, len(c.masterOrder))
	for _, master := range c.masterOrder {
		if _, ok := c.masters[master]; ok {
			masters = append(masters, master)
		}
	}
	return masters
}

// confirmSessionCallback adapts the injected SessionConfirmer into the bounded,
// fail-closed callback a master uses for ask/autoask mode.
func (c *Connector) confirmSessionCallback(nodeName string, cfg *ClientConfig) func(string) bool {
	if c.sessionConfirmer == nil || (cfg != nil && cfg.Options != nil && cfg.Options.BatchMode()) {
		return nil
	}
	confirmer := c.sessionConfirmer
	return func(action string) bool {
		ctx, cancel := context.WithTimeout(c.lifecycleCtx, c.getInteractionTimeout())
		defer cancel()
		approved, err := confirmer.ConfirmSession(ctx, action)
		if err != nil {
			c.getLogger().Debugf("mux: session confirmation for node %s (%s) failed: %v", nodeName, action, err)
			return false
		}
		return approved
	}
}

// publishPooled publishes client into the Merkle-keyed CAS pool and atomically
// starts its owned keepalive (if configured) under the pool lock.
func (c *Connector) publishPooled(key HopDigest, client *PooledClient, expectParent *PooledClient, clientCfg *ClientConfig) (*PooledClient, error) {
	return c.pool.Publish(key, client, expectParent, func(published *PooledClient) {
		c.attachKeepAliveLocked(published, clientCfg)
	})
}

func (c *Connector) resolveKeepAliveParams(clientCfg *ClientConfig) (parentCtx context.Context, interval, timeout time.Duration, nodeScoped bool) {
	c.kaMu.Lock()
	if cfg := c.keepAliveCfg; cfg != nil && cfg.ctx.Err() == nil {
		parentCtx = cfg.ctx
		interval = cfg.interval
		timeout = cfg.timeout
	}
	c.kaMu.Unlock()

	if clientCfg != nil && clientCfg.Options != nil {
		countMax := clientCfg.Options.ServerAliveCountMax()
		if nodeInterval := clientCfg.Options.ServerAliveInterval(); nodeInterval > 0 {
			nodeScoped = true
			parentCtx = c.lifecycleCtx
			interval = nodeInterval
			if countMax <= 0 {
				countMax = 3
			}
			timeout = multiplyDurationSaturated(nodeInterval, countMax)
		} else if interval > 0 && countMax > 0 {
			timeout = multiplyDurationSaturated(interval, countMax)
		}
	}
	return parentCtx, interval, timeout, nodeScoped
}

// attachKeepAliveLocked starts client's owned keepalive while connPool.mu is held.
// Lock ordering: connPool.mu -> Connector.kaMu -> PooledClient.kaMu.
func (c *Connector) attachKeepAliveLocked(client *PooledClient, clientCfg *ClientConfig) {
	parentCtx, interval, timeout, nodeScoped := c.resolveKeepAliveParams(clientCfg)
	if parentCtx == nil || parentCtx.Err() != nil || interval <= 0 {
		return
	}
	hopScopedClose := client.isJumpChildLocked()
	client.startKeepAlive(parentCtx, c.lifecycleCtx, interval, timeout, nodeScoped, func(err error) {
		if errors.Is(err, errKeepaliveTimeout) {
			// Timeout termination already detached and closed client (and its
			// descendants) via beforeClose/interrupt/afterClose; avoid issuing
			// a duplicate synchronous child.closeSelf() on a wedged bastion.
			return
		}
		c.pool.Evict(ZeroHopDigest, client, !hopScopedClose)
	}, &c.keepAliveWG)
}

// EnableKeepAlive 启用连接池周期心跳（opt-in，幂等）。
// 启用后所有新入池的连接（含 ProxyJump 跳板机连接）会挂载周期性 keepalive 探测：
// 接收数据会推迟空闲探测；等待回复期间持续接收数据会刷新超时。
// 探测失败或持续无接收进展直到超时才关闭连接并从池中驱逐，下次 Connect 自动重建。
// interval/timeout 传非正值时回退到 DefaultKeepAliveInterval/DefaultKeepAliveTimeout。
// Connect 的缓存复检以 timeout 为总时限，不随接收进展延长。
// 生命周期同时绑定 ctx 与 CloseAll：任一方取消都会终止全部心跳 goroutine 并清理配置；
// ctx 取消完成清理后允许再次启用，CloseAll 之后则不会恢复。
// 仅对启用后入池的连接生效，存量连接不补挂。
// 适用于 MCP server 等长驻进程；CLI 短生命周期命令无需启用（Connect 的缓存探测已兜底）。
func (c *Connector) EnableKeepAlive(ctx context.Context, interval, timeout time.Duration) {
	if ctx == nil {
		c.getLogger().Debug("ignore EnableKeepAlive call with nil context")
		return
	}
	if ctx.Err() != nil {
		return
	}
	if interval <= 0 {
		interval = DefaultKeepAliveInterval
	}
	if timeout <= 0 {
		timeout = DefaultKeepAliveTimeout
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed {
		return
	}
	c.kaMu.Lock()
	defer c.kaMu.Unlock()
	if c.keepAliveCfg != nil {
		return
	}
	derivedCtx, cancel := context.WithCancel(ctx)
	cfg := &keepAliveConfig{
		ctx:      derivedCtx,
		cancel:   cancel,
		interval: interval,
		timeout:  timeout,
	}
	c.keepAliveCfg = cfg
	for _, plan := range c.plans {
		plan.connector.EnableKeepAlive(derivedCtx, interval, timeout)
	}
	c.keepAliveWG.Add(1)
	go c.watchKeepAliveConfig(cfg)
}

func (c *Connector) watchKeepAliveConfig(cfg *keepAliveConfig) {
	defer c.keepAliveWG.Done()
	<-cfg.ctx.Done()

	c.kaMu.Lock()
	if c.keepAliveCfg != cfg {
		c.kaMu.Unlock()
		return
	}
	c.keepAliveCfg = nil
	c.kaMu.Unlock()

	c.pool.StopGlobalKeepAlives()
}

func multiplyDurationSaturated(d time.Duration, count int) time.Duration {
	if d <= 0 || count <= 0 {
		return 0
	}
	if int64(d) > math.MaxInt64/int64(count) {
		return time.Duration(math.MaxInt64)
	}
	return d * time.Duration(count)
}

func normalizeHostAddress(host string) string {
	return cleanHostLiteral(host)
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(normalizeHostAddress(host), strconv.Itoa(port))
}

func setInitialHandshakeDeadline(ctx context.Context, conn net.Conn, nodeName string, timeout time.Duration) error {
	handshakeDeadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(handshakeDeadline) {
		handshakeDeadline = ctxDeadline
	}
	if err := conn.SetDeadline(handshakeDeadline); err != nil {
		if !strings.Contains(err.Error(), "deadline not supported") {
			if closeErr := conn.Close(); closeErr != nil {
				return fmt.Errorf(
					"set SSH handshake deadline for '%s' failed: %w; close connection after deadline setup failed: %w",
					nodeName,
					err,
					closeErr,
				)
			}
			return fmt.Errorf("set SSH handshake deadline for '%s' failed: %w", nodeName, err)
		}
	}
	return nil
}

func wrapCloseError(err error, operation string) error {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

func combineSSHOperationErrors(primary, secondary error) error {
	if secondary == nil {
		return primary
	}
	return fmt.Errorf("%w; %w", primary, secondary)
}

// CloseAll 关闭所有缓存的连接并等待在途建连与心跳 goroutine 退出。
// 调用后 Connector 进入永久关闭状态，后续 Connect 返回 ErrConnectorClosed。
func (c *Connector) CloseAll() error {
	c.lifecycleMu.Lock()
	if c.closed {
		closeDone := c.closeDone
		c.lifecycleMu.Unlock()
		<-closeDone
		return c.closeErr
	}
	c.closed = true
	c.lifecycleCancel()
	planConnectors := make([]*planEntry, 0, len(c.allPlans))
	for plan := range c.allPlans {
		planConnectors = append(planConnectors, plan)
	}
	ownedMasters := make([]*MuxServer, 0, len(c.masterOrder))
	for _, master := range c.masterOrder {
		if _, ok := c.masters[master]; ok {
			ownedMasters = append(ownedMasters, master)
		}
	}
	c.masters = nil
	c.masterOrder = nil
	clear(c.plans)
	clear(c.retiredPlans)
	c.lifecycleMu.Unlock()

	var closeErrs []error

	// 1. Immediately stop listening and unlink control sockets on all owned
	// masters without performing any blocking SSH channel I/O so no new clients
	// attach during teardown.
	for _, master := range ownedMasters {
		master.beginShutdown()
	}

	// 2. Close the pool to forbid new publication, stop all per-client
	// keepalives, and drain active, retired, and closing transports ordered
	// root-first before shutting down masters or joining connect workers.
	var pooledClients []*PooledClient
	if c.pool != nil {
		pooledClients = c.pool.Close()
	}

	// 3. Abort physical root transports FIRST so any write-wedged or blackholed
	// upstream bastion unblocks immediately before child masters or multiplexed
	// child channels shut down.
	closedRoots, rootErrs := abortPhysicalRootConns(pooledClients, ownedMasters)
	closeErrs = append(closeErrs, rootErrs...)

	// 4. Finish shutting down owned masters (root-first) and plan connectors.
	for _, master := range ownedMasters {
		if err := master.Shutdown(); err != nil {
			closeErrs = append(closeErrs, err)
		}
	}
	for _, plan := range planConnectors {
		if err := c.closePlan(plan); err != nil {
			closeErrs = append(closeErrs, err)
		}
	}
	closeErrs = append(closeErrs, interruptUniquePooledClients(closedRoots, pooledClients)...)
	c.connectWG.Wait()

	c.kaMu.Lock()
	if c.keepAliveCfg != nil {
		c.keepAliveCfg.cancel()
		c.keepAliveCfg = nil
	}
	c.kaMu.Unlock()

	c.keepAliveWG.Wait()

	if len(closeErrs) > 0 {
		c.closeErr = fmt.Errorf("close pooled SSH clients failed: %w", errors.Join(closeErrs...))
	}
	close(c.closeDone)
	return c.closeErr
}

func isComparableConn(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	t := reflect.TypeOf(conn)
	return t != nil && t.Comparable()
}

func abortPhysicalRootConns(pooled []*PooledClient, masters []*MuxServer) (map[net.Conn]struct{}, []error) {
	closedRoots := make(map[net.Conn]struct{})
	var errs []error
	closeConn := func(conn net.Conn) {
		if conn == nil {
			return
		}
		if _, isProxyChan := conn.(*proxyChanConn); isProxyChan {
			return
		}
		if isComparableConn(conn) {
			if _, seen := closedRoots[conn]; seen {
				return
			}
			closedRoots[conn] = struct{}{}
		}
		if err := closeResource(conn, "root SSH transport"); err != nil {
			errs = append(errs, err)
		}
	}
	for _, client := range pooled {
		if client != nil {
			closeConn(client.RootConn)
		}
	}
	for _, master := range masters {
		if master == nil {
			continue
		}
		if master.physicalRoot != nil {
			closeConn(master.physicalRoot)
		} else {
			closeConn(master.rootConn)
		}
	}
	return closedRoots, errs
}

func interruptUniquePooledClients(closedRoots map[net.Conn]struct{}, groups ...[]*PooledClient) []error {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	seen := make(map[*PooledClient]struct{}, total)
	var errs []error
	for _, group := range groups {
		for _, client := range group {
			if client == nil {
				continue
			}
			if _, ok := seen[client]; ok {
				continue
			}
			seen[client] = struct{}{}
			rootConn := client.RootConn
			if rootConn != nil && closedRoots != nil && isComparableConn(rootConn) {
				if _, alreadyClosed := closedRoots[rootConn]; alreadyClosed {
					rootConn = nil
				}
			}
			var sshClient *ssh.Client
			if client.SSHClient != nil && client.SSHClient.Conn != nil {
				sshClient = client.SSHClient
			}
			if err := interruptSSHTransport(rootConn, sshClient); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errs
}
