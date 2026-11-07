package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
	logger "github.com/wentf9/xops-cli/core/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
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
	// 连接池：缓存 nodeName -> *ssh.Client
	clients *concurrent.Map[string, *PooledClient]
	// singleflight 组，用来控制并发和去重
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

	// kaMu 保护 keepAliveCfg 的启用/关闭（keepAlives 自带分片锁，无需 kaMu）
	kaMu sync.Mutex
	// keepAliveCfg 为 nil 表示未启用周期心跳（CLI 短生命周期命令默认不启用）
	keepAliveCfg *keepAliveConfig
	// keepAlives 心跳注册表：nodeName -> 运行中的心跳条目
	keepAlives *concurrent.Map[string, *keepAliveEntry]
	// keepAliveWG 覆盖配置 watcher 及已从注册表驱逐、但尚未完全返回的心跳 goroutine。
	keepAliveWG sync.WaitGroup
	logger      logger.DebugLogger
	diagnostics logger.DiagnosticObserver
}

// keepAliveConfig 描述 Connector 级心跳配置（见 EnableKeepAlive）
type keepAliveConfig struct {
	ctx               context.Context // 根心跳 ctx，取消后级联终止所有 per-node 心跳
	cancel            context.CancelFunc
	interval, timeout time.Duration
}

// keepAliveEntry 单个连接的心跳注册条目
type keepAliveEntry struct {
	cancel     context.CancelFunc // per-node ctx 的取消函数
	client     *PooledClient      // 心跳目标，用于驱逐时指针比对防止误删新连接
	done       <-chan struct{}    // 心跳 goroutine 的退出通知
	nodeScoped bool               // 是否由节点自身的 ServerAliveInterval 驱动（独立于全局 keepAliveCfg 生命周期）
}

var knownHostsFileMutex sync.Mutex

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
		clients:            concurrent.NewMap[string, *PooledClient](concurrent.HashString),
		lifecycleCtx:       lifecycleCtx,
		lifecycleCancel:    lifecycleCancel,
		closeDone:          make(chan struct{}),
		keepAlives:         concurrent.NewMap[string, *keepAliveEntry](concurrent.HashString),
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
	name    string
	cfg     *ClientConfig
	control *ControlConfig
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

	// A downstream probe can invalidate the jump clients already visited in
	// this plan. Restart outside singleflight, so no node task waits recursively
	// for another node task. Bound restarts even under repeated concurrent loss.
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

// reuseJumpChainedTarget reuses the final target without rebuilding its jump
// chain. Cached intermediate hops are still validated first: a bastion that
// stops answering while it keeps forwarding would otherwise go unnoticed,
// because the target's own probe only exercises the outermost session. A hop
// without a cached transport contributes nothing to check, which is exactly the
// case where the target's control master must be used without dialing the
// bastion. Hops go through the node's shared task so the probe runs on the
// connector lifecycle: one caller's cancellation must not interrupt a transport
// other callers still use. The validated hops are returned so the chain build
// can reuse them instead of probing the same transports a second time.
func (c *Connector) reuseJumpChainedTarget(ctx context.Context, plan []connectionPlanNode) (*Client, map[string]*Client, error) {
	validated := make(map[string]*Client, len(plan)-1)
	for index := len(plan) - 1; index > 0; index-- {
		planNode := plan[index]
		cached, ok := c.clients.Get(planNode.name)
		if !ok || cached.SSHClient.Conn == nil {
			continue
		}
		hopClient, err := c.connectPlannedNode(ctx, planNode, nil, true)
		if err != nil {
			// Only "not reusable" falls back to building the chain; a canceled caller
			// or a closed connector must surface as itself so the caller stops here and
			// the failure keeps the hop it happened on.
			c.getLogger().Debugf("mux: cached jump hop %s is not reusable (%v)", planNode.name, err)
			if errors.Is(err, errJumpChainRequired) {
				// The cached hop was stale and evicted; evict any in-process cached
				// target that rode on it, but still let plan[0] attach to an external
				// control master socket if one exists on disk.
				if staleTarget, ok := c.clients.Get(plan[0].name); ok {
					c.evictCachedClient(plan[0].name, staleTarget)
					_ = staleTarget.interrupt()
				}
				validated = nil
				break
			}
			return nil, nil, err
		}
		// This transport was validated a moment ago on the connector lifecycle;
		// probing it again while the chain is rebuilt would repeat a network
		// round trip per cached hop.
		validated[planNode.name] = hopClient
	}
	client, err := c.connectPlannedNode(ctx, plan[0], nil, true)
	return client, validated, err
}

func (c *Connector) connectPlan(ctx context.Context, plan []connectionPlanNode) (*Client, error) {
	var connected *Client
	// A cached target transport or an active control master already carries the
	// whole jump chain, so reusing it must not dial (and re-authenticate to) the
	// bastion first. Probe the final target alone before building the chain; an
	// unreusable target reports errJumpChainRequired and falls through below.
	var validatedHops map[string]*Client
	if len(plan) > 1 {
		reused, validated, err := c.reuseJumpChainedTarget(ctx, plan)
		if err == nil {
			return reused, nil
		}
		if !errors.Is(err, errJumpChainRequired) {
			return nil, err
		}
		validatedHops = validated
	}
	for index := len(plan) - 1; index >= 0; index-- {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("connect node '%s' canceled: %w", plan[0].name, err)
		}

		planNode := plan[index]
		if validated, ok := validatedHops[planNode.name]; ok && validated != nil {
			// Already validated in this call; reuse it instead of dialing the hop
			// again. It still carries the whole chain for the next hop below.
			connected = validated
			continue
		}
		dialer := c.baseDialer
		if dialer == nil {
			dialer = c.directDialerFor(planNode.cfg)
		}
		if planNode.cfg.ProxyJump != "" {
			if connected == nil {
				return nil, fmt.Errorf("resolved proxy jump '%s' for node '%s' has no client", planNode.cfg.ProxyJump, planNode.name)
			}
			dialer = &SSHProxyDialer{Client: connected.sshClient, RootConn: connected.rootConn}
		}

		var err error
		connected, err = c.connectPlannedNode(ctx, planNode, dialer, false)
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
		nodeCfg := *cfg
		if nodeCfg.Port <= 0 {
			nodeCfg.Port = 22
		}
		if !nodeCfg.HasOriginalProxyJump {
			nodeCfg.OriginalProxyJump = nodeCfg.ProxyJump
			nodeCfg.HasOriginalProxyJump = true
		}
		positions[current] = len(plan)
		plan = append(plan, connectionPlanNode{name: current, cfg: &nodeCfg, control: c.resolveControl(current, &nodeCfg)})

		jumps := splitProxyJumpChain(nodeCfg.ProxyJump)
		if len(jumps) > 1 {
			for index := len(jumps) - 1; index >= 0; index-- {
				jumpName := jumps[index]
				if cycleStart, ok := positions[jumpName]; ok {
					path := make([]string, 0, len(plan)-cycleStart+1)
					for _, item := range plan[cycleStart:] {
						path = append(path, item.name)
					}
					path = append(path, jumpName)
					return nil, &ProxyCycleError{NodeID: jumpName, Path: path}
				}
				jumpCfg, jumpErr := c.provider.GetConfig(jumpName)
				if jumpErr != nil {
					return nil, fmt.Errorf("fetch config for proxy jump %q failed: %w", jumpName, jumpErr)
				}
				if jumpCfg == nil {
					return nil, fmt.Errorf("config for proxy jump %q is nil", jumpName)
				}
				cloned := *jumpCfg
				if cloned.Port <= 0 {
					cloned.Port = 22
				}
				cloned.OriginalProxyJump = jumpCfg.ProxyJump
				cloned.HasOriginalProxyJump = true
				if index > 0 {
					cloned.ProxyJump = strings.Join(jumps[:index], ",")
				} else {
					cloned.ProxyJump = ""
				}
				positions[jumpName] = len(plan)
				plan = append(plan, connectionPlanNode{name: jumpName, cfg: &cloned, control: c.resolveControl(jumpName, &cloned)})
			}
			return plan, nil
		}
		current = cfg.ProxyJump
	}
	return plan, nil
}

// expectedPeerUID is the identity a control socket endpoint must run as. It
// mirrors StartMuxServer so a client and the master it talks to agree even when
// the host injects a UID that differs from the effective one (containers).
func (c *Connector) expectedPeerUID() uint32 {
	return expectedPeerUIDFromEnvironment(c.environment)
}

func (c *Connector) resolveControl(nodeName string, cfg *ClientConfig) *ControlConfig {
	if c.controlProvider != nil {
		if ctrl, err := c.controlProvider.GetControlConfig(nodeName); err == nil && ctrl != nil {
			return ctrl
		}
		return nil
	}
	if cp, ok := c.provider.(ControlProvider); ok {
		if ctrl, err := cp.GetControlConfig(nodeName); err == nil && ctrl != nil {
			return ctrl
		}
		return nil
	}
	if cfg != nil && cfg.Options != nil {
		if err := cfg.Options.ValidateEffective(); err == nil {
			return cfg.Options.ControlConfig()
		} else {
			c.getLogger().Debugf("ssh: ignoring invalid effective control options for %q: %v", nodeName, err)
		}
	}
	return nil
}

func splitProxyJumpChain(proxyJump string) []string {
	var jumps []string
	for jump := range strings.SplitSeq(proxyJump, ",") {
		jump = strings.TrimSpace(jump)
		if jump != "" {
			jumps = append(jumps, jump)
		}
	}
	return jumps
}

// connectPlannedNode runs the cache/multiplex/connect decision for one node in a
// shared task. reuseOnly stops before dialing so a jump-chained target can be
// reused without its bastion; a caller that finds errJumpChainRequired retries
// with the full chain once the reuse-only task has finished.
func (c *Connector) connectPlannedNode(ctx context.Context, planNode connectionPlanNode, dialer Dialer, reuseOnly bool) (*Client, error) {
	for {
		// 缓存复检、失效驱逐和重建位于同一个共享任务内。任务仅绑定 Connector 生命周期，
		// 单个调用者取消只停止等待，不会关闭连接池中由其他调用者共享的连接。
		resultCh := c.sf.DoChan(planNode.name, func() (any, error) {
			sharedCtx, finish, err := c.beginSharedConnect()
			if err != nil {
				return nil, err
			}
			defer finish()
			return c.connectNode(sharedCtx, planNode, dialer, reuseOnly)
		})

		client, err := c.awaitPlannedNode(ctx, planNode.name, resultCh)
		if err != nil && !reuseOnly && errors.Is(err, errJumpChainRequired) {
			// This call joined another caller's reuse-only task, so the target was
			// reported as not reusable. The task is finished; asking again runs the
			// full chain. Each repeat needs another caller to start a fresh probe and
			// the wait stays bounded by ctx, so a full-mode call never surfaces the
			// internal sentinel.
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

func (c *Connector) connectNode(ctx context.Context, planNode connectionPlanNode, dialer Dialer, reuseOnly bool) (*Client, error) {
	nodeName := planNode.name
	var probeErr error
	if cachedClient, ok := c.clients.Get(nodeName); ok {
		if cachedClient.SSHClient.Conn == nil {
			logger.EmitDiagnostic(c.diagnostics, logger.Diagnostic{Kind: logger.ConnectionReused, NodeID: nodeName})
			return c.wrapCachedClient(planNode.cfg, cachedClient), nil
		}

		if err := c.probeCachedClient(ctx, cachedClient); err == nil {
			logger.EmitDiagnostic(c.diagnostics, logger.Diagnostic{Kind: logger.ConnectionReused, NodeID: nodeName})
			return c.wrapCachedClient(planNode.cfg, cachedClient), nil
		} else {
			probeErr = err
			c.evictCachedClient(nodeName, cachedClient)
			if ctx.Err() != nil {
				return nil, fmt.Errorf("probe cached SSH connection for node '%s' failed: %w", nodeName, ctx.Err())
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

	client, err := c.initializeConnection(ctx, planNode, dialer)
	// Another caller can invalidate the same root after the check above.
	if proxy, ok := dialer.(*SSHProxyDialer); err != nil && ok && proxy.transportClosed() && ctx.Err() == nil {
		return nil, fmt.Errorf("rebuild proxy chain for '%s': %w", nodeName, errors.Join(errProxyTransportClosed, err))
	}
	return client, err
}

func (c *Connector) wrapCachedClient(cfg *ClientConfig, cachedClient *PooledClient) *Client {
	client := c.configureClient(newClientWithComponents(
		cachedClient.SSHClient,
		cachedClient.RootConn,
		cfg,
		c.provider,
		c.secretResolver,
		c.getNodeSecretPrompter(cfg),
		c.credentialRecorder,
		c.PasswordPromptPattern,
		c.getNodeHandshakeTimeout(cfg),
		c.getInteractionTimeout(),
		c.getLogger(),
	))
	cachedClient.probeMu.Lock()
	if cachedClient.probeCache == nil {
		cachedClient.probeCache = &executionProbeCache{}
	}
	client.probeCache = cachedClient.probeCache
	cachedClient.probeMu.Unlock()
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
	return probeWithTimeoutAndInterrupt(probeCtx, client.SSHClient, timeout, client.interrupt)
}

func (c *Connector) keepAliveProbeTimeout() time.Duration {
	c.kaMu.Lock()
	defer c.kaMu.Unlock()
	if c.keepAliveCfg != nil {
		return c.keepAliveCfg.timeout
	}
	return DefaultKeepAliveTimeout
}

func (c *Connector) evictCachedClient(nodeName string, stale *PooledClient) {
	concurrent.RemoveIfMatch(c.clients, nodeName, stale)
	c.removeKeepAliveFor(nodeName, stale)
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

func (c *Connector) recordAuthUpdate(ctx context.Context, nodeName string, cfg *ClientConfig, rootConn net.Conn) (string, error) {
	if (cfg.Password == "" && cfg.Passphrase == "") || cfg.AuthUpdateToken == "" {
		return cfg.AuthUpdateToken, nil
	}
	committedToken, err := c.credentialRecorder.UpdateAuth(ctx, nodeName, cfg.AuthUpdateToken, cfg.Password, cfg.KeyPath, cfg.Passphrase)
	if err != nil {
		if reportCredentialFailure(ctx, c.getNodeSecretPrompter(cfg), "save", err) {
			return "", errCredentialNotSaved
		}
		if closeErr := rootConn.Close(); closeErr != nil {
			return "", fmt.Errorf("failed to update authentication for node '%s': %w; close unpublished SSH client failed: %w", nodeName, err, closeErr)
		}
		return "", fmt.Errorf("failed to update authentication for node '%s': %w", nodeName, err)
	}
	return committedToken, nil
}

func shouldRecordDiscoveredAuth(discoveredAuth bool, oldAuthToken string, cfg *ClientConfig) bool {
	if !discoveredAuth || oldAuthToken == "" || cfg == nil {
		return false
	}
	return cfg.Password != "" || cfg.Passphrase != ""
}

func (c *Connector) initializeConnection(ctx context.Context, planNode connectionPlanNode, dialer Dialer) (_ *Client, retErr error) {
	nodeName := planNode.name
	cfg := planNode.cfg
	originalKeyPath := cfg.KeyPath

	coordinator := newHandshakeCoordinator(ctx, c.getNodeHandshakeTimeout(cfg))
	defer coordinator.Close()

	var discoveredAuth bool
	authentication := newAuthenticationTrace(c.diagnostics, nodeName)
	sshConfig, cleanup, err := c.buildSSHConfig(ctx, cfg, coordinator, func() {
		discoveredAuth = true
	}, authentication)
	if err != nil {
		return nil, fmt.Errorf("failed to build ssh config for '%s': %w", nodeName, err)
	}
	if cleanup != nil {
		cleanup = sync.OnceValue(cleanup)
		defer func() { retErr = errors.Join(retErr, cleanup()) }()
	}

	// 共享任务不继承任一调用者的 deadline，由 coordinator 统一施加有界超时并在交互时暂停；
	// 这同时约束直连和 ProxyJump 的通道建立，避免共享任务无限占用 singleflight。
	rawClient, rootConn, err := c.dialAndHandshake(coordinator.Context(), nodeName, cfg, dialer, sshConfig, coordinator, authentication)
	if err != nil {
		return nil, fmt.Errorf("failed to dial and handshake: %w", err)
	}
	if cleanup != nil {
		if err := cleanup(); err != nil {
			return nil, errors.Join(fmt.Errorf("release SSH authentication material: %w", err), closeResource(rawClient, "SSH client after authentication cleanup"), closeResource(rootConn, "SSH transport after authentication cleanup"))
		}
	}
	transportRoot := rootConn
	if proxy, ok := dialer.(*SSHProxyDialer); ok && proxy.RootConn != nil {
		transportRoot = proxy.RootConn
	}
	client := c.wrapCachedClient(cfg, &PooledClient{SSHClient: rawClient, RootConn: transportRoot})
	if err := c.confirmAuthenticatedConnection(ctx, nodeName, rootConn, client, cfg); err != nil {
		return nil, err
	}
	if err := checkInitializedTransport(nodeName, cfg, client); err != nil {
		return nil, err
	}

	// 认证并连接成功后，检查我们是否通过 "auto" 下的终端交互获取到了新凭证（密码或密钥密码）。
	oldAuthToken := cfg.AuthUpdateToken
	hasAuthUpdate := shouldRecordDiscoveredAuth(discoveredAuth, oldAuthToken, cfg)
	var committedAuthToken string
	recordingFailed := false
	if hasAuthUpdate {
		var err error
		committedAuthToken, err = c.recordAuthUpdate(ctx, nodeName, cfg, rootConn)
		if errors.Is(err, errCredentialNotSaved) {
			recordingFailed = true
			hasAuthUpdate = false
		} else if err != nil {
			return nil, err
		}
	}

	// [P1] 认证写回可能更新了 Repository 的认证版本（如 auto 认证交互记录了新密码/私钥密码），
	// 必须从底层 provider 重新刷新 cfg 中的最新版本令牌并校验目标与版本推进兼容性。
	if err := c.syncConnectionAfterRecording(nodeName, cfg, committedAuthToken, hasAuthUpdate, recordingFailed, originalKeyPath, rootConn); err != nil {
		return nil, err
	}

	if recordingFailed {
		// The write may have applied without durable confirmation. Keep the
		// authenticated connection, but never authorize subsequent writes using
		// either stale tokens or an unrelated refreshed configuration version.
		cfg.AuthUpdateToken = ""
		cfg.SudoUpdateToken = ""
	}

	// 连接与凭证记录完成后，立即抹除单次握手使用的明文机密，防止敏感材料残留在池化 Client 中
	cfg.Password = ""
	cfg.Passphrase = ""
	cfg.SuPwd = ""

	if err := checkInitializedTransport(nodeName, cfg, client); err != nil {
		return nil, err
	}
	pooled := &PooledClient{SSHClient: rawClient, RootConn: transportRoot, probeCache: client.executionProbeCache()}
	if err := c.publishClient(nodeName, pooled); err != nil {
		if closeErr := rootConn.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w; close unpublished SSH client failed: %w", err, closeErr)
		}
		return nil, err
	}
	c.startKeepAliveFor(nodeName, pooled, cfg)
	// Start multiplexing master if configured. Pass rootConn (this hop's own
	// connection, not the bastion's transportRoot) so shutting down a jump-target
	// master never closes the underlying bastion TCP connection.
	c.maybeStartMasterListener(planNode, rawClient, rootConn)
	// 返回封装的 Client，注入组件，且 Client 不持有 AuthMaterial
	client.cfgMu.Lock()
	client.connCfg = cfg.ToConnectionConfig()
	client.cfgMu.Unlock()
	return client, nil
}

func (c *Connector) buildTargetContext(planNode connectionPlanNode) TargetContext {
	cfg := planNode.cfg
	port := cfg.Port
	if port <= 0 {
		port = 22
	}
	user := cfg.User
	if user == "" {
		user = c.environment.LocalUser
	}
	originalHost := cfg.NodeID
	if originalHost == "" {
		originalHost = planNode.name
	}
	return TargetContext{
		Host:         cfg.Address,
		Port:         port,
		User:         user,
		OriginalHost: originalHost,
		JumpHost:     cfg.ProxyJump,
		KeyPath:      cfg.KeyPath,
		Control:      planNode.control,
	}
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
	if !ok || target.MatchesMasterTarget(masterTarget) {
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

func (c *Connector) tryConnectMultiplex(ctx context.Context, planNode connectionPlanNode) (*Client, error) {
	target := c.buildTargetContext(planNode)
	ctrl := target.Control
	if ctrl == nil || ctrl.Path == "" || ctrl.Path == "none" {
		return nil, nil // Multiplexing disabled
	}

	explicitMaster := ctrl.Master == ControlMasterYes || ctrl.Master == ControlMasterAsk

	// 1. Expand ControlPath tokens
	expandedPath, err := ExpandControlPath(ctrl.Path, c.environment, target)
	if err != nil {
		c.warnOrDebugf(explicitMaster, "mux: expand control path %q failed: %v; continuing without connection sharing", ctrl.Path, err)
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
	dialCtx, cancel := context.WithTimeout(ctx, c.getNodeHandshakeTimeout(planNode.cfg))
	defer cancel()
	rawClient, proxyConn, proxyErr := DialControlProxy(dialCtx, expandedPath, target, WithExpectedPeerUID(c.expectedPeerUID()))
	if proxyErr != nil {
		return nil, proxyErr
	}

	pooled := &PooledClient{
		SSHClient: rawClient,
		RootConn:  proxyConn.RawConn(),
	}
	if err := c.publishClient(planNode.name, pooled); err != nil {
		_ = rawClient.Close()
		_ = proxyConn.Close()
		return nil, err
	}
	c.startKeepAliveFor(planNode.name, pooled, planNode.cfg)
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
	currFi, err := os.Lstat(expandedPath)
	if err != nil || !isControlSocketFileInfo(currFi) {
		c.getLogger().Debugf("mux: stale socket %q already unlinked by another process", expandedPath)
		return nil, nil
	}

	ctrl := target.Control
	explicitMaster := ctrl != nil && (ctrl.Master == ControlMasterYes || ctrl.Master == ControlMasterAsk)

	// 1. If file identity changed, another process replaced the socket
	if !os.SameFile(origFi, currFi) {
		return c.probeLiveSocketBeforeUnlink(ctx, planNode, expandedPath, target, explicitMaster, 2*time.Second)
	}

	// 2. File identity is unchanged. Perform a brief probe dial to ensure the socket didn't just activate
	if client, err, handled := c.tryAttachReactivatedSocket(ctx, planNode, expandedPath, target, explicitMaster); handled {
		return client, err
	}

	// 3. Atomically confirm file identity directly before unlinking to close TOCTOU window
	if finalFi, finalErr := os.Lstat(expandedPath); finalErr == nil && isControlSocketFileInfo(finalFi) && os.SameFile(origFi, finalFi) {
		c.getLogger().Debugf("mux: unlinking verified stale control socket %q", expandedPath)
		_ = os.Remove(expandedPath)
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

func (c *Connector) maybeStartMasterListener(planNode connectionPlanNode, rawClient *ssh.Client, rootConn net.Conn) {
	target := c.buildTargetContext(planNode)
	ctrl := target.Control
	if ctrl == nil || ctrl.Path == "" || ctrl.Path == "none" {
		return
	}
	if ctrl.Master != ControlMasterYes && ctrl.Master != ControlMasterAuto && ctrl.Master != ControlMasterAsk && ctrl.Master != ControlMasterAutoAsk {
		return
	}

	expandedPath, err := ExpandControlPath(ctrl.Path, c.environment, target)
	if err != nil || ValidateControlPath(expandedPath) != nil {
		return
	}

	server, err := StartMuxServer(context.Background(), rawClient, MuxMasterOptions{
		Path:                  expandedPath,
		Target:                target,
		Environment:           c.environment,
		RootConn:              rootConn,
		InitialActiveSessions: 1,
		ConfirmSession:        c.confirmSessionCallback(planNode.name, planNode.cfg),
	})
	if err != nil {
		// A concurrent master already owns this path (or the bind was rejected).
		// OpenSSH reports the conflict and continues without sharing.
		explicitMaster := ctrl.Master == ControlMasterYes || ctrl.Master == ControlMasterAsk
		c.warnOrDebugf(explicitMaster, "mux: start master server on %q failed: %v; continuing without connection sharing", expandedPath, err)
		return
	}
	c.trackMaster(server)
}

// masterOwnership records this connector's hold on a master it started.
// A connector that keeps using a transport is a live session for that master:
// without the reference a bounded ControlPersist idle timer, or another client
// disconnecting, would tear down a transport still in use by this process.
type masterOwnership struct {
	foregroundSession bool
}

// trackMaster records an owned master so CloseAll can release it. A connector
// that is already closed shuts the master down immediately.
func (c *Connector) trackMaster(server *MuxServer) {
	if server == nil {
		return
	}
	c.lifecycleMu.Lock()
	if c.closed {
		c.lifecycleMu.Unlock()
		_ = server.Shutdown()
		return
	}
	if c.masters == nil {
		c.masters = make(map[*MuxServer]*masterOwnership)
	}
	if _, exists := c.masters[server]; !exists {
		c.masterOrder = append(c.masterOrder, server)
	}
	c.masters[server] = &masterOwnership{foregroundSession: true}
	c.lifecycleMu.Unlock()
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
	ownership := c.masters[server]
	release := ownership != nil && ownership.foregroundSession
	if release {
		ownership.foregroundSession = false
	}
	c.lifecycleMu.Unlock()
	if release {
		server.RemoveForegroundSession()
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

	if !server.AddForegroundSession() {
		return false
	}

	c.lifecycleMu.Lock()
	ownership = c.masters[server]
	if c.closed || ownership == nil || ownership.foregroundSession {
		c.lifecycleMu.Unlock()
		server.RemoveForegroundSession()
		return ownership != nil && ownership.foregroundSession
	}
	ownership.foregroundSession = true
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
	ownership := c.masters[server]
	return ownership != nil && ownership.foregroundSession
}

// Masters returns a snapshot of the multiplexing masters this connector started
// in deterministic creation order (outermost jump master to innermost target).
func (c *Connector) Masters() []*MuxServer {
	if c == nil {
		return nil
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
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

func (c *Connector) publishClient(nodeName string, client *PooledClient) error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed {
		return ErrConnectorClosed
	}
	c.clients.Set(nodeName, client)
	return nil
}

func checkInitializedTransport(nodeID string, cfg *ClientConfig, client *Client) error {
	if err := client.transportError(); err != nil {
		connectionErr := &ConnectionError{NodeID: nodeID, Address: cfg.Address, Port: cfg.Port, AuthType: cfg.AuthType,
			Err: fmt.Errorf("SSH transport closed during initialization: %w", err)}
		return errors.Join(connectionErr, client.Interrupt())
	}
	return nil
}

func (c *Connector) syncAuthTokensAfterConnection(nodeName string, cfg *ClientConfig, committedAuthToken string, hasAuthUpdate bool, rootConn net.Conn, originalKeyPaths ...string) error {
	if c.provider == nil {
		return nil
	}
	newCfg, err := c.provider.GetConfig(nodeName)
	if err != nil {
		if hasAuthUpdate {
			if closeErr := rootConn.Close(); closeErr != nil {
				return fmt.Errorf("reload config for node %q after auth update failed: %w; close unpublished SSH client failed: %w", nodeName, err, closeErr)
			}
			return fmt.Errorf("reload config for node %q after auth update failed: %w", nodeName, err)
		}
		return nil
	}
	if newCfg == nil {
		return nil
	}

	reconcileFailedWriteKeyPath(cfg, newCfg, originalKeyPaths)

	// [P1] 校验完整连接目标（Address, Port, User, KeyPath, ProxyJump）是否仍然与当前已建立的连接一致
	if err := validateTargetCompatibility(cfg.ToConnectionConfig(), newCfg); err != nil {
		if closeErr := rootConn.Close(); closeErr != nil {
			return fmt.Errorf("incompatible target update for node %q during connection setup: %w; close unpublished SSH client failed: %w", nodeName, err, closeErr)
		}
		return fmt.Errorf("incompatible target update for node %q during connection setup: %w", nodeName, err)
	}

	// [P1] 校验刷新版本与本次写回的对应关系：必须严格等于本次事务实际提交的版本，拒绝采纳后续无关更新，且允许幂等未变
	if hasAuthUpdate {
		if committedAuthToken != "" && newCfg.AuthUpdateToken != committedAuthToken {
			if closeErr := rootConn.Close(); closeErr != nil {
				return fmt.Errorf("%w: auth version mismatch after update for node %q (expected %q, got %q); close unpublished SSH client failed: %w",
					ErrSnapshotMismatch, nodeName, committedAuthToken, newCfg.AuthUpdateToken, closeErr)
			}
			return fmt.Errorf("%w: auth version mismatch after update for node %q (expected %q, got %q)",
				ErrSnapshotMismatch, nodeName, committedAuthToken, newCfg.AuthUpdateToken)
		}
		cfg.AuthUpdateToken = newCfg.AuthUpdateToken
		if newCfg.HasOriginalProxyJump {
			cfg.OriginalProxyJump = newCfg.OriginalProxyJump
			cfg.HasOriginalProxyJump = true
		} else if newCfg.OriginalProxyJump != "" {
			cfg.OriginalProxyJump = newCfg.OriginalProxyJump
		}
	}
	return nil
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
	defer c.kaMu.Unlock()
	if c.keepAliveCfg != cfg {
		return
	}
	c.keepAliveCfg = nil
	var globalNodes []string
	c.keepAlives.IterCb(func(nodeName string, entry *keepAliveEntry) bool {
		if !entry.nodeScoped {
			entry.cancel()
			globalNodes = append(globalNodes, nodeName)
		}
		return true
	})
	for _, nodeName := range globalNodes {
		c.keepAlives.Remove(nodeName)
	}
}

// startKeepAliveFor 为入池连接挂载心跳；未启用心跳时为 no-op。
// 全程持有 kaMu：与 CloseAll（cancel 根 ctx + 清空注册表）完全互斥，
// 杜绝"读到 cfg 后、写入注册表前"窗口内 CloseAll 先行清空导致的孤儿注册条目。
// 同节点重连时先取消旧心跳，避免同一节点存在多个心跳 goroutine。
// 锁序恒为 kaMu -> keepAlives 分片锁，evictDeadClient 不取 kaMu，无死锁风险
func (c *Connector) startKeepAliveFor(nodeName string, client *PooledClient, clientCfgs ...*ClientConfig) {
	c.kaMu.Lock()
	defer c.kaMu.Unlock()

	var clientCfg *ClientConfig
	if len(clientCfgs) > 0 {
		clientCfg = clientCfgs[0]
	}

	var parentCtx context.Context
	var interval, timeout time.Duration
	var nodeScoped bool
	if cfg := c.keepAliveCfg; cfg != nil && cfg.ctx.Err() == nil {
		parentCtx = cfg.ctx
		interval = cfg.interval
		timeout = cfg.timeout
	}
	if clientCfg != nil && clientCfg.Options != nil {
		countMax := clientCfg.Options.ServerAliveCountMax()
		if nodeInterval := clientCfg.Options.ServerAliveInterval(); nodeInterval > 0 {
			nodeScoped = true
			parentCtx = c.lifecycleCtx
			interval = nodeInterval
			if countMax <= 0 {
				countMax = 3
			}
			timeout = nodeInterval * time.Duration(countMax)
		} else if interval > 0 && countMax > 0 {
			timeout = interval * time.Duration(countMax)
		}
	}
	if parentCtx == nil || parentCtx.Err() != nil || interval <= 0 {
		return
	}

	// 终止同节点旧心跳（入池点在 singleflight 保护内，无并发冲突）
	if old, ok := c.keepAlives.Pop(nodeName); ok {
		old.cancel()
	}

	nodeCtx, cancel := context.WithCancel(parentCtx)
	entry := &keepAliveEntry{
		cancel:     cancel,
		client:     client,
		nodeScoped: nodeScoped,
	}
	c.keepAlives.Set(nodeName, entry)
	c.keepAliveWG.Add(1)
	entry.done = startKeepAlive(nodeCtx, client.SSHClient, interval, timeout, func(error) {
		c.evictDeadClient(nodeName, client, entry)
	}, client.interrupt)
	go func() {
		<-entry.done
		c.keepAliveWG.Done()
	}()
}

func (c *Connector) removeKeepAliveFor(nodeName string, client *PooledClient) {
	c.kaMu.Lock()
	defer c.kaMu.Unlock()
	entry, ok := c.keepAlives.Get(nodeName)
	if !ok || entry.client != client {
		return
	}
	if concurrent.RemoveIfMatch(c.keepAlives, nodeName, entry) {
		entry.cancel()
	}
}

// evictDeadClient 心跳失败后的池驱逐（StartKeepAlive 已 Close 该连接）。
// 使用 RemoveIfMatch 原子"比对并删除"：仅当池/注册表中仍是失败连接本人时才驱逐，
// 防止"读取-比对-删除"间隙内并发重连写入新连接后被旧心跳误删
func (c *Connector) evictDeadClient(nodeName string, dead *PooledClient, entry *keepAliveEntry) {
	concurrent.RemoveIfMatch(c.clients, nodeName, dead)
	concurrent.RemoveIfMatch(c.keepAlives, nodeName, entry)
	entry.cancel()
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

func (c *Connector) dialAndHandshake(ctx context.Context, nodeName string, cfg *ClientConfig, dialer Dialer, sshConfig *ssh.ClientConfig, coordinator *handshakeCoordinator, authentication *authenticationTrace) (*ssh.Client, net.Conn, error) {
	if dialer == nil {
		dialer = c.baseDialer
	}
	if dialer == nil {
		dialer = c.directDialerFor(cfg)
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	targetAddr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	_, proxied := dialer.(*SSHProxyDialer)
	event := logger.Diagnostic{Kind: logger.Connecting, NodeID: nodeName, Host: cfg.Address, User: cfg.User, Port: cfg.Port, Proxied: proxied}
	logger.EmitDiagnostic(c.diagnostics, event)
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
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
			Address:  cfg.Address,
			Port:     cfg.Port,
			AuthType: cfg.AuthType,
			Err:      dialErr,
		}
	}
	event.Kind = logger.Connected
	logger.EmitDiagnostic(c.diagnostics, event)
	if _, proxied := dialer.(*SSHProxyDialer); !proxied {
		conn = &physicalSSHConn{Conn: conn}
	}
	if err := c.initHandshakeDeadline(ctx, conn, nodeName, c.getNodeHandshakeTimeout(cfg), coordinator); err != nil {
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
		closeErr := ncc.Close()
		cancelErr := handshakeCancelError(ctx, coordinator, nodeName)
		if cancelErr == nil {
			cancelErr = fmt.Errorf("ssh handshake canceled for '%s': %w", nodeName, context.Canceled)
		}
		return nil, nil, combineSSHOperationErrors(cancelErr, wrapCloseError(closeErr, "close canceled SSH connection"))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		if !strings.Contains(err.Error(), "deadline not supported") {
			if closeErr := ncc.Close(); closeErr != nil {
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
	for i := len(c.masterOrder) - 1; i >= 0; i-- {
		master := c.masterOrder[i]
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

	// Masters own the control socket, its registry entry, and the SSH transport
	// they serve. Closing the connector without them would leave a dead socket
	// file that later commands must detect and unlink.
	for _, master := range ownedMasters {
		if err := master.Shutdown(); err != nil {
			closeErrs = append(closeErrs, err)
		}
	}

	// Closing forbids new publication. Snapshot the existing clients without
	// holding map locks during network cleanup, then interrupt their physical
	// transports BEFORE joining connection workers. A downstream handshake can
	// otherwise remain blocked in a ProxyJump channel after context cancellation.
	var pooledClients []*PooledClient
	c.clients.IterCb(func(_ string, client *PooledClient) bool {
		pooledClients = append(pooledClients, client)
		return true
	})
	for _, plan := range planConnectors {
		if err := c.closePlan(plan); err != nil {
			closeErrs = append(closeErrs, err)
		}
	}
	for _, client := range pooledClients {
		if err := client.interrupt(); err != nil {
			closeErrs = append(closeErrs, err)
		}
	}
	c.connectWG.Wait()
	c.clients.Clear()

	// startKeepAliveFor 只可能由已结束的 Connect 调用，此处可完整取得并清空注册表。
	c.kaMu.Lock()
	if c.keepAliveCfg != nil {
		c.keepAliveCfg.cancel()
		c.keepAliveCfg = nil
	}
	c.keepAlives.IterCb(func(_ string, entry *keepAliveEntry) bool {
		entry.cancel()
		return true
	})
	c.keepAlives.Clear()
	c.kaMu.Unlock()

	c.keepAliveWG.Wait()

	if len(closeErrs) > 0 {
		c.closeErr = fmt.Errorf("close pooled SSH clients failed: %w", errors.Join(closeErrs...))
	}
	close(c.closeDone)
	return c.closeErr
}

func (c *Connector) resolvePasswordAuth(cfg *ClientConfig) (ssh.AuthMethod, error) {
	if cfg.Password == "" {
		secret, err := c.resolveSecret(cfg, SecretRequest{
			Kind:         SecretKindLoginPassword,
			NodeID:       cfg.NodeID,
			User:         cfg.User,
			Host:         cfg.Address,
			Port:         cfg.Port,
			VersionToken: cfg.AuthUpdateToken,
		})
		if len(secret) > 0 {
			defer zeroBytes(secret)
		}
		if err == nil && len(secret) > 0 {
			cfg.Password = string(secret)
		} else if err != nil && !errors.Is(err, ErrInteractionRequired) {
			return nil, fmt.Errorf("resolve login password failed: %w", err)
		}
	}
	if cfg.Password == "" {
		return nil, ErrPasswordRequired
	}
	return ssh.Password(cfg.Password), nil
}

func (c *Connector) resolveKeyAuth(cfg *ClientConfig) (ssh.AuthMethod, error) {
	var secret []byte
	if cfg.Passphrase == "" {
		var err error
		secret, err = c.resolveSecret(cfg, SecretRequest{
			Kind:         SecretKindPrivateKeyPassphrase,
			NodeID:       cfg.NodeID,
			User:         cfg.User,
			Host:         cfg.Address,
			Port:         cfg.Port,
			KeyPath:      cfg.KeyPath,
			VersionToken: cfg.AuthUpdateToken,
		})
		if len(secret) > 0 {
			defer zeroBytes(secret)
		}
		if err != nil && !errors.Is(err, ErrInteractionRequired) {
			return nil, fmt.Errorf("resolve private key passphrase failed: %w", err)
		}
	}
	return buildKeyAuthMethod(cfg, secret, c.environment.ResolveKeyPath)
}

func (c *Connector) resolveAgentAuth(ctx context.Context) (ssh.AuthMethod, func(), error) {
	socket := c.environment.AgentSocket
	if socket == "" {
		return nil, nil, ErrAgentNotAvailable
	}
	conn, err := dialSSHAgent(ctx, socket)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to ssh-agent: %w", err)
	}
	agentClient := agent.NewClient(conn)
	cleanup := func() { debugCloseResource(c.getLogger(), conn, "ssh agent connection") }
	return ssh.PublicKeysCallback(agentClient.Signers), cleanup, nil
}

// buildSSHConfig 根据 Identity 模型构建 ssh.ClientConfig
//
//nolint:gocyclo // buildSSHConfig coordinates multiple authentication strategies, host key verification, and diagnostics.
func (c *Connector) buildSSHConfig(ctx context.Context, cfg *ClientConfig, coordinator *handshakeCoordinator, onAuthDiscovered func(), authentication *authenticationTrace) (*ssh.ClientConfig, func() error, error) {
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
	policy := newAuthPolicy(cfg.Options, hostKeyChanged)
	pubkeyAllowed, passwordAllowed, kbAllowed := policy.pubkeyAllowed, policy.passwordAllowed, policy.kbAllowed

	// 根据 AuthType 处理不同的认证方式
	switch cfg.AuthType {
	case "auto":
		var failClosed func(error)
		if coordinator != nil {
			failClosed = coordinator.FailClosed
		}
		originalAuthType := cfg.AuthType
		originalKeyPath := cfg.KeyPath
		plan, release, err := c.buildOwnedAutoAuth(ctx, cfg, AutoAuthOptions{
			AgentSocket:        c.environment.AgentSocket,
			DefaultKeyPaths:    c.environment.DefaultKeyPaths,
			ResolveKeyPath:     c.environment.ResolveKeyPath,
			LifecycleCtx:       authCtx,
			NodeID:             cfg.NodeID,
			User:               cfg.User,
			Host:               cfg.Address,
			Port:               cfg.Port,
			VersionToken:       cfg.AuthUpdateToken,
			Resolver:           c.secretResolver,
			Prompter:           prompter,
			HandshakeTimeout:   c.getNodeHandshakeTimeout(cfg),
			InteractionTimeout: c.interactionTimeout,
			FailClosed:         failClosed,
			RecoveryPrompter:   credentialRecoveryPrompter(basePrompter),
			KeyPath:            cfg.KeyPath,
			SSHOptions:         cfg.Options,
			HostKeyChanged:     hostKeyChanged,
			PasswordCallback: func(s string) {
				if s != "" {
					// Rejected earlier key candidates are cleared by
					// CandidateRejectedCallback; preserve cfg.Passphrase if an
					// earlier key stage achieved PartialSuccess in MFA.
					cfg.Password = s
					if cfg.Passphrase == "" {
						cfg.AuthType = "password"
					}
					if onAuthDiscovered != nil {
						onAuthDiscovered()
					}
				}
			},
			PassphraseCallback: func(keyPath, passphrase string) {
				if passphrase != "" {
					// This key candidate precedes password fallback. Clear an
					// untried session password so a successful key login cannot
					// persist credentials that were never authenticated.
					cfg.Password = ""
					cfg.KeyPath = keyPath
					cfg.Passphrase = passphrase
					cfg.AuthType = "key"
					if onAuthDiscovered != nil {
						onAuthDiscovered()
					}
				}
			},
			CandidateRejectedCallback: func(protocol string) {
				switch protocol {
				case autoAuthProtocolPublicKey:
					cfg.Passphrase = ""
					cfg.KeyPath = originalKeyPath
					if cfg.Password == "" {
						cfg.AuthType = originalAuthType
					}
				case autoAuthProtocolPassword:
					cfg.Password = ""
					if cfg.Passphrase == "" {
						cfg.AuthType = originalAuthType
					}
				}
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
		authCallback = c.buildKeyboardInteractiveAuth(authCtx, cfg, policy, prompter, coordinator, observer)

	case "password":
		if !passwordAllowed {
			return nil, nil, errors.New("password authentication disabled by SSH options")
		}
		if credentialRecoveryPrompter(basePrompter) != nil {
			authMethods = append(authMethods, c.recoverablePasswordAuth(authCtx, cfg, prompter, onAuthDiscovered))
			break
		}
		method, err := c.resolvePasswordAuth(cfg)
		if err != nil {
			return nil, nil, err
		}
		authMethods = append(authMethods, method)

	case "key":
		if !pubkeyAllowed {
			return nil, nil, errors.New("publickey authentication disabled by SSH options")
		}
		method, release, err := c.keyAuth(authCtx, cfg, prompter, onAuthDiscovered)
		if err != nil {
			return nil, nil, err
		}
		authMethods = append(authMethods, method)
		cleanup = release

	case "agent":
		if !pubkeyAllowed {
			return nil, nil, errors.New("publickey authentication disabled by SSH options")
		}
		if policy.identitiesOnly {
			return nil, nil, errors.New("ssh-agent authentication disabled by IdentitiesOnly=yes")
		}
		method, agentCleanup, err := c.resolveAgentAuth(ctx)
		if err != nil {
			return nil, nil, err
		}
		authMethods = append(authMethods, method)
		cleanup = legacyAuthCleanup(agentCleanup)

	default:
		return nil, nil, fmt.Errorf("unsupported auth type: %s", cfg.AuthType)
	}

	if authCallback == nil && len(authMethods) == 1 {
		authCallback = c.buildSingleMethodTransitionCallback(authCtx, cfg, policy, prompter, coordinator, observer)
	}

	hostKeyCallback, hostKeyAlgorithms, err := c.getHostKeyOptions(ctx, coordinator, cfg, hostKeyChanged)
	if err != nil {
		if cleanup != nil {
			err = errors.Join(err, cleanup())
		}
		return nil, nil, err
	}

	cryptoCfg, err := buildTransportCryptoConfig(cfg.Options)
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
		User:              cfg.User,
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

func (c *Connector) buildKeyboardInteractiveAuth(authCtx context.Context, cfg *ClientConfig, policy authPolicy, prompter SecretPrompter, coordinator *handshakeCoordinator, observer logger.DiagnosticObserver) ssh.ClientAuthCallback {
	secProvider := c.newAutoSecretProvider(authCtx, cfg, prompter, coordinator)
	kbMethod := buildKeyboardInteractiveAuthMethod(secProvider)
	candidates := []autoAuthCandidate{
		{
			protocol: autoAuthProtocolKeyboardInteractive,
			label:    cfg.AuthType,
			method:   kbMethod,
		},
	}
	if policy.passwordAllowed {
		passwordAttempts := 0
		initialPassword := cfg.Password
		passwordMethod := ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
			retry := passwordAttempts > 0
			if retry && secProvider.recoveryPrompter == nil {
				return "", ErrInteractionRequired
			}
			passwordAttempts++
			if !retry && initialPassword != "" {
				pwd := initialPassword
				initialPassword = ""
				return pwd, nil
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
	// [P2] 在函数最入口处接管 passphrase 并注册所有出口（包括失败路径）的清零清理
	var passBytes []byte
	if len(extraPassphrase) > 0 {
		passBytes = extraPassphrase
	} else if cfg != nil && cfg.Passphrase != "" {
		passBytes = []byte(cfg.Passphrase)
		cfg.Passphrase = ""
	}
	if len(passBytes) > 0 {
		defer zeroBytes(passBytes)
	}

	if cfg == nil || cfg.KeyPath == "" {
		return nil, ErrKeyPathRequired
	}
	keyBytes, err := os.ReadFile(resolveKeyPath(cfg.KeyPath, resolve))
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
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

func (c *Connector) getHostKeyCallback(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig, hostKeyChangedFlags ...*atomic.Bool) (ssh.HostKeyCallback, error) {
	if c.hostKeyVerifier != nil {
		return c.verifierHostKeyCallback(ctx, coordinator, cfg), nil
	}

	var hostKeyChanged *atomic.Bool
	if len(hostKeyChangedFlags) > 0 {
		hostKeyChanged = hostKeyChangedFlags[0]
	}

	strictMode, userKH, batchMode := extractHostKeyPolicy(cfg)
	knownHostsFile, noKnownHostsFile, hostKeyCallback, err := c.openKnownHostsCallback(userKH, cfg)
	if err != nil {
		return nil, err
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) (retErr error) {
		err := hostKeyCallback(hostname, remote, key)
		if err == nil {
			return nil
		}

		if keyErr, ok := errors.AsType[*knownhosts.KeyError](err); ok {
			return c.handleKnownHostsKeyError(ctx, coordinator, keyErr, strictMode, batchMode, noKnownHostsFile, knownHostsFile, hostname, remote, key, hostKeyChanged)
		}
		return err
	}, nil
}

func (c *Connector) verifierHostKeyCallback(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig) ssh.HostKeyCallback {
	verificationParent := ctx
	if coordinator != nil {
		verificationParent = coordinator.Context()
	}
	request := HostKeyRequest{NodeID: cfg.NodeID, Host: cfg.Address, Port: cfg.Port, User: cfg.User, VersionToken: cfg.TrustVersion}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		verification, cancel := context.WithTimeout(verificationParent, c.getNodeHandshakeTimeout(cfg))
		defer cancel()
		if err := verification.Err(); err != nil {
			return err
		}
		requestCopy := request
		requestCopy.Hostname, requestCopy.Remote = hostname, remote
		return c.hostKeyVerifier.Verify(verification, requestCopy, key)
	}
}

func extractHostKeyPolicy(cfg *ClientConfig) (strictMode string, userKH string, batchMode bool) {
	strictMode = StrictHostKeyCheckingAsk
	if cfg != nil && cfg.Options != nil {
		if m := cfg.Options.StrictHostKeyChecking(); m != "" {
			strictMode = m
		}
		userKH = strings.TrimSpace(cfg.Options.UserKnownHostsFile())
		batchMode = cfg.Options.BatchMode()
	}
	return strictMode, userKH, batchMode
}

func (c *Connector) openKnownHostsCallback(userKH string, cfg *ClientConfig) (string, bool, ssh.HostKeyCallback, error) {
	emptyCallback := func(string, net.Addr, ssh.PublicKey) error {
		return &knownhosts.KeyError{}
	}
	if strings.EqualFold(userKH, "none") || userKH == "/dev/null" {
		return "", true, emptyCallback, nil
	}

	if userKH != "" {
		return c.openCustomKnownHostsFiles(userKH, cfg, emptyCallback)
	}

	if err := validateEnvironment(c.environment); err != nil {
		return "", false, nil, err
	}
	knownHostsFile := c.environment.KnownHostsFile
	if _, err := os.Stat(knownHostsFile); os.IsNotExist(err) {
		if mkdirErr := os.MkdirAll(filepath.Dir(knownHostsFile), 0700); mkdirErr != nil {
			return "", false, nil, fmt.Errorf("create .ssh directory failed: %w", mkdirErr)
		}
		if writeErr := os.WriteFile(knownHostsFile, []byte(""), 0600); writeErr != nil {
			return "", false, nil, fmt.Errorf("create known_hosts file failed: %w", writeErr)
		}
	}

	hostKeyCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return "", false, nil, fmt.Errorf("parse known_hosts file failed: %w", err)
	}
	return knownHostsFile, false, hostKeyCallback, nil
}

func (c *Connector) openCustomKnownHostsFiles(userKH string, cfg *ClientConfig, emptyCallback ssh.HostKeyCallback) (string, bool, ssh.HostKeyCallback, error) {
	fields := strings.Fields(userKH)
	var existingFiles []string
	var primaryWriteFile string
	target := TargetContext{}
	if cfg != nil {
		target = TargetContext{
			Host:         cfg.Address,
			Port:         cfg.Port,
			User:         cfg.User,
			OriginalHost: cfg.NodeID,
			JumpHost:     cfg.ProxyJump,
		}
	}
	for _, tokenPath := range fields {
		if strings.EqualFold(tokenPath, "none") || tokenPath == "/dev/null" {
			continue
		}
		expanded, expErr := expandKnownHostsPath(tokenPath, c.environment, target)
		if expErr != nil {
			return "", false, nil, fmt.Errorf("expand UserKnownHostsFile %q failed: %w", tokenPath, expErr)
		}
		if primaryWriteFile == "" {
			primaryWriteFile = expanded
		}
		st, err := os.Stat(expanded)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return "", false, nil, fmt.Errorf("stat UserKnownHostsFile %q failed: %w", expanded, err)
			}
			continue
		}
		if st.IsDir() {
			return "", false, nil, fmt.Errorf("UserKnownHostsFile %q is a directory", expanded)
		}
		existingFiles = append(existingFiles, expanded)
	}
	if len(existingFiles) == 0 {
		return primaryWriteFile, primaryWriteFile == "", emptyCallback, nil
	}
	hostKeyCallback, err := knownhosts.New(existingFiles...)
	if err != nil {
		return "", false, nil, fmt.Errorf("parse known_hosts file failed: %w", err)
	}
	return primaryWriteFile, primaryWriteFile == "", hostKeyCallback, nil
}

func expandKnownHostsPath(pattern string, env Environment, target TargetContext) (string, error) {
	return ExpandControlPath(pattern, env, target)
}

func (c *Connector) handleKnownHostsKeyError(
	ctx context.Context,
	coordinator *handshakeCoordinator,
	keyErr *knownhosts.KeyError,
	strictMode string,
	batchMode bool,
	noKnownHostsFile bool,
	knownHostsFile string,
	hostname string,
	remote net.Addr,
	key ssh.PublicKey,
	hostKeyChanged *atomic.Bool,
) (retErr error) {
	if len(keyErr.Want) > 0 {
		if strictMode == StrictHostKeyCheckingNo {
			if hostKeyChanged != nil {
				hostKeyChanged.Store(true)
			}
			c.getLogger().Debugf("host key verification: remote host identification changed for %s; continuing due to StrictHostKeyChecking=no with password and keyboard-interactive authentication disabled", hostname)
			return nil
		}
		return fmt.Errorf("%w: remote host identification has changed for %s: %w", ErrHostKeyMismatch, hostname, keyErr)
	}

	switch strictMode {
	case StrictHostKeyCheckingYes:
		return fmt.Errorf("%w: no host key is known for %s and StrictHostKeyChecking=yes", ErrHostKeyMismatch, hostname)
	case StrictHostKeyCheckingNo:
		if !noKnownHostsFile && knownHostsFile != "" {
			_ = appendKnownHost(knownHostsFile, hostname, key)
		}
		return nil
	case StrictHostKeyCheckingAcceptNew:
		if noKnownHostsFile || knownHostsFile == "" {
			return nil
		}
		return appendKnownHost(knownHostsFile, hostname, key)
	default:
		if batchMode && !c.AcceptNewHostKey.Load() {
			return ErrInteractionRequired
		}
		if coordinator != nil {
			if pauseErr := coordinator.Pause(); pauseErr != nil {
				return pauseErr
			}
			defer func() {
				if resumeErr := coordinator.Resume(); resumeErr != nil {
					retErr = errors.Join(retErr, resumeErr)
				}
			}()
		}

		if promptErr := c.promptHostKeyVerification(ctx, hostname, remote, key); promptErr != nil {
			return promptErr
		}

		if noKnownHostsFile || knownHostsFile == "" {
			return nil
		}
		return appendKnownHost(knownHostsFile, hostname, key)
	}
}

func (c *Connector) promptHostKeyVerification(ctx context.Context, hostname string, remote net.Addr, key ssh.PublicKey) error {
	if c.AcceptNewHostKey.Load() {
		return nil
	}

	var remoteAddr string
	if remote != nil {
		remoteAddr = remote.String()
	}
	fingerprint := ssh.FingerprintSHA256(key)

	promptCtx, cancel := c.interactionContext(ctx)
	defer cancel()

	agreed, err := c.hostKeyConfirmer.ConfirmHostKey(promptCtx, HostKeyConfirmation{
		Hostname:      hostname,
		RemoteAddress: remoteAddr,
		Algorithm:     key.Type(),
		Fingerprint:   fingerprint,
	})
	if err != nil {
		return fmt.Errorf("read response failed: %w", err)
	}

	if agreed {
		return nil
	}
	return ErrHostKeyMismatch
}

func appendKnownHost(knownHostsFile, hostname string, key ssh.PublicKey) (err error) {
	knownHostsFileMutex.Lock()
	defer knownHostsFileMutex.Unlock()

	if mkdirErr := os.MkdirAll(filepath.Dir(knownHostsFile), 0700); mkdirErr != nil {
		return fmt.Errorf("create known_hosts directory failed: %w", mkdirErr)
	}

	f, openErr := os.OpenFile(knownHostsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if openErr != nil {
		return fmt.Errorf("open known_hosts file failed: %w", openErr)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close known_hosts file failed: %w", closeErr)
		}
	}()

	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	if _, writeErr := f.WriteString(line + "\n"); writeErr != nil {
		return fmt.Errorf("write known_hosts file failed: %w", writeErr)
	}
	return nil
}

// PooledClient retains the outermost transport, including for ProxyJump clients.
// Interrupting it also terminates other clients sharing that transport.
type PooledClient struct {
	SSHClient  *ssh.Client
	RootConn   net.Conn
	probeMu    sync.Mutex
	probeCache *executionProbeCache
}

func (c *PooledClient) interrupt() error {
	return interruptSSHTransport(c.RootConn, c.SSHClient)
}

// A confirmation failure must close the authenticated but unpublished client.
func (c *Connector) confirmAuthenticatedConnection(ctx context.Context, nodeID string, root net.Conn, client *Client, cfg *ClientConfig) (err error) {
	defer func() {
		if err != nil {
			if closeErr := root.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close unpublished SSH connection: %w", closeErr))
			}
		}
	}()
	if confirmer, ok := c.provider.(AuthenticatedConnectionConfirmer); ok {
		execution, err := confirmer.ConfirmAuthenticatedConnection(ctx, nodeID, client)
		if err != nil {
			return fmt.Errorf("confirm authenticated node %q: %w", nodeID, err)
		}
		if err := execution.Validate(); err != nil {
			return fmt.Errorf("validate authenticated execution: %w", err)
		}
		if execution != nil {
			cfg.Execution = execution.Clone()
		}
	} else if confirmer, ok := c.provider.(ConnectionConfirmer); ok {
		if err := confirmer.ConfirmConnection(ctx, nodeID); err != nil {
			return fmt.Errorf("confirm authenticated node %q: %w", nodeID, err)
		}
	}
	return nil
}

func (c *Connector) syncConnectionAfterRecording(node string, cfg *ClientConfig, token string, updated, failed bool, originalKeyPath string, root net.Conn) error {
	if failed {
		return c.syncAuthTokensAfterConnection(node, cfg, token, updated, root, originalKeyPath)
	}
	return c.syncAuthTokensAfterConnection(node, cfg, token, updated, root)
}

func reconcileFailedWriteKeyPath(cfg, latest *ClientConfig, original []string) {
	// A failed write may retain the original path or publish the discovered one.
	// An unrelated path must still fail normal target compatibility checks.
	if len(original) == 1 && latest.KeyPath == original[0] {
		cfg.KeyPath = latest.KeyPath
	}
}
