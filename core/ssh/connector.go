package ssh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
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
	// 连接池：按规范路由键（routeKey）缓存 *PooledClient，隔离不同 ProxyJump 路径到达的同名节点
	clients *concurrent.Map[string, *PooledClient]
	// singleflight 组，按规范路由键控制并发和去重
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
	// retiredClients tracks pooled transports displaced by incompatible config
	// updates so active sessions keep running while CloseAll still shuts them down.
	// Guarded by lifecycleMu.
	retiredClients []*PooledClient
	connectWG      sync.WaitGroup

	// kaMu 保护 keepAliveCfg 的启用/关闭（keepAlives 自带分片锁，无需 kaMu）
	kaMu sync.Mutex
	// keepAliveCfg 为 nil 表示未启用周期心跳（CLI 短生命周期命令默认不启用）
	keepAliveCfg *keepAliveConfig
	// keepAlives 心跳注册表：routeKey -> 运行中的心跳条目
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
	name     string
	routeKey string
	cfg      *ClientConfig
	control  *ControlConfig
}

// connectionRouteKey returns the canonical pool/singleflight/keepalive key for
// reaching nodeName through the ordered upstream jump chain (outermost hop first).
// Direct hops (no upstream jumps) keep bare nodeName as their key; jump-chained
// hops use a length-prefixed encoding so distinct routes to the same node can
// never collide or bypass an upstream bastion regardless of node ID characters.
func connectionRouteKey(upstream []string, nodeName string) string {
	if len(upstream) == 0 {
		return nodeName
	}
	var b strings.Builder
	b.WriteString("\x00route\x00")
	for _, hop := range upstream {
		b.WriteString(strconv.Itoa(len(hop)))
		b.WriteByte(':')
		b.WriteString(hop)
		b.WriteByte(';')
	}
	b.WriteString(strconv.Itoa(len(nodeName)))
	b.WriteByte(':')
	b.WriteString(nodeName)
	b.WriteByte(';')
	return b.String()
}

func assignPlanRouteKeys(plan []connectionPlanNode) {
	upstream := make([]string, 0, len(plan))
	for i := len(plan) - 1; i >= 0; i-- {
		plan[i].routeKey = connectionRouteKey(upstream, plan[i].name)
		upstream = append(upstream, plan[i].name)
	}
}

func (n connectionPlanNode) poolKey() string {
	if n.routeKey != "" {
		return n.routeKey
	}
	if n.cfg != nil {
		if jumps := splitProxyJumpChain(n.cfg.ProxyJump); len(jumps) > 0 {
			return connectionRouteKey(jumps, n.name)
		}
	}
	return n.name
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
func isClientTransportClosed(client *Client) bool {
	if client == nil {
		return true
	}
	root, ok := client.rootConn.(*physicalSSHConn)
	return ok && root.closed.Load()
}

func (c *Connector) cascadeInvalidateDownstream(
	plan []connectionPlanNode,
	index int,
	cached *PooledClient,
	beforeDownstream []*PooledClient,
	nonDisruptive bool,
) {
	for downstream := 0; downstream < index; downstream++ {
		dsKey := plan[downstream].poolKey()
		staleDownstream, exists := c.clients.Get(dsKey)
		if !exists {
			continue
		}
		sameGeneration := (cached.RootConn != nil && staleDownstream.RootConn == cached.RootConn) ||
			(cached.RootConn == nil && staleDownstream == beforeDownstream[downstream])
		if !sameGeneration {
			continue
		}
		if nonDisruptive {
			c.retireIncompatibleClient(dsKey, staleDownstream)
		} else {
			c.evictCachedClient(dsKey, staleDownstream)
			_ = staleDownstream.interrupt()
		}
	}
}

func (c *Connector) reuseJumpChainedTarget(ctx context.Context, plan []connectionPlanNode) (*Client, map[string]*Client, error) {
	validated := make(map[string]*Client, len(plan)-1)
	for index := len(plan) - 1; index > 0; index-- {
		planNode := plan[index]
		routeKey := planNode.poolKey()
		cached, ok := c.clients.Get(routeKey)
		if !ok || cached.SSHClient == nil || (cached.SSHClient.Conn == nil && !cached.hasSnapshot) {
			continue
		}
		var beforeDownstream []*PooledClient
		if cached.RootConn == nil {
			beforeDownstream = make([]*PooledClient, index)
			for downstream := 0; downstream < index; downstream++ {
				if cur, exists := c.clients.Get(plan[downstream].poolKey()); exists {
					beforeDownstream[downstream] = cur
				}
			}
		}
		hopClient, err := c.connectPlannedNode(ctx, planNode, nil, true)
		if err != nil {
			// Only "not reusable" falls back to building the chain; a canceled caller
			// or a closed connector must surface as itself so the caller stops here and
			// the failure keeps the hop it happened on.
			c.getLogger().Debugf("mux: cached jump hop %s is not reusable (%v)", planNode.name, err)
			if errors.Is(err, errJumpChainRequired) {
				// The cached hop was stale and evicted (or retired due to config change);
				// cascade-invalidate all in-process cached downstream hops (plan[0..index-1])
				// that rode on the same transport generation, without clobbering a fresher
				// replacement published concurrently by another caller, while still letting
				// plan[0] attach to an external control master socket if one exists on disk.
				// Config-change retirements leave live sessions on the previous generation
				// running until CloseAll; failed liveness probes interrupt dead transports.
				c.cascadeInvalidateDownstream(plan, index, cached, beforeDownstream, errors.Is(err, ErrSnapshotMismatch))
				validated = nil
				break
			}
			return nil, nil, err
		}
		if hopClient.sshClient != cached.SSHClient {
			c.cascadeInvalidateDownstream(plan, index, cached, beforeDownstream, true)
		}
		// This transport was validated a moment ago on the connector lifecycle;
		// probing it again while the chain is rebuilt would repeat a network
		// round trip per cached hop.
		validated[routeKey] = hopClient
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
		if validated, ok := validatedHops[planNode.poolKey()]; ok && validated != nil && !isClientTransportClosed(validated) {
			// Already validated in this call and its physical transport is still open;
			// reuse it instead of dialing the hop again. It still carries the whole
			// chain for the next hop below.
			connected = validated
			continue
		}
		var dialer Dialer
		switch {
		case planNode.cfg.ProxyJump != "":
			if connected == nil {
				return nil, fmt.Errorf("resolved proxy jump '%s' for node '%s' has no client", planNode.cfg.ProxyJump, planNode.name)
			}
			dialer = &SSHProxyDialer{Client: connected.sshClient, RootConn: connected.rootConn}
		case planNode.cfg.Options.ActiveProxyCommand() != "":
			dialer = &proxyCommandDialer{connector: c, planNode: planNode}
		case c.baseDialer != nil:
			dialer = c.baseDialer
		default:
			dialer = c.directDialerFor(planNode.cfg)
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
		nodeCfg := *cfg
		nodeCfg.Address = normalizeHostAddress(nodeCfg.Address)
		nodeCfg.BaseHost = normalizeHostAddress(nodeCfg.BaseHost)
		nodeCfg.KeyPaths = slices.Clone(cfg.KeyPaths)
		nodeCfg.AdmittedCertificates = cloneAdmittedCertificates(cfg.AdmittedCertificates)
		nodeCfg.AdmittedKeyDigests = cloneAdmittedKeyDigests(cfg.AdmittedKeyDigests)
		if nodeCfg.Port <= 0 {
			nodeCfg.Port = 22
		}
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
		positions[current] = len(plan)
		plan = append(plan, connectionPlanNode{name: current, cfg: &nodeCfg, control: c.resolveControl(current, &nodeCfg)})

		if len(activeJumps) > 0 {
			current = activeJumps[len(activeJumps)-1]
			remainingJumps = activeJumps[:len(activeJumps)-1]
		} else {
			current = ""
			remainingJumps = nil
		}
	}
	assignPlanRouteKeys(plan)
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
		if ctrl, err := cfg.Options.ValidatedControlConfig(); err == nil {
			return ctrl
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
		if jump != "" && !strings.EqualFold(jump, "none") {
			jumps = append(jumps, jump)
		}
	}
	return jumps
}

func writeHashStr(h hash.Hash, s string) {
	_, _ = h.Write([]byte(strconv.Itoa(len(s))))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{';'})
}

func writeHashBool(h hash.Hash, v bool) {
	if v {
		_, _ = h.Write([]byte{'1', ';'})
	} else {
		_, _ = h.Write([]byte{'0', ';'})
	}
}

func writeHashOptBool(h hash.Hash, v, ok bool) {
	writeHashBool(h, ok)
	writeHashBool(h, v)
}

func writeHashStrings(h hash.Hash, list []string) {
	_, _ = h.Write([]byte(strconv.Itoa(len(list))))
	_, _ = h.Write([]byte{'['})
	for _, s := range list {
		writeHashStr(h, s)
	}
	_, _ = h.Write([]byte{']', ';'})
}

// targetCompatDigest hashes every compatibility-checked field of cfg so
// singleflight never coalesces concurrent dials with differing targets,
// trust/auth versions, auth policies, admitted materials, or transport options.
func targetCompatDigest(cfg *ClientConfig) string {
	h := sha256.New()
	if cfg == nil {
		writeHashStr(h, "nil")
		return hex.EncodeToString(h.Sum(nil))
	}
	port := cfg.Port
	if port <= 0 {
		port = 22
	}
	writeHashStr(h, normalizeHostAddress(cfg.Address))
	writeHashStr(h, strings.TrimSpace(normalizeHostAddress(cfg.BaseHost)))
	writeHashStr(h, strconv.Itoa(port))
	writeHashStr(h, cfg.User)
	writeHashStr(h, effectiveOriginalHost(cfg.OriginalHost, cfg.NodeID))
	writeHashStr(h, strings.TrimSpace(cfg.CanonicalHost))
	writeHashStr(h, cfg.KeyRef)
	writeHashStr(h, cfg.TrustVersion)
	writeHashStr(h, cfg.AuthUpdateToken)
	writeHashStr(h, normalizeAuthType(cfg.AuthType))
	writeHashStr(h, cfg.KeyPath)
	writeHashStrings(h, cfg.KeyPaths)

	writeHashBool(h, cfg.EnforceAdmittedCertificates)
	_, _ = h.Write([]byte(strconv.Itoa(len(cfg.AdmittedCertificates))))
	_, _ = h.Write([]byte{'['})
	for _, cert := range cfg.AdmittedCertificates {
		writeHashStr(h, cert.Path)
		writeHashStr(h, cert.SHA256)
		writeHashBool(h, cert.Missing)
		writeHashBool(h, cert.NonRegular)
	}
	_, _ = h.Write([]byte{']', ';'})

	writeHashBool(h, cfg.EnforceAdmittedKeyDigests)
	_, _ = h.Write([]byte(strconv.Itoa(len(cfg.AdmittedKeyDigests))))
	_, _ = h.Write([]byte{'['})
	for _, kd := range cfg.AdmittedKeyDigests {
		writeHashStr(h, kd.Path)
		writeHashStr(h, kd.SHA256)
		writeHashBool(h, kd.Missing)
		writeHashBool(h, kd.NonRegular)
	}
	_, _ = h.Write([]byte{']', ';'})

	origJump := cfg.ProxyJump
	if cfg.HasOriginalProxyJump || cfg.OriginalProxyJump != "" {
		origJump = cfg.OriginalProxyJump
	}
	writeHashStr(h, origJump)
	activeJump := HasActiveProxyJump(cfg.ProxyJump)
	writeHashBool(h, activeJump)
	if !activeJump {
		writeHashStr(h, cfg.Options.ActiveProxyCommand())
	}

	opts := cfg.Options
	writeHashStr(h, opts.StrictHostKeyChecking())
	writeHashStr(h, opts.UserKnownHostsFile())
	writeHashStr(h, opts.GlobalKnownHostsFile())
	writeHashStr(h, opts.VerifyHostKeyDNS())
	writeHashBool(h, opts.HashKnownHosts())
	writeHashStrings(h, opts.IdentityFiles())
	writeHashStrings(h, opts.CertificateFiles())
	writeHashStr(h, opts.IdentityAgent())
	writeHashBool(h, opts.IdentitiesOnly())
	writeHashBool(h, opts.BatchMode())
	pub, pubOK := opts.PubkeyAuthentication()
	writeHashOptBool(h, pub, pubOK)
	pwd, pwdOK := opts.PasswordAuthentication()
	writeHashOptBool(h, pwd, pwdOK)
	kbd, kbdOK := opts.KbdInteractiveAuthentication()
	writeHashOptBool(h, kbd, kbdOK)
	writeHashStrings(h, opts.PreferredAuthentications())
	writeHashStr(h, opts.Ciphers())
	writeHashStr(h, opts.MACs())
	writeHashStr(h, opts.KexAlgorithms())
	writeHashStr(h, opts.HostKeyAlgorithms())
	writeHashStr(h, opts.AddressFamily())
	writeHashStr(h, strconv.FormatInt(int64(opts.ServerAliveInterval()), 10))
	writeHashStr(h, strconv.Itoa(opts.ServerAliveCountMax()))
	tcpKA, tcpKAOK := opts.TCPKeepAlive()
	writeHashOptBool(h, tcpKA, tcpKAOK)
	writeHashStr(h, opts.ForwardAgent())
	writeHashStr(h, opts.GatewayPortsMode())
	unlink, unlinkOK := opts.StreamLocalBindUnlink()
	writeHashOptBool(h, unlink, unlinkOK)
	mask, maskOK := opts.StreamLocalBindMask()
	writeHashBool(h, maskOK)
	writeHashStr(h, strconv.FormatUint(uint64(mask), 8))
	writeHashStr(h, opts.CanonicalizeHostname())
	writeHashStrings(h, opts.CanonicalDomains())
	dots, dotsOK := opts.CanonicalizeMaxDots()
	writeHashBool(h, dotsOK)
	writeHashStr(h, strconv.Itoa(dots))
	fb, fbOK := opts.CanonicalizeFallbackLocal()
	writeHashOptBool(h, fb, fbOK)
	writeHashStrings(h, opts.CanonicalizePermittedCNAMEs())

	return hex.EncodeToString(h.Sum(nil))
}

// connectPlannedNode runs the cache/multiplex/connect decision for one node in a
// shared task. reuseOnly stops before dialing so a jump-chained target can be
// reused without its bastion; a caller that finds errJumpChainRequired retries
// with the full chain once the reuse-only task has finished.
func (c *Connector) connectPlannedNode(ctx context.Context, planNode connectionPlanNode, dialer Dialer, reuseOnly bool) (*Client, error) {
	routeKey := planNode.poolKey()
	sfKey := routeKey + "\x00" + targetCompatDigest(planNode.cfg)
	for {
		// 缓存复检、失效驱逐和重建位于同一个共享任务内。任务仅绑定 Connector 生命周期，
		// 单个调用者取消只停止等待，不会关闭连接池中由其他调用者共享的连接。
		resultCh := c.sf.DoChan(sfKey, func() (any, error) {
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
	routeKey := planNode.poolKey()
	var probeErr error
	var compatErr error
	if cachedClient, ok := c.clients.Get(routeKey); ok {
		if cachedClient.hasSnapshot {
			compatErr = validateTargetCompatibility(cachedClient.Snapshot, planNode.cfg)
		}
		switch {
		case compatErr != nil:
			c.getLogger().Debugf("ssh: cached connection for node %q is incompatible with updated config (%v); retiring", nodeName, compatErr)
			c.retireIncompatibleClient(routeKey, cachedClient)
			c.retireDownstreamGeneration(routeKey, cachedClient)
		case cachedClient.SSHClient.Conn == nil:
			logger.EmitDiagnostic(c.diagnostics, logger.Diagnostic{Kind: logger.ConnectionReused, NodeID: nodeName})
			return c.wrapCachedClient(planNode.cfg, cachedClient), nil
		default:
			if err := c.probeCachedClient(ctx, cachedClient); err == nil {
				logger.EmitDiagnostic(c.diagnostics, logger.Diagnostic{Kind: logger.ConnectionReused, NodeID: nodeName})
				return c.wrapCachedClient(planNode.cfg, cachedClient), nil
			} else {
				probeErr = err
				c.evictCachedClient(routeKey, cachedClient)
				c.evictDownstreamGeneration(routeKey, cachedClient)
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
		if compatErr != nil {
			return nil, fmt.Errorf("%w: %w", errJumpChainRequired, compatErr)
		}
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

// retireIncompatibleClient removes displaced from the active pool and cancels
// its keepalive without interrupting its transport while the connector remains
// open, preserving live sessions on earlier generations until CloseAll.
func (c *Connector) retireIncompatibleClient(routeKey string, displaced *PooledClient) {
	if displaced == nil {
		return
	}
	c.lifecycleMu.Lock()
	if c.closed {
		c.lifecycleMu.Unlock()
		c.removeKeepAliveFor(routeKey, displaced)
		_ = displaced.interrupt()
		return
	}
	concurrent.RemoveIfMatch(c.clients, routeKey, displaced)
	if !slices.Contains(c.retiredClients, displaced) {
		c.retiredClients = append(c.retiredClients, displaced)
	}
	c.lifecycleMu.Unlock()
	c.removeKeepAliveFor(routeKey, displaced)
}

func isDownstreamRouteKey(parentKey, candidateKey string) bool {
	if candidateKey == "" || candidateKey == parentKey {
		return false
	}
	var prefix string
	if strings.HasPrefix(parentKey, "\x00route\x00") {
		prefix = parentKey
	} else {
		prefix = "\x00route\x00" + strconv.Itoa(len(parentKey)) + ":" + parentKey + ";"
	}
	return len(candidateKey) > len(prefix) && strings.HasPrefix(candidateKey, prefix)
}

// retireDownstreamGeneration non-disruptively retires cached downstream hops
// riding on displaced's physical transport generation after parentKey drifted.
// When displaced.RootConn is nil (e.g. control proxy or test double without a
// tracked physical root), all cached downstream hops under parentKey are retired.
func (c *Connector) retireDownstreamGeneration(parentKey string, displaced *PooledClient) {
	if displaced == nil {
		return
	}
	type candidate struct {
		key    string
		client *PooledClient
	}
	var downstream []candidate
	c.clients.IterCb(func(key string, client *PooledClient) bool {
		if client == nil || !isDownstreamRouteKey(parentKey, key) {
			return true
		}
		if displaced.RootConn != nil && client.RootConn != displaced.RootConn {
			return true
		}
		downstream = append(downstream, candidate{key: key, client: client})
		return true
	})
	for _, item := range downstream {
		c.retireIncompatibleClient(item.key, item.client)
	}
}

// evictDownstreamGeneration evicts and interrupts cached downstream hops riding
// on a dead parent generation after a failed liveness probe or keepalive death.
func (c *Connector) evictDownstreamGeneration(parentKey string, dead *PooledClient) {
	if dead == nil {
		return
	}
	type candidate struct {
		key    string
		client *PooledClient
	}
	var downstream []candidate
	c.clients.IterCb(func(key string, client *PooledClient) bool {
		if client == nil || !isDownstreamRouteKey(parentKey, key) {
			return true
		}
		if dead.RootConn != nil && client.RootConn != dead.RootConn {
			return true
		}
		downstream = append(downstream, candidate{key: key, client: client})
		return true
	})
	for _, item := range downstream {
		if concurrent.RemoveIfMatch(c.clients, item.key, item.client) {
			c.removeKeepAliveFor(item.key, item.client)
			_ = item.client.interrupt()
		}
	}
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
	if rootConn != nil {
		if _, ok := rootConn.(*physicalSSHConn); !ok {
			rootConn = &physicalSSHConn{Conn: rootConn}
		}
	}
	pooled := &PooledClient{
		SSHClient:          rawClient,
		RootConn:           rootConn,
		ControlSocketPath:  expandedPath,
		ControlExpectedUID: c.expectedPeerUID(),
		Snapshot:           planNode.cfg.ToConnectionConfig(),
		hasSnapshot:        true,
	}
	routeKey := planNode.poolKey()
	if err := c.publishClient(routeKey, pooled); err != nil {
		_ = rawClient.Close()
		_ = proxyConn.Close()
		return nil, err
	}
	c.startKeepAliveFor(routeKey, pooled, planNode.cfg)
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
	explicitMaster := ctrl != nil && (ctrl.Master == ControlMasterYes || ctrl.Master == ControlMasterAsk) && !ctrl.AllowReuse

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

func (c *Connector) maybeStartMasterListener(planNode connectionPlanNode, resolvedKeyPath string, rawClient *ssh.Client, rootConn net.Conn) {
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

	var gatewayPorts bool
	var gatewayPortsMode string
	var dialNetwork string
	var streamLocalBindUnlink bool
	var streamLocalBindMask uint32
	var hasStreamLocalBindMask bool
	var allowAgentForward bool
	var agentSocket string
	if planNode.cfg != nil && planNode.cfg.Options != nil {
		gatewayPorts = planNode.cfg.Options.EffectiveGatewayPorts()
		gatewayPortsMode = planNode.cfg.Options.GatewayPortsMode()
		dialNetwork = planNode.cfg.Options.DialNetwork()
		streamLocalBindUnlink = planNode.cfg.Options.EffectiveStreamLocalBindUnlink()
		if mask, ok := planNode.cfg.Options.StreamLocalBindMask(); ok {
			streamLocalBindMask = mask
			hasStreamLocalBindMask = true
		}
		if sock, enabled, fwdErr := ResolveForwardAgent(
			planNode.cfg.Options.ForwardAgent(),
			planNode.cfg.Options.IdentityAgent(),
			c.environment,
			target,
		); fwdErr == nil && enabled && sock != "" && c.environment.DialAgent != nil {
			allowAgentForward = true
			agentSocket = sock
		}
	}

	server, err := StartMuxServer(context.Background(), rawClient, MuxMasterOptions{
		Path:                   expandedPath,
		Target:                 target,
		Environment:            c.environment,
		RootConn:               rootConn,
		InitialActiveSessions:  1,
		ConfirmSession:         c.confirmSessionCallback(planNode.name, planNode.cfg),
		GatewayPorts:           gatewayPorts,
		GatewayPortsMode:       gatewayPortsMode,
		DialNetwork:            dialNetwork,
		StreamLocalBindUnlink:  streamLocalBindUnlink,
		StreamLocalBindMask:    streamLocalBindMask,
		HasStreamLocalBindMask: hasStreamLocalBindMask,
		AllowAgentForward:      allowAgentForward,
		AgentSocket:            agentSocket,
		DialAgent:              c.environment.DialAgent,
		Logger:                 c.getLogger(),
	})
	if err != nil {
		// A concurrent master already owns this path (or the bind was rejected).
		// OpenSSH reports the conflict and continues without sharing.
		explicitMaster := (ctrl.Master == ControlMasterYes || ctrl.Master == ControlMasterAsk) && !ctrl.AllowReuse
		c.warnOrDebugf(explicitMaster, "mux: start master server on %q failed: %v; continuing without connection sharing", expandedPath, err)
		return
	}
	c.trackMaster(server, planNode.name)
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

func (c *Connector) watchMasterShutdown(lifecycleCtx context.Context, waitCh <-chan struct{}) {
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
		if !c.closed {
			c.pruneClosedMastersLocked()
		}
		c.lifecycleMu.Unlock()
	}()
}

// trackMaster records an owned master so CloseAll can release it. A connector
// that is already closed shuts the master down immediately.
func (c *Connector) trackMaster(server *MuxServer, nodeIDs ...string) {
	if server == nil {
		return
	}
	var nodeID string
	if len(nodeIDs) > 0 {
		nodeID = nodeIDs[0]
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

	if !exists {
		c.watchMasterShutdown(lifecycleCtx, server.Wait())
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

func (c *Connector) publishClient(nodeName string, client *PooledClient) error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed {
		return ErrConnectorClosed
	}
	c.clients.Set(nodeName, client)
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
			timeout = multiplyDurationSaturated(nodeInterval, countMax)
		} else if interval > 0 && countMax > 0 {
			timeout = multiplyDurationSaturated(interval, countMax)
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

func multiplyDurationSaturated(d time.Duration, count int) time.Duration {
	if d <= 0 || count <= 0 {
		return 0
	}
	if int64(d) > math.MaxInt64/int64(count) {
		return time.Duration(math.MaxInt64)
	}
	return d * time.Duration(count)
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
	removed := concurrent.RemoveIfMatch(c.clients, nodeName, dead)
	if removed || (dead != nil && dead.RootConn != nil) {
		c.evictDownstreamGeneration(nodeName, dead)
	}
	concurrent.RemoveIfMatch(c.keepAlives, nodeName, entry)
	entry.cancel()
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
	for i := len(c.masterOrder) - 1; i >= 0; i-- {
		master := c.masterOrder[i]
		if _, ok := c.masters[master]; ok {
			ownedMasters = append(ownedMasters, master)
		}
	}
	retiredClients := c.retiredClients
	c.retiredClients = nil
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
	closeErrs = append(closeErrs, interruptUniquePooledClients(pooledClients, retiredClients)...)
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

func interruptUniquePooledClients(groups ...[]*PooledClient) []error {
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
			if err := client.interrupt(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errs
}

// PooledClient retains the outermost transport, including for ProxyJump clients.
// Interrupting it also terminates other clients sharing that transport.
type PooledClient struct {
	SSHClient          *ssh.Client
	RootConn           net.Conn
	probeMu            sync.Mutex
	probeCache         *executionProbeCache
	ControlSocketPath  string
	ControlExpectedUID uint32
	Snapshot           ConnectionConfig
	hasSnapshot        bool
}

func (c *PooledClient) interrupt() error {
	var sshClient *ssh.Client
	if c.SSHClient != nil && c.SSHClient.Conn != nil {
		sshClient = c.SSHClient
	}
	return interruptSSHTransport(c.RootConn, sshClient)
}
