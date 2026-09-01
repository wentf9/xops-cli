package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sync/singleflight"
)

// Connector 负责创建 SSH 连接
type Connector struct {
	store ConfigStore
	ui    InteractionHandler
	// 连接池：缓存 nodeName -> *ssh.Client
	clients *concurrent.Map[string, *PooledClient]
	// singleflight 组，用来控制并发和去重
	sf singleflight.Group
	// 自动接受新的主机密钥
	AcceptNewHostKey atomic.Bool
	// PasswordPromptPattern 全局级自定义密码提示正则（可选）。
	// 当节点的 ClientConfig.PasswordPromptPattern 为空时，使用此值；
	// 两者均为空则使用内置的 DefaultPasswordPromptPattern。
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
}

// keepAliveConfig 描述 Connector 级心跳配置（见 EnableKeepAlive）
type keepAliveConfig struct {
	ctx               context.Context // 根心跳 ctx，取消后级联终止所有 per-node 心跳
	cancel            context.CancelFunc
	interval, timeout time.Duration
}

// keepAliveEntry 单个连接的心跳注册条目
type keepAliveEntry struct {
	cancel context.CancelFunc // per-node ctx 的取消函数
	client *PooledClient      // 心跳目标，用于驱逐时指针比对防止误删新连接
	done   <-chan struct{}    // 心跳 goroutine 的退出通知
}

var hostKeyPromptMutex sync.Mutex

// ErrConnectorClosed 表示 Connector 已执行 CloseAll，不能再建立或返回连接。
var ErrConnectorClosed = errors.New("ssh connector is closed")

const defaultSSHHandshakeTimeout = 10 * time.Second

// NewConnector 创建一个新的 Connector，支持 Functional Options。
func NewConnector(store ConfigStore, ui InteractionHandler, opts ...Option) *Connector {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	c := &Connector{
		store:           store,
		ui:              ui,
		clients:         concurrent.NewMap[string, *PooledClient](concurrent.HashString),
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		closeDone:       make(chan struct{}),
		keepAlives:      concurrent.NewMap[string, *keepAliveEntry](concurrent.HashString),
		logger:          logger.NopLogger,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

func (c *Connector) getLogger() logger.DebugLogger {
	if c != nil && c.logger != nil {
		return c.logger
	}
	return logger.NopLogger
}

type connectionPlanNode struct {
	name string
	cfg  *ClientConfig
}

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

	var connected *Client
	for index := len(plan) - 1; index >= 0; index-- {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("connect node '%s' canceled: %w", nodeName, err)
		}

		planNode := plan[index]
		var dialer Dialer = &net.Dialer{Timeout: defaultSSHHandshakeTimeout}
		if planNode.cfg.ProxyJump != "" {
			if connected == nil {
				return nil, fmt.Errorf("resolved proxy jump '%s' for node '%s' has no client", planNode.cfg.ProxyJump, planNode.name)
			}
			dialer = &SSHProxyDialer{Client: connected.sshClient}
		}

		connected, err = c.connectPlannedNode(ctx, planNode, dialer)
		if err != nil {
			return nil, err
		}
	}
	return connected, nil
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

		cfg, err := c.store.GetConfig(current)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch config for node '%s': %w", current, err)
		}
		if cfg == nil {
			return nil, fmt.Errorf("config for node '%s' is nil", current)
		}
		positions[current] = len(plan)
		plan = append(plan, connectionPlanNode{name: current, cfg: cfg})

		jumps := splitProxyJumpChain(cfg.ProxyJump)
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
				jumpCfg, jumpErr := c.store.GetConfig(jumpName)
				if jumpErr != nil {
					return nil, fmt.Errorf("fetch config for proxy jump %q failed: %w", jumpName, jumpErr)
				}
				if jumpCfg == nil {
					return nil, fmt.Errorf("config for proxy jump %q is nil", jumpName)
				}
				cloned := *jumpCfg
				if index > 0 {
					cloned.ProxyJump = jumps[index-1]
				} else {
					cloned.ProxyJump = ""
				}
				positions[jumpName] = len(plan)
				plan = append(plan, connectionPlanNode{name: jumpName, cfg: &cloned})
			}
			return plan, nil
		}
		current = cfg.ProxyJump
	}
	return plan, nil
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

func (c *Connector) connectPlannedNode(ctx context.Context, planNode connectionPlanNode, dialer Dialer) (*Client, error) {
	// 缓存复检、失效驱逐和重建位于同一个共享任务内。任务仅绑定 Connector 生命周期，
	// 单个调用者取消只停止等待，不会关闭连接池中由其他调用者共享的连接。
	resultCh := c.sf.DoChan(planNode.name, func() (any, error) {
		sharedCtx, finish, err := c.beginSharedConnect()
		if err != nil {
			return nil, err
		}
		defer finish()
		return c.connectNode(sharedCtx, planNode, dialer)
	})

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("connect node '%s' canceled: %w", planNode.name, ctx.Err())
	case <-c.lifecycleCtx.Done():
		return nil, ErrConnectorClosed
	case result := <-resultCh:
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("connect node '%s' canceled: %w", planNode.name, err)
		}
		if result.Err != nil {
			return nil, result.Err
		}
		client, ok := result.Val.(*Client)
		if !ok || client == nil {
			return nil, fmt.Errorf("shared connect for node '%s' returned invalid client", planNode.name)
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

func (c *Connector) connectNode(ctx context.Context, planNode connectionPlanNode, dialer Dialer) (*Client, error) {
	nodeName := planNode.name
	if cachedClient, ok := c.clients.Get(nodeName); ok {
		if cachedClient.SSHClient.Conn == nil {
			return c.wrapCachedClient(planNode.cfg, cachedClient), nil
		}

		if err := probeWithTimeout(ctx, cachedClient.SSHClient, c.keepAliveProbeTimeout()); err == nil {
			return c.wrapCachedClient(planNode.cfg, cachedClient), nil
		} else {
			c.evictCachedClient(nodeName, cachedClient)
			if ctx.Err() != nil {
				return nil, fmt.Errorf("probe cached SSH connection for node '%s' failed: %w", nodeName, ctx.Err())
			}
		}
	}

	return c.initializeConnection(ctx, planNode, dialer)
}

func (c *Connector) wrapCachedClient(cfg *ClientConfig, cachedClient *PooledClient) *Client {
	return newClientWithLogger(cachedClient.SSHClient, cachedClient.RootConn, cfg, c.store, c.PasswordPromptPattern, c.getLogger())
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

func (c *Connector) initializeConnection(ctx context.Context, planNode connectionPlanNode, dialer Dialer) (*Client, error) {
	nodeName := planNode.name
	cfg := planNode.cfg

	// SudoMode 为 su 时若未配置密码，交互式提示并写回 Provider（调用方负责持久化）
	if cfg.SudoMode == SudoModeSu && cfg.SuPwd == "" {
		suPwd, err := c.ui.PromptPassword(fmt.Sprintf("Enter su password for node %s: ", nodeName))
		if err != nil {
			return nil, fmt.Errorf("failed to read su password: %w", err)
		}
		cfg.SuPwd = suPwd
		if cfg.SudoUpdateToken != "" {
			if err := c.store.UpdateSudo(ctx, nodeName, cfg.SudoUpdateToken, cfg.SudoMode, suPwd); err != nil {
				return nil, fmt.Errorf("failed to update sudo credentials for node '%s': %w", nodeName, err)
			}
		}
	}

	sshConfig, cleanup, err := c.buildSSHConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build ssh config for '%s': %w", nodeName, err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	// 共享任务不继承任一调用者的 deadline，因此在网络阶段施加内部总超时；
	// 这同时约束直连和 ProxyJump 的通道建立，避免共享任务无限占用 singleflight。
	networkCtx, cancelNetwork := context.WithTimeout(ctx, defaultSSHHandshakeTimeout)
	defer cancelNetwork()
	rawClient, rootConn, err := c.dialAndHandshake(networkCtx, nodeName, cfg, dialer, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial and handshake: %w", err)
	}

	// 认证并连接成功后，检查我们是否通过 "auto" 下的终端交互获取到了新凭证（密码或密钥密码）。
	if (cfg.Password != "" || cfg.Passphrase != "") && cfg.AuthUpdateToken != "" {
		if err := c.store.UpdateAuth(ctx, nodeName, cfg.AuthUpdateToken, cfg.Password, cfg.KeyPath, cfg.Passphrase); err != nil {
			if closeErr := rootConn.Close(); closeErr != nil {
				return nil, fmt.Errorf("failed to update authentication for node '%s': %w; close unpublished SSH client failed: %w", nodeName, err, closeErr)
			}
			return nil, fmt.Errorf("failed to update authentication for node '%s': %w", nodeName, err)
		}
	}

	pooled := &PooledClient{SSHClient: rawClient, RootConn: rootConn}
	if err := c.publishClient(nodeName, pooled); err != nil {
		if closeErr := rootConn.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w; close unpublished SSH client failed: %w", err, closeErr)
		}
		return nil, err
	}
	c.startKeepAliveFor(nodeName, pooled)
	// 返回封装的 Client
	return newClientWithLogger(rawClient, rootConn, cfg, c.store, c.PasswordPromptPattern, c.getLogger()), nil
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
// 探测失败或超时即关闭连接并从池中驱逐，下次 Connect 自动重建。
// interval/timeout 传非正值时回退到 DefaultKeepAliveInterval/DefaultKeepAliveTimeout。
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
	c.keepAlives.IterCb(func(_ string, entry *keepAliveEntry) bool {
		entry.cancel()
		return true
	})
	c.keepAlives.Clear()
}

// startKeepAliveFor 为入池连接挂载心跳；未启用心跳时为 no-op。
// 全程持有 kaMu：与 CloseAll（cancel 根 ctx + 清空注册表）完全互斥，
// 杜绝"读到 cfg 后、写入注册表前"窗口内 CloseAll 先行清空导致的孤儿注册条目。
// 同节点重连时先取消旧心跳，避免同一节点存在多个心跳 goroutine。
// 锁序恒为 kaMu -> keepAlives 分片锁，evictDeadClient 不取 kaMu，无死锁风险
func (c *Connector) startKeepAliveFor(nodeName string, client *PooledClient) {
	c.kaMu.Lock()
	defer c.kaMu.Unlock()
	cfg := c.keepAliveCfg
	if cfg == nil || cfg.ctx.Err() != nil {
		return
	}

	// 终止同节点旧心跳（入池点在 singleflight 保护内，无并发冲突）
	if old, ok := c.keepAlives.Pop(nodeName); ok {
		old.cancel()
	}

	nodeCtx, cancel := context.WithCancel(cfg.ctx)
	entry := &keepAliveEntry{
		cancel: cancel,
		client: client,
	}
	c.keepAlives.Set(nodeName, entry)
	c.keepAliveWG.Add(1)
	entry.done = StartKeepAlive(nodeCtx, client.SSHClient, cfg.interval, cfg.timeout, func(error) {
		c.evictDeadClient(nodeName, client, entry)
	})
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

func (c *Connector) dialAndHandshake(ctx context.Context, nodeName string, cfg *ClientConfig, dialer Dialer, sshConfig *ssh.ClientConfig) (*ssh.Client, net.Conn, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	targetAddr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, nil, &ConnectionError{
			NodeID:   nodeName,
			Address:  cfg.Address,
			Port:     cfg.Port,
			AuthType: cfg.AuthType,
			Err:      err,
		}
	}
	handshakeDeadline := time.Now().Add(defaultSSHHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(handshakeDeadline) {
		handshakeDeadline = ctxDeadline
	}
	if err := conn.SetDeadline(handshakeDeadline); err != nil {
		if !strings.Contains(err.Error(), "deadline not supported") {
			if closeErr := conn.Close(); closeErr != nil {
				return nil, nil, fmt.Errorf(
					"set SSH handshake deadline for '%s' failed: %w; close connection after deadline setup failed: %w",
					nodeName,
					err,
					closeErr,
				)
			}
			return nil, nil, fmt.Errorf("set SSH handshake deadline for '%s' failed: %w", nodeName, err)
		}
	}
	stopCancelClose := context.AfterFunc(ctx, func() {
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			c.getLogger().Debugf("close SSH handshake connection after cancellation failed: %v", closeErr)
		}
	})

	// 建立 SSH 会话
	// 使用 NewClientConn 接管底层的 conn
	ncc, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, sshConfig)
	if err != nil {
		stopCancelClose()
		closeErr := conn.Close()
		if ctx.Err() != nil {
			primaryErr := fmt.Errorf("ssh handshake canceled for '%s': %w", nodeName, ctx.Err())
			return nil, nil, combineSSHOperationErrors(primaryErr, wrapCloseError(closeErr, "close canceled SSH handshake connection"))
		}
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return nil, nil, fmt.Errorf(
				"ssh handshake failed for '%s': %w; close failed SSH handshake connection: %w",
				nodeName,
				&HandshakeError{NodeID: nodeName, Err: err},
				closeErr,
			)
		}
		return nil, nil, &HandshakeError{NodeID: nodeName, Err: err}
	}
	stoppedCancelClose := stopCancelClose()
	if ctx.Err() != nil || !stoppedCancelClose {
		closeErr := ncc.Close()
		cancelErr := ctx.Err()
		if cancelErr == nil {
			cancelErr = context.Canceled
		}
		primaryErr := fmt.Errorf("ssh handshake canceled for '%s': %w", nodeName, cancelErr)
		return nil, nil, combineSSHOperationErrors(primaryErr, wrapCloseError(closeErr, "close canceled SSH connection"))
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

	return ssh.NewClient(ncc, chans, reqs), conn, nil
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
	c.lifecycleMu.Unlock()

	// closed 置位后不会再有新的 Connect 登记；等待在途 Connect 停止并拒绝发布。
	c.connectWG.Wait()

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

	var closeErrs []error
	c.clients.IterCb(func(_ string, client *PooledClient) bool {
		if err := client.SSHClient.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErrs = append(closeErrs, err)
		}
		return true
	})
	c.clients.Clear()
	c.keepAliveWG.Wait()

	if len(closeErrs) > 0 {
		c.closeErr = fmt.Errorf("close pooled SSH clients failed: %w", errors.Join(closeErrs...))
	}
	close(c.closeDone)
	return c.closeErr
}

// buildSSHConfig 根据 Identity 模型构建 ssh.ClientConfig
func (c *Connector) buildSSHConfig(cfg *ClientConfig) (*ssh.ClientConfig, func(), error) {
	var cleanup func()
	authMethods := []ssh.AuthMethod{}

	// 根据 AuthType 处理不同的认证方式
	switch cfg.AuthType {
	case "auto":
		var autoCleanup func()
		authMethods, autoCleanup = BuildAutoAuthMethodsWithLogger(cfg.User, cfg.Address, c.ui, func(s string) {
			if s != "" {
				cfg.Password = s
				cfg.AuthType = "password"
			}
		}, func(keyPath, passphrase string) {
			if passphrase != "" {
				cfg.KeyPath = keyPath
				cfg.Passphrase = passphrase
				cfg.AuthType = "key"
			}
		}, c.getLogger())
		cleanup = autoCleanup

	case "password":
		if cfg.Password == "" {
			return nil, nil, ErrPasswordRequired
		}
		authMethods = append(authMethods, ssh.Password(cfg.Password))

	case "key":
		authMethod, err := buildKeyAuthMethod(cfg)
		if err != nil {
			return nil, nil, err
		}
		authMethods = append(authMethods, authMethod)

	case "agent":
		socket := os.Getenv("SSH_AUTH_SOCK")
		if socket == "" {
			return nil, nil, ErrAgentNotAvailable
		}
		conn, err := net.Dial("unix", socket)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to connect to ssh-agent: %w", err)
		}
		agentClient := agent.NewClient(conn)
		authMethods = append(authMethods, ssh.PublicKeysCallback(agentClient.Signers))
		cleanup = func() { debugCloseResource(c.getLogger(), conn, "ssh agent connection") }

	default:
		return nil, nil, fmt.Errorf("unsupported auth type: %s", cfg.AuthType)
	}

	hostKeyCallback, err := c.getHostKeyCallback()
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, nil, fmt.Errorf("get host key callback failed: %w", err)
	}

	return &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}, cleanup, nil
}

func buildKeyAuthMethod(cfg *ClientConfig) (ssh.AuthMethod, error) {
	if cfg.KeyPath == "" {
		return nil, ErrKeyPathRequired
	}
	keyBytes, err := os.ReadFile(expandHomeDir(cfg.KeyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	var signer ssh.Signer
	if cfg.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(cfg.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return ssh.PublicKeys(signer), nil
}

// expandHomeDir 简单的路径处理辅助函数
func expandHomeDir(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[1:])
		}
	}
	return path
}

func (c *Connector) getHostKeyCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get user home dir failed: %w", err)
	}
	knownHostsFile := filepath.Join(home, ".ssh", "known_hosts")

	if _, err := os.Stat(knownHostsFile); os.IsNotExist(err) {
		if mkdirErr := os.MkdirAll(filepath.Dir(knownHostsFile), 0700); mkdirErr != nil {
			return nil, fmt.Errorf("create .ssh directory failed: %w", mkdirErr)
		}
		if writeErr := os.WriteFile(knownHostsFile, []byte(""), 0600); writeErr != nil {
			return nil, fmt.Errorf("create known_hosts file failed: %w", writeErr)
		}
	}

	hostKeyCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("parse known_hosts file failed: %w", err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := hostKeyCallback(hostname, remote, key)
		if err == nil {
			return nil
		}

		if keyErr, ok := errors.AsType[*knownhosts.KeyError](err); ok {
			if len(keyErr.Want) > 0 {
				return fmt.Errorf("%w: remote host identification has changed for %s: %w", ErrHostKeyMismatch, hostname, err)
			}

			if promptErr := c.promptHostKeyVerification(hostname, key); promptErr != nil {
				return promptErr
			}

			return appendKnownHost(knownHostsFile, hostname, key)
		}
		return err
	}, nil
}

func (c *Connector) promptHostKeyVerification(hostname string, key ssh.PublicKey) error {
	if c.AcceptNewHostKey.Load() {
		return nil
	}

	hostKeyPromptMutex.Lock()
	defer hostKeyPromptMutex.Unlock()

	// Double check after acquiring lock
	if c.AcceptNewHostKey.Load() {
		return nil
	}

	fingerprint := ssh.FingerprintSHA256(key)
	agreed, err := c.ui.ConfirmHostKey(hostname, fingerprint)
	if err != nil {
		return fmt.Errorf("read response failed: %w", err)
	}

	if agreed {
		return nil
	}
	return ErrHostKeyMismatch
}

func appendKnownHost(knownHostsFile, hostname string, key ssh.PublicKey) (err error) {
	hostKeyPromptMutex.Lock()
	defer hostKeyPromptMutex.Unlock()

	f, openErr := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_WRONLY, 0600)
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

// PooledClient represents a pooled SSH client with its underlying connection
type PooledClient struct {
	SSHClient *ssh.Client
	RootConn  net.Conn
}
