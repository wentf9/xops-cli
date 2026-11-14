package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
)

const (
	// MaxAgentForwardChannels caps concurrent remote-initiated auth-agent@openssh.com
	// channels per underlying SSH client transport.
	MaxAgentForwardChannels = 64

	agentForwardChannelType  = "auth-agent@openssh.com"
	agentForwardRequestType  = "auth-agent-req@openssh.com"
	agentForwardDrainTimeout = time.Second
)

// agentNonHalfCloseTimeout bounds how long a forwarded agent channel waits for
// the local ssh-agent response after remote EOF when the local agent transport
// lacks half-close (e.g., Windows Named Pipes). Hardware-backed keys and touch/PIN
// prompts (YubiKey/FIDO2, 1Password, Windows Hello) regularly take several seconds,
// so this uses DefaultInteractionTimeout rather than a sub-second grace window.
var agentNonHalfCloseTimeout = DefaultInteractionTimeout

var (
	errAgentLeaseConflict = errors.New("conflicting agent forwarding target is already active on this SSH connection")
	errEmptyAgentSocket   = errors.New("agent forwarding socket path cannot be empty")
)

// ResolveForwardAgent resolves an OpenSSH ForwardAgent specification against
// identityAgentSpec, env, and target.
//   - "", "no", "false" -> ("", false, nil)
//   - "yes", "true" -> delegates socket resolution to ResolveIdentityAgent
//     (returning ("", false, nil) if IdentityAgent="none" or empty)
//   - "SSH_AUTH_SOCK" -> uses normalized env.AgentSocket
//   - custom path / "$VAR" / "${VAR}" / "~" / "%" tokens -> expands via env and target
func ResolveForwardAgent(forwardSpec, identityAgentSpec string, env Environment, target TargetContext) (socket string, enabled bool, err error) {
	return resolveForwardAgentSpec(forwardSpec, identityAgentSpec, env, target, false)
}

func resolveEnvAgentSocket(env Environment, allowEmptyEnvSocket bool) (socket string, enabled bool, err error) {
	rawSock := strings.TrimSpace(env.AgentSocket)
	if rawSock != "" {
		sock := normalizeExpandedAgentSocketPath(rawSock, env)
		if sock != "" {
			return sock, true, nil
		}
	}
	if allowEmptyEnvSocket {
		return "", true, nil
	}
	return "", false, nil
}

func resolveForwardAgentSpec(
	forwardSpec, identityAgentSpec string,
	env Environment,
	target TargetContext,
	allowEmptyEnvSocket bool,
) (socket string, enabled bool, err error) {
	trimmed := strings.TrimSpace(forwardSpec)
	if trimmed == "" || strings.EqualFold(trimmed, "no") || strings.EqualFold(trimmed, "false") {
		return "", false, nil
	}
	if strings.EqualFold(trimmed, "yes") || strings.EqualFold(trimmed, "true") {
		idTrimmed := strings.TrimSpace(identityAgentSpec)
		if strings.EqualFold(idTrimmed, "none") {
			return "", false, nil
		}
		if idTrimmed == "" || idTrimmed == "SSH_AUTH_SOCK" {
			return resolveEnvAgentSocket(env, allowEmptyEnvSocket)
		}
		sock, disabled, err := ResolveIdentityAgent(identityAgentSpec, env, target)
		if err != nil {
			return "", false, err
		}
		if disabled || sock == "" {
			return "", false, nil
		}
		sock = normalizeExpandedAgentSocketPath(sock, env)
		return sock, sock != "", nil
	}
	if trimmed == "SSH_AUTH_SOCK" {
		return resolveEnvAgentSocket(env, allowEmptyEnvSocket)
	}
	expanded, err := expandAgentSocketPath(trimmed, env, target, "ForwardAgent")
	if err != nil {
		return "", false, err
	}
	return expanded, expanded != "", nil
}

var (
	sshAgentRoutersMu sync.Mutex
	sshAgentRouters   sync.Map // *cryptoSSH.Client -> *sshAgentChannelRouter
)

type activeAgentChannel struct {
	agentConn net.Conn
	sshCh     cryptoSSH.Channel
	closeFn   func()
}

type agentForwardLease struct {
	router    *sshAgentChannelRouter
	ctx       context.Context
	cancel    context.CancelFunc
	socket    string
	dialAgent func(context.Context, string) (net.Conn, error)
	logger    logger.DebugLogger

	mu          sync.Mutex
	closed      bool
	active      map[*activeAgentChannel]struct{}
	pumps       sync.WaitGroup
	releaseOnce sync.Once
}

func (l *agentForwardLease) Release() {
	l.releaseWithDeadline(time.Now().Add(agentForwardDrainTimeout))
}

func (l *agentForwardLease) releaseWithDeadline(deadline time.Time) {
	if l == nil {
		return
	}
	l.releaseOnce.Do(func() {
		if l.router != nil {
			l.router.removeLease(l)
		}
		if l.cancel != nil {
			l.cancel()
		}
		l.mu.Lock()
		l.closed = true
		entries := make([]*activeAgentChannel, 0, len(l.active))
		for entry := range l.active {
			entries = append(entries, entry)
		}
		clear(l.active)
		l.mu.Unlock()

		for _, entry := range entries {
			if entry.agentConn != nil {
				_ = entry.agentConn.Close()
			}
			if entry.sshCh != nil {
				_ = entry.sshCh.Close()
			}
			if entry.closeFn != nil {
				entry.closeFn()
			}
		}

		drained := make(chan struct{})
		go func() {
			l.pumps.Wait()
			close(drained)
		}()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			select {
			case <-drained:
			default:
				if l.logger != nil {
					l.logger.Debugf("ForwardAgent: timed out after %s waiting for forwarded agent channels to drain", agentForwardDrainTimeout)
				}
			}
			return
		}
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		select {
		case <-drained:
		case <-timer.C:
			if l.logger != nil {
				l.logger.Debugf("ForwardAgent: timed out after %s waiting for forwarded agent channels to drain", agentForwardDrainTimeout)
			}
		}
	})
}

func (l *agentForwardLease) tryBeginPump() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.pumps.Add(1)
	return true
}

func (l *agentForwardLease) registerActive(entry *activeAgentChannel) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	if l.active == nil {
		l.active = make(map[*activeAgentChannel]struct{})
	}
	l.active[entry] = struct{}{}
	return true
}

func (l *agentForwardLease) removeActive(entry *activeAgentChannel) {
	l.mu.Lock()
	delete(l.active, entry)
	l.mu.Unlock()
}

func (l *agentForwardLease) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// sshAgentChannelRouter owns the single HandleChannelOpen("auth-agent@openssh.com")
// registration on one *cryptoSSH.Client. Its dispatchLoop exits automatically when
// the underlying *cryptoSSH.Client closes its channel-open stream.
type sshAgentChannelRouter struct {
	sshClient      *cryptoSSH.Client
	mu             sync.Mutex
	leases         []*agentForwardLease
	activeChannels atomic.Int32
}

func getOrCreateAgentRouter(sshClient *cryptoSSH.Client) (*sshAgentChannelRouter, error) {
	if sshClient == nil {
		return nil, errors.New("ssh client is nil")
	}
	if existing, ok := sshAgentRouters.Load(sshClient); ok {
		return existing.(*sshAgentChannelRouter), nil
	}
	sshAgentRoutersMu.Lock()
	defer sshAgentRoutersMu.Unlock()
	if existing, ok := sshAgentRouters.Load(sshClient); ok {
		return existing.(*sshAgentChannelRouter), nil
	}
	chans := sshClient.HandleChannelOpen(agentForwardChannelType)
	if chans == nil {
		return nil, errors.New("auth-agent@openssh.com channel handler is already registered on SSH client")
	}
	router := &sshAgentChannelRouter{
		sshClient: sshClient,
	}
	sshAgentRouters.Store(sshClient, router)
	go router.dispatchLoop(chans)
	return router, nil
}

func isLeaseActiveLocked(cand *agentForwardLease) bool {
	return cand != nil && !cand.isClosed()
}

func (r *sshAgentChannelRouter) hasConflictingActiveLeaseLocked(socket string) bool {
	for _, cand := range r.leases {
		if !isLeaseActiveLocked(cand) {
			continue
		}
		if socket == "" || cand.socket == "" || cand.socket != socket {
			return true
		}
	}
	return false
}

func (r *sshAgentChannelRouter) acquireLocalLease(
	ctx context.Context,
	socket string,
	dialAgent func(context.Context, string) (net.Conn, error),
	l logger.DebugLogger,
) (*agentForwardLease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if l == nil {
		l = logger.NopLogger
	}
	socket = strings.TrimSpace(socket)
	if socket == "" {
		l.Debugf("ForwardAgent: rejecting empty local agent socket path")
		return nil, errEmptyAgentSocket
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hasConflictingActiveLeaseLocked(socket) {
		l.Debugf("ForwardAgent: rejecting conflicting local agent lease for %q on shared SSH connection", socket)
		return nil, errAgentLeaseConflict
	}
	leaseCtx, cancel := context.WithCancel(ctx)
	lease := &agentForwardLease{
		router:    r,
		ctx:       leaseCtx,
		cancel:    cancel,
		socket:    socket,
		dialAgent: dialAgent,
		logger:    l,
	}
	r.leases = append(r.leases, lease)
	return lease, nil
}

func (r *sshAgentChannelRouter) removeLease(lease *agentForwardLease) {
	r.mu.Lock()
	r.leases = slices.DeleteFunc(r.leases, func(item *agentForwardLease) bool {
		return item == lease
	})
	r.mu.Unlock()
}

func (r *sshAgentChannelRouter) beginActiveLease() *agentForwardLease {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.leases) - 1; i >= 0; i-- {
		cand := r.leases[i]
		if cand == nil {
			continue
		}
		if cand.tryBeginPump() {
			return cand
		}
	}
	return nil
}

func (r *sshAgentChannelRouter) tryAcquireChannelSlot() bool {
	for {
		cur := r.activeChannels.Load()
		if cur >= MaxAgentForwardChannels {
			return false
		}
		if r.activeChannels.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (r *sshAgentChannelRouter) releaseChannelSlot() {
	r.activeChannels.Add(-1)
}

func (r *sshAgentChannelRouter) dispatchLoop(chans <-chan cryptoSSH.NewChannel) {
	defer sshAgentRouters.Delete(r.sshClient)
	for newCh := range chans {
		lease := r.beginActiveLease()
		if lease == nil {
			_ = newCh.Reject(cryptoSSH.Prohibited, "agent forwarding is not enabled")
			continue
		}
		if !r.tryAcquireChannelSlot() {
			lease.pumps.Done()
			_ = newCh.Reject(cryptoSSH.ResourceShortage, "too many concurrent agent forwarding channels")
			continue
		}
		go func(l *agentForwardLease, ch cryptoSSH.NewChannel) {
			defer l.pumps.Done()
			r.serveLocalAgentChannel(l, ch)
		}(lease, newCh)
	}
}

func (r *sshAgentChannelRouter) serveLocalAgentChannel(lease *agentForwardLease, newCh cryptoSSH.NewChannel) {
	if lease.isClosed() {
		r.releaseChannelSlot()
		_ = newCh.Reject(cryptoSSH.Prohibited, "agent forwarding session closed")
		return
	}
	agentConn, err := dialAgentConn(lease.ctx, lease.dialAgent, lease.socket)
	if err != nil {
		r.releaseChannelSlot()
		lease.logger.Debugf("ForwardAgent: dial local agent %q failed: %v", lease.socket, err)
		_ = newCh.Reject(cryptoSSH.ConnectionFailed, "failed to connect to local ssh-agent")
		return
	}

	sshCh, reqs, err := newCh.Accept()
	if err != nil {
		r.releaseChannelSlot()
		_ = agentConn.Close()
		return
	}

	entry := &activeAgentChannel{
		agentConn: agentConn,
		sshCh:     sshCh,
	}
	if !lease.registerActive(entry) {
		r.releaseChannelSlot()
		_ = agentConn.Close()
		_ = sshCh.Close()
		go cryptoSSH.DiscardRequests(reqs)
		return
	}

	reverseDone := make(chan struct{})
	closedCh := make(chan struct{})
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			close(closedCh)
			_ = agentConn.Close()
			_ = sshCh.Close()
			lease.removeActive(entry)
			r.releaseChannelSlot()
		})
	}

	go func() {
		cryptoSSH.DiscardRequests(reqs)
		closeBoth()
	}()

	var copyWG sync.WaitGroup
	copyWG.Add(2)

	go func() {
		defer copyWG.Done()
		_, _ = io.Copy(agentConn, sshCh)
		if cw, ok := agentConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
		timer := time.NewTimer(agentNonHalfCloseTimeout)
		defer timer.Stop()
		select {
		case <-reverseDone:
		case <-closedCh:
		case <-lease.ctx.Done():
		case <-timer.C:
		}
		_ = agentConn.Close()
	}()

	go func() {
		defer copyWG.Done()
		defer close(reverseDone)
		_, _ = io.Copy(sshCh, agentConn)
		_ = sshCh.CloseWrite()
	}()

	copyWG.Wait()
	closeBoth()
}

func (c *Client) clientForwardAgentTarget(connCfg ConnectionConfig) TargetContext {
	port := connCfg.Port
	if port <= 0 {
		port = 22
	}
	user := connCfg.User
	if user == "" {
		user = c.environment.LocalUser
	}
	return TargetContext{
		Host:         connCfg.Address,
		Port:         port,
		User:         user,
		OriginalHost: effectiveOriginalHost(connCfg.OriginalHost, connCfg.NodeID),
		JumpHost:     connCfg.ProxyJump,
		KeyPath:      connCfg.KeyPath,
	}
}

func (c *Client) resolveClientForwardAgent() (socket string, enabled bool) {
	if c == nil || c.sshClient == nil {
		return "", false
	}
	connCfg := c.ConnectionConfig()
	if connCfg.Options == nil {
		return "", false
	}
	sock, ok, err := ResolveForwardAgent(
		connCfg.Options.ForwardAgent(),
		connCfg.Options.IdentityAgent(),
		c.environment,
		c.clientForwardAgentTarget(connCfg),
	)
	if err != nil {
		c.getLogger().Debugf("ForwardAgent disabled: %v", err)
		return "", false
	}
	if !ok || sock == "" {
		return "", false
	}
	if c.environment.DialAgent == nil {
		c.getLogger().Debugf("ForwardAgent disabled: DialAgent is not configured")
		return "", false
	}
	return sock, true
}

func (c *Client) trackAgentLease(lease *agentForwardLease) {
	if c == nil || lease == nil {
		return
	}
	c.activeMu.Lock()
	if c.activeAgentLeases == nil {
		c.activeAgentLeases = make(map[*agentForwardLease]struct{})
	}
	c.activeAgentLeases[lease] = struct{}{}
	c.activeMu.Unlock()
}

func (c *Client) untrackAgentLease(lease *agentForwardLease) {
	if c == nil || lease == nil {
		return
	}
	c.activeMu.Lock()
	delete(c.activeAgentLeases, lease)
	c.activeMu.Unlock()
}

func (c *Client) releaseAllAgentLeases() {
	if c == nil {
		return
	}
	c.activeMu.Lock()
	leases := make([]*agentForwardLease, 0, len(c.activeAgentLeases))
	for lease := range c.activeAgentLeases {
		leases = append(leases, lease)
	}
	clear(c.activeAgentLeases)
	c.activeMu.Unlock()
	if len(leases) == 0 {
		return
	}
	deadline := time.Now().Add(agentForwardDrainTimeout)
	var wg sync.WaitGroup
	wg.Add(len(leases))
	for _, lease := range leases {
		go func(l *agentForwardLease) {
			defer wg.Done()
			l.releaseWithDeadline(deadline)
		}(lease)
	}
	wg.Wait()
}

func (c *Client) acquireSessionAgentLease(ctx context.Context) *agentForwardLease {
	sock, enabled := c.resolveClientForwardAgent()
	if !enabled {
		return nil
	}
	router, err := getOrCreateAgentRouter(c.sshClient)
	if err != nil {
		c.getLogger().Debugf("ForwardAgent disabled: %v", err)
		return nil
	}
	lease, err := router.acquireLocalLease(ctx, sock, c.environment.DialAgent, c.getLogger())
	if err != nil {
		return nil
	}
	c.trackAgentLease(lease)
	return lease
}

func (c *Client) isMultiplexedProxy() bool {
	if c == nil {
		return false
	}
	if c.muxSocketPath != "" {
		return true
	}
	if c.sshClient != nil && c.sshClient.Conn != nil {
		if _, ok := c.sshClient.Conn.(*muxProxySSHConn); ok {
			return true
		}
	}
	return false
}

// shouldRequestMuxProxyAgentForward reports whether a multiplexed control-proxy
// passenger should send auth-agent-req@openssh.com to ask the ControlMaster to
// forward the Master's own verified ssh-agent (matching native OpenSSH mux.c).
func (c *Client) shouldRequestMuxProxyAgentForward() bool {
	if c == nil || c.sshClient == nil {
		return false
	}
	connCfg := c.ConnectionConfig()
	if connCfg.Options == nil {
		return false
	}
	_, enabled, err := resolveForwardAgentSpec(
		connCfg.Options.ForwardAgent(),
		connCfg.Options.IdentityAgent(),
		c.environment,
		c.clientForwardAgentTarget(connCfg),
		true,
	)
	if err != nil {
		c.getLogger().Debugf("ForwardAgent disabled over mux proxy: %v", err)
		return false
	}
	return enabled
}

func (c *Client) prepareChannelAgentForward(ctx context.Context) (wantAgent bool, release func()) {
	if c == nil || c.sshClient == nil {
		return false, func() {}
	}
	if c.isMultiplexedProxy() {
		return c.shouldRequestMuxProxyAgentForward(), func() {}
	}
	lease := c.acquireSessionAgentLease(ctx)
	if lease == nil {
		return false, func() {}
	}
	return true, sync.OnceFunc(func() {
		c.untrackAgentLease(lease)
		lease.Release()
	})
}

func (c *Client) enableSessionAgentForward(ctx context.Context, session *cryptoSSH.Session) func() {
	wantAgent, release := c.prepareChannelAgentForward(ctx)
	if !wantAgent {
		return func() {}
	}
	var accepted bool
	err := c.sessionRequest(ctx, session, agentForwardRequestType, func() error {
		var reqErr error
		accepted, reqErr = session.SendRequest(agentForwardRequestType, true, nil)
		return reqErr
	})
	if err != nil || !accepted {
		release()
		c.getLogger().Debugf("SSH server rejected or failed %s (accepted=%v, err=%v); continuing without agent forwarding", agentForwardRequestType, accepted, err)
		return func() {}
	}
	return release
}
