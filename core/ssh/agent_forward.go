package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/verdict"
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

// agentForwardDialTimeout bounds each local ssh-agent dial for forwarded channels
// so an unresponsive local agent socket cannot pin channel slots indefinitely.
var agentForwardDialTimeout = defaultSSHHandshakeTimeout

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
	if hasControlOrLineSepChar(env.AgentSocket) {
		return "", false, fmt.Errorf("invalid SSH_AUTH_SOCK %q: contains invalid ASCII control character", env.AgentSocket)
	}
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
	if hasControlOrLineSepChar(forwardSpec) {
		return "", false, fmt.Errorf("invalid ForwardAgent %q: contains invalid ASCII control character", forwardSpec)
	}
	trimmed := strings.TrimSpace(forwardSpec)
	if trimmed == "" || strings.EqualFold(trimmed, "no") || strings.EqualFold(trimmed, "false") {
		return "", false, nil
	}
	if strings.EqualFold(trimmed, "yes") || strings.EqualFold(trimmed, "true") {
		if hasControlOrLineSepChar(identityAgentSpec) {
			return "", false, fmt.Errorf("invalid IdentityAgent %q: contains invalid ASCII control character", identityAgentSpec)
		}
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
		sock = normalizeExpandedAgentSocketPathWithTilde(sock, env, false)
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

type agentForwardTransportControl struct {
	interrupt    func() error
	closeTimeout func() time.Duration
}

type agentForwardLease struct {
	router             *sshAgentChannelRouter
	ctx                context.Context
	cancel             context.CancelFunc
	socket             string
	dialAgent          func(context.Context, string) (net.Conn, error)
	interruptTransport func() error
	closeTimeoutFn     func() time.Duration
	logger             logger.DebugLogger

	mu          sync.Mutex
	closed      bool
	active      map[*activeAgentChannel]struct{}
	pumps       sync.WaitGroup
	releaseOnce sync.Once
}

func (l *agentForwardLease) drainTimeout() time.Duration {
	if l != nil && l.closeTimeoutFn != nil {
		if d := l.closeTimeoutFn(); d > 0 && d < agentForwardDrainTimeout {
			return d
		}
	}
	if l != nil && l.router != nil {
		if d := l.router.drainTimeout(); d > 0 && d < agentForwardDrainTimeout {
			return d
		}
	}
	return agentForwardDrainTimeout
}

func (l *agentForwardLease) hasInterruptTransport() bool {
	if l == nil {
		return false
	}
	if l.interruptTransport != nil {
		return true
	}
	return l.router != nil && l.router.hasInterruptTransport()
}

func (l *agentForwardLease) interruptTransportNow() error {
	if l == nil {
		return nil
	}
	if l.interruptTransport != nil {
		return l.interruptTransport()
	}
	if l.router != nil {
		return l.router.interruptTransportNow()
	}
	return nil
}

func runBoundedAgentTransportOp(
	timeout time.Duration,
	hasInterrupt bool,
	interrupt func() error,
	label string,
	op func() error,
) error {
	if timeout <= 0 {
		timeout = agentForwardDrainTimeout
	}
	done := make(chan error, 1)
	go func() {
		done <- op()
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if !hasInterrupt || interrupt == nil {
			return fmt.Errorf("agent forward %s exceeded %s", label, timeout)
		}
		interruptErr := interrupt()
		postTimer := time.NewTimer(timeout)
		defer postTimer.Stop()
		select {
		case opErr := <-done:
			return errors.Join(fmt.Errorf("agent forward %s exceeded %s", label, timeout), interruptErr, opErr)
		case <-postTimer.C:
			return errors.Join(fmt.Errorf("agent forward %s exceeded %s", label, timeout), interruptErr)
		}
	}
}

func (l *agentForwardLease) closeSSHChannelBounded(ch cryptoSSH.Channel) error {
	if ch == nil {
		return nil
	}
	return runBoundedAgentTransportOp(
		l.drainTimeout(),
		l.hasInterruptTransport(),
		l.interruptTransportNow,
		"channel close",
		func() error { return closeSSHChannel(ch) },
	)
}

func (l *agentForwardLease) closeSSHChannelWriteBounded(ch cryptoSSH.Channel) error {
	if ch == nil {
		return nil
	}
	return runBoundedAgentTransportOp(
		l.drainTimeout(),
		l.hasInterruptTransport(),
		l.interruptTransportNow,
		"channel CloseWrite",
		func() error {
			err := ch.CloseWrite()
			if err != nil && (errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed)) {
				return nil
			}
			return err
		},
	)
}

func (l *agentForwardLease) replyChannelRequestBounded(req *cryptoSSH.Request, ok bool, payload []byte) error {
	if req == nil || !req.WantReply {
		return nil
	}
	return runBoundedAgentTransportOp(
		l.drainTimeout(),
		l.hasInterruptTransport(),
		l.interruptTransportNow,
		"channel request reply",
		func() error {
			err := req.Reply(ok, payload)
			if err != nil && (errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed)) {
				return nil
			}
			return err
		},
	)
}

func (l *agentForwardLease) discardChannelRequests(reqs <-chan *cryptoSSH.Request) {
	if reqs == nil {
		return
	}
	for req := range reqs {
		if req != nil && req.WantReply {
			_ = l.replyChannelRequestBounded(req, false, nil)
		}
	}
}

func (l *agentForwardLease) rejectNewChannelBounded(newCh cryptoSSH.NewChannel, reason cryptoSSH.RejectionReason, msg string) error {
	if newCh == nil {
		return nil
	}
	return runBoundedAgentTransportOp(
		l.drainTimeout(),
		l.hasInterruptTransport(),
		l.interruptTransportNow,
		"channel reject",
		func() error { return newCh.Reject(reason, msg) },
	)
}

func (l *agentForwardLease) acceptNewChannelBounded(newCh cryptoSSH.NewChannel) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if newCh == nil {
		return nil, nil, errors.New("nil incoming agent channel")
	}
	result := make(chan openChannelResult, 1)
	go func() {
		ch, reqs, err := newCh.Accept()
		result <- openChannelResult{channel: ch, requests: reqs, err: err}
	}()
	timeout := l.drainTimeout()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-result:
		return res.channel, res.requests, res.err
	case <-timer.C:
		if !l.hasInterruptTransport() {
			return nil, nil, fmt.Errorf("agent forward channel accept exceeded %s", timeout)
		}
		interruptErr := l.interruptTransportNow()
		postTimer := time.NewTimer(timeout)
		defer postTimer.Stop()
		select {
		case res := <-result:
			if res.channel != nil {
				go l.discardChannelRequests(res.requests)
				_ = closeSSHChannel(res.channel)
			}
			return nil, nil, errors.Join(fmt.Errorf("agent forward channel accept exceeded %s", timeout), interruptErr, res.err)
		case <-postTimer.C:
			return nil, nil, errors.Join(fmt.Errorf("agent forward channel accept exceeded %s", timeout), interruptErr)
		}
	}
}

func (l *agentForwardLease) Release() {
	if l == nil {
		return
	}
	l.releaseWithDeadline(time.Now().Add(l.drainTimeout()))
}

func waitChanUntilDeadline(ch <-chan struct{}, deadline time.Time) bool {
	select {
	case <-ch:
		return true
	default:
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	}
}

func drainSSHChannelStderr(sshCh cryptoSSH.Channel) {
	if sshCh == nil {
		return
	}
	if se := sshCh.Stderr(); se != nil {
		_, _ = io.Copy(io.Discard, se)
	}
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

		var closeWG sync.WaitGroup
		hasCloseWork := false
		for _, entry := range entries {
			if entry.agentConn != nil {
				_ = entry.agentConn.Close()
			}
			if entry.sshCh != nil {
				// Close entry.sshCh asynchronously inside the drain deadline
				// window so a write-wedged SSH transport cannot block
				// releaseWithDeadline before its escalation timer starts.
				hasCloseWork = true
				closeWG.Add(1)
				go func(ch cryptoSSH.Channel) {
					defer closeWG.Done()
					_ = closeSSHChannel(ch)
				}(entry.sshCh)
			}
			if entry.closeFn != nil {
				entry.closeFn()
			}
		}

		// Separate outbound channel-close completion (closeWG) from inbound
		// pump drain (l.pumps): in golang.org/x/crypto/ssh, (*channel).Close()
		// sends outbound SSH_MSG_CHANNEL_CLOSE promptly on a healthy transport
		// without EOF-ing sshCh.Read until the remote peer echoes
		// SSH_MSG_CHANNEL_CLOSE. Only an outbound closeWG timeout proves the
		// transport is write-wedged and justifies interruptTransportNow().
		closeDone := make(chan struct{})
		if hasCloseWork {
			go func() {
				closeWG.Wait()
				close(closeDone)
			}()
		} else {
			close(closeDone)
		}

		pumpsDone := make(chan struct{})
		go func() {
			l.pumps.Wait()
			close(pumpsDone)
		}()

		if !waitChanUntilDeadline(closeDone, deadline) {
			if l.logger != nil {
				l.logger.Debugf("ForwardAgent: timed out after %s waiting for outbound SSH channel close; interrupting transport", l.drainTimeout())
			}
			if l.hasInterruptTransport() {
				_ = l.interruptTransportNow()
				postDeadline := time.Now().Add(l.drainTimeout())
				if waitChanUntilDeadline(closeDone, postDeadline) {
					_ = waitChanUntilDeadline(pumpsDone, postDeadline)
				}
			}
			return
		}

		// Outbound SSH_MSG_CHANNEL_CLOSE completed within deadline, so the
		// transport is healthy. Wait best-effort up to the remaining deadline
		// for inbound pumps to exit, but never interrupt a healthy shared
		// MuxServer / pooled Client / ProxyJump bastion when the remote peer
		// keeps the agent channel open without echoing SSH_MSG_CHANNEL_CLOSE.
		if !waitChanUntilDeadline(pumpsDone, deadline) && l.logger != nil {
			l.logger.Debugf("ForwardAgent: outbound channel close completed; returning without transport interrupt while remote agent channel remains open")
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
	sshClient          *cryptoSSH.Client
	mu                 sync.Mutex
	leases             []*agentForwardLease
	interruptTransport func() error
	closeTimeoutFn     func() time.Duration
	activeChannels     atomic.Int32
}

func (r *sshAgentChannelRouter) hasInterruptTransport() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	has := r.interruptTransport != nil
	r.mu.Unlock()
	return has
}

func (r *sshAgentChannelRouter) interruptTransportNow() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	fn := r.interruptTransport
	r.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn()
}

func (r *sshAgentChannelRouter) drainTimeout() time.Duration {
	if r == nil {
		return agentForwardDrainTimeout
	}
	r.mu.Lock()
	fn := r.closeTimeoutFn
	r.mu.Unlock()
	if fn != nil {
		if d := fn(); d > 0 && d < agentForwardDrainTimeout {
			return d
		}
	}
	return agentForwardDrainTimeout
}

func (r *sshAgentChannelRouter) rejectNewChannelBounded(newCh cryptoSSH.NewChannel, reason cryptoSSH.RejectionReason, msg string) error {
	if newCh == nil {
		return nil
	}
	return runBoundedAgentTransportOp(
		r.drainTimeout(),
		r.hasInterruptTransport(),
		r.interruptTransportNow,
		"channel reject",
		func() error { return newCh.Reject(reason, msg) },
	)
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
	return r.acquireLocalLeaseWithControl(ctx, socket, dialAgent, l, agentForwardTransportControl{})
}

func (r *sshAgentChannelRouter) acquireLocalLeaseWithControl(
	ctx context.Context,
	socket string,
	dialAgent func(context.Context, string) (net.Conn, error),
	l logger.DebugLogger,
	ctrl agentForwardTransportControl,
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
	if ctrl.interrupt != nil {
		r.interruptTransport = ctrl.interrupt
	}
	if ctrl.closeTimeout != nil {
		r.closeTimeoutFn = ctrl.closeTimeout
	}
	leaseCtx, cancel := context.WithCancel(ctx)
	lease := &agentForwardLease{
		router:             r,
		ctx:                leaseCtx,
		cancel:             cancel,
		socket:             socket,
		dialAgent:          dialAgent,
		interruptTransport: ctrl.interrupt,
		closeTimeoutFn:     ctrl.closeTimeout,
		logger:             l,
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
			_ = r.rejectNewChannelBounded(newCh, cryptoSSH.Prohibited, "agent forwarding is not enabled")
			continue
		}
		if !r.tryAcquireChannelSlot() {
			lease.pumps.Done()
			_ = lease.rejectNewChannelBounded(newCh, cryptoSSH.ResourceShortage, "too many concurrent agent forwarding channels")
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
		_ = lease.rejectNewChannelBounded(newCh, cryptoSSH.Prohibited, "agent forwarding session closed")
		return
	}
	dialTimeout := agentForwardDialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultSSHHandshakeTimeout
	}
	dialCtx, dialCancel := context.WithTimeout(lease.ctx, dialTimeout)
	agentConn, err := dialAgentConn(dialCtx, lease.dialAgent, lease.socket)
	dialCancel()
	if err != nil {
		r.releaseChannelSlot()
		lease.logger.Debugf("ForwardAgent: dial local agent %q failed: %v", lease.socket, err)
		_ = lease.rejectNewChannelBounded(newCh, cryptoSSH.ConnectionFailed, "failed to connect to local ssh-agent")
		return
	}

	stopClose := context.AfterFunc(lease.ctx, func() {
		_ = agentConn.Close()
	})

	sshCh, reqs, err := lease.acceptNewChannelBounded(newCh)
	if err != nil {
		stopClose()
		r.releaseChannelSlot()
		_ = agentConn.Close()
		return
	}

	entry := &activeAgentChannel{
		agentConn: agentConn,
		sshCh:     sshCh,
	}
	if !lease.registerActive(entry) {
		stopClose()
		r.releaseChannelSlot()
		_ = agentConn.Close()
		_ = lease.closeSSHChannelBounded(sshCh)
		go lease.discardChannelRequests(reqs)
		go drainSSHChannelStderr(sshCh)
		return
	}
	stopClose()

	reverseDone := make(chan struct{})
	closedCh := make(chan struct{})
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			close(closedCh)
			_ = agentConn.Close()
			_ = lease.closeSSHChannelBounded(sshCh)
			lease.removeActive(entry)
			r.releaseChannelSlot()
		})
	}

	go func() {
		lease.discardChannelRequests(reqs)
		closeBoth()
	}()
	go drainSSHChannelStderr(sshCh)

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
		_ = lease.closeSSHChannelWriteBounded(sshCh)
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
		JumpHost:     NormalizeProxyJump(connCfg.ProxyJump),
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
	lease, err := router.acquireLocalLeaseWithControl(
		ctx,
		sock,
		c.environment.DialAgent,
		c.getLogger(),
		agentForwardTransportControl{interrupt: c.Interrupt},
	)
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
func (c *Client) shouldRequestMuxProxyAgentForward() (verdict.Verdict, error) {
	if c == nil || c.sshClient == nil {
		return verdict.Deny, nil
	}
	connCfg := c.ConnectionConfig()
	if connCfg.Options == nil {
		return verdict.Deny, nil
	}
	_, enabled, err := resolveForwardAgentSpec(
		connCfg.Options.ForwardAgent(),
		connCfg.Options.IdentityAgent(),
		c.environment,
		c.clientForwardAgentTarget(connCfg),
		true,
	)
	if err != nil {
		return verdict.Deny, err
	}
	if !enabled {
		return verdict.Deny, nil
	}
	return verdict.Allow, nil
}

func (c *Client) prepareChannelAgentForward(ctx context.Context) (wantAgent bool, release func()) {
	if c == nil || c.sshClient == nil {
		return false, func() {}
	}
	if c.isMultiplexedProxy() {
		v, err := c.shouldRequestMuxProxyAgentForward()
		if err != nil {
			c.getLogger().Debugf("ForwardAgent disabled over mux proxy: %v", err)
			return false, func() {}
		}
		return v.Allowed(), func() {}
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

func (c *Client) enableSessionAgentForward(ctx context.Context, session *cryptoSSH.Session) (func(), error) {
	if ctx == nil {
		return func() {}, fmt.Errorf("SSH %s request context is nil", agentForwardRequestType)
	}
	if err := ctx.Err(); err != nil {
		return func() {}, fmt.Errorf("SSH %s request canceled: %w", agentForwardRequestType, err)
	}
	wantAgent, release := c.prepareChannelAgentForward(ctx)
	if !wantAgent {
		if err := ctx.Err(); err != nil {
			return func() {}, fmt.Errorf("SSH %s request canceled: %w", agentForwardRequestType, err)
		}
		return func() {}, nil
	}
	if err := ctx.Err(); err != nil {
		release()
		return func() {}, fmt.Errorf("SSH %s request canceled: %w", agentForwardRequestType, err)
	}
	c.observeSession(logger.SessionRequest, 2, agentForwardRequestType, "sending")
	work, cancel := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancel()
	var accepted bool
	done := make(chan error, 1)
	go func() {
		var reqErr error
		accepted, reqErr = session.SendRequest(agentForwardRequestType, true, nil)
		done <- reqErr
	}()
	select {
	case err := <-done:
		if err != nil {
			c.observeSession(logger.SessionRequest, 2, agentForwardRequestType, "failed or interrupted")
			release()
			return func() {}, fmt.Errorf("SSH %s request failed: %w", agentForwardRequestType, err)
		}
		if !accepted {
			c.observeSession(logger.SessionRequest, 2, agentForwardRequestType, "rejected")
			release()
			c.getLogger().Debugf("SSH server rejected %s; continuing without agent forwarding", agentForwardRequestType)
			return func() {}, nil
		}
		c.observeSession(logger.SessionRequest, 2, agentForwardRequestType, "accepted")
		return release, nil
	case <-work.Done():
		cancelErr := c.closeCanceledSession(work, session, done)
		c.observeSession(logger.SessionRequest, 2, agentForwardRequestType, "failed or interrupted")
		release()
		return func() {}, fmt.Errorf("SSH %s request interrupted: %w", agentForwardRequestType, cancelErr)
	}
}
