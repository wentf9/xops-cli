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

func effectiveDrainTimeout(fns ...func() time.Duration) time.Duration {
	for _, fn := range fns {
		if fn == nil {
			continue
		}
		if d := fn(); d > 0 && d < agentForwardDrainTimeout {
			return d
		}
	}
	return agentForwardDrainTimeout
}

// agentForwardEpoch owns the connection-scoped auth-agent@openssh.com channels
// and pump WaitGroup shared by all concurrent agentForwardLeases bound to the
// same normalized socket on one sshAgentChannelRouter. Its ctx is derived from
// context.Background() and is canceled only when the final lease in the epoch
// releases, so short-lived sibling sessions never sever a surviving session's
// open agent channel.
type agentForwardEpoch struct {
	router *sshAgentChannelRouter
	ctx    context.Context
	cancel context.CancelFunc
	socket string

	mu        sync.Mutex
	dialAgent func(context.Context, string) (net.Conn, error)
	logger    logger.DebugLogger
	closed    bool
	active    map[*activeAgentChannel]struct{}
	pumps     sync.WaitGroup
}

type agentForwardLease struct {
	router             *sshAgentChannelRouter
	epoch              *agentForwardEpoch
	socket             string
	interruptTransport func() error
	closeTimeoutFn     func() time.Duration
	logger             logger.DebugLogger

	mu          sync.Mutex
	closed      bool
	pumps       sync.WaitGroup
	releaseOnce sync.Once
}

func (l *agentForwardLease) drainTimeout() time.Duration {
	if l == nil {
		return agentForwardDrainTimeout
	}
	var routerFn func() time.Duration
	if l.router != nil {
		routerFn = l.router.drainTimeout
	}
	return effectiveDrainTimeout(l.closeTimeoutFn, routerFn)
}

func (e *agentForwardEpoch) drainTimeout() time.Duration {
	if e != nil && e.router != nil {
		return e.router.drainTimeout()
	}
	return agentForwardDrainTimeout
}

func (e *agentForwardEpoch) hasInterruptTransport() bool {
	return e != nil && e.router != nil && e.router.hasInterruptTransport()
}

func (e *agentForwardEpoch) interruptTransportNow() error {
	if e == nil || e.router == nil {
		return nil
	}
	return e.router.interruptTransportNow()
}

func (e *agentForwardEpoch) updateConfig(dialAgent func(context.Context, string) (net.Conn, error), l logger.DebugLogger) {
	e.mu.Lock()
	if dialAgent != nil {
		e.dialAgent = dialAgent
	}
	if l != nil && l != logger.NopLogger {
		e.logger = l
	}
	e.mu.Unlock()
}

func (e *agentForwardEpoch) dialConfig() (func(context.Context, string) (net.Conn, error), logger.DebugLogger) {
	e.mu.Lock()
	dialFn := e.dialAgent
	l := e.logger
	e.mu.Unlock()
	if l == nil {
		l = logger.NopLogger
	}
	return dialFn, l
}

func (e *agentForwardEpoch) getLogger() logger.DebugLogger {
	if e == nil {
		return logger.NopLogger
	}
	e.mu.Lock()
	l := e.logger
	e.mu.Unlock()
	if l == nil {
		return logger.NopLogger
	}
	return l
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

func (e *agentForwardEpoch) closeSSHChannelBounded(ch cryptoSSH.Channel) error {
	if ch == nil {
		return nil
	}
	return runBoundedAgentTransportOp(
		e.drainTimeout(),
		e.hasInterruptTransport(),
		e.interruptTransportNow,
		"channel close",
		func() error { return closeSSHChannel(ch) },
	)
}

func (e *agentForwardEpoch) closeSSHChannelWriteBounded(ch cryptoSSH.Channel) error {
	if ch == nil {
		return nil
	}
	return runBoundedAgentTransportOp(
		e.drainTimeout(),
		e.hasInterruptTransport(),
		e.interruptTransportNow,
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

func (e *agentForwardEpoch) replyChannelRequestBounded(req *cryptoSSH.Request, ok bool, payload []byte) error {
	if req == nil || !req.WantReply {
		return nil
	}
	return runBoundedAgentTransportOp(
		e.drainTimeout(),
		e.hasInterruptTransport(),
		e.interruptTransportNow,
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

func (e *agentForwardEpoch) discardChannelRequests(reqs <-chan *cryptoSSH.Request) {
	if reqs == nil {
		return
	}
	for req := range reqs {
		if req != nil && req.WantReply {
			_ = e.replyChannelRequestBounded(req, false, nil)
		}
	}
}

func (e *agentForwardEpoch) rejectNewChannelBounded(newCh cryptoSSH.NewChannel, reason cryptoSSH.RejectionReason, msg string) error {
	if newCh == nil {
		return nil
	}
	return runBoundedAgentTransportOp(
		e.drainTimeout(),
		e.hasInterruptTransport(),
		e.interruptTransportNow,
		"channel reject",
		func() error { return newCh.Reject(reason, msg) },
	)
}

func (e *agentForwardEpoch) acceptNewChannelBounded(newCh cryptoSSH.NewChannel) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if newCh == nil {
		return nil, nil, errors.New("nil incoming agent channel")
	}
	result := make(chan openChannelResult, 1)
	go func() {
		ch, reqs, err := newCh.Accept()
		result <- openChannelResult{channel: ch, requests: reqs, err: err}
	}()
	timeout := e.drainTimeout()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-result:
		return res.channel, res.requests, res.err
	case <-timer.C:
		if !e.hasInterruptTransport() {
			return nil, nil, fmt.Errorf("agent forward channel accept exceeded %s", timeout)
		}
		interruptErr := e.interruptTransportNow()
		postTimer := time.NewTimer(timeout)
		defer postTimer.Stop()
		select {
		case res := <-result:
			if res.channel != nil {
				go e.discardChannelRequests(res.requests)
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

func startAgentChannelCloses(entries []*activeAgentChannel) <-chan struct{} {
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

	closeDone := make(chan struct{})
	if hasCloseWork {
		go func() {
			closeWG.Wait()
			close(closeDone)
		}()
	} else {
		close(closeDone)
	}
	return closeDone
}

func (e *agentForwardEpoch) shutdownEntriesWithDeadline(
	entries []*activeAgentChannel,
	deadline time.Time,
	ctrl agentForwardTransportControl,
	releaseLogger logger.DebugLogger,
) {
	if e == nil {
		return
	}
	if e.cancel != nil {
		e.cancel()
	}

	// Separate outbound channel-close completion (closeDone) from inbound
	// pump drain (e.pumps): in golang.org/x/crypto/ssh, (*channel).Close()
	// sends outbound SSH_MSG_CHANNEL_CLOSE promptly on a healthy transport
	// without EOF-ing sshCh.Read until the remote peer echoes
	// SSH_MSG_CHANNEL_CLOSE. Only an outbound closeDone timeout proves the
	// transport is write-wedged and justifies interruptTransportNow().
	closeDone := startAgentChannelCloses(entries)

	pumpsDone := make(chan struct{})
	go func() {
		e.pumps.Wait()
		close(pumpsDone)
	}()

	log := releaseLogger
	if log == nil {
		log = e.getLogger()
	}
	timeout := effectiveDrainTimeout(ctrl.closeTimeout, e.drainTimeout)
	hasInterrupt := ctrl.interrupt != nil || e.hasInterruptTransport()
	interruptFn := ctrl.interrupt
	if interruptFn == nil {
		interruptFn = e.interruptTransportNow
	}

	if !waitChanUntilDeadline(closeDone, deadline) {
		if log != nil {
			log.Debugf("ForwardAgent: timed out after %s waiting for outbound SSH channel close; interrupting transport", timeout)
		}
		if hasInterrupt && interruptFn != nil {
			_ = interruptFn()
			postDeadline := time.Now().Add(timeout)
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
	if !waitChanUntilDeadline(pumpsDone, deadline) && log != nil {
		log.Debugf("ForwardAgent: outbound channel close completed; returning without transport interrupt while remote agent channel remains open")
	}
}

func (l *agentForwardLease) drainStandalonePumps(deadline time.Time) {
	pumpsDone := make(chan struct{})
	go func() {
		l.pumps.Wait()
		close(pumpsDone)
	}()
	_ = waitChanUntilDeadline(pumpsDone, deadline)
}

func (l *agentForwardLease) releaseWithDeadline(deadline time.Time) {
	if l == nil {
		return
	}
	l.releaseOnce.Do(func() {
		if l.router == nil {
			l.mu.Lock()
			l.closed = true
			l.mu.Unlock()
			l.drainStandalonePumps(deadline)
			return
		}

		retiredEpoch, entries, ctrl := l.router.releaseLease(l)
		if retiredEpoch == nil {
			return
		}
		retiredEpoch.shutdownEntriesWithDeadline(entries, deadline, ctrl, l.logger)
	})
}

func (e *agentForwardEpoch) tryBeginPump() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	e.pumps.Add(1)
	return true
}

func (e *agentForwardEpoch) registerActive(entry *activeAgentChannel) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	if e.active == nil {
		e.active = make(map[*activeAgentChannel]struct{})
	}
	e.active[entry] = struct{}{}
	return true
}

func (e *agentForwardEpoch) removeActive(entry *activeAgentChannel) {
	e.mu.Lock()
	delete(e.active, entry)
	e.mu.Unlock()
}

func (e *agentForwardEpoch) isClosed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

func (e *agentForwardEpoch) closeAndTakeActive() []*activeAgentChannel {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	entries := make([]*activeAgentChannel, 0, len(e.active))
	for entry := range e.active {
		entries = append(entries, entry)
	}
	clear(e.active)
	return entries
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
	epoch              *agentForwardEpoch
	interruptTransport func() error
	closeTimeoutFn     func() time.Duration
	activeChannels     atomic.Int32
}

func (r *sshAgentChannelRouter) currentInterruptTransport() func() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.leases) - 1; i >= 0; i-- {
		if cand := r.leases[i]; cand != nil && cand.interruptTransport != nil {
			return cand.interruptTransport
		}
	}
	return r.interruptTransport
}

func (r *sshAgentChannelRouter) hasInterruptTransport() bool {
	return r.currentInterruptTransport() != nil
}

func (r *sshAgentChannelRouter) interruptTransportNow() error {
	fn := r.currentInterruptTransport()
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
	var leaseFn func() time.Duration
	for i := len(r.leases) - 1; i >= 0; i-- {
		if cand := r.leases[i]; cand != nil && cand.closeTimeoutFn != nil {
			leaseFn = cand.closeTimeoutFn
			break
		}
	}
	routerFn := r.closeTimeoutFn
	r.mu.Unlock()
	return effectiveDrainTimeout(leaseFn, routerFn)
}

func (r *sshAgentChannelRouter) transportControlLocked(fallback agentForwardTransportControl) agentForwardTransportControl {
	var ctrl agentForwardTransportControl
	for i := len(r.leases) - 1; i >= 0; i-- {
		cand := r.leases[i]
		if cand == nil {
			continue
		}
		if ctrl.interrupt == nil && cand.interruptTransport != nil {
			ctrl.interrupt = cand.interruptTransport
		}
		if ctrl.closeTimeout == nil && cand.closeTimeoutFn != nil {
			ctrl.closeTimeout = cand.closeTimeoutFn
		}
		if ctrl.interrupt != nil && ctrl.closeTimeout != nil {
			break
		}
	}
	if ctrl.interrupt == nil {
		ctrl.interrupt = fallback.interrupt
	}
	if ctrl.interrupt == nil {
		ctrl.interrupt = r.interruptTransport
	}
	if ctrl.closeTimeout == nil {
		ctrl.closeTimeout = fallback.closeTimeout
	}
	if ctrl.closeTimeout == nil {
		ctrl.closeTimeout = r.closeTimeoutFn
	}
	return ctrl
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
	if sshClient.Conn == nil {
		return nil, errors.New("ssh client connection is nil")
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

func (r *sshAgentChannelRouter) hasLeaseForEpochLocked(epoch *agentForwardEpoch) bool {
	if epoch == nil {
		return false
	}
	for _, cand := range r.leases {
		if cand != nil && cand.epoch == epoch {
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
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
	var epoch *agentForwardEpoch
	if r.epoch != nil && !r.epoch.isClosed() && r.epoch.socket == socket {
		epoch = r.epoch
		epoch.updateConfig(dialAgent, l)
	} else {
		epochCtx, epochCancel := context.WithCancel(context.Background())
		epoch = &agentForwardEpoch{
			router:    r,
			ctx:       epochCtx,
			cancel:    epochCancel,
			socket:    socket,
			dialAgent: dialAgent,
			logger:    l,
		}
		r.epoch = epoch
	}
	lease := &agentForwardLease{
		router:             r,
		epoch:              epoch,
		socket:             socket,
		interruptTransport: ctrl.interrupt,
		closeTimeoutFn:     ctrl.closeTimeout,
		logger:             l,
	}
	r.leases = append(r.leases, lease)
	return lease, nil
}

func (r *sshAgentChannelRouter) releaseLease(lease *agentForwardLease) (
	*agentForwardEpoch,
	[]*activeAgentChannel,
	agentForwardTransportControl,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if lease != nil {
		lease.mu.Lock()
		lease.closed = true
		lease.mu.Unlock()
	}

	r.leases = slices.DeleteFunc(r.leases, func(item *agentForwardLease) bool {
		return item == lease
	})

	if lease == nil || lease.epoch == nil {
		return nil, nil, agentForwardTransportControl{}
	}
	epoch := lease.epoch
	if r.epoch != epoch || r.hasLeaseForEpochLocked(epoch) {
		return nil, nil, agentForwardTransportControl{}
	}

	r.epoch = nil
	entries := epoch.closeAndTakeActive()
	ctrl := r.transportControlLocked(agentForwardTransportControl{
		interrupt:    lease.interruptTransport,
		closeTimeout: lease.closeTimeoutFn,
	})
	return epoch, entries, ctrl
}

func (r *sshAgentChannelRouter) beginActiveEpoch() *agentForwardEpoch {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.epoch == nil || !r.hasLeaseForEpochLocked(r.epoch) {
		return nil
	}
	if r.epoch.tryBeginPump() {
		return r.epoch
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
	defer func() {
		sshAgentRouters.Delete(r.sshClient)
		r.mu.Lock()
		epoch := r.epoch
		r.mu.Unlock()
		if epoch != nil && epoch.cancel != nil {
			epoch.cancel()
		}
	}()
	for newCh := range chans {
		epoch := r.beginActiveEpoch()
		if epoch == nil {
			_ = r.rejectNewChannelBounded(newCh, cryptoSSH.Prohibited, "agent forwarding is not enabled")
			continue
		}
		if !r.tryAcquireChannelSlot() {
			epoch.pumps.Done()
			_ = epoch.rejectNewChannelBounded(newCh, cryptoSSH.ResourceShortage, "too many concurrent agent forwarding channels")
			continue
		}
		go func(e *agentForwardEpoch, ch cryptoSSH.NewChannel) {
			defer e.pumps.Done()
			r.serveLocalAgentChannel(e, ch)
		}(epoch, newCh)
	}
}

func (r *sshAgentChannelRouter) serveLocalAgentChannel(epoch *agentForwardEpoch, newCh cryptoSSH.NewChannel) {
	if epoch == nil || epoch.isClosed() {
		r.releaseChannelSlot()
		if epoch != nil {
			_ = epoch.rejectNewChannelBounded(newCh, cryptoSSH.Prohibited, "agent forwarding session closed")
		} else {
			_ = r.rejectNewChannelBounded(newCh, cryptoSSH.Prohibited, "agent forwarding session closed")
		}
		return
	}
	dialTimeout := agentForwardDialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultSSHHandshakeTimeout
	}
	dialFn, log := epoch.dialConfig()
	dialCtx, dialCancel := context.WithTimeout(epoch.ctx, dialTimeout)
	agentConn, err := dialAgentConn(dialCtx, dialFn, epoch.socket)
	dialCancel()
	if err != nil {
		r.releaseChannelSlot()
		log.Debugf("ForwardAgent: dial local agent %q failed: %v", epoch.socket, err)
		_ = epoch.rejectNewChannelBounded(newCh, cryptoSSH.ConnectionFailed, "failed to connect to local ssh-agent")
		return
	}

	stopClose := context.AfterFunc(epoch.ctx, func() {
		_ = agentConn.Close()
	})

	sshCh, reqs, err := epoch.acceptNewChannelBounded(newCh)
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
	if !epoch.registerActive(entry) {
		stopClose()
		r.releaseChannelSlot()
		_ = agentConn.Close()
		_ = epoch.closeSSHChannelBounded(sshCh)
		go epoch.discardChannelRequests(reqs)
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
			_ = epoch.closeSSHChannelBounded(sshCh)
			epoch.removeActive(entry)
			r.releaseChannelSlot()
		})
	}

	go func() {
		epoch.discardChannelRequests(reqs)
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
		case <-epoch.ctx.Done():
		case <-timer.C:
		}
		_ = agentConn.Close()
	}()

	go func() {
		defer copyWG.Done()
		defer close(reverseDone)
		_, _ = io.Copy(sshCh, agentConn)
		_ = epoch.closeSSHChannelWriteBounded(sshCh)
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
