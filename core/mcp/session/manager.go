// Package session manages persistent SSH PTY shell sessions for the MCP
// terminal tool.
//
// Ownership: the Manager owns every managedSession it stores and the PTY
// channel inside it. A session is closed when it is replaced (generation
// change), idles past its TTL, its reader observes EOF, or the Manager shuts
// down. The idle reaper goroutine is started lazily with the first session and
// joined by Shutdown.
package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
)

const (
	DefaultTimeout          = 5 * time.Second
	DefaultIdleTTL          = 30 * time.Minute
	DefaultMaxSessions      = 16
	DefaultMaxTotalSessions = 64
	maxSessionLifetime      = 12 * time.Hour
	maxBufferBytes          = 256 * 1024
	signalSettleWindow      = 100 * time.Millisecond
	eofSettleWindow         = time.Second
	minReaperInterval       = 10 * time.Millisecond

	sentinelHead = "___MCP_"
	sentinelTail = "DONE_"
	sentinelMark = sentinelHead + sentinelTail
	sentinelEnd  = "___"
)

var (
	// ErrSessionBusy is returned when a new command is submitted while the
	// previous command has not yet reported completion.
	ErrSessionBusy = errors.New("terminal session is still running a previous command; poll with an empty cmd or send SIGINT/EOF/SIGTERM/SIGKILL first")
	// ErrSessionInUse is returned when another Execute call is actively waiting
	// on the session; callers should wait for that call to return or send a
	// control signal (SIGINT/EOF/SIGTERM/SIGKILL) to interrupt it.
	ErrSessionInUse = errors.New("another call is currently waiting on this terminal session; wait for it to return or send SIGINT/EOF/SIGTERM/SIGKILL to interrupt")
	// ErrSessionNotFound is returned when a poll or signal targets a session
	// that has not been created or has already closed/expired.
	ErrSessionNotFound = errors.New("terminal session does not exist or has expired")
	// ErrTooManySessions is returned when the live session limit is reached.
	ErrTooManySessions = errors.New("too many persistent terminal sessions")
	// ErrManagerClosed is returned after Shutdown.
	ErrManagerClosed = errors.New("session manager is shut down")

	staleSentinelPattern = regexp.MustCompile(`\n?` + sentinelMark + `[0-9a-f]+_[0-9]+` + sentinelEnd + `\n?`)
	ansiEscapePattern    = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])`)
)

// State describes what is known about the command after an Execute call.
type State int

const (
	// StateIdle means no command was in flight (plain poll or signal).
	StateIdle State = iota
	// StateCompleted means the completion sentinel was observed; ExitCode is set.
	StateCompleted
	// StateRunning means the wait window elapsed before completion.
	StateRunning
	// StateLost means the session ended before the completion sentinel was
	// observed; the command outcome is unknown.
	StateLost
)

// Key uniquely identifies a persistent terminal session within an isolation scope.
type Key struct {
	Scope       string
	NodeID      string
	SessionName string
}

// ExecuteRequest describes a command, signal, or poll operation on a persistent session.
type ExecuteRequest struct {
	Key Key
	// Generation identifies the admitted target configuration. A session
	// created under a different generation is closed and replaced so that
	// configuration or credential changes are never bypassed by reuse.
	// Generation is compared by equality only; callers must ensure that no
	// requests carrying a stale generation are admitted after a configuration
	// update (enforced by the state.Coordinator update barrier).
	Generation string
	Dial       func(ctx context.Context) (ports.PTYSession, error)
	Command    string
	Cwd        string
	Timeout    time.Duration
}

// ExecuteResult contains incremental terminal output and completion state.
type ExecuteResult struct {
	Output     string
	ExitCode   *uint32
	State      State
	Truncated  bool
	NewSession bool
}

// Manager maintains active PTY sessions indexed by Key.
type Manager struct {
	idleTTL          time.Duration
	maxSessions      int
	maxTotalSessions int
	now              func() time.Time

	mu         sync.Mutex
	closed     bool
	sessions   map[Key]*managedSession
	pending    map[string]int
	inflight   map[Key]*dialCall
	reaperStop chan struct{}
	reaperDone chan struct{}
}

type dialCall struct {
	generation     string
	done           chan struct{}
	waiters        int
	sess           *managedSession
	err            error
	leaderCanceled bool
}

type managedSession struct {
	pty        ports.PTYSession
	generation string
	createdAt  time.Time
	execMu     sync.Mutex
	inputMu    sync.Mutex
	notifyCh   chan struct{}
	readerDone chan struct{}
	lastActive atomic.Int64
	claimedNew atomic.Bool

	bufMu          sync.Mutex
	buf            []byte
	truncated      bool
	activeSentinel string

	closeOnce sync.Once
	closeErr  error
}

// NewManager creates a persistent PTY session manager with the given idle TTL.
func NewManager(idleTTL time.Duration) *Manager {
	if idleTTL <= 0 {
		idleTTL = DefaultIdleTTL
	}
	return &Manager{
		idleTTL:          idleTTL,
		maxSessions:      DefaultMaxSessions,
		maxTotalSessions: DefaultMaxTotalSessions,
		now:              time.Now,
		sessions:         make(map[Key]*managedSession),
		pending:          make(map[string]int),
		inflight:         make(map[Key]*dialCall),
	}
}

func isSignalCommand(upper string) bool {
	return upper == "SIGINT" || upper == "EOF" || upper == "SIGTERM" || upper == "SIGKILL"
}

func signalWritesStdin(upper string) bool {
	return upper == "SIGINT" || upper == "EOF"
}

// Execute runs a command, sends a control signal, or polls incremental output
// on the named session.
func (m *Manager) Execute(ctx context.Context, req ExecuteRequest) (ExecuteResult, error) {
	if ctx == nil {
		return ExecuteResult{}, errors.New("session context is required")
	}
	if err := ctx.Err(); err != nil {
		return ExecuteResult{}, err
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	trimmedCmd := strings.TrimSpace(req.Command)
	upper := strings.ToUpper(trimmedCmd)
	if isSignalCommand(upper) || (trimmedCmd == "" && req.Cwd == "") {
		return m.executeExisting(ctx, req, upper, timeout)
	}

	sess, created, err := m.acquire(ctx, req)
	if err != nil {
		return ExecuteResult{}, err
	}
	defer sess.execMu.Unlock()

	if sess.busy() {
		return ExecuteResult{}, ErrSessionBusy
	}
	sentinelPrefix, payload, err := buildSentinelPayload(req.Cwd, req.Command, trimmedCmd)
	if err != nil {
		return ExecuteResult{}, err
	}
	// Serialize sentinel activation and command payload write under inputMu so
	// an in-flight signal is ordered strictly after the complete payload write
	// and never writes to the underlying SSH channel concurrently.
	sess.inputMu.Lock()
	sess.setSentinel(sentinelPrefix)
	_, writeErr := io.WriteString(sess.pty, payload)
	if writeErr != nil {
		sess.setSentinel("")
	}
	sess.inputMu.Unlock()
	if writeErr != nil {
		m.remove(req.Key, sess)
		_ = sess.close()
		return ExecuteResult{}, fmt.Errorf("write to PTY session %q: %w", req.Key.SessionName, writeErr)
	}
	res, err := sess.waitSentinelOrTimeout(ctx, sentinelPrefix, timeout)
	res.NewSession = created
	if res.State == StateLost {
		m.remove(req.Key, sess)
	}
	return res, err
}

func (m *Manager) executeExisting(ctx context.Context, req ExecuteRequest, upper string, timeout time.Duration) (ExecuteResult, error) {
	sess, err := m.lookupExisting(req.Key, req.Generation)
	if err != nil {
		return ExecuteResult{}, err
	}
	if !sess.execMu.TryLock() {
		if isSignalCommand(upper) {
			return m.signalInFlight(sess, req.Key, upper)
		}
		return ExecuteResult{}, ErrSessionInUse
	}
	defer sess.execMu.Unlock()
	if sess.isClosed() {
		m.remove(req.Key, sess)
		return ExecuteResult{}, fmt.Errorf("%w: %q", ErrSessionNotFound, req.Key.SessionName)
	}
	sess.touch(m.now())

	var res ExecuteResult
	if isSignalCommand(upper) {
		res, err = sess.sendSignal(ctx, req.Key.SessionName, upper)
	} else {
		res, err = sess.pollOutput(ctx, timeout)
	}
	if res.State == StateLost {
		m.remove(req.Key, sess)
	}
	return res, err
}

// signalInFlight delivers a control signal when another Execute call is
// currently holding sess.execMu for a busy command (sess.busy() == true). The
// waiting call owns the output buffer and will observe the resulting completion
// sentinel or session closure.
func (m *Manager) signalInFlight(sess *managedSession, key Key, upper string) (ExecuteResult, error) {
	needsInputLock := signalWritesStdin(upper)
	if needsInputLock {
		sess.inputMu.Lock()
	}
	if !sess.busy() {
		if needsInputLock {
			sess.inputMu.Unlock()
		}
		return ExecuteResult{}, ErrSessionInUse
	}
	if sess.isClosed() {
		if needsInputLock {
			sess.inputMu.Unlock()
		}
		m.remove(key, sess)
		return ExecuteResult{}, fmt.Errorf("%w: %q", ErrSessionNotFound, key.SessionName)
	}
	sess.touch(m.now())
	sigErr := sess.pty.Signal(upper)
	if needsInputLock {
		sess.inputMu.Unlock()
	}
	if sigErr != nil && upper != "SIGKILL" {
		return ExecuteResult{}, fmt.Errorf("send %s to session %q: %w", upper, key.SessionName, sigErr)
	}
	if upper == "SIGKILL" {
		m.remove(key, sess)
		_ = sess.close()
		return ExecuteResult{Output: "[Status: Session terminated by SIGKILL]", State: StateLost}, nil
	}
	return ExecuteResult{
		Output: fmt.Sprintf("[Status: Signal %s sent; another call is waiting for command output]", upper),
		State:  StateRunning,
	}, nil
}

func (m *Manager) lookupExisting(key Key, generation string) (*managedSession, error) {
	var evictReason string
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, ErrManagerClosed
		}
		reuse, stale, reason := m.takeReusableLocked(key, generation, m.now())
		m.mu.Unlock()
		if stale != nil {
			evictReason = reason
			_ = stale.close()
			continue
		}
		if reuse == nil {
			if evictReason != "" {
				return nil, fmt.Errorf("%w: %q (%s)", ErrSessionNotFound, key.SessionName, evictReason)
			}
			return nil, fmt.Errorf("%w: %q", ErrSessionNotFound, key.SessionName)
		}
		return reuse, nil
	}
}

// acquire returns a live session for req with its execMu held.
func (m *Manager) acquire(ctx context.Context, req ExecuteRequest) (*managedSession, bool, error) {
	for range 2 {
		sess, err := m.getOrCreate(ctx, req)
		if err != nil {
			return nil, false, err
		}
		if !sess.execMu.TryLock() {
			return nil, false, ErrSessionInUse
		}
		if !sess.isClosed() {
			sess.touch(m.now())
			return sess, sess.claimedNew.CompareAndSwap(false, true), nil
		}
		sess.execMu.Unlock()
		m.remove(req.Key, sess)
	}
	return nil, false, fmt.Errorf("PTY session %q closed during setup", req.Key.SessionName)
}

func (m *Manager) checkCapacityLocked(scope string) error {
	if m.closed {
		return ErrManagerClosed
	}
	totalPending := 0
	for _, n := range m.pending {
		totalPending += n
	}
	if len(m.sessions)+totalPending >= m.maxTotalSessions {
		return fmt.Errorf("%w (total limit %d); idle sessions expire after %s", ErrTooManySessions, m.maxTotalSessions, m.idleTTL)
	}
	scopeCount := m.pending[scope]
	for k := range m.sessions {
		if k.Scope == scope {
			scopeCount++
		}
	}
	if scopeCount >= m.maxSessions {
		return fmt.Errorf("%w (scope limit %d); idle sessions expire after %s", ErrTooManySessions, m.maxSessions, m.idleTTL)
	}
	return nil
}

func (m *Manager) findOrReserveSlot(ctx context.Context, req ExecuteRequest) (*managedSession, *dialCall, error) {
	swept := false
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, nil, ErrManagerClosed
		}
		reuse, stale, _ := m.takeReusableLocked(req.Key, req.Generation, m.now())
		if stale != nil {
			m.mu.Unlock()
			_ = stale.close()
			continue
		}
		if reuse != nil {
			m.mu.Unlock()
			return reuse, nil, nil
		}
		if call := m.inflight[req.Key]; call != nil && call.generation == req.Generation {
			call.waiters++
			m.mu.Unlock()
			select {
			case <-call.done:
				if call.err != nil {
					if call.leaderCanceled {
						if err := ctx.Err(); err != nil {
							return nil, nil, err
						}
						continue
					}
					return nil, nil, call.err
				}
				if call.sess != nil && !call.sess.isClosed() {
					return call.sess, nil, nil
				}
				continue
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		err := m.checkCapacityLocked(req.Key.Scope)
		if err == nil {
			call := &dialCall{generation: req.Generation, done: make(chan struct{})}
			m.pending[req.Key.Scope]++
			m.inflight[req.Key] = call
			m.mu.Unlock()
			return nil, call, nil
		}
		m.mu.Unlock()
		if swept {
			return nil, nil, err
		}
		swept = true
		m.SweepIdle(m.now())
	}
}

func (m *Manager) releaseSlotLocked(scope string) {
	if n := m.pending[scope]; n <= 1 {
		delete(m.pending, scope)
	} else {
		m.pending[scope] = n - 1
	}
}

func (m *Manager) finishReservedDialLocked(key Key, call *dialCall, sess *managedSession, err error, leaderCanceled bool) {
	m.releaseSlotLocked(key.Scope)
	if m.inflight[key] == call {
		delete(m.inflight, key)
	}
	call.sess, call.err, call.leaderCanceled = sess, err, leaderCanceled
	close(call.done)
}

func (m *Manager) getOrCreate(ctx context.Context, req ExecuteRequest) (sess *managedSession, retErr error) {
	existing, call, err := m.findOrReserveSlot(ctx, req)
	if err != nil || existing != nil {
		return existing, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			m.mu.Lock()
			m.finishReservedDialLocked(req.Key, call, nil, retErr, ctx.Err() != nil)
			m.mu.Unlock()
		}
	}()

	if req.Dial == nil {
		return nil, errors.New("PTY dialer is required to open a persistent session")
	}
	pty, err := req.Dial(ctx)
	if err != nil {
		return nil, err
	}
	now := m.now()
	newSess := &managedSession{
		pty:        pty,
		generation: req.Generation,
		createdAt:  now,
		notifyCh:   make(chan struct{}, 1),
		readerDone: make(chan struct{}),
	}
	newSess.touch(now)
	go newSess.readLoop()

	initCmd := "stty -echo noflsh 2>/dev/null; PS1=''; export TERM=dumb NO_COLOR=1 DEBIAN_FRONTEND=noninteractive GIT_TERMINAL_PROMPT=0 CI=true\n"
	if _, err := io.WriteString(pty, initCmd); err != nil {
		_ = newSess.close()
		return nil, fmt.Errorf("initialize PTY session %q: %w", req.Key.SessionName, err)
	}

	handedOff = true
	return m.publishSession(req, call, newSess)
}

func (m *Manager) publishSession(req ExecuteRequest, call *dialCall, sess *managedSession) (*managedSession, error) {
	m.mu.Lock()
	if m.closed {
		m.finishReservedDialLocked(req.Key, call, nil, ErrManagerClosed, false)
		m.mu.Unlock()
		_ = sess.close()
		return nil, ErrManagerClosed
	}
	var stale *managedSession
	if raced, ok := m.sessions[req.Key]; ok {
		if raced.generation == req.Generation && !raced.isClosed() {
			m.finishReservedDialLocked(req.Key, call, raced, nil, false)
			m.mu.Unlock()
			_ = sess.close()
			return raced, nil
		}
		stale = raced
	}
	m.releaseSlotLocked(req.Key.Scope)
	if stale == nil {
		if err := m.checkCapacityLocked(req.Key.Scope); err != nil {
			if m.inflight[req.Key] == call {
				delete(m.inflight, req.Key)
			}
			call.err = err
			close(call.done)
			m.mu.Unlock()
			_ = sess.close()
			return nil, err
		}
	}
	m.sessions[req.Key] = sess
	m.startReaperLocked()
	if m.inflight[req.Key] == call {
		delete(m.inflight, req.Key)
	}
	call.sess = sess
	close(call.done)
	m.mu.Unlock()

	if stale != nil {
		_ = stale.close()
	}
	return sess, nil
}

// takeReusableLocked inspects key while m.mu is held. If a stored session is
// closed, belongs to a different generation, or has expired, it is removed
// from m.sessions and returned as stale (with a human-readable reason) so the
// caller can close it outside m.mu.
func (m *Manager) takeReusableLocked(key Key, generation string, now time.Time) (reuse, stale *managedSession, reason string) {
	existing, ok := m.sessions[key]
	if !ok {
		return nil, nil, ""
	}
	switch {
	case existing.isClosed():
		delete(m.sessions, key)
		return nil, existing, "closed"
	case existing.generation != generation:
		delete(m.sessions, key)
		return nil, existing, "reconfigured: node configuration or credentials changed"
	case existing.isExpired(now, m.idleTTL):
		delete(m.sessions, key)
		return nil, existing, "expired"
	default:
		return existing, nil, ""
	}
}

func (m *Manager) remove(key Key, target *managedSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.sessions[key]; ok && cur == target {
		delete(m.sessions, key)
	}
}

// SweepIdle closes and removes any sessions that have had no client activity
// longer than idleTTL (2*idleTTL while a command is still running) or have
// exceeded maxSessionLifetime.
func (m *Manager) SweepIdle(now time.Time) {
	m.mu.Lock()
	var expired []*managedSession
	for k, sess := range m.sessions {
		if sess.isExpired(now, m.idleTTL) {
			delete(m.sessions, k)
			expired = append(expired, sess)
		}
	}
	m.mu.Unlock()

	for _, sess := range expired {
		_ = sess.close()
	}
}

func (m *Manager) startReaperLocked() {
	if m.reaperStop != nil {
		return
	}
	m.reaperStop = make(chan struct{})
	m.reaperDone = make(chan struct{})
	interval := max(min(m.idleTTL/2, time.Minute), minReaperInterval)
	go func(stop <-chan struct{}, done chan<- struct{}) {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				m.SweepIdle(m.now())
			}
		}
	}(m.reaperStop, m.reaperDone)
}

// Shutdown closes all active PTY sessions and joins the idle reaper.
func (m *Manager) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return errors.New("session manager shutdown context is required")
	}
	m.mu.Lock()
	m.closed = true
	toClose := make([]*managedSession, 0, len(m.sessions))
	for k, sess := range m.sessions {
		delete(m.sessions, k)
		toClose = append(toClose, sess)
	}
	stop, reaperDone := m.reaperStop, m.reaperDone
	m.reaperStop = nil
	m.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		if stop != nil {
			close(stop)
			<-reaperDone
		}
		var errs []error
		for _, sess := range toClose {
			errs = append(errs, sess.close())
		}
		done <- errors.Join(errs...)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *managedSession) touch(now time.Time) {
	s.lastActive.Store(now.UnixNano())
}

func (s *managedSession) isExpired(now time.Time, idleTTL time.Duration) bool {
	last := time.Unix(0, s.lastActive.Load())
	ttl := idleTTL
	if s.busy() {
		ttl *= 2
	}
	lifetimeExceeded := !s.createdAt.IsZero() && now.Sub(s.createdAt) >= maxSessionLifetime
	return s.isClosed() || now.Sub(last) >= ttl || lifetimeExceeded
}

func (s *managedSession) isClosed() bool {
	select {
	case <-s.readerDone:
		return true
	default:
		return false
	}
}

func (s *managedSession) busy() bool {
	return s.currentSentinel() != ""
}

func (s *managedSession) currentSentinel() string {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	return s.activeSentinel
}

func (s *managedSession) setSentinel(prefix string) {
	s.bufMu.Lock()
	s.activeSentinel = prefix
	s.bufMu.Unlock()
}

func (s *managedSession) readLoop() {
	defer close(s.readerDone)
	tmp := make([]byte, 4096)
	for {
		n, err := s.pty.Read(tmp)
		if n > 0 {
			s.bufMu.Lock()
			s.buf = append(s.buf, tmp[:n]...)
			if len(s.buf) > maxBufferBytes {
				s.buf = append([]byte(nil), s.buf[len(s.buf)-maxBufferBytes:]...)
				s.truncated = true
			}
			s.bufMu.Unlock()
			select {
			case s.notifyCh <- struct{}{}:
			default:
			}
		}
		if err != nil {
			return
		}
	}
}

// sendSignal delivers a control signal to the PTY. When a command is in flight,
// activeSentinel is cleared only if the completion sentinel is actually
// observed during the settle window (or if SIGKILL forcibly terminates the
// session), so an ignored signal cannot be used to bypass ErrSessionBusy.
func (s *managedSession) sendSignal(ctx context.Context, sessionName, upperCmd string) (ExecuteResult, error) {
	needsInputLock := signalWritesStdin(upperCmd)
	if needsInputLock {
		s.inputMu.Lock()
	}
	sigErr := s.pty.Signal(upperCmd)
	if needsInputLock {
		s.inputMu.Unlock()
	}
	if sigErr != nil && upperCmd != "SIGKILL" {
		return ExecuteResult{}, fmt.Errorf("send %s to session %q: %w", upperCmd, sessionName, sigErr)
	}
	sentinel := s.currentSentinel()
	if sentinel == "" || upperCmd == "SIGKILL" {
		return s.settleIdleSignal(ctx, upperCmd), nil
	}

	res, err := s.waitSentinel(ctx, sentinel, signalSettleWindow)
	if err != nil {
		return ExecuteResult{}, err
	}
	switch res.State {
	case StateCompleted:
		res.Output = appendStatusLine(res.Output, fmt.Sprintf("[Status: Signal %s sent]", upperCmd))
		return res, nil
	case StateRunning:
		res.Output = appendStatusLine(res.Output, fmt.Sprintf("[Status: Signal %s sent; command still running]", upperCmd))
		return res, nil
	default:
		res.Output = appendStatusLine(res.Output, "[Status: Session ended before the command reported completion]")
		return res, nil
	}
}

func (s *managedSession) settleIdleSignal(ctx context.Context, upperCmd string) ExecuteResult {
	if upperCmd == "SIGKILL" {
		_ = s.close()
		out, truncated := s.drain()
		out = appendStatusLine(out, "[Status: Session terminated by SIGKILL]")
		return ExecuteResult{Output: out, State: StateLost, Truncated: truncated}
	}
	if upperCmd == "EOF" {
		// An exiting shell typically prints "exit" or "logout" before closing
		// the PTY, so wait up to eofSettleWindow for readerDone.
		timer := time.NewTimer(eofSettleWindow)
		select {
		case <-s.readerDone:
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
	} else {
		timer := time.NewTimer(signalSettleWindow)
		select {
		case <-s.notifyCh:
		case <-s.readerDone:
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
	}

	out, truncated := s.drain()
	if s.isClosed() {
		out = appendStatusLine(out, fmt.Sprintf("[Status: Signal %s sent; session closed]", upperCmd))
		return ExecuteResult{Output: out, State: StateLost, Truncated: truncated}
	}
	out = appendStatusLine(out, fmt.Sprintf("[Status: Signal %s sent]", upperCmd))
	return ExecuteResult{Output: out, State: StateIdle, Truncated: truncated}
}

func appendStatusLine(out, status string) string {
	if out != "" && !strings.HasSuffix(out, "\n") {
		return out + "\n" + status
	}
	return out + status
}

func (s *managedSession) pollOutput(ctx context.Context, timeout time.Duration) (ExecuteResult, error) {
	if sentinel := s.currentSentinel(); sentinel != "" {
		return s.waitSentinelOrTimeout(ctx, sentinel, timeout)
	}
	out, truncated := s.drain()
	return ExecuteResult{Output: out, State: StateIdle, Truncated: truncated}, nil
}

func (s *managedSession) waitSentinelOrTimeout(ctx context.Context, sentinelPrefix string, timeout time.Duration) (ExecuteResult, error) {
	res, err := s.waitSentinel(ctx, sentinelPrefix, timeout)
	if err != nil {
		return ExecuteResult{}, err
	}
	switch res.State {
	case StateRunning:
		res.Output = appendStatusLine(res.Output, "[Status: Running in background]")
	case StateLost:
		res.Output = appendStatusLine(res.Output, "[Status: Session ended before the command reported completion]")
	}
	return res, nil
}

func (s *managedSession) waitSentinel(ctx context.Context, sentinelPrefix string, timeout time.Duration) (ExecuteResult, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		if res, ok := s.tryConsumeSentinel(sentinelPrefix); ok {
			return res, nil
		}
		select {
		case <-s.notifyCh:
		case <-s.readerDone:
			if res, ok := s.tryConsumeSentinel(sentinelPrefix); ok {
				return res, nil
			}
			out, truncated := s.drain()
			return ExecuteResult{Output: out, State: StateLost, Truncated: truncated}, nil
		case <-timer.C:
			out, truncated := s.drain()
			return ExecuteResult{Output: out, State: StateRunning, Truncated: truncated}, nil
		case <-ctx.Done():
			return ExecuteResult{}, ctx.Err()
		}
	}
}

// tryConsumeSentinel looks for "<prefix><digits>___" in the buffer. Partial or
// malformed candidates (for example an echoed command line) are skipped rather
// than being interpreted as completion.
func (s *managedSession) tryConsumeSentinel(sentinelPrefix string) (ExecuteResult, bool) {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()

	prefix := []byte(sentinelPrefix)
	for offset := 0; offset < len(s.buf); {
		rel := bytes.Index(s.buf[offset:], prefix)
		if rel < 0 {
			return ExecuteResult{}, false
		}
		idx := offset + rel
		codeStart := idx + len(prefix)
		code, codeLen, ok := parseExitCode(s.buf[codeStart:])
		if !ok {
			offset = codeStart
			continue
		}
		consumeEnd := codeStart + codeLen + len(sentinelEnd)
		for consumeEnd < len(s.buf) && (s.buf[consumeEnd] == '\r' || s.buf[consumeEnd] == '\n') {
			consumeEnd++
		}
		before := string(s.buf[:idx])
		s.buf = append([]byte(nil), s.buf[consumeEnd:]...)
		s.activeSentinel = ""
		truncated := s.truncated
		s.truncated = false
		return ExecuteResult{Output: cleanTerminalOutput(before), ExitCode: &code, State: StateCompleted, Truncated: truncated}, true
	}
	return ExecuteResult{}, false
}

// parseExitCode parses "<digits>___" at the start of b.
func parseExitCode(b []byte) (uint32, int, bool) {
	n := 0
	for n < len(b) && b[n] >= '0' && b[n] <= '9' {
		n++
	}
	if n == 0 || !bytes.HasPrefix(b[n:], []byte(sentinelEnd)) {
		return 0, 0, false
	}
	code, err := strconv.ParseUint(string(b[:n]), 10, 32)
	if err != nil {
		return 0, 0, false
	}
	return uint32(code), n, true
}

func (s *managedSession) drain() (string, bool) {
	s.bufMu.Lock()
	raw := string(s.buf)
	s.buf = nil
	truncated := s.truncated
	s.truncated = false
	s.bufMu.Unlock()
	return cleanTerminalOutput(raw), truncated
}

// cleanTerminalOutput normalizes line endings, strips ANSI control sequences
// and stale completion sentinels, and collapses carriage-return progress frames
// so only the final visible state of each line is retained.
func cleanTerminalOutput(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = ansiEscapePattern.ReplaceAllString(raw, "")
	raw = staleSentinelPattern.ReplaceAllString(raw, "\n")
	if strings.ContainsRune(raw, '\r') {
		lines := strings.Split(raw, "\n")
		for i, line := range lines {
			line = strings.TrimRight(line, "\r")
			if idx := strings.LastIndexByte(line, '\r'); idx >= 0 {
				line = line[idx+1:]
			}
			lines[i] = line
		}
		raw = strings.Join(lines, "\n")
	}
	return strings.Trim(raw, "\n")
}

func (s *managedSession) close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.pty.Close()
		<-s.readerDone
	})
	return s.closeErr
}

// buildSentinelPayload returns the expected sentinel prefix and the shell
// payload. The sentinel is assembled by printf from two separate arguments so
// the literal prefix never appears in the command text itself; an echoed
// command line therefore cannot be mistaken for completion.
func buildSentinelPayload(cwd, rawCmd, trimmedCmd string) (string, string, error) {
	token, err := randomToken()
	if err != nil {
		return "", "", err
	}
	var b strings.Builder
	if cwd != "" {
		if strings.ContainsAny(cwd, "\r\n\x00") {
			return "", "", errors.New("working directory contains illegal newline or null character")
		}
		fmt.Fprintf(&b, "cd -- '%s'\n", strings.ReplaceAll(cwd, "'", `'\''`))
	}
	if trimmedCmd != "" {
		b.WriteString(rawCmd)
		if !strings.HasSuffix(rawCmd, "\n") {
			b.WriteByte('\n')
		}
	}
	fmt.Fprintf(&b, "printf '\\n%%s%%s_%%d%s\\n' '%s' '%s%s' \"$?\"\n", sentinelEnd, sentinelHead, sentinelTail, token)
	return sentinelMark + token + "_", b.String(), nil
}

func randomToken() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
