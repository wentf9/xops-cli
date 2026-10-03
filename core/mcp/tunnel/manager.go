// Package tunnel manages process-local SSH forwards independently of MCP calls.
package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	DefaultTTL      = time.Hour
	MaxTTL          = 24 * time.Hour
	MaxActive       = 16
	MaxRecords      = 1024
	ConnectionLimit = 64
	Retention       = 24 * time.Hour
)

var (
	errStopped          = errors.New("tunnel stopped")
	errExpired          = errors.New("tunnel expired")
	errStartupCancelled = errors.New("tunnel startup cancelled")
)

// Spec is an immutable, normalized request. A request ID is unique for the
// lifetime of its retained record, including after the tunnel has stopped.
type Spec struct {
	RequestID  string `json:"requestID"`
	NodeID     string `json:"nodeID"`
	Mode       string `json:"mode"`
	ListenHost string `json:"listenHost"`
	ListenPort int    `json:"listenPort"`
	TargetHost string `json:"targetHost"`
	TargetPort int    `json:"targetPort"`
	TTLSeconds int    `json:"ttlSeconds"`
}

func (s Spec) ListenAddress() string {
	return net.JoinHostPort(s.ListenHost, strconv.Itoa(s.ListenPort))
}
func (s Spec) TargetAddress() string {
	return net.JoinHostPort(s.TargetHost, strconv.Itoa(s.TargetPort))
}

// Normalize validates before authorization or any network activity. Listen
// hosts are literals so exposure classification cannot be changed by DNS.
func Normalize(s Spec) (Spec, error) {
	if err := validateNames(s); err != nil {
		return s, err
	}
	if err := validateTargetHost(s.TargetHost); err != nil {
		return s, err
	}
	return normalizeEndpoints(s)
}

func validateNames(s Spec) error {
	if s.RequestID == "" || len(s.RequestID) > 128 || strings.TrimSpace(s.RequestID) != s.RequestID || strings.IndexFunc(s.RequestID, unicode.IsControl) >= 0 {
		return errors.New("requestID must contain 1 to 128 non-control characters")
	}
	if s.NodeID == "" || len(s.NodeID) > 1024 || strings.IndexFunc(s.NodeID, unicode.IsControl) >= 0 {
		return errors.New("a bounded nodeID is required")
	}
	return nil
}

func normalizeEndpoints(s Spec) (Spec, error) {
	if s.Mode != "local" && s.Mode != "remote" {
		return s, errors.New("mode must be local (-L) or remote (-R)")
	}
	if s.ListenHost == "" || s.ListenHost == "localhost" {
		s.ListenHost = "127.0.0.1"
	}
	addr, err := netip.ParseAddr(s.ListenHost)
	if err != nil {
		return s, fmt.Errorf("listenHost must be an IP literal or localhost: %w", err)
	}
	s.ListenHost = addr.String()
	if s.ListenPort < 0 || s.ListenPort > 65535 || s.TargetPort < 1 || s.TargetPort > 65535 {
		return s, errors.New("listenPort must be 0 to 65535 and targetPort must be 1 to 65535")
	}
	if s.TTLSeconds == 0 {
		s.TTLSeconds = int(DefaultTTL / time.Second)
	}
	if s.TTLSeconds < 1 || s.TTLSeconds > int(MaxTTL/time.Second) {
		return s, errors.New("ttlSeconds must be 1 to 86400")
	}
	return s, nil
}

func validateTargetHost(host string) error {
	if host == "" || len(host) > 253 || strings.IndexFunc(host, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 || strings.ContainsAny(host, "/\\[]") {
		return errors.New("targetHost must be a host name or an unbracketed IP literal")
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("invalid targetHost: %w", err)
		}
	}
	return nil
}

// Status is a value snapshot; callers never receive mutable task internals.
type Status struct {
	Spec
	TunnelID            string    `json:"tunnelID"`
	OperationID         string    `json:"operationID"`
	State               string    `json:"state"`
	ListenAddress       string    `json:"listenAddress,omitempty"`
	ListenScope         string    `json:"listenScope"`
	TargetScope         string    `json:"targetScope"`
	CreatedAt           time.Time `json:"createdAt"`
	ExpiresAt           time.Time `json:"expiresAt,omitempty"`
	FinishedAt          time.Time `json:"finishedAt,omitempty"`
	Error               string    `json:"error,omitempty"`
	LastConnectionError string    `json:"lastConnectionError,omitempty"`
	AuditError          string    `json:"auditError,omitempty"`
	RemoteRelease       string    `json:"remoteRelease,omitempty"`
}

// Runner owns and joins all network resources before returning. It must obey
// ctx during both startup and serving. ready commits startup only when it
// returns true; report records recoverable connection-level failures.
type Runner func(ctx context.Context, spec Spec, ready func(string) bool, report func(error)) error
type Observer func(Status, string, error) error

type task struct {
	runner    Runner
	status    Status
	ctx       context.Context
	cancel    context.CancelCauseFunc
	ready     chan struct{}
	readyOnce sync.Once
	done      chan struct{}
	runErr    error
}

type Manager struct {
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	run            Runner
	observe        Observer
	tasks          map[string]*task
	requests       map[string]string
	closed         bool
	startupTimeout time.Duration
}

func New(ctx context.Context, run Runner, observe Observer) *Manager {
	ctx, cancel := context.WithCancel(ctx)
	return &Manager{ctx: ctx, cancel: cancel, run: run, observe: observe,
		tasks: make(map[string]*task), requests: make(map[string]string), startupTimeout: 30 * time.Second}
}

func (m *Manager) retryLocked(s Spec) (*task, error) {
	if id, ok := m.requests[s.RequestID]; ok {
		t := m.tasks[id]
		if t.status.Spec != s {
			return nil, errors.New("tunnel_request_conflict: requestID was used with different parameters")
		}
		return t, nil
	}
	return nil, nil
}

// Retry returns the existing state without repeating authorization or network
// side effects. A subsequent Create performs the same check atomically.
func (m *Manager) Retry(s Spec) (Status, bool, error) {
	var err error
	s, err = Normalize(s)
	if err != nil {
		return Status{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	t, err := m.retryLocked(s)
	if err != nil || t == nil {
		return Status{}, false, err
	}
	return t.status, true, nil
}

func (m *Manager) pruneLocked() {
	cutoff := time.Now().Add(-Retention)
	for id, t := range m.tasks {
		if !t.status.FinishedAt.IsZero() && t.status.FinishedAt.Before(cutoff) {
			delete(m.requests, t.status.RequestID)
			delete(m.tasks, id)
		}
	}
}

// Create waits only for startup. After ready commits, cancellation of the
// creating call cannot stop the tunnel. Lost responses can be recovered by ID.
func (m *Manager) Create(ctx context.Context, s Spec, operationID string) (Status, error) {
	return m.CreateWithRunner(ctx, s, operationID, nil)
}

// CreateWithRunner binds a process-local execution closure to the reserved
// task. Retries retain the original runner and never substitute a new target.
// The runner is retained only for the manager's bounded task retention period.
func (m *Manager) CreateWithRunner(ctx context.Context, s Spec, operationID string, runner Runner) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	var err error
	s, err = Normalize(s)
	if err != nil {
		return Status{}, err
	}
	m.mu.Lock()
	m.pruneLocked()
	t, err := m.reserveLocked(ctx, s, operationID, runner)
	m.mu.Unlock()
	if err != nil {
		return Status{}, err
	}
	if t == nil {
		return Status{}, errors.New("tunnel reservation unavailable")
	}
	select {
	case <-t.ready:
		return m.Status(t.status.TunnelID)
	case <-ctx.Done():
		return Status{}, fmt.Errorf("wait for tunnel startup: %w", ctx.Err())
	}
}

func (m *Manager) reserveLocked(requestCtx context.Context, s Spec, operationID string, runner Runner) (*task, error) {
	if m.closed || m.ctx.Err() != nil {
		return nil, errors.New("tunnel manager is closed")
	}
	if existing, err := m.retryLocked(s); existing != nil || err != nil {
		return existing, err
	}
	active := 0
	for _, t := range m.tasks {
		if t.status.FinishedAt.IsZero() {
			active++
		}
	}
	if active >= MaxActive || len(m.tasks) >= MaxRecords {
		return nil, errors.New("tunnel_capacity: active or retained tunnel limit reached")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("generate tunnel ID: %w", err)
	}
	id := hex.EncodeToString(random[:])
	ctx, cancel := context.WithCancelCause(m.ctx)
	scope, targetScope := "mcp_process", "ssh_node"
	if s.Mode == "remote" {
		scope, targetScope = "ssh_node", "mcp_process"
	}
	if runner == nil {
		runner = m.run
	}
	if runner == nil {
		cancel(errStopped)
		return nil, errors.New("tunnel runner is required")
	}
	t := &task{ctx: ctx, cancel: cancel, ready: make(chan struct{}), done: make(chan struct{}), runner: runner,
		status: Status{Spec: s, TunnelID: id, OperationID: operationID, State: "starting", ListenScope: scope, TargetScope: targetScope, CreatedAt: time.Now().UTC()}}
	m.tasks[id], m.requests[s.RequestID] = t, id
	// The worker is owned by the manager; cancellation and Shutdown join it.
	go m.serve(requestCtx, t)
	return t, nil
}

func (m *Manager) serve(requestCtx context.Context, t *task) {
	defer close(t.done)
	defer t.cancel(errStopped)
	if err := requestCtx.Err(); err != nil {
		m.abortStartup(t, errors.Join(errStartupCancelled, err))
	}
	requestDone := make(chan struct{})
	stopRequest := context.AfterFunc(requestCtx, func() {
		defer close(requestDone)
		m.abortStartup(t, errors.Join(errStartupCancelled, requestCtx.Err()))
	})
	var unlinkOnce sync.Once
	unlinkRequest := func() {
		unlinkOnce.Do(func() {
			if !stopRequest() {
				<-requestDone
			}
		})
	}
	defer unlinkRequest()
	startup := time.AfterFunc(m.startupTimeout, func() { m.abortStartup(t, context.DeadlineExceeded) })
	defer startup.Stop()
	var expiration *time.Timer
	defer func() {
		if expiration != nil {
			expiration.Stop()
		}
	}()
	err := m.record(t, "starting", nil)
	if err == nil {
		err = t.runner(t.ctx, t.status.Spec, func(address string) bool {
			m.mu.Lock()
			if t.ctx.Err() != nil || requestCtx.Err() != nil || t.status.State != "starting" {
				if requestCtx.Err() != nil {
					t.cancel(errors.Join(errStartupCancelled, requestCtx.Err()))
				}
				m.mu.Unlock()
				return false
			}
			t.status.State, t.status.ListenAddress = "running", address
			t.status.ExpiresAt = time.Now().UTC().Add(time.Duration(t.status.TTLSeconds) * time.Second)
			expiration = time.AfterFunc(time.Until(t.status.ExpiresAt), func() { t.cancel(errExpired) })
			startup.Stop()
			m.mu.Unlock()
			unlinkRequest()
			if auditErr := m.record(t, "running", nil); auditErr != nil {
				m.setAuditError(t, auditErr)
			}
			t.readyOnce.Do(func() { close(t.ready) })
			return true
		}, func(err error) {
			if err != nil {
				m.mu.Lock()
				t.status.LastConnectionError = err.Error()
				m.mu.Unlock()
			}
		})
	}
	m.finish(t, err)
	t.readyOnce.Do(func() { close(t.ready) })
}

func (m *Manager) abortStartup(t *task, cause error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.status.State == "starting" {
		t.cancel(cause)
	}
}

func (m *Manager) finish(t *task, err error) {
	m.mu.Lock()
	if t.ctx.Err() != nil {
		t.runErr = err
	}
	t.status.State = "stopped"
	cause := context.Cause(t.ctx)
	switch {
	case errors.Is(cause, context.DeadlineExceeded):
		t.status.State = "failed"
		err = errors.Join(errors.New("tunnel startup timed out"), err)
	case errors.Is(cause, errStartupCancelled):
		t.status.State = "failed"
		err = errors.Join(cause, err)
	case err != nil || cause == nil:
		t.status.State = "failed"
	case errors.Is(cause, errExpired):
		t.status.State = "expired"
	}
	if cause == nil && err == nil {
		err = errors.New("tunnel exited unexpectedly")
	}
	if err != nil {
		t.status.Error = err.Error()
	}
	t.status.FinishedAt = time.Now().UTC()
	if t.status.Mode == "remote" {
		t.status.RemoteRelease = "unconfirmed"
	}
	state := t.status.State
	m.mu.Unlock()
	if auditErr := m.record(t, state, err); auditErr != nil {
		m.setAuditError(t, auditErr)
	}
}

func (m *Manager) record(t *task, event string, cause error) error {
	if m.observe == nil {
		return nil
	}
	m.mu.RLock()
	status := t.status
	m.mu.RUnlock()
	return m.observe(status, event, cause)
}

func (m *Manager) setAuditError(t *task, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t.status.AuditError = err.Error()
}

func (m *Manager) Status(id string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	t := m.tasks[id]
	if t == nil {
		return Status{}, errors.New("tunnel_not_found")
	}
	return t.status, nil
}

func (m *Manager) List(nodeID, state string) []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	out := make([]Status, 0)
	for _, t := range m.tasks {
		if (nodeID == "" || nodeID == t.status.NodeID) && (state == "" || state == t.status.State) {
			out = append(out, t.status)
		}
	}
	slices.SortFunc(out, func(a, b Status) int { return strings.Compare(a.TunnelID, b.TunnelID) })
	return out
}

func (m *Manager) Stop(ctx context.Context, id string) (Status, error) {
	m.mu.Lock()
	t := m.tasks[id]
	if t == nil {
		m.mu.Unlock()
		return Status{}, errors.New("tunnel_not_found")
	}
	if t.status.FinishedAt.IsZero() {
		t.status.State = "stopping"
		t.cancel(errStopped)
	}
	m.mu.Unlock()
	select {
	case <-t.done:
		return m.Status(id)
	case <-ctx.Done():
		return Status{}, fmt.Errorf("wait for tunnel cleanup: %w", ctx.Err())
	}
}

// Shutdown cancels all tasks before joining any one, so a blackholed jump
// cannot keep another tunnel alive while its cleanup is awaited.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	m.cancel()
	tasks := make([]*task, 0, len(m.tasks))
	for _, t := range m.tasks {
		tasks = append(tasks, t)
	}
	m.mu.Unlock()
	var cleanupErrors []error
	for _, t := range tasks {
		select {
		case <-t.done:
			if t.ctx.Err() != nil && t.runErr != nil {
				cleanupErrors = append(cleanupErrors, t.runErr)
			}
		case <-ctx.Done():
			return fmt.Errorf("join tunnel workers: %w", ctx.Err())
		}
	}
	return errors.Join(cleanupErrors...)
}
