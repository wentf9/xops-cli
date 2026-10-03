package transfer

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Store persists complete task snapshots. Save errors may follow an applied
// write and must disable new mutations until storage is recovered.
type Store interface {
	Load(limit int) ([]Record, error)
	Save(Record) error
	Remove(id string) error
	Close() error
}

type Limits struct {
	MaxFileBytes  int64
	MaxActive     int
	MaxPerTarget  int
	MaxReady      int
	MaxRecords    int
	StartWindow   time.Duration
	Retention     time.Duration
	TotalTimeout  time.Duration
	CommitTimeout time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes: 10 << 30, MaxActive: 4, MaxPerTarget: 2, MaxReady: 256, MaxRecords: 4096,
		StartWindow: 5 * time.Minute, Retention: 24 * time.Hour,
		TotalTimeout: 2 * time.Hour, CommitTimeout: 30 * time.Second,
	}
}

func (l Limits) Validate() error {
	if l.MaxFileBytes <= 0 || l.MaxFileBytes > 1<<50 || l.MaxActive <= 0 || l.MaxActive > 1024 || l.MaxPerTarget <= 0 || l.MaxReady <= 0 || l.MaxRecords <= 0 || l.MaxRecords > 65536 {
		return errors.New("transfer resource limits must be positive")
	}
	if l.MaxPerTarget > l.MaxActive || l.MaxReady > l.MaxRecords {
		return errors.New("transfer target/ready limits exceed their total limits")
	}
	if l.StartWindow <= 0 || l.TotalTimeout <= 0 || l.CommitTimeout <= 0 || l.Retention <= l.StartWindow ||
		l.Retention-l.StartWindow <= l.TotalTimeout || l.Retention-l.StartWindow-l.TotalTimeout <= l.CommitTimeout {
		return errors.New("transfer retention must exceed positive start, transfer and commit limits")
	}
	return nil
}

// Status deliberately excludes authentication scope and credential digests.
type Status struct {
	ID              string    `json:"transferID"`
	OperationID     string    `json:"operationID"`
	Direction       Direction `json:"direction"`
	NodeID          string    `json:"nodeID"`
	RemotePath      string    `json:"remotePath"`
	State           State     `json:"state"`
	Size            int64     `json:"size"`
	Bytes           int64     `json:"bytes"`
	SHA256          string    `json:"sha256,omitempty"`
	Error           string    `json:"error,omitempty"`
	Warning         string    `json:"warning,omitempty"`
	CleanupPending  bool      `json:"cleanupPending"`
	TempOwned       bool      `json:"temporaryOwnershipConfirmed"`
	CancelRequested bool      `json:"cancelRequested"`
	Resolved        bool      `json:"resolved"`
	StartBefore     time.Time `json:"startBefore"`
	StatusExpiresAt time.Time `json:"statusExpiresAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

func statusOf(r Record) Status {
	return Status{ID: r.ID, OperationID: r.OperationID, Direction: r.Spec.Direction,
		NodeID: r.Spec.NodeID, RemotePath: r.Spec.RemotePath, State: r.State, Size: r.Spec.Size,
		Bytes: r.Bytes, SHA256: r.SHA256, Error: r.Error, Warning: r.Warning, CleanupPending: r.CleanupPending, TempOwned: r.TempOwned,
		CancelRequested: r.CancelRequested, Resolved: r.Resolved,
		StartBefore: r.StartBefore, StatusExpiresAt: r.StatusExpiresAt, UpdatedAt: r.UpdatedAt}
}

type Prepared struct {
	Status Status
	Token  string
}

type requestKey struct{ scope, id string }
type activeTask struct {
	ctx            context.Context
	requestCtx     context.Context
	deadline       time.Time
	commitReserved bool
	cancel         context.CancelFunc
	stopRequest    func() bool
}

type Manager struct {
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	store     Store
	limits    Limits
	now       func() time.Time
	records   map[string]Record
	requests  map[requestKey]string
	active    map[string]*activeTask
	closed    bool
	storeErr  error
	drained   chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// NewManager takes ownership of store even if recovery fails. Recovery never
// resumes a stream or commits a remote file; it only classifies durable intent.
func NewManager(ctx context.Context, store Store, limits Limits) (_ *Manager, retErr error) {
	if store == nil {
		return nil, errors.New("transfer store is required")
	}
	keepStore := false
	defer func() {
		if !keepStore {
			retErr = errors.Join(retErr, closeJournalResource(store, "store"))
		}
	}()
	if ctx == nil {
		return nil, errors.New("transfer context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("start transfer manager: %w", err)
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	records, err := store.Load(limits.MaxRecords)
	if err != nil {
		return nil, fmt.Errorf("load transfer metadata: %w", err)
	}
	m := &Manager{store: store, limits: limits, now: time.Now,
		records: make(map[string]Record), requests: make(map[requestKey]string), active: make(map[string]*activeTask), drained: make(chan struct{})}
	close(m.drained)
	if err := m.recoverRecords(records); err != nil {
		return nil, err
	}
	m.ctx, m.cancel = context.WithCancel(ctx)
	keepStore = true
	return m, nil
}

func (m *Manager) recoverRecords(records []Record) error {
	for _, record := range records {
		if err := record.validate(); err != nil {
			return fmt.Errorf("recover transfer: %w", err)
		}
		key := requestKey{record.Spec.Scope, record.Spec.RequestID}
		if _, ok := m.requests[key]; ok {
			return errors.New("duplicate transfer idempotency key in metadata")
		}
		if _, ok := m.records[record.ID]; ok {
			return errors.New("duplicate transfer identity in metadata")
		}
		previous := record.State
		switch record.State {
		case Ready:
			record.State, record.Error = Expired, "service restarted before transfer began"
		case Transferring, Verifying:
			record.State, record.Error = Failed, "service restarted before commit"
		case Committing:
			record.State, record.Error = Unknown, "service restarted with uncertain commit result"
		}
		if record.State != previous {
			record.UpdatedAt = m.now().UTC()
			if _, err := encodeRecord(record); errors.Is(err, ErrRecordTooLarge) {
				// Older writers could fill the journal with immutable authorization.
				// Keep the original disk evidence and classify it on every restart;
				// never resume an unstarted task or lose an unknown destination lock.
				record.Warning = boundedDiagnostic("recovery state is in memory; original journal retained because it has no update headroom")
			} else if err != nil {
				return fmt.Errorf("validate transfer recovery: %w", err)
			} else if err := m.store.Save(record); err != nil {
				return fmt.Errorf("persist transfer recovery: %w", err)
			}
		}
		m.records[record.ID], m.requests[key] = record, record.ID
	}
	return nil
}

func (m *Manager) mutationAllowed() error {
	if m.closed || m.ctx.Err() != nil {
		return ErrClosed
	}
	if m.storeErr != nil {
		return errors.Join(ErrStoreUnusable, m.storeErr)
	}
	return nil
}

func (m *Manager) save(record Record) error {
	if _, err := encodeRecord(record); err != nil {
		return err
	}
	if err := m.store.Save(record); err != nil {
		m.storeErr = fmt.Errorf("persist transfer state: %w", err)
		return errors.Join(ErrStoreUnusable, m.storeErr)
	}
	m.records[record.ID] = record.Clone()
	return nil
}

// Prepare returns the same task for an identical request. A still-ready task
// receives a new credential, revoking the previous one without extending TTL.
func (m *Manager) Prepare(spec Spec, operationID string) (Prepared, error) {
	return m.prepare(spec, operationID, nil)
}

func (m *Manager) prepare(spec Spec, operationID string, authorization *Authorization) (Prepared, error) {
	if err := spec.validate(); err != nil {
		return Prepared{}, err
	}
	if spec.Size > m.limits.MaxFileBytes {
		return Prepared{}, errors.New("file exceeds transfer size limit")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.mutationAllowed(); err != nil {
		return Prepared{}, err
	}
	if err := m.collect(); err != nil {
		return Prepared{}, err
	}
	key := requestKey{spec.Scope, spec.RequestID}
	if id, ok := m.requests[key]; ok {
		record := m.records[id]
		if record.Spec != spec || (record.Authorization == nil) != (authorization == nil) || (authorization != nil && record.Authorization.Binding != authorization.Binding) {
			return Prepared{}, ErrConflict
		}
		if record.State != Ready {
			return Prepared{Status: statusOf(record)}, nil
		}
		return m.issue(record)
	}
	if len(m.records) >= m.limits.MaxRecords || m.readyCount() >= m.limits.MaxReady {
		return Prepared{}, ErrBusy
	}
	if m.pathBlocked(spec) {
		return Prepared{}, ErrConflict
	}
	id, err := randomHex(16)
	if err != nil {
		return Prepared{}, err
	}
	now := m.now().UTC()
	version := legacyRecordVersion
	if authorization != nil {
		version = recordVersion
	}
	record := Record{Version: version, Authorization: authorization.clone(), ID: id, OperationID: operationID, Spec: spec, State: Ready,
		CreatedAt: now, UpdatedAt: now, StartBefore: now.Add(m.limits.StartWindow), StatusExpiresAt: now.Add(m.limits.Retention)}
	prepared, err := m.issue(record)
	if err != nil {
		return Prepared{}, err
	}
	m.requests[key] = id
	return prepared, nil
}

func (m *Manager) issue(record Record) (Prepared, error) {
	token, err := randomHex(32)
	if err != nil {
		return Prepared{}, err
	}
	digest := sha256.Sum256([]byte(token))
	record.TokenDigest = hex.EncodeToString(digest[:])
	record.UpdatedAt = m.now().UTC()
	if err := validatePreparationSize(record); err != nil {
		return Prepared{}, err
	}
	if err := m.save(record); err != nil {
		return Prepared{}, err
	}
	return Prepared{Status: statusOf(record), Token: token}, nil
}

func (m *Manager) readyCount() int {
	count := 0
	for _, record := range m.records {
		if record.State == Ready {
			count++
		}
	}
	return count
}

func (m *Manager) pathBlocked(spec Spec) bool {
	if spec.Direction != Upload {
		return false
	}
	for _, record := range m.records {
		if record.State == Unknown && !record.Resolved && record.Spec.TargetID == spec.TargetID && record.Spec.RemotePath == spec.RemotePath {
			return true
		}
	}
	return false
}

// collect is bounded by MaxRecords. It never discards unresolved commit or
// cleanup evidence, even when that forces the service to reject new tasks.
func (m *Manager) collect() error {
	now := m.now().UTC()
	for id, record := range m.records {
		if _, active := m.active[id]; active {
			continue
		}
		if record.State == Ready && !now.Before(record.StartBefore) {
			record.State, record.UpdatedAt = Expired, now
			if err := m.save(record); err != nil {
				return err
			}
		}
		if now.Before(record.StatusExpiresAt) || record.CleanupPending || (record.State == Unknown && !record.Resolved) {
			continue
		}
		if err := m.store.Remove(id); err != nil {
			m.storeErr = fmt.Errorf("remove expired transfer metadata: %w", err)
			return errors.Join(ErrStoreUnusable, m.storeErr)
		}
		delete(m.records, id)
		delete(m.requests, requestKey{record.Spec.Scope, record.Spec.RequestID})
	}
	return nil
}

// Authenticate deliberately returns the same error for an unknown task and a
// bad credential. Lookup for MCP management is separately scoped by service auth.
func (m *Manager) Authenticate(id, token string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.authenticate(id, token)
	if err != nil {
		return Status{}, err
	}
	return m.currentStatus(record), nil
}

func (m *Manager) authenticate(id, token string) (Record, error) {
	record, ok := m.records[id]
	digest := sha256.Sum256([]byte(token))
	want, err := hex.DecodeString(record.TokenDigest)
	if !ok || err != nil || subtle.ConstantTimeCompare(digest[:], want) != 1 || !m.now().Before(record.StatusExpiresAt) {
		return Record{}, ErrUnauthorized
	}
	return record, nil
}

func (m *Manager) Lookup(scope, id string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.records[id]
	if !ok || record.Spec.Scope != scope {
		return Status{}, ErrNotFound
	}
	return m.currentStatus(record), nil
}

func (m *Manager) currentStatus(record Record) Status {
	if record.State == Ready && !m.now().Before(record.StartBefore) {
		record.State = Expired
	}
	return statusOf(record)
}

// Records provides an immutable snapshot for local recovery and owned-file
// cleanup. It is not a client status response and contains credential digests.
func (m *Manager) Records() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	records := make([]Record, 0, len(m.records))
	for _, record := range m.records {
		records = append(records, record.Clone())
	}
	return records
}
