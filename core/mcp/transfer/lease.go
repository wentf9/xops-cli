package transfer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
)

// Lease owns a single data request. Call Close on every path, including error
// paths. No background worker is started: the HTTP handler performs the stream.
type Lease struct {
	manager *Manager
	id      string
	ctx     context.Context
	spec    Spec
}

func (l *Lease) Context() context.Context { return l.ctx }
func (l *Lease) Spec() Spec               { return l.spec }

func (m *Manager) Claim(ctx context.Context, id, token string, direction Direction) (*Lease, error) {
	return m.claim(ctx, id, token, direction, nil)
}

// ClaimBound takes the original client/request context separately from the
// stream permit. This distinction preserves task cancellation during commit
// admission while allowing an already granted commit to outlive stream revocation.
func (m *Manager) ClaimBound(ctx context.Context, id, token string, direction Direction, permit ports.Permit) (*Lease, error) {
	if ports.Nil(permit) {
		return nil, ErrBindingRequired
	}
	return m.claim(ctx, id, token, direction, permit)
}

func (m *Manager) claim(ctx context.Context, id, token string, direction Direction, permit ports.Permit) (*Lease, error) {
	if ctx == nil {
		return nil, errors.New("transfer request context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("start transfer: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.mutationAllowed(); err != nil {
		return nil, err
	}
	record, err := m.authenticate(id, token)
	if err != nil {
		return nil, err
	}
	if record.Authorization != nil || !ports.Nil(permit) {
		if err := record.CheckPermit(permit, ports.TransferStart); err != nil {
			return nil, err
		}
	}
	if record.Spec.Direction != direction {
		return nil, ErrUnauthorized
	}
	if record.State == Expired {
		return nil, ErrExpired
	}
	if record.State != Ready {
		return nil, ErrInvalidState
	}
	if !m.now().Before(record.StartBefore) {
		record.State, record.UpdatedAt = Expired, m.now().UTC()
		return nil, errors.Join(ErrExpired, m.save(record))
	}
	if m.pathBlocked(record.Spec) {
		return nil, ErrConflict
	}
	if !m.hasCapacity(record.Spec) {
		return nil, ErrBusy
	}
	record.State, record.UpdatedAt = Transferring, m.now().UTC()
	if err := m.save(record); err != nil {
		return nil, err
	}
	if len(m.active) == 0 {
		m.drained = make(chan struct{})
	}
	active := m.newActiveTask(ctx, permit)
	m.active[id] = active
	return &Lease{manager: m, id: id, ctx: active.ctx, spec: record.Spec}, nil
}

func (m *Manager) newActiveTask(ctx context.Context, permit ports.Permit) *activeTask {
	taskCtx, cancel := context.WithTimeout(m.ctx, m.limits.TotalTimeout)
	stopCaller := context.AfterFunc(ctx, cancel)
	stopPermit := func() bool { return true }
	deadline, _ := taskCtx.Deadline()
	if !ports.Nil(permit) {
		stopPermit = context.AfterFunc(permit.Context(), cancel)
		if limit, ok := permit.Context().Deadline(); ok && limit.Before(deadline) {
			deadline = limit
		}
		if permit.Context().Err() != nil {
			cancel()
		}
	}
	if ctx.Err() != nil {
		cancel()
	}
	stopRequest := func() bool { caller, permission := stopCaller(), stopPermit(); return caller && permission }
	return &activeTask{ctx: taskCtx, requestCtx: ctx, deadline: deadline, cancel: cancel, stopRequest: stopRequest}
}

func (m *Manager) hasCapacity(spec Spec) bool {
	if len(m.active) >= m.limits.MaxActive {
		return false
	}
	onTarget := 0
	for id := range m.active {
		other := m.records[id].Spec
		if other.TargetID != spec.TargetID {
			continue
		}
		onTarget++
		if other.Direction == Upload && spec.Direction == Upload && other.RemotePath == spec.RemotePath {
			return false
		}
	}
	return onTarget < m.limits.MaxPerTarget
}

// Progress updates observable bytes without writing the journal per chunk.
func (l *Lease) Progress(bytes int64) error {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[l.id]
	if _, ok := m.active[l.id]; !ok || r.State != Transferring {
		return ErrInvalidState
	}
	if bytes < 0 || bytes > r.Spec.Size-r.Bytes {
		return errors.New("transfer exceeds declared file length")
	}
	r.Bytes += bytes
	r.UpdatedAt = m.now().UTC()
	m.records[l.id] = r
	return nil
}

// Temporary records the exclusive-create intent before the remote file is
// opened. If exclusive creation fails, the caller must clear this intent and
// must not remove the conflicting remote file.
func (l *Lease) Temporary() (string, error) {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[l.id]
	if _, ok := m.active[l.id]; !ok || r.State != Transferring || r.Spec.Direction != Upload {
		return "", ErrInvalidState
	}
	r.TempPath = temporaryPath(r.Spec.RemotePath, r.ID)
	r.CleanupPending = true
	r.UpdatedAt = m.now().UTC()
	if err := m.save(r); err != nil {
		return "", err
	}
	return r.TempPath, nil
}

func (l *Lease) Verify(bytes int64, digest string) error {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[l.id]
	a, ok := m.active[l.id]
	if !ok || r.State != Transferring {
		return ErrInvalidState
	}
	if err := a.ctx.Err(); err != nil && r.Spec.Direction == Upload {
		return fmt.Errorf("verify cancelled upload: %w", err)
	}
	if bytes != r.Spec.Size || bytes != r.Bytes || !validHex(digest, 32) {
		return errors.New("file length or digest does not match transfer declaration")
	}
	if r.Spec.Direction == Upload && digest != r.Spec.SHA256 {
		return errors.New("upload SHA-256 does not match approved content")
	}
	r.Bytes, r.SHA256, r.State = bytes, digest, Verifying
	r.UpdatedAt = m.now().UTC()
	return m.save(r)
}

// ConfirmTemporary runs immediately after a successful exclusive open and
// before writing content. Lost open replies leave ownership unconfirmed.
func (l *Lease) ConfirmTemporary() error {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[l.id]
	if _, ok := m.active[l.id]; !ok || r.State != Transferring || r.TempPath == "" {
		return ErrInvalidState
	}
	r.TempOwned, r.UpdatedAt = true, m.now().UTC()
	err := m.save(r)
	// The opened handle proves ownership in this process even if the durable
	// confirmation fails; recovery must rely only on its journal evidence.
	m.records[l.id] = r
	return err
}

// BeginCommit durably records intent before returning a separate bounded
// context. Client disconnects after this boundary cannot cancel remote commit.
func (l *Lease) BeginCommit() (context.Context, error) {
	return l.beginCommit(nil)
}

// ReserveCommit completes gate admission under the same lock as task Cancel.
// The caller supplies a gate-issued commit permit; no remote I/O occurs here.
func (l *Lease) ReserveCommit(permit ports.Permit) error {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reserveCommit(l.id, permit)
}

func (m *Manager) reserveCommit(id string, permit ports.Permit) error {
	r, a := m.records[id], m.active[id]
	if a == nil || r.State != Verifying || r.Spec.Direction != Upload || r.TempPath == "" || !r.TempOwned {
		return ErrInvalidState
	}
	if err := r.CheckPermit(permit, ports.Commit); err != nil {
		return err
	}
	if a.commitReserved {
		return nil
	}
	if err := m.mutationAllowed(); err != nil {
		return err
	}
	if r.CancelRequested {
		return fmt.Errorf("reserve cancelled transfer: %w", context.Canceled)
	}
	if err := a.requestCtx.Err(); err != nil {
		return fmt.Errorf("reserve cancelled request: %w", err)
	}
	if !time.Now().Before(a.deadline) {
		return fmt.Errorf("reserve expired transfer: %w", context.DeadlineExceeded)
	}
	// Stream authority may have been revoked just after the gate admitted this
	// commit. Only the independent caller/task cancellation state is checked.
	a.commitReserved = true
	return nil
}

// BeginCommitBound durably records an admitted reservation. Direct callers
// without a prior ReserveCommit atomically reserve here before persistence.
func (l *Lease) BeginCommitBound(permit ports.Permit) (context.Context, error) {
	if ports.Nil(permit) {
		return nil, ErrBindingRequired
	}
	return l.beginCommit(permit)
}

func (l *Lease) beginCommit(permit ports.Permit) (context.Context, error) {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[l.id]
	a, ok := m.active[l.id]
	if !ok || r.State != Verifying || r.Spec.Direction != Upload || r.TempPath == "" || !r.TempOwned {
		return nil, ErrInvalidState
	}
	if r.Authorization != nil || !ports.Nil(permit) {
		if err := m.reserveCommit(l.id, permit); err != nil {
			return nil, err
		}
	} else if err := a.ctx.Err(); err != nil {
		return nil, fmt.Errorf("commit cancelled transfer: %w", err)
	}
	if a.commitReserved {
		if m.storeErr != nil {
			return nil, errors.Join(ErrStoreUnusable, m.storeErr)
		}
	} else if err := m.mutationAllowed(); err != nil {
		return nil, err
	}
	r.State, r.UpdatedAt = Committing, m.now().UTC()
	if err := m.save(r); err != nil {
		return nil, err
	}
	a.stopRequest()
	a.cancel()
	parent := context.WithoutCancel(m.ctx)
	if !ports.Nil(permit) {
		parent = permit.Context()
	}
	commitCtx, cancel := context.WithTimeout(parent, m.limits.CommitTimeout)
	a.ctx, a.cancel = commitCtx, cancel
	return commitCtx, nil
}

func (l *Lease) Complete() (Status, error) {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[l.id]
	a, ok := m.active[l.id]
	if !ok {
		return statusOf(r), ErrInvalidState
	}
	switch {
	case r.State == Committing && r.Spec.Direction == Upload:
		// The caller received successful rename confirmation. Preserve that fact
		// even if cancellation/deadline races the final local journal write.
		r.State, r.CleanupPending = Completed, false
	case r.State == Verifying && r.Spec.Direction == Download:
		// The caller has successfully flushed all verified bytes. HTTP clients
		// may close their connection immediately after Content-Length bytes,
		// cancelling the request while final journal writes are still running.
		// Preserve the known stream result; this is not proof of client saving.
		r.State = Streamed
	default:
		return statusOf(r), ErrInvalidState
	}
	r.UpdatedAt = m.now().UTC()
	err := m.save(r)
	// Known completed side effects must not be reclassified as failed merely
	// because persistence failed. Restart will recover the durable commit intent.
	m.records[l.id] = r
	a.stopRequest()
	a.cancel()
	return statusOf(r), err
}

// Fail classifies uncertain commits conservatively. It does not remove any
// remote file; cleanup uses a separate connection and this task's owned path.
func (l *Lease) Fail(cause error) (Status, error) {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[l.id]
	a, ok := m.active[l.id]
	if !ok {
		return statusOf(r), nil
	}
	if terminalState(r.State) {
		return statusOf(r), nil
	}
	switch {
	case r.State == Committing:
		r.State = Unknown
	case r.CancelRequested || !a.commitReserved && (errors.Is(a.ctx.Err(), context.Canceled) || errors.Is(a.requestCtx.Err(), context.Canceled)):
		r.State = Cancelled
	default:
		// A reserved commit has outlived its stream authority. Closing that old
		// permit must not turn a pre-rename persistence/handoff error into a
		// claimed user cancellation. Durable commit intent is handled above.
		r.State = Failed
	}
	if cause != nil {
		r.Error = boundedDiagnostic(cause.Error())
	}
	r.UpdatedAt = m.now().UTC()
	err := m.save(r)
	m.records[l.id] = r
	a.stopRequest()
	a.cancel()
	return statusOf(r), err
}

func (m *Manager) release(id string) {
	a := m.active[id]
	a.stopRequest()
	a.cancel()
	delete(m.active, id)
	if len(m.active) == 0 {
		close(m.drained)
	}
}

func (l *Lease) Close() error {
	_, err := l.Fail(errors.New("transfer handler ended without confirming completion"))
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.active[l.id]; ok {
		m.release(l.id)
	}
	return err
}

func terminalState(state State) bool {
	switch state {
	case Completed, Streamed, Failed, Cancelled, Expired, Unknown:
		return true
	default:
		return false
	}
}

func (m *Manager) Cancel(scope, id string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok || r.Spec.Scope != scope {
		return Status{}, ErrNotFound
	}
	return m.cancelTask(r)
}

func (m *Manager) CancelWithToken(id, token string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.authenticate(id, token)
	if err != nil {
		return Status{}, err
	}
	return m.cancelTask(r)
}

func (m *Manager) cancelTask(r Record) (Status, error) {
	if active := m.active[r.ID]; active != nil && active.commitReserved && r.State == Verifying {
		return statusOf(r), ErrInvalidState
	}
	if r.State == Committing || r.State == Unknown {
		return statusOf(r), ErrInvalidState
	}
	if r.State != Ready && r.State != Transferring && r.State != Verifying {
		return statusOf(r), nil
	}
	r.CancelRequested, r.UpdatedAt = true, m.now().UTC()
	if r.State == Ready {
		r.State = Cancelled
	}
	err := m.save(r)
	m.records[r.ID] = r
	if active, ok := m.active[r.ID]; ok {
		active.cancel()
	}
	return statusOf(r), err
}

// Cleaned records confirmed temporary-file removal or a failed exclusive
// creation that produced no owned file. Never use it to resolve unknown commit.
func (m *Manager) Cleaned(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return ErrNotFound
	}
	if r.State == Unknown && !r.Resolved {
		return ErrInvalidState
	}
	r.CleanupPending, r.UpdatedAt = false, m.now().UTC()
	return m.save(r)
}

// Shutdown rejects new claims, cancels precommit work and gives committing
// leases their bounded completion window. It can be retried after a timeout.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	for id, active := range m.active {
		if m.records[id].State != Committing && !active.commitReserved {
			active.cancel()
		}
	}
	drained := m.drained
	m.mu.Unlock()
	select {
	case <-drained:
		m.closeOnce.Do(func() {
			m.cancel()
			m.closeErr = closeJournalResource(m.store, "store")
		})
		return m.closeErr
	case <-ctx.Done():
		m.mu.Lock()
		for _, active := range m.active {
			active.cancel()
		}
		m.mu.Unlock()
		return fmt.Errorf("wait for transfer shutdown: %w", ctx.Err())
	}
}

func (m *Manager) Close() error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(m.ctx), 45*time.Second)
	defer cancel()
	return m.Shutdown(ctx)
}
