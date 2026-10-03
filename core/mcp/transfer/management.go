package transfer

import (
	"errors"
)

// Retry returns an already-authorized task without opening the remote target
// or approving it again. Exact client input is compared before credential reissue.
func (m *Manager) Retry(scope, requestID, requestDigest string) (Prepared, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.mutationAllowed(); err != nil {
		return Prepared{}, false, err
	}
	if err := m.collect(); err != nil {
		return Prepared{}, false, err
	}
	id, ok := m.requests[requestKey{scope, requestID}]
	if !ok {
		return Prepared{}, false, nil
	}
	r := m.records[id]
	if requestDigest == "" || r.Spec.RequestDigest != requestDigest {
		return Prepared{}, true, ErrConflict
	}
	if r.State != Ready {
		return Prepared{Status: statusOf(r)}, true, nil
	}
	if r.Authorization != nil {
		return Prepared{}, true, ErrBindingRequired
	}
	p, err := m.issue(r)
	return p, true, err
}

func (m *Manager) Record(id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r.Clone(), nil
}

func (m *Manager) Warn(id, warning string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return ErrNotFound
	}
	r.Warning, r.UpdatedAt = boundedDiagnostic(warning), m.now().UTC()
	err := m.save(r)
	m.records[id] = r
	return err
}

// RejectCommit is reserved for a caller with evidence that rename was never
// attempted or was explicitly rejected by the remote SFTP server. Transport
// failure without that evidence must use Fail, producing Unknown instead.
func (l *Lease) RejectCommit(cause error) (Status, error) {
	m := l.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[l.id]
	if _, ok := m.active[l.id]; !ok || r.State != Committing {
		return statusOf(r), ErrInvalidState
	}
	if cause == nil {
		return statusOf(r), errors.New("commit rejection requires a cause")
	}
	r.State, r.Error, r.UpdatedAt = Failed, boundedDiagnostic(cause.Error()), m.now().UTC()
	err := m.save(r)
	m.records[l.id] = r
	m.active[l.id].stopRequest()
	m.active[l.id].cancel()
	return statusOf(r), err
}
