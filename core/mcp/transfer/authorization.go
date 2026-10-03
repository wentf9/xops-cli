package transfer

import (
	"errors"

	"github.com/wentf9/xops-cli/core/mcp/ports"
)

var ErrBindingRequired = errors.New("transfer requires its original authorization binding")

// Authorization is secret-free, private journal data. Binding covers the
// canonical Spec; RequestDigest in Spec continues to identify the client input.
type Authorization struct {
	Snapshot ports.OperationSnapshot `json:"snapshot"`
	Binding  ports.Binding           `json:"binding"`
}

func (a *Authorization) clone() *Authorization {
	if a == nil {
		return nil
	}
	return &Authorization{Snapshot: a.Snapshot.Clone(), Binding: a.Binding}
}

func (a *Authorization) validate(spec Spec) error {
	if a == nil {
		return ErrBindingRequired
	}
	want, err := ports.Bind(a.Snapshot, spec.Scope, "xops_prepare_"+string(spec.Direction), spec)
	if err != nil {
		return err
	}
	if want != a.Binding {
		return ports.ErrStaleBinding
	}
	if len(a.Snapshot.Targets) != 1 {
		return ports.ErrStaleBinding
	}
	_, _, err = a.Snapshot.Resolve(spec.NodeID)
	return err
}

func (r Record) Clone() Record { r.Authorization = r.Authorization.clone(); return r }

// CheckPermit validates recorded intent and the host's admitted capability.
// The gate, not the journal, establishes whether dependencies are still current.
func (r Record) CheckPermit(permit ports.Permit, phase ports.Phase) error {
	if err := r.Authorization.validate(r.Spec); err != nil {
		return err
	}
	if ports.Nil(permit) || permit.Phase() != phase || permit.Binding() != r.Authorization.Binding {
		return ports.ErrStaleBinding
	}
	if err := permit.Binding().Validate(permit.Snapshot()); err != nil {
		return err
	}
	if permit.Context() == nil {
		return ErrBindingRequired
	}
	return permit.Context().Err()
}

// PrepareBound is the versioned runtime entry. Legacy Prepare keeps writing v1
// for compatibility; unbound records cannot acquire runtime execution authority.
func (m *Manager) PrepareBound(spec Spec, operationID string, permit ports.Permit) (Prepared, error) {
	if ports.Nil(permit) {
		return Prepared{}, ErrBindingRequired
	}
	a := &Authorization{Snapshot: permit.Snapshot(), Binding: permit.Binding()}
	if err := (Record{Spec: spec, Authorization: a}).CheckPermit(permit, ports.Inspect); err != nil {
		return Prepared{}, err
	}
	return m.prepare(spec, operationID, a)
}

// FindRequest never rotates credentials. It lets the runtime validate the
// original binding before RetryBound, without holding the manager lock over I/O.
func (m *Manager) FindRequest(scope, requestID, digest string) (Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.mutationAllowed(); err != nil {
		return Record{}, false, err
	}
	if err := m.collect(); err != nil {
		return Record{}, false, err
	}
	id, found := m.requests[requestKey{scope, requestID}]
	if !found {
		return Record{}, false, nil
	}
	record := m.records[id]
	if digest == "" || record.Spec.RequestDigest != digest {
		return Record{}, true, ErrConflict
	}
	return record.Clone(), true, nil
}

func (m *Manager) RetryBound(id string, permit ports.Permit) (Prepared, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.mutationAllowed(); err != nil {
		return Prepared{}, err
	}
	if err := m.collect(); err != nil {
		return Prepared{}, err
	}
	record, ok := m.records[id]
	if !ok {
		return Prepared{}, ErrNotFound
	}
	if record.State != Ready {
		return Prepared{Status: statusOf(record)}, nil
	}
	if err := record.CheckPermit(permit, ports.Inspect); err != nil {
		return Prepared{}, err
	}
	return m.issue(record)
}

// InvalidateReady does not change active, completed, or uncertain results.
func (m *Manager) InvalidateReady(id string, cause error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.mutationAllowed(); err != nil {
		return err
	}
	r, ok := m.records[id]
	if !ok {
		return ErrNotFound
	}
	if r.State != Ready {
		return nil
	}
	if cause == nil {
		return errors.New("invalidating a binding requires a cause")
	}
	r.State, r.Error, r.UpdatedAt = Failed, boundedDiagnostic(cause.Error()), m.now().UTC()
	return m.save(r)
}
