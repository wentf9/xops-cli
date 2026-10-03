package ports

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
)

// Nil detects typed nil capabilities before a lifecycle callback is invoked.
func Nil(value any) bool {
	if value == nil {
		return true
	}
	r := reflect.ValueOf(value)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	default:
		return false
	}
}

func (d Dependencies) Validate() error {
	if Nil(d.State) || Nil(d.Gate) || d.NewBackend == nil || Nil(d.Audit) {
		return errors.New("MCP state, gate, backend factory, and audit sink are required")
	}
	if domain := d.State.DomainID(); domain == "" || domain != d.Gate.DomainID() {
		return errors.New("MCP state and gate must share a nonempty publication domain")
	}
	return nil
}

type permit struct {
	ctx       context.Context
	admission Admission
	close     func() error
}

// NewPermit is for trusted host gates, after atomic validation/registration.
// It validates structure but cannot establish that the snapshot is current.
func NewPermit(ctx context.Context, admission Admission, release func() error) (Permit, error) {
	if ctx == nil {
		return nil, errors.New("permit context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("permit requires an execution deadline")
	}
	if admission.OperationID == "" {
		return nil, errors.New("operation ID is required")
	}
	if !slices.Contains([]Phase{Inspect, Execute, TransferStart, Commit, Recovery}, admission.Phase) {
		return nil, ErrPurpose
	}
	if err := admission.Binding.Validate(admission.Snapshot); err != nil {
		return nil, err
	}
	admission.Snapshot = admission.Snapshot.Clone()
	// The new permit does not own or retain the prior phase's capability.
	admission.Previous = nil
	work, cancel := context.WithCancel(ctx)
	return &permit{ctx: work, admission: admission, close: sync.OnceValue(func() error {
		cancel()
		if release != nil {
			return release()
		}
		return nil
	})}, nil
}

func (p *permit) Context() context.Context    { return p.ctx }
func (p *permit) Snapshot() OperationSnapshot { return p.admission.Snapshot.Clone() }
func (p *permit) Binding() Binding            { return p.admission.Binding }
func (p *permit) Phase() Phase                { return p.admission.Phase }
func (p *permit) Close() error                { return p.close() }

// WorkContext intersects call and permit lifetimes. A longer caller context
// cannot bypass the execution deadline or host revocation of the permit.
func WorkContext(ctx context.Context, permit Permit, phases ...Phase) (context.Context, context.CancelFunc, error) {
	if ctx == nil || Nil(permit) || permit.Context() == nil {
		return nil, nil, errors.New("call context and permit are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := permit.Context().Err(); err != nil {
		return nil, nil, err
	}
	if !slices.Contains(phases, permit.Phase()) {
		return nil, nil, ErrPurpose
	}
	deadline, ok := permit.Context().Deadline()
	if !ok {
		return nil, nil, errors.New("permit lacks an execution deadline")
	}
	if err := permit.Binding().Validate(permit.Snapshot()); err != nil {
		return nil, nil, fmt.Errorf("validate execution permit: %w", err)
	}
	work, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(permit.Context(), cancel)
	if permit.Context().Err() != nil {
		cancel()
	}
	return work, func() { stop(); cancel() }, nil
}
