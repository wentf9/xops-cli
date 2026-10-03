package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
)

func (r *Runtime) admitTransfer(ctx context.Context, record transfer.Record, phase ports.Phase, previous ...ports.Permit) (ports.Permit, error) {
	if record.Authorization == nil {
		return nil, transfer.ErrBindingRequired
	}
	a := record.Authorization
	_, target, err := transferTarget(a.Snapshot, record.Spec.NodeID)
	if err != nil || target != record.Spec.TargetID {
		return nil, errors.Join(ports.ErrStaleBinding, err)
	}
	permit, err := r.enter(ctx, a.Snapshot, a.Binding, phase, record.OperationID, previous...)
	if err != nil {
		return nil, err
	}
	if err := record.CheckPermit(permit, phase); err != nil {
		return nil, errors.Join(err, permit.Close())
	}
	return permit, nil
}

func (r *Runtime) retryTransfer(ctx context.Context, spec transfer.Spec) (_ transfer.Prepared, found bool, retErr error) {
	record, found, err := r.transfers.FindRequest(spec.Scope, spec.RequestID, spec.RequestDigest)
	if err != nil || !found {
		return transfer.Prepared{}, found, err
	}
	if record.State != transfer.Ready {
		return transfer.Prepared{Status: record.Status()}, true, nil
	}
	permit, err := r.admitTransfer(ctx, record, ports.Inspect)
	if err != nil {
		if errors.Is(err, ports.ErrStaleBinding) || errors.Is(err, ports.ErrNotFound) || errors.Is(err, ports.ErrNodeDisabled) || errors.Is(err, transfer.ErrBindingRequired) {
			err = errors.Join(err, r.transfers.InvalidateReady(record.ID, err))
		}
		return transfer.Prepared{}, true, err
	}
	defer func() { retErr = errors.Join(retErr, permit.Close()) }()
	prepared, err := r.transfers.RetryBound(record.ID, permit)
	return prepared, true, err
}

func (r *Runtime) openAdmittedTransfer(ctx context.Context, record transfer.Record, permit ports.Permit) (ports.TransferSession, error) {
	if err := record.CheckPermit(permit, permit.Phase()); err != nil {
		return nil, err
	}
	if r.transferDial != nil {
		remote, err := r.transferDial(ctx, record.Spec.NodeID)
		if err != nil {
			return nil, err
		}
		return ports.GuardTransfer(context.WithoutCancel(ctx), remote, permit)
	}
	return r.backend.OpenTransfer(ctx, permit, record.Spec.NodeID)
}

func (r *Runtime) reserveTransferCommit(ctx context.Context, id string, lease *transfer.Lease, remote ports.TransferSession, stream ports.Permit) (_ ports.Permit, retErr error) {
	record, err := r.transfers.Record(id)
	if err != nil {
		return nil, err
	}
	permit, err := r.admitTransfer(ctx, record, ports.Commit, stream)
	if err != nil {
		return nil, fmt.Errorf("reserve transfer commit: %w", err)
	}
	// A capacity-aware gate already consumed this phase atomically. Close is
	// also required for static gates that do not maintain a capacity ledger.
	if err := stream.Close(); err != nil {
		return nil, errors.Join(err, permit.Close())
	}
	if err := lease.ReserveCommit(permit); err != nil {
		return nil, errors.Join(err, permit.Close())
	}
	if err := remote.ReserveCommit(ctx, permit); err != nil {
		return nil, errors.Join(err, permit.Close())
	}
	return permit, nil
}
