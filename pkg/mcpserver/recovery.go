package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/wentf9/xops-cli/pkg/mcpserver/transfer"
)

type RecoveryOptions struct {
	StateDir       string
	TransferID     string
	Verify         bool
	Cleanup        bool
	ResolveUnknown bool
	Reason         string
	MaxRecords     int
	MaxFileBytes   int64
}

type RecoveryEntry struct {
	Task              transfer.Status `json:"task"`
	TemporaryPath     string          `json:"temporaryPath,omitempty"`
	Verified          bool            `json:"verified"`
	DestinationExists bool            `json:"destinationExists"`
	ActualSize        int64           `json:"actualSize,omitempty"`
	ActualSHA256      string          `json:"actualSHA256,omitempty"`
	MatchesExpected   bool            `json:"matchesExpected"`
	Resolution        string          `json:"resolution,omitempty"`
}

func (o *RecoveryOptions) validate() error {
	if o.MaxFileBytes == 0 {
		o.MaxFileBytes = transfer.DefaultLimits().MaxFileBytes
	}
	if o.StateDir == "" {
		return errors.New("recovery state directory is required")
	}
	if (o.Verify || o.Cleanup || o.ResolveUnknown) && o.TransferID == "" {
		return errors.New("recovery actions require a specific transfer ID")
	}
	if o.ResolveUnknown && (o.Reason == "" || len(o.Reason) > 4096) {
		return errors.New("resolving an unknown outcome requires a bounded operator reason")
	}
	if o.Reason != "" && (!o.ResolveUnknown && !o.Cleanup || len(o.Reason) > 4096) {
		return errors.New("a bounded recovery reason requires --resolve-unknown or --cleanup")
	}
	if o.MaxFileBytes <= 0 || o.MaxFileBytes > 1<<50 {
		return errors.New("invalid recovery file size limit")
	}
	if o.MaxRecords <= 0 || o.MaxRecords > 65536 {
		return errors.New("invalid recovery record limit")
	}
	return nil
}

// RecoverTransfers is offline maintenance: the permanent journal lock prevents
// racing a running service. Listing never mutates task records or contacts SSH.
// Remote verification/cleanup and operator acknowledgement are explicit options.
func RecoverTransfers(ctx context.Context, options RecoveryOptions, opts ...Option) (_ []RecoveryEntry, retErr error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(options.StateDir); err != nil {
		if errors.Is(err, os.ErrNotExist) && options.TransferID == "" && !options.Verify && !options.Cleanup && !options.ResolveUnknown {
			return []RecoveryEntry{}, nil
		}
		return nil, fmt.Errorf("inspect recovery metadata directory: %w", err)
	}
	journal, err := transfer.OpenJournal(options.StateDir)
	if err != nil {
		return nil, err
	}
	defer joinCloseError(&retErr, journal, "recovery journal")
	records, err := journal.Load(options.MaxRecords)
	if err != nil {
		return nil, err
	}
	if options.TransferID != "" {
		selected := records[:0]
		for _, record := range records {
			if record.ID == options.TransferID {
				selected = append(selected, record)
			}
		}
		records = selected
		if len(records) == 0 {
			return nil, transfer.ErrNotFound
		}
	}
	var runtime *Runtime
	if options.Verify || options.Cleanup || options.ResolveUnknown {
		runtime, err = NewRuntime(ctx, opts...)
		if err != nil {
			return nil, err
		}
		defer joinCloseError(&retErr, runtime, "recovery runtime")
	}
	entries := make([]RecoveryEntry, 0, len(records))
	for _, record := range records {
		entry, err := recoverTransferRecord(ctx, runtime, journal, record, options)
		entries = append(entries, entry)
		if err != nil {
			return entries, err
		}
	}
	return entries, nil
}

func recoveredView(record transfer.Record) transfer.Record {
	switch record.State {
	case transfer.Ready:
		record.State = transfer.Expired
	case transfer.Transferring, transfer.Verifying:
		record.State = transfer.Failed
	case transfer.Committing:
		record.State = transfer.Unknown
	}
	return record
}

func recoverTransferRecord(ctx context.Context, r *Runtime, journal *transfer.Journal, record transfer.Record, options RecoveryOptions) (entry RecoveryEntry, retErr error) {
	record = recoveredView(record)
	entry = RecoveryEntry{Task: record.Status(), TemporaryPath: record.TempPath, Resolution: record.Resolution}
	if options.Verify {
		if err := r.verifyRecovery(ctx, record, &entry, options.MaxFileBytes); err != nil {
			return entry, err
		}
	}
	if options.ResolveUnknown {
		if record.State != transfer.Unknown {
			return entry, errors.New("only an uncertain upload can be resolved")
		}
		ri := transferRisk(record.Spec)
		ri.Details += "; operator resolution: " + options.Reason
		if err := r.guardrail.RecordAuthorized(record.OperationID, ri, "recovery_resolution_intent", nil); err != nil {
			return entry, err
		}
		record.Resolved, record.Resolution = true, options.Reason
		record.UpdatedAt = time.Now().UTC()
		if err := journal.Save(record); err != nil {
			return entry, err
		}
		entry.Task, entry.Resolution = record.Status(), record.Resolution
		if err := r.guardrail.RecordAuthorized(record.OperationID, ri, "recovery_resolved", nil); err != nil {
			return entry, err
		}
	}
	if options.Cleanup && record.CleanupPending {
		if err := r.recoverCleanup(ctx, journal, &record, options); err != nil {
			return entry, err
		}
		entry.Task = record.Status()
	}
	return entry, nil
}

func (r *Runtime) checkRecoveryTarget(record transfer.Record) error {
	_, target, err := r.resolveTransferTarget(record.Spec.NodeID)
	if err != nil || target != record.Spec.TargetID {
		return errors.Join(errors.New("recovery target identity differs from the recorded operation"), err)
	}
	return nil
}

func (r *Runtime) verifyRecovery(ctx context.Context, record transfer.Record, entry *RecoveryEntry, maxFileBytes int64) (retErr error) {
	if err := r.checkRecoveryTarget(record); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	remote, err := r.openTransferRemote(ctx, record.Spec.NodeID)
	if err != nil {
		return err
	}
	defer joinCloseError(&retErr, remote, "recovery verification connection")
	metadata, err := remote.Inspect(ctx, record.Spec.RemotePath, false, false)
	if errors.Is(err, os.ErrNotExist) {
		entry.Verified = true
		return nil
	}
	if err != nil {
		return err
	}
	if metadata.Size > maxFileBytes {
		return errors.New("recovery verification file exceeds the configured size limit")
	}
	result, err := remote.Download(ctx, metadata, io.Discard, nil)
	if err != nil {
		return fmt.Errorf("verify current recovery destination: %w", err)
	}
	entry.Verified, entry.DestinationExists = true, true
	entry.ActualSize, entry.ActualSHA256 = result.Bytes, result.SHA256
	expectedDigest := record.Spec.SHA256
	if expectedDigest == "" {
		expectedDigest = record.SHA256
	}
	entry.MatchesExpected = result.Bytes == record.Spec.Size && result.SHA256 == expectedDigest
	return nil
}

func (r *Runtime) recoverCleanup(ctx context.Context, journal *transfer.Journal, record *transfer.Record, options RecoveryOptions) error {
	if record.State == transfer.Unknown && !record.Resolved {
		return errors.New("resolve the uncertain outcome before cleaning its temporary file")
	}
	if !record.TempOwned && options.Reason == "" {
		return errors.New("unconfirmed temporary ownership requires --reason recording operator verification")
	}
	ri := transferRisk(record.Spec)
	if options.Reason != "" {
		ri.Details += "; operator cleanup verification: " + options.Reason
	}
	if err := r.guardrail.RecordAuthorized(record.OperationID, ri, "recovery_cleanup_intent", nil); err != nil {
		return err
	}
	if err := r.checkRecoveryTarget(*record); err != nil {
		return err
	}
	if !record.TempOwned {
		record.TempOwned = true
		record.UpdatedAt = time.Now().UTC()
		if err := journal.Save(*record); err != nil {
			return err
		}
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := r.removeTransferTemporary(cleanupCtx, record.Spec.NodeID, record.TempPath); err != nil {
		return err
	}
	record.CleanupPending, record.UpdatedAt = false, time.Now().UTC()
	if err := journal.Save(*record); err != nil {
		return err
	}
	if err := r.guardrail.RecordAuthorized(record.OperationID, transferRisk(record.Spec), "recovery_cleaned", nil); err != nil {
		return err
	}

	return nil
}
