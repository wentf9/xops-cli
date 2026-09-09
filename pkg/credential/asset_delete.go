package credential

import (
	"context"
	"errors"
	"fmt"
)

// DeleteAssets journals every candidate ref before a single inventory commit.
// The callback must preserve its exact entity version preconditions. No backend
// I/O runs inside that callback or the repository's configuration locks.
func (s *Service) DeleteAssets(ctx context.Context, refs []Ref, commit func(context.Context) (MutationOutcome, error)) (outcome MutationOutcome, retErr error) {
	if ctx == nil {
		return outcome, fmt.Errorf("asset deletion context is nil")
	}
	if commit == nil {
		return outcome, fmt.Errorf("asset deletion commit is nil")
	}
	entries := make([]JournalEntry, 0, len(refs))
	seen := make(map[Ref]bool)
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return outcome, err
		}
		if err := ref.Validate(); err != nil {
			return outcome, err
		}
		if ref.IsEmpty() || seen[ref] {
			continue
		}
		seen[ref] = true
		entry := JournalEntry{ID: GenerateJournalID(), Op: OpAssetDelete, OldRef: ref.Clone()}
		lock, err := s.journal.AcquireEntryLock(entry.ID)
		if err != nil {
			return outcome, fmt.Errorf("lock asset deletion journal: %w", err)
		}
		s.activeTx.Store(entry.ID, struct{}{})
		defer func() {
			if err := lock.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close asset deletion lock: %w", err))
			}
			s.activeTx.Delete(entry.ID)
		}()
		if err := s.journal.RecordIntent(&entry); err != nil {
			return outcome, fmt.Errorf("record asset deletion intent: %w", err)
		}
		entries = append(entries, entry)
	}
	outcome, retErr = commit(ctx)
	if !outcome.Applied {
		for _, entry := range entries {
			retErr = errors.Join(retErr, s.journal.Remove(entry.ID))
		}
		return outcome, retErr
	}
	if !outcome.Durable {
		for _, entry := range entries {
			retErr = errors.Join(retErr, s.journal.MarkAppliedUncertain(entry.ID))
		}
		return outcome, errors.Join(retErr, fmt.Errorf("asset deletion applied but durability is uncertain"))
	}
	for _, entry := range entries {
		if err := s.journal.MarkCommitted(entry.ID); err != nil {
			retErr = errors.Join(retErr, &CleanupError{OldRef: *entry.OldRef, Err: err})
			continue
		}
		if err := s.cleanupAssetReference(ctx, entry); err != nil {
			retErr = errors.Join(retErr, &CleanupError{OldRef: *entry.OldRef, Err: errors.Join(err, s.journal.MarkCleanup(entry.ID))})
		}
	}
	return outcome, retErr
}

// cleanupAssetReference is safe for every journal stage, including a crash
// before commit. The repository checks current on-disk refs and syncs their
// absence before permitting deletion. Shared or rolled-back refs are retained.
func (s *Service) cleanupAssetReference(ctx context.Context, entry JournalEntry) error {
	unreferenced, err := s.config.CheckRefUnreferenced(ctx, *entry.OldRef)
	if err != nil {
		return fmt.Errorf("check deleted asset reference durability: %w", err)
	}
	if unreferenced {
		store, err := s.getWritableStore(entry.OldRef.StoreID)
		if err != nil {
			return err
		}
		if err := store.Delete(ctx, *entry.OldRef); err != nil && !errors.Is(err, ErrCredentialNotFound) {
			return fmt.Errorf("delete unreferenced asset credential: %w", err)
		}
		if s.cache != nil {
			s.cache.Invalidate(*entry.OldRef)
		}
	}
	if err := s.journal.Remove(entry.ID); err != nil {
		return fmt.Errorf("remove asset deletion journal: %w", err)
	}
	return nil
}
