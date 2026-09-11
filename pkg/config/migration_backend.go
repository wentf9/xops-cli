package config

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func (m *CredentialMigrator) migrateBackend(ctx context.Context, opts MigrationOptions, raw []byte) (MigrationReport, error) {
	prior, err := m.loadBackendState()
	if err != nil {
		return MigrationReport{}, err
	}
	if prior != nil && !prior.Verified && !opts.Restart && prior.Store != opts.ToStore {
		return MigrationReport{}, fmt.Errorf("pending backend migration targets %q; resume it first", prior.Store)
	}
	if prior != nil && migrationDigest(raw) == prior.CandidateHash && prior.Store == opts.ToStore {
		return m.finishBackendMigration(ctx, prior)
	}
	return m.runBackendMigration(ctx, opts, raw, prior)
}

func (m *CredentialMigrator) runBackendMigration(ctx context.Context, opts MigrationOptions, raw []byte, prior *backendMigrationState) (MigrationReport, error) {
	var err error
	var receipt []byte
	if prior != nil && (prior.Verified || opts.Restart) {
		// Archive the completed receipt before another migration replaces it.
		receipt, err = readMigrationFile(m.backendStatePath())
		if err != nil {
			return MigrationReport{}, err
		}
		prior = nil
	}
	state, candidate, err := planBackendMigration(raw, opts.ToStore, prior)
	if err != nil {
		return MigrationReport{}, err
	}
	report := m.backendReport(state, false)
	cfg, err := UnmarshalV2(raw)
	if err != nil {
		return report, err
	}
	registry, err := m.migrationRegistry(&cfg.Credential, opts.ToStore)
	if err != nil {
		return report, err
	}
	if err := m.protectBackendMigrationPaths(&cfg.Credential, state.SourceHash); err != nil {
		return report, err
	}
	if len(receipt) != 0 {
		archive := m.backendStatePath() + "." + migrationDigest(receipt) + ".bak"
		if err := m.protectBackendMigrationPaths(&cfg.Credential, state.SourceHash, archive); err != nil {
			return report, err
		}
		if err := m.ensureBackup(archive, receipt); err != nil {
			return report, err
		}
	}
	if err := m.saveBackendState(state); err != nil {
		return report, err
	}
	if err := m.step("backend_intent"); err != nil {
		return report, err
	}
	if err := m.ensureBackup(report.BackupPath, raw); err != nil {
		return report, err
	}
	if err := m.step("backend_backup"); err != nil {
		return report, err
	}
	return m.publishBackendMigration(ctx, registry, state, candidate)
}

func (m *CredentialMigrator) publishBackendMigration(ctx context.Context, registry *credential.Registry, state *backendMigrationState, candidate []byte) (MigrationReport, error) {
	report := m.backendReport(state, false)
	if err := m.copyBackendCredentials(ctx, registry, state); err != nil {
		return report, err
	}
	if err := m.verifyBackendCandidate(ctx, state, candidate); err != nil {
		return report, err
	}
	if err := m.step("backend_before_commit"); err != nil {
		return report, err
	}
	err := m.commitBackendMigration(ctx, state, candidate)
	if err != nil {
		return report, err
	}
	if err := m.step("backend_committed"); err != nil {
		return report, err
	}
	return m.finishBackendMigration(ctx, state)
}

func (m *CredentialMigrator) commitBackendMigration(ctx context.Context, state *backendMigrationState, candidate []byte) error {
	return m.withConfigLock(ctx, func() error {
		current, err := readMigrationFile(m.path)
		if err != nil {
			return err
		}
		if migrationDigest(current) != state.SourceHash {
			return fmt.Errorf("%w: configuration changed; pending refs and backup retained; use --restart to plan from current configuration", ErrConfigConflict)
		}
		result, err := m.write(m.path, candidate, 0600)
		if err != nil {
			return fmt.Errorf("commit backend migration (applied=%t, durable=%t): %w", result.Applied, result.Durable, err)
		}
		if !result.Applied || !result.Durable {
			return fmt.Errorf("backend migration commit is not confirmed durable")
		}
		return nil
	})
}

func (m *CredentialMigrator) copyBackendCredentials(ctx context.Context, registry *credential.Registry, state *backendMigrationState) error {
	store, err := registry.GetStore(state.Store)
	if err != nil {
		return err
	}
	if backend, ok := store.(*encryptedBackend); ok && len(state.Entries) != 0 {
		if err := backend.prepareWrite(ctx); err != nil {
			return err
		}
	}
	for i, entry := range state.Entries {
		if err := m.copyBackendCredential(ctx, registry, store, entry, i); err != nil {
			return err
		}
	}
	return nil
}

func (m *CredentialMigrator) copyBackendCredential(ctx context.Context, registry *credential.Registry, store credential.Store, entry backendMigrationEntry, index int) error {
	source, err := registry.Resolve(ctx, entry.Source)
	defer source.Zero()
	if err != nil {
		return fmt.Errorf("read migration source %d: %w", index, err)
	}
	if len(source.Value) == 0 || source.IsExpired(time.Now()) {
		return fmt.Errorf("%w: migration source %d empty or expired", credential.ErrCredentialNotFound, index)
	}
	got, err := store.Get(ctx, entry.Target)
	defer got.Zero()
	if errors.Is(err, credential.ErrCredentialNotFound) {
		if err := store.Put(ctx, entry.Target, source); err != nil {
			return fmt.Errorf("write backend migration item %d: %w", index, err)
		}
		if err := m.step(fmt.Sprintf("backend_put:%d", index)); err != nil {
			return err
		}
		got.Zero()
		got, err = store.Get(ctx, entry.Target)
	}
	if err != nil {
		return fmt.Errorf("read backend migration item %d: %w", index, err)
	}
	if !sameMigrationSecret(source, got) {
		return fmt.Errorf("backend migration item %d read-back mismatch", index)
	}
	return m.step(fmt.Sprintf("backend_readback:%d", index))
}

func sameMigrationSecret(a, b credential.Secret) bool {
	if subtle.ConstantTimeCompare(a.Value, b.Value) != 1 {
		return false
	}
	if a.ExpiresAt == nil || b.ExpiresAt == nil {
		return a.ExpiresAt == nil && b.ExpiresAt == nil
	}
	return a.ExpiresAt.Equal(*b.ExpiresAt)
}

func (m *CredentialMigrator) verifyBackendCandidate(ctx context.Context, state *backendMigrationState, candidate []byte) error {
	raw, err := readMigrationFile(m.backendBackupPath(state.SourceHash))
	if err != nil {
		return err
	}
	_, expected, err := planBackendMigration(raw, state.Store, state)
	if err != nil {
		return err
	}
	if migrationDigest(candidate) != migrationDigest(expected) {
		return fmt.Errorf("%w: backend candidate changed", ErrConfigConflict)
	}
	cfg, err := UnmarshalV2(raw)
	if err != nil {
		return err
	}
	registry, err := m.migrationRegistry(&cfg.Credential, "")
	if err != nil {
		return err
	}
	for i, entry := range state.Entries {
		if err := compareBackendReferences(ctx, registry, entry, i); err != nil {
			return err
		}
	}
	return m.verifyV2(ctx, candidate, nil)
}

func compareBackendReferences(ctx context.Context, registry *credential.Registry, entry backendMigrationEntry, index int) error {
	source, err := registry.Resolve(ctx, entry.Source)
	defer source.Zero()
	if err != nil {
		return fmt.Errorf("verify backend source %d: %w", index, err)
	}
	target, err := registry.Resolve(ctx, entry.Target)
	defer target.Zero()
	if err != nil {
		return fmt.Errorf("verify backend target %d: %w", index, err)
	}
	if !sameMigrationSecret(source, target) {
		return fmt.Errorf("backend migration item %d differs from source", index)
	}
	return nil
}

func (m *CredentialMigrator) finishBackendMigration(ctx context.Context, state *backendMigrationState) (MigrationReport, error) {
	report := m.backendReport(state, false)
	raw, err := readMigrationFile(m.path)
	if err != nil {
		return report, err
	}
	if err := m.verifyBackendCandidate(ctx, state, raw); err != nil {
		return report, err
	}
	err = m.withConfigLock(ctx, func() error {
		current, err := readMigrationFile(m.path)
		if err != nil {
			return err
		}
		if migrationDigest(current) != state.CandidateHash {
			return fmt.Errorf("%w: configuration changed during backend verification", ErrConfigConflict)
		}
		if err := syncMigrationConfiguration(m.path); err != nil {
			return err
		}
		state.Verified = true
		return m.saveBackendState(state)
	})
	if err != nil {
		return report, err
	}
	return m.backendReport(state, false), m.step("backend_verified")
}

func (m *CredentialMigrator) dryRunBackend(ctx context.Context, opts MigrationOptions, raw []byte) (MigrationReport, error) {
	state, _, err := planBackendMigration(raw, opts.ToStore, nil)
	if err != nil {
		return MigrationReport{}, err
	}
	cfg, err := UnmarshalV2(raw)
	if err != nil {
		return MigrationReport{}, err
	}
	registry, err := m.migrationRegistry(&cfg.Credential, opts.ToStore)
	if err != nil {
		return MigrationReport{}, err
	}
	if err := m.protectBackendMigrationPaths(&cfg.Credential, state.SourceHash); err != nil {
		return MigrationReport{}, err
	}
	for _, ref := range backendRefs(cfg) {
		if err := verifyMigrationRef(ctx, registry, ref, nil); err != nil {
			return MigrationReport{}, err
		}
	}
	// An absent offline vault is a valid future destination. Initialization and
	// write authorization are tested only by actual mutation/read-back.
	target := cfg.Credential.Stores[opts.ToStore]
	probe := true
	if target.Type == StoreTypeEncryptedFile {
		resolved, err := ResolveFileStore(target, m.path)
		if err != nil {
			return MigrationReport{}, err
		}
		if _, err := os.Lstat(resolved.Path); errors.Is(err, os.ErrNotExist) {
			probe = false
		} else if err != nil {
			return MigrationReport{}, err
		}
	}
	if probe {
		secret, err := registry.Resolve(ctx, credential.Ref{StoreID: opts.ToStore, ItemID: "migration-probe-" + credential.GenerateItemID()})
		defer secret.Zero()
		if err != nil && !errors.Is(err, credential.ErrCredentialNotFound) {
			return MigrationReport{}, fmt.Errorf("probe destination: %w", err)
		}
	}
	return m.backendReport(state, true), nil
}

func (m *CredentialMigrator) protectBackendMigrationPaths(cfg *CredentialConfig, hash string, extra ...string) error {
	reserved := append([]string{m.backendStatePath(), m.backendBackupPath(hash)}, extra...)
	for _, st := range cfg.Stores {
		if st.Type != StoreTypeEncryptedFile {
			continue
		}
		resolved, err := ResolveFileStore(st, m.path)
		if err != nil {
			return err
		}
		for _, path := range reserved {
			candidate, err := canonicalMigrationPath(path)
			if err != nil {
				return err
			}
			key, err := canonicalMigrationPath(resolved.KeyFile)
			if err != nil {
				return err
			}
			vault, err := canonicalMigrationPath(resolved.Path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(vault, candidate)
			if key == candidate || err == nil && (rel == "." || filepath.IsLocal(rel)) {
				return fmt.Errorf("%w: backend migration artifact overlaps offline store", ErrConfigConflict)
			}
		}
	}
	return nil
}
