package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wentf9/xops-cli/pkg/credential"
)

// MigrationOptions selects an explicitly configured writable destination.
type MigrationOptions struct {
	ToStore string
	DryRun  bool
}

// MigrationReport contains metadata only. It never returns decoded secrets.
type MigrationReport struct {
	Store         string
	Credentials   int
	BackupPath    string
	BackupKeyPath string
	DryRun        bool
	Verified      bool
	Finalized     bool
}

// CredentialMigrator operates directly on files, never publishing legacy
// secrets into a Repository or Provider. It serializes migrations separately
// from ordinary configuration edits; backend I/O never holds the config lock.
type CredentialMigrator struct {
	path       string
	keyPath    string
	write      func(string, []byte, os.FileMode) (PersistResult, error)
	registry   func(*CredentialConfig) (*credential.Registry, error)
	checkpoint func(string) error // failure/crash injection, unexported
}

// NewCredentialMigrator binds migration to fixed local paths without reading or writing them.
func NewCredentialMigrator(configPath, keyPath string) (*CredentialMigrator, error) {
	if configPath == "" || keyPath == "" {
		return nil, fmt.Errorf("migration requires configuration and key paths")
	}
	path, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}
	key, err := filepath.Abs(keyPath)
	if err != nil {
		return nil, err
	}
	m := &CredentialMigrator{path: path, keyPath: key, write: atomicWriteFile, registry: BuildRegistryFromConfig}
	for _, reserved := range []string{path, m.statePath(), m.backupPath(), m.backupKeyPath(), path + ".lock", path + ".migration.lock"} {
		if key == reserved {
			return nil, fmt.Errorf("migration key path overlaps configuration or recovery artifacts")
		}
	}
	return m, nil
}

func (m *CredentialMigrator) report(state *migrationState, dryRun bool) MigrationReport {
	r := MigrationReport{Store: state.Store, Credentials: len(state.Entries), BackupPath: m.backupPath(), DryRun: dryRun,
		Verified: state.Phase == "verified" || state.Phase == "complete", Finalized: state.Phase == "complete"}
	if state.KeyHash != "" {
		r.BackupKeyPath = m.backupKeyPath()
	}
	return r
}

// Migrate preserves all old materials until an explicit Finalize call. A failed
// or interrupted run can reuse the recorded immutable refs on the next run.
func (m *CredentialMigrator) Migrate(ctx context.Context, opts MigrationOptions) (report MigrationReport, retErr error) {
	if ctx == nil || opts.ToStore == "" {
		return report, fmt.Errorf("migration requires context and destination store")
	}
	if opts.DryRun {
		return m.dryRun(ctx, opts)
	}
	lock, err := acquireConfigLock(ctx, m.path+".migration")
	if err != nil {
		return report, err
	}
	defer func() { retErr = errors.Join(retErr, lock.Close()) }()
	state, err := m.loadState()
	if err != nil {
		return report, err
	}
	raw, key, err := m.readInputs(ctx)
	if err != nil {
		return report, err
	}
	defer clear(raw)
	defer clear(key)
	if state != nil && state.Store != opts.ToStore {
		return report, fmt.Errorf("migration already targets store %q", state.Store)
	}
	if state != nil && (state.Phase == "finalizing" || state.Phase == "complete") {
		return m.report(state, false), fmt.Errorf("migration is already finalizing or finalized; do not restart it")
	}
	if state != nil && state.CandidateHash != "" && migrationDigest(raw) == state.CandidateHash {
		return m.finishVerification(ctx, state, raw)
	}
	if state != nil && state.Phase != "intent" {
		return report, fmt.Errorf("migration already committed; use finalize-migration after validation")
	}
	return m.migrateLegacy(ctx, opts, state, raw, key)
}

func (m *CredentialMigrator) migrateLegacy(ctx context.Context, opts MigrationOptions, state *migrationState, raw, key []byte) (report MigrationReport, retErr error) {
	cfg, err := decodeMigrationLegacy(raw)
	if err != nil {
		return report, err
	}
	defer clearMigrationConfiguration(cfg)
	state, err = prepareMigrationState(cfg, raw, key, opts.ToStore, state)
	if err != nil {
		return report, err
	}
	registry, err := m.registryForPlan(cfg.Credential, state)
	if err != nil {
		return report, err
	}
	report = m.report(state, false)
	if err := m.step("target_validated"); err != nil {
		return report, err
	}
	if err := m.prepareBackups(state, raw, key); err != nil {
		return report, err
	}
	if err := completeExistingKeyFingerprints(ctx, cfg, registry); err != nil {
		return report, err
	}
	candidate, secrets, err := buildMigrationV2(cfg, state.Entries, key)
	defer clearMigrationSecrets(secrets)
	if err != nil {
		return report, err
	}
	defer clear(candidate)
	if err := m.step("decoded"); err != nil {
		return report, err
	}
	state.CandidateHash = migrationDigest(candidate)
	if err := m.saveState(state); err != nil {
		return report, err
	}
	if err := m.transferSecrets(ctx, registry, state, secrets); err != nil {
		return report, err
	}
	if err := m.step("before_commit"); err != nil {
		return report, err
	}
	if err := m.commitV2(ctx, state, candidate); err != nil {
		return report, err
	}
	if err := m.step("committed"); err != nil {
		return report, err
	}
	return m.finishVerification(ctx, state, candidate)
}

func (m *CredentialMigrator) readInputs(ctx context.Context) (raw, key []byte, err error) {
	err = m.withConfigLock(ctx, func() error {
		var err error
		raw, err = readMigrationFile(m.path)
		if err != nil {
			return err
		}
		key, err = readMigrationFile(m.keyPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	})
	return raw, key, err
}

func (m *CredentialMigrator) commitV2(ctx context.Context, state *migrationState, data []byte) error {
	return m.withConfigLock(ctx, func() error {
		current, err := readMigrationFile(m.path)
		if err != nil {
			return err
		}
		defer clear(current)
		if migrationDigest(current) != state.SourceHash {
			return fmt.Errorf("%w: configuration changed during migration; backups and pending refs retained", ErrConfigConflict)
		}
		if err := checkMigrationKey(m.keyPath, state.KeyHash, false); err != nil {
			return err
		}
		result, err := m.write(m.path, data, 0600)
		if err != nil {
			return fmt.Errorf("commit schema v2 (applied=%t, durable=%t): %w", result.Applied, result.Durable, err)
		}
		if !result.Applied || !result.Durable {
			return fmt.Errorf("schema v2 commit is not confirmed durable")
		}
		state.Phase = "committed"
		return m.saveState(state)
	})
}

func (m *CredentialMigrator) dryRun(ctx context.Context, opts MigrationOptions) (MigrationReport, error) {
	// No lock files, backups, journals, key generation or backend writes.
	raw, err := readMigrationFile(m.path)
	if err != nil {
		return MigrationReport{}, err
	}
	defer clear(raw)
	key, err := readMigrationFile(m.keyPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return MigrationReport{}, err
	}
	defer clear(key)
	cfg, err := decodeMigrationLegacy(raw)
	if err != nil {
		return MigrationReport{}, err
	}
	defer clearMigrationConfiguration(cfg)
	state, err := prepareMigrationState(cfg, raw, key, opts.ToStore, nil)
	if err != nil {
		return MigrationReport{}, err
	}
	registry, err := m.registryForPlan(cfg.Credential, state)
	if err != nil {
		return MigrationReport{}, err
	}
	if err := completeExistingKeyFingerprints(ctx, cfg, registry); err != nil {
		return MigrationReport{}, err
	}
	data, secrets, err := buildMigrationV2(cfg, state.Entries, key)
	defer clear(data)
	defer clearMigrationSecrets(secrets)
	if err != nil {
		return MigrationReport{}, err
	}
	if len(state.Entries) == 0 {
		return m.report(state, true), m.verifyV2(ctx, data, nil)
	}
	// The random item is only read. NotFound proves a reachable read path,
	// not write authorization; actual writes still require read-back checks.
	secret, err := registry.Resolve(ctx, credential.Ref{StoreID: opts.ToStore, ItemID: "migration-probe-" + credential.GenerateItemID()})
	defer clear(secret.Value)
	if err != nil && !errors.Is(err, credential.ErrCredentialNotFound) {
		return MigrationReport{}, fmt.Errorf("probe destination: %w", err)
	}
	return m.report(state, true), nil
}

func (m *CredentialMigrator) prepareBackups(state *migrationState, raw, key []byte) error {
	if err := m.saveState(state); err != nil {
		return err
	}
	if err := m.step("intent"); err != nil {
		return err
	}
	if err := m.ensureBackup(m.backupPath(), raw); err != nil {
		return err
	}
	if err := m.step("backup"); err != nil {
		return err
	}
	if len(key) != 0 {
		if err := m.ensureBackup(m.backupKeyPath(), key); err != nil {
			return err
		}
	}
	if err := m.step("key_backup"); err != nil {
		return err
	}
	return nil
}

func (m *CredentialMigrator) registryForPlan(cfg *CredentialConfig, state *migrationState) (*credential.Registry, error) {
	if len(state.Entries) != 0 {
		return m.migrationRegistry(cfg, state.Store)
	}
	if cfg == nil {
		return nil, fmt.Errorf("configure the destination store before migration")
	}
	if _, ok := cfg.Stores[state.Store]; !ok {
		return nil, fmt.Errorf("%w: destination %q", credential.ErrStoreNotFound, state.Store)
	}
	return m.migrationRegistry(cfg, "")
}
