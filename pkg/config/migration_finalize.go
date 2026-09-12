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

func checkMigrationKey(path, expected string, allowMissing bool) error {
	data, err := readMigrationFile(path)
	if errors.Is(err, os.ErrNotExist) && (expected == "" || allowMissing) {
		return nil
	}
	if err != nil {
		return err
	}
	defer clear(data)
	if expected == "" || migrationDigest(data) != expected {
		return fmt.Errorf("%w: legacy material %q changed", ErrConfigConflict, path)
	}
	return nil
}

func (m *CredentialMigrator) finishVerification(ctx context.Context, state *migrationState, data []byte) (MigrationReport, error) {
	report := m.report(state, false)
	raw, err := readMigrationFile(m.backupPath())
	if err != nil {
		return report, err
	}
	defer clear(raw)
	if migrationDigest(raw) != state.SourceHash {
		return report, fmt.Errorf("migration backup differs from original configuration")
	}
	var key []byte
	if state.KeyHash != "" {
		key, err = readMigrationFile(m.backupKeyPath())
		if err != nil {
			return report, err
		}
		defer clear(key)
		if migrationDigest(key) != state.KeyHash {
			return report, fmt.Errorf("migration backup key changed")
		}
	}
	cfg, err := decodeMigrationLegacy(raw)
	if err != nil {
		return report, err
	}
	defer clearMigrationConfiguration(cfg)
	registry, err := m.migrationRegistry(cfg.Credential, "")
	if err != nil {
		return report, err
	}
	if err := completeExistingKeyFingerprints(ctx, cfg, registry); err != nil {
		return report, err
	}
	candidate, secrets, err := buildMigrationV2(cfg, state.Entries, key)
	defer clear(candidate)
	defer clearMigrationSecrets(secrets)
	if err != nil {
		return report, err
	}
	if migrationDigest(candidate) != state.CandidateHash || migrationDigest(data) != state.CandidateHash {
		return report, fmt.Errorf("%w: migrated configuration changed before verification", ErrConfigConflict)
	}
	expected := make(map[credential.Ref][]byte, len(secrets))
	for i, entry := range state.Entries {
		expected[entry.Ref] = secrets[i]
	}
	if err := m.verifyV2(ctx, data, expected); err != nil {
		return report, err
	}
	err = m.withConfigLock(ctx, func() error {
		current, err := readMigrationFile(m.path)
		if err != nil {
			return err
		}
		if migrationDigest(current) != state.CandidateHash {
			return fmt.Errorf("%w: configuration changed during verification", ErrConfigConflict)
		}
		if err := syncMigrationConfiguration(m.path); err != nil {
			return err
		}
		state.Phase = "verified"
		return m.saveState(state)
	})
	if err != nil {
		return report, err
	}
	return m.report(state, false), m.step("verified")
}

func (m *CredentialMigrator) verifyV2(ctx context.Context, data []byte, expected map[credential.Ref][]byte) error {
	dto, err := UnmarshalV2(data)
	if err != nil {
		return fmt.Errorf("%w: migrated schema v2 is invalid", ErrSchemaValidation)
	}
	cfg, err := FromV2(dto)
	if err != nil {
		return err
	}
	// Exercise the exact metadata snapshot contract without publishing secrets.
	if _, err := cfg.Snapshot().ToV2(); err != nil {
		return err
	}
	registry, err := m.migrationRegistry(cfg.Credential, "")
	if err != nil {
		return err
	}
	refs := make(map[credential.Ref]struct{})
	for _, id := range dto.Identities {
		for _, ref := range []*credential.Ref{id.LoginPasswordRef, id.PassphraseRef} {
			if ref != nil && !ref.IsEmpty() {
				refs[*ref] = struct{}{}
			}
		}
	}
	for _, node := range dto.Nodes {
		if ref := node.PrivilegePasswordRef; ref != nil && !ref.IsEmpty() {
			refs[*ref] = struct{}{}
		}
	}
	for ref := range refs {
		if err := verifyMigrationRef(ctx, registry, ref, expected); err != nil {
			return err
		}
	}
	return nil
}

func verifyMigrationRef(ctx context.Context, registry *credential.Registry, ref credential.Ref, expected map[credential.Ref][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	secret, err := registry.Resolve(ctx, ref)
	defer clear(secret.Value)
	if err != nil {
		return fmt.Errorf("verify reference in store %q: %w", ref.StoreID, err)
	}
	if len(secret.Value) == 0 || secret.IsExpired(time.Now()) {
		return fmt.Errorf("%w: migrated credential is empty or expired", credential.ErrCredentialNotFound)
	}
	if value, ok := expected[ref]; ok && subtle.ConstantTimeCompare(secret.Value, value) != 1 {
		return fmt.Errorf("migrated credential differs from legacy source")
	}
	return nil
}

// Finalize rechecks the current metadata-only config and all live references,
// then removes old files. Only this explicitly invoked operation deletes old
// material. Partial cleanup is retryable and never touches backend secrets.
func (m *CredentialMigrator) Finalize(ctx context.Context) (report MigrationReport, retErr error) {
	if ctx == nil {
		return report, fmt.Errorf("finalize requires context")
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
	if state == nil {
		return report, fmt.Errorf("no migration is pending finalization")
	}
	report = m.report(state, false)
	if state.Phase == "complete" {
		return report, nil
	}
	if state.Phase != "verified" && state.Phase != "finalizing" {
		return report, fmt.Errorf("migration must be verified before finalization; rerun migrate")
	}
	raw, err := readMigrationFile(m.path)
	if err != nil {
		return report, err
	}
	defer clear(raw)
	expected, secrets, err := m.finalizationExpectations(state)
	defer clearMigrationSecrets(secrets)
	if err != nil {
		return report, err
	}
	if err := m.verifyV2(ctx, raw, expected); err != nil {
		return report, err
	}
	if err := m.step("finalize_verified"); err != nil {
		return report, err
	}
	err = m.withConfigLock(ctx, func() error {
		current, err := readMigrationFile(m.path)
		if err != nil {
			return err
		}
		if migrationDigest(current) != migrationDigest(raw) {
			return fmt.Errorf("%w: configuration changed during finalization", ErrConfigConflict)
		}
		if err := syncMigrationConfiguration(m.path); err != nil {
			return err
		}
		if err := m.protectFinalizationKeys(current); err != nil {
			return err
		}
		return m.finalizeFiles(state)
	})
	if err != nil {
		return report, err
	}
	return m.report(state, false), nil
}

func (m *CredentialMigrator) finalizeFiles(state *migrationState) error {
	files := []struct{ path, hash, step string }{
		{m.keyPath, state.KeyHash, "remove_key"},
		{m.backupPath(), state.SourceHash, "remove_backup"},
		{m.backupKeyPath(), state.KeyHash, "remove_backup_key"},
	}
	for _, file := range files {
		if err := checkMigrationKey(file.path, file.hash, state.Phase == "finalizing"); err != nil {
			return err
		}
	}
	state.Phase = "finalizing"
	if err := m.saveState(state); err != nil {
		return err
	}
	if err := m.step("finalizing"); err != nil {
		return err
	}
	for _, file := range files {
		if file.hash == "" {
			continue
		}
		if err := os.Remove(file.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove legacy material %q: %w", file.path, err)
		}
		if err := syncParentDirectory(filepath.Dir(file.path)); err != nil {
			return err
		}
		if err := m.step(file.step); err != nil {
			return err
		}
	}
	state.Phase = "complete"
	return m.saveState(state)
}

// While rollback material still exists, compare unchanged migration refs to
// the source. Readability alone must not authorize deletion of the last good
// copy when a backend returns an incorrect value.
func (m *CredentialMigrator) finalizationExpectations(state *migrationState) (map[credential.Ref][]byte, [][]byte, error) {
	raw, err := readMigrationFile(m.backupPath())
	if errors.Is(err, os.ErrNotExist) && state.Phase == "finalizing" {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer clear(raw)
	if migrationDigest(raw) != state.SourceHash {
		return nil, nil, fmt.Errorf("migration backup changed")
	}
	var key []byte
	if state.KeyHash != "" {
		key, err = readMigrationFile(m.backupKeyPath())
		if err != nil {
			return nil, nil, err
		}
		defer clear(key)
		if migrationDigest(key) != state.KeyHash {
			return nil, nil, fmt.Errorf("migration key backup changed")
		}
	}
	cfg, err := decodeMigrationLegacy(raw)
	if err != nil {
		return nil, nil, err
	}
	defer clearMigrationConfiguration(cfg)
	// No key-file access is needed here: finalize compares secret values, not
	// authentication against potentially changed private-key files.
	values := make([][]byte, 0, len(state.Entries))
	expected := make(map[credential.Ref][]byte, len(state.Entries))
	for _, entry := range state.Entries {
		var value string
		if entry.Node != "" {
			node, _ := cfg.Nodes.Get(entry.Node)
			value = node.SuPwd
		} else {
			id, _ := cfg.Identities.Get(entry.Identity)
			value = id.Password
			if entry.Kind == credential.KindPassphrase {
				value = id.Passphrase
			}
		}
		secret, err := migrationPlaintext(value, key)
		if err != nil {
			clearMigrationSecrets(values)
			return nil, nil, err
		}
		values = append(values, secret)
		expected[entry.Ref] = secret
	}
	return expected, values, nil
}
