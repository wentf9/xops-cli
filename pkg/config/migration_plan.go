package config

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/crypto"
	"github.com/wentf9/xops-cli/pkg/models"
	"gopkg.in/yaml.v3"
)

// Plain maps keep KnownFields active inside inventory records. The normal
// concurrent-map decoder deliberately accepts unknown fields for compatibility.
type migrationLegacyDTO struct {
	SchemaVersion         int                        `yaml:"schema_version,omitempty"`
	Credential            *CredentialConfig          `yaml:"credential,omitempty"`
	Identities            map[string]models.Identity `yaml:"identities"`
	Hosts                 map[string]models.Host     `yaml:"hosts"`
	Nodes                 map[string]models.Node     `yaml:"nodes"`
	Guardrail             *GuardrailConfig           `yaml:"guardrail,omitempty"`
	PasswordPromptPattern string                     `yaml:"password_prompt_pattern,omitempty"`
}

func decodeMigrationLegacy(data []byte) (*Configuration, error) {
	version, err := DetectSchemaVersion(data)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source schema", ErrSchemaValidation)
	}
	if version != 1 {
		return nil, fmt.Errorf("migration requires schema v1; source is schema v%d", version)
	}
	var dto migrationLegacyDTO
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&dto); err != nil {
		return nil, fmt.Errorf("%w: invalid legacy configuration", ErrSchemaValidation)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing YAML documents", ErrSchemaValidation)
	}
	cfg := cloneConfiguration(nil)
	cfg.SchemaVersion = dto.SchemaVersion
	cfg.Credential = dto.Credential
	cfg.Guardrail = dto.Guardrail
	cfg.PasswordPromptPattern = dto.PasswordPromptPattern
	for name, id := range dto.Identities {
		cfg.Identities.Set(name, id)
	}
	for name, host := range dto.Hosts {
		cfg.Hosts.Set(name, host)
	}
	for name, node := range dto.Nodes {
		cfg.Nodes.Set(name, node)
	}
	return cfg, nil
}

func (m *CredentialMigrator) migrationRegistry(cfg *CredentialConfig, destination string) (*credential.Registry, error) {
	if err := m.protectBackendKeys(cfg); err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("configure a credential store before migration")
	}
	if err := validateCredentialConfig(cfg); err != nil {
		return nil, err
	}
	if destination != "" {
		store, ok := cfg.Stores[destination]
		if !ok {
			return nil, fmt.Errorf("%w: destination %q", credential.ErrStoreNotFound, destination)
		}
		if store.Type == StoreTypeNone || store.ReadOnly {
			return nil, fmt.Errorf("%w: destination must support writes", credential.ErrCredentialStoreReadOnly)
		}
	}
	cloned := cfg.Clone()
	for name, store := range cloned.Stores {
		store.CacheTTL = 0
		cloned.Stores[name] = store
	}
	return m.registry(cloned)
}

func migrationEntries(cfg *Configuration, store string) ([]migrationEntry, error) {
	var entries []migrationEntry
	identities := cfg.Identities.Keys()
	sort.Strings(identities)
	for _, name := range identities {
		id, _ := cfg.Identities.Get(name)
		for _, item := range []struct {
			kind  credential.Kind
			value string
			ref   *credential.Ref
		}{
			{credential.KindLoginPassword, id.Password, id.LoginPasswordRef},
			{credential.KindPassphrase, id.Passphrase, id.PassphraseRef},
		} {
			if item.value == "" {
				continue
			}
			if item.ref != nil && !item.ref.IsEmpty() {
				return nil, fmt.Errorf("identity %q has both a legacy secret and a reference", name)
			}
			entries = append(entries, migrationEntry{Identity: name, Kind: item.kind, Ref: credential.Ref{StoreID: store, ItemID: credential.GenerateItemID()}})
		}
	}
	nodes := cfg.Nodes.Keys()
	sort.Strings(nodes)
	for _, name := range nodes {
		node, _ := cfg.Nodes.Get(name)
		if node.SuPwd == "" {
			continue
		}
		if node.PrivilegePasswordRef != nil && !node.PrivilegePasswordRef.IsEmpty() {
			return nil, fmt.Errorf("node %q has both a legacy secret and a reference", name)
		}
		entries = append(entries, migrationEntry{Node: name, Kind: credential.KindPrivilegePassword, Ref: credential.Ref{StoreID: store, ItemID: credential.GenerateItemID()}})
	}
	return entries, nil
}

func prepareMigrationState(cfg *Configuration, raw, key []byte, store string, existing *migrationState) (*migrationState, error) {
	if len(key) != 0 && len(key) != crypto.KeySize {
		return nil, fmt.Errorf("legacy key must contain %d bytes", crypto.KeySize)
	}
	keyHash := ""
	if len(key) != 0 {
		keyHash = migrationDigest(key)
	}
	entries, err := migrationEntries(cfg, store)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return &migrationState{Version: 1, Store: store, Phase: "intent", SourceHash: migrationDigest(raw), KeyHash: keyHash, Entries: entries}, nil
	}
	if existing.SourceHash != migrationDigest(raw) || existing.KeyHash != keyHash {
		return nil, fmt.Errorf("%w: source or legacy key differs from pending migration", ErrConfigConflict)
	}
	if len(entries) != len(existing.Entries) {
		return nil, fmt.Errorf("migration plan does not match source")
	}
	for i, entry := range entries {
		prior := existing.Entries[i]
		if entry.Identity != prior.Identity || entry.Node != prior.Node || entry.Kind != prior.Kind {
			return nil, fmt.Errorf("migration plan target mismatch")
		}
	}
	return existing, nil
}

func clearMigrationConfiguration(cfg *Configuration) {
	for _, name := range cfg.Identities.Keys() {
		id, _ := cfg.Identities.Get(name)
		id.Password = ""
		id.Passphrase = ""
		cfg.Identities.Set(name, id)
	}
	for _, name := range cfg.Nodes.Keys() {
		node, _ := cfg.Nodes.Get(name)
		node.SuPwd = ""
		cfg.Nodes.Set(name, node)
	}
}

func clearMigrationSecrets(secrets [][]byte) {
	for _, secret := range secrets {
		clear(secret)
	}
}

func migrationPlaintext(value string, key []byte) ([]byte, error) {
	if !crypto.IsEncrypted(value) {
		return []byte(value), nil
	}
	if len(key) != crypto.KeySize {
		return nil, fmt.Errorf("legacy key is missing for encrypted credentials")
	}
	crypter, err := crypto.NewCrypter(key)
	if err != nil {
		return nil, err
	}
	plain, err := crypter.Decrypt(value)
	if err != nil {
		return nil, fmt.Errorf("decrypt legacy credential failed")
	}
	return []byte(plain), nil
}

func buildMigrationV2(source *Configuration, entries []migrationEntry, key []byte) ([]byte, [][]byte, error) {
	cfg := source.Snapshot()
	defer clearMigrationConfiguration(cfg)
	secrets := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		plain, err := applyMigrationEntry(cfg, entry, key)
		if err != nil {
			clearMigrationSecrets(secrets)
			return nil, nil, err
		}
		secrets = append(secrets, plain)
	}
	cfg.SchemaVersion = 2
	dto, err := cfg.ToV2()
	if err != nil {
		return nil, secrets, err
	}
	data, err := yaml.Marshal(dto)
	return data, secrets, err
}

func applyMigrationEntry(cfg *Configuration, entry migrationEntry, key []byte) ([]byte, error) {
	if entry.Kind == credential.KindPrivilegePassword {
		node, ok := cfg.Nodes.Get(entry.Node)
		if !ok {
			return nil, fmt.Errorf("migration node not found")
		}
		plain, err := migrationPlaintext(node.SuPwd, key)
		if err != nil {
			return nil, err
		}
		node.SuPwd = ""
		node.PrivilegePasswordRef = entry.Ref.Clone()
		cfg.Nodes.Set(entry.Node, node)
		return plain, nil
	}
	id, ok := cfg.Identities.Get(entry.Identity)
	if !ok {
		return nil, fmt.Errorf("migration identity not found")
	}
	value := id.Password
	if entry.Kind == credential.KindPassphrase {
		value = id.Passphrase
	}
	plain, err := migrationPlaintext(value, key)
	if err != nil {
		return nil, err
	}
	if entry.Kind == credential.KindPassphrase {
		fingerprint, err := PrivateKeyFingerprint(id.KeyPath, plain)
		if err != nil {
			clear(plain)
			return nil, err
		}
		id.KeyFingerprint = fingerprint
		id.Passphrase = ""
		id.PassphraseRef = entry.Ref.Clone()
	} else {
		id.Password = ""
		id.LoginPasswordRef = entry.Ref.Clone()
	}
	cfg.Identities.Set(entry.Identity, id)
	return plain, nil
}

func (m *CredentialMigrator) transferSecrets(ctx context.Context, registry *credential.Registry, state *migrationState, secrets [][]byte) error {
	store, err := registry.GetStore(state.Store)
	if err != nil {
		return err
	}
	for i, entry := range state.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.transferSecret(ctx, store, entry.Ref, secrets[i], i); err != nil {
			return err
		}
	}
	return nil
}

func (m *CredentialMigrator) transferSecret(ctx context.Context, store credential.Store, ref credential.Ref, value []byte, index int) error {
	got, err := store.Get(ctx, ref)
	if err == nil {
		defer clear(got.Value)
		if subtle.ConstantTimeCompare(got.Value, value) != 1 {
			return fmt.Errorf("migration item %d already exists with different content", index)
		}
		return nil
	}
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		return fmt.Errorf("read pending migration item %d: %w", index, err)
	}
	if err := store.Put(ctx, ref, credential.Secret{Value: value}); err != nil {
		return fmt.Errorf("write migration item %d: %w", index, err)
	}
	if err := m.step(fmt.Sprintf("put:%d", index)); err != nil {
		return err
	}
	got, err = store.Get(ctx, ref)
	defer clear(got.Value)
	if err != nil {
		return fmt.Errorf("verify migration item %d: %w", index, err)
	}
	if subtle.ConstantTimeCompare(got.Value, value) != 1 {
		return fmt.Errorf("migration item %d read-back mismatch", index)
	}
	return m.step(fmt.Sprintf("readback:%d", index))
}

// Phase 6 can leave refs in a v1 file without the fingerprint required by v2.
// Preserve those refs and derive only missing metadata; never copy or overwrite
// the existing backend item as part of legacy migration.
func completeExistingKeyFingerprints(ctx context.Context, cfg *Configuration, registry *credential.Registry) error {
	for _, name := range cfg.Identities.Keys() {
		id, _ := cfg.Identities.Get(name)
		if id.PassphraseRef == nil || id.PassphraseRef.IsEmpty() || id.KeyFingerprint != "" {
			continue
		}
		fingerprint, err := fingerprintStoredKey(ctx, registry, *id.PassphraseRef, id.KeyPath)
		if err != nil {
			return err
		}
		id.KeyFingerprint = fingerprint
		cfg.Identities.Set(name, id)
	}
	return nil
}

func fingerprintStoredKey(ctx context.Context, registry *credential.Registry, ref credential.Ref, path string) (string, error) {
	secret, err := registry.Resolve(ctx, ref)
	defer clear(secret.Value)
	if err != nil {
		return "", fmt.Errorf("read existing passphrase reference for key binding: %w", err)
	}
	return PrivateKeyFingerprint(path, secret.Value)
}
