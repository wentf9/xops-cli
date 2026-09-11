package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/wentf9/xops-cli/pkg/credential"
	"gopkg.in/yaml.v3"
)

type backendMigrationEntry struct {
	Source credential.Ref `json:"source"`
	Target credential.Ref `json:"target"`
}

// Separate from legacy migration state: neither this record nor its backup
// contains secret values, and completing it never authorizes source deletion.
type backendMigrationState struct {
	Version       int                     `json:"version"`
	Store         string                  `json:"store"`
	SourceHash    string                  `json:"sourceHash"`
	CandidateHash string                  `json:"candidateHash"`
	Verified      bool                    `json:"verified"`
	Entries       []backendMigrationEntry `json:"entries"`
}

func (m *CredentialMigrator) backendStatePath() string { return m.path + ".backend-migration.json" }
func (m *CredentialMigrator) backendBackupPath(hash string) string {
	return m.path + ".v2." + hash + ".bak"
}

func (m *CredentialMigrator) loadBackendState() (*backendMigrationState, error) {
	raw, err := readMigrationFile(m.backendStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state backendMigrationState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("invalid backend migration state")
	}
	if state.Version != 1 || !validMigrationHash(state.SourceHash) || !validMigrationHash(state.CandidateHash) || state.Store == "" {
		return nil, fmt.Errorf("invalid backend migration state header")
	}
	seen := make(map[credential.Ref]bool)
	targets := make(map[credential.Ref]bool)
	for _, e := range state.Entries {
		if e.Source.Validate() != nil || e.Target.Validate() != nil || e.Source.IsEmpty() || e.Target.IsEmpty() || e.Source.StoreID == state.Store || e.Target.StoreID != state.Store || seen[e.Source] || targets[e.Target] {
			return nil, fmt.Errorf("invalid backend migration references")
		}
		seen[e.Source], targets[e.Target] = true, true
	}
	return &state, nil
}

func validMigrationHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (m *CredentialMigrator) saveBackendState(state *backendMigrationState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode backend migration: %w", err)
	}
	result, err := m.write(m.backendStatePath(), raw, 0600)
	if err != nil {
		return fmt.Errorf("persist backend migration: %w", err)
	}
	if !result.Applied || !result.Durable {
		return fmt.Errorf("backend migration state is not confirmed durable")
	}
	return nil
}

func backendRefs(cfg *ConfigurationV2) []credential.Ref {
	seen := make(map[credential.Ref]bool)
	add := func(ref *credential.Ref) {
		if ref != nil && !ref.IsEmpty() {
			seen[*ref] = true
		}
	}
	for _, id := range cfg.Identities {
		add(id.LoginPasswordRef)
		add(id.PassphraseRef)
	}
	for _, node := range cfg.Nodes {
		add(node.PrivilegePasswordRef)
	}
	refs := make([]credential.Ref, 0, len(seen))
	for ref := range seen {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].StoreID != refs[j].StoreID {
			return refs[i].StoreID < refs[j].StoreID
		}
		return refs[i].ItemID < refs[j].ItemID
	})
	return refs
}

func planBackendMigration(raw []byte, store string, prior *backendMigrationState) (*backendMigrationState, []byte, error) {
	cfg, err := UnmarshalV2(raw)
	if err != nil {
		return nil, nil, err
	}
	state := &backendMigrationState{Version: 1, Store: store, SourceHash: migrationDigest(raw)}
	for _, ref := range backendRefs(cfg) {
		if ref.StoreID != store {
			state.Entries = append(state.Entries, backendMigrationEntry{Source: ref, Target: credential.Ref{StoreID: store, ItemID: credential.GenerateItemID()}})
		}
	}
	if prior != nil {
		if prior.SourceHash != state.SourceHash || prior.Store != store || len(prior.Entries) != len(state.Entries) {
			return nil, nil, fmt.Errorf("%w: pending backend migration differs from source or destination; use --restart to plan from current configuration", ErrConfigConflict)
		}
		for i := range state.Entries {
			if prior.Entries[i].Source != state.Entries[i].Source {
				return nil, nil, fmt.Errorf("invalid backend migration plan")
			}
		}
		state = prior
	}
	replacements := make(map[credential.Ref]credential.Ref)
	for _, entry := range state.Entries {
		replacements[entry.Source] = entry.Target
	}
	replace := func(ref *credential.Ref) *credential.Ref {
		if ref != nil {
			if target, ok := replacements[*ref]; ok {
				return target.Clone()
			}
		}
		return ref
	}
	for name, id := range cfg.Identities {
		id.LoginPasswordRef = replace(id.LoginPasswordRef)
		id.PassphraseRef = replace(id.PassphraseRef)
		cfg.Identities[name] = id
	}
	for name, node := range cfg.Nodes {
		node.PrivilegePasswordRef = replace(node.PrivilegePasswordRef)
		cfg.Nodes[name] = node
	}
	cfg.Credential.DefaultStore = store
	if err := ValidateV2(cfg); err != nil {
		return nil, nil, err
	}
	candidate, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("encode backend migration candidate: %w", err)
	}
	hash := migrationDigest(candidate)
	if state.CandidateHash != "" && state.CandidateHash != hash {
		return nil, nil, fmt.Errorf("backend migration candidate differs from recorded plan")
	}
	state.CandidateHash = hash
	return state, candidate, nil
}

func (m *CredentialMigrator) backendReport(state *backendMigrationState, dry bool) MigrationReport {
	return MigrationReport{Store: state.Store, Credentials: len(state.Entries), BackupPath: m.backendBackupPath(state.SourceHash), DryRun: dry, Verified: state.Verified, BackendMigration: true}
}
