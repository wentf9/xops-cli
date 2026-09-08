package tui

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

type memoryCredentialStore struct {
	data map[string]credential.Secret
}

type failingCredentialStore struct {
	*memoryCredentialStore
	failPut bool
	onPut   func() error
}

func (s *failingCredentialStore) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	if s.failPut {
		return credential.ErrCredentialStoreUnavailable
	}
	if s.onPut != nil {
		if err := s.onPut(); err != nil {
			return err
		}
	}
	return s.memoryCredentialStore.Put(ctx, ref, secret)
}

func newMemoryCredentialStore() *memoryCredentialStore {
	return &memoryCredentialStore{
		data: make(map[string]credential.Secret),
	}
}

func (m *memoryCredentialStore) Get(_ context.Context, ref credential.Ref) (credential.Secret, error) {
	s, ok := m.data[ref.ItemID]
	if !ok {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}
	return credential.Secret{Value: bytes.Clone(s.Value)}, nil
}

func (m *memoryCredentialStore) Put(_ context.Context, ref credential.Ref, secret credential.Secret) error {
	m.data[ref.ItemID] = credential.Secret{Value: bytes.Clone(secret.Value)}
	return nil
}

func (m *memoryCredentialStore) Delete(_ context.Context, ref credential.Ref) error {
	delete(m.data, ref.ItemID)
	return nil
}

func TestNodeFormState_NoSecretBackfilling(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{DefaultStore: "mem"},
	}

	nodeID := "user1@192.168.1.10:22"
	cfg.Nodes.Set(nodeID, models.Node{
		HostRef:     "192.168.1.10:22",
		IdentityRef: "user1@192.168.1.10",
		SudoMode:    models.SudoModeAuto,
	})
	cfg.Hosts.Set("192.168.1.10:22", models.Host{
		Address: "192.168.1.10",
		Port:    22,
	})
	cfg.Identities.Set("user1@192.168.1.10", models.Identity{
		User:     "user1",
		AuthType: "password",
		Password: "super_secret_plain_password",
		LoginPasswordRef: &credential.Ref{
			StoreID: "system",
			ItemID:  "item-12345",
		},
		Passphrase: "super_secret_passphrase",
		PassphraseRef: &credential.Ref{
			StoreID: "system",
			ItemID:  "item-67890",
		},
	})

	repo := newTestRepository(t, cfg)
	m := &Model{repository: repo}

	state, err := m.newNodeFormState(nodeID)
	if err != nil {
		t.Fatalf("newNodeFormState failed: %v", err)
	}

	// 核心红线 1：绝不将已有密码/私钥密码回填到表单明文字段中
	if state.password != "" {
		t.Errorf("expected password to not be backfilled, got %q", state.password)
	}
	if state.passphrase != "" {
		t.Errorf("expected passphrase to not be backfilled, got %q", state.passphrase)
	}

	// 核心要求 2：正确显示 Store 状态，且默认动作是 keep
	if !strings.Contains(state.passwordStoreStatus, "system") {
		t.Errorf("expected password store status to show 'system', got %q", state.passwordStoreStatus)
	}
	if state.passwordAction != "keep" {
		t.Errorf("expected default password action to be 'keep', got %q", state.passwordAction)
	}

	if !strings.Contains(state.passphraseStoreStatus, "system") {
		t.Errorf("expected passphrase store status to show 'system', got %q", state.passphraseStoreStatus)
	}
	if state.passphraseAction != "keep" {
		t.Errorf("expected default passphrase action to be 'keep', got %q", state.passphraseAction)
	}
}

func TestNodeFormState_KeepPreservesExistingCredentials(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	nodeID := "user2@192.168.1.20:22"
	cfg.Nodes.Set(nodeID, models.Node{
		HostRef:     "192.168.1.20:22",
		IdentityRef: "user2@192.168.1.20",
		SudoMode:    models.SudoModeAuto,
	})
	cfg.Hosts.Set("192.168.1.20:22", models.Host{
		Address: "192.168.1.20",
		Port:    22,
	})
	existingRef := &credential.Ref{
		StoreID: "mem",
		ItemID:  "item-keep-test",
	}
	cfg.Identities.Set("user2@192.168.1.20", models.Identity{
		User:             "user2",
		AuthType:         "password",
		LoginPasswordRef: existingRef.Clone(),
	})

	repo := newTestRepository(t, cfg)
	memStore := newMemoryCredentialStore()
	memStore.data[existingRef.ItemID] = credential.NewSecret([]byte("delete-me"))
	service := newFormCredentialTestService(t, repo, memStore)
	m := &Model{
		repository:        repo,
		credentialService: service,
		formState: &nodeFormState{
			isEdit:              true,
			originalID:          nodeID,
			user:                "user2",
			address:             "192.168.1.20",
			port:                "22",
			authType:            "password",
			password:            "", // 未输入新密码
			passwordAction:      "keep",
			existingPasswordRef: existingRef.Clone(),
			sudoMode:            "auto",
		},
	}

	if cmd := m.saveFormCmd(); cmd != nil {
		cmd()
	} else {
		t.Fatal("expected configuration mutation command")
	}

	updatedIdent, ok := repo.View().Configuration.Identities.Get("user2@192.168.1.20")
	if !ok {
		t.Fatalf("identity not found after mutation")
	}
	if updatedIdent.LoginPasswordRef == nil || updatedIdent.LoginPasswordRef.ItemID != "item-keep-test" {
		t.Errorf("expected LoginPasswordRef to be preserved, got %v", updatedIdent.LoginPasswordRef)
	}
}

func TestNodeFormState_DeleteRemovesCredentials(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{DefaultStore: "mem"},
	}

	nodeID := "user3@192.168.1.30:22"
	cfg.Nodes.Set(nodeID, models.Node{
		HostRef:     "192.168.1.30:22",
		IdentityRef: "user3@192.168.1.30",
		SudoMode:    models.SudoModeAuto,
	})
	cfg.Hosts.Set("192.168.1.30:22", models.Host{
		Address: "192.168.1.30",
		Port:    22,
	})
	existingRef := &credential.Ref{
		StoreID: "mem",
		ItemID:  "item-delete-test",
	}
	cfg.Identities.Set("user3@192.168.1.30", models.Identity{
		User:             "user3",
		AuthType:         "password",
		LoginPasswordRef: existingRef.Clone(),
	})

	repo := newTestRepository(t, cfg)
	memStore := newMemoryCredentialStore()
	memStore.data[existingRef.ItemID] = credential.NewSecret([]byte("delete-me"))
	service := newFormCredentialTestService(t, repo, memStore)
	m := &Model{
		repository:        repo,
		credentialService: service,
		formState: &nodeFormState{
			isEdit:              true,
			originalID:          nodeID,
			user:                "user3",
			address:             "192.168.1.30",
			port:                "22",
			authType:            "password",
			password:            "",
			passwordAction:      "delete",
			existingPasswordRef: existingRef.Clone(),
			sudoMode:            "auto",
		},
	}

	if cmd := m.saveFormCmd(); cmd != nil {
		cmd()
	} else {
		t.Fatal("expected configuration mutation command")
	}

	updatedIdent, ok := repo.View().Configuration.Identities.Get("user3@192.168.1.30")
	if !ok {
		t.Fatalf("identity not found after mutation")
	}
	if updatedIdent.LoginPasswordRef != nil && !updatedIdent.LoginPasswordRef.IsEmpty() {
		t.Errorf("expected LoginPasswordRef to be cleared, got %v", updatedIdent.LoginPasswordRef)
	}
	if updatedIdent.Password != "" {
		t.Errorf("expected plain password to be empty, got %q", updatedIdent.Password)
	}
}

func TestNodeFormState_ReplaceCredentialsWithService(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{
			DefaultStore: "mem",
			Stores: map[string]config.StoreConfig{
				"mem": {
					Type: "memory",
				},
			},
		},
	}

	nodeID := "user4@192.168.1.40:22"
	cfg.Nodes.Set(nodeID, models.Node{
		HostRef:     "192.168.1.40:22",
		IdentityRef: "user4@192.168.1.40",
		SudoMode:    models.SudoModeAuto,
	})
	cfg.Hosts.Set("192.168.1.40:22", models.Host{
		Address: "192.168.1.40",
		Port:    22,
	})
	cfg.Identities.Set("user4@192.168.1.40", models.Identity{
		User:     "user4",
		AuthType: "password",
	})

	repo := newTestRepository(t, cfg)
	memStore := newMemoryCredentialStore()
	reg := credential.NewRegistry()
	if err := reg.Register("mem", memStore); err != nil {
		t.Fatalf("Register mem store failed: %v", err)
	}
	journalStore, err := credential.NewJournalStore(tempDir)
	if err != nil {
		t.Fatalf("NewJournalStore failed: %v", err)
	}
	svc, err := credential.NewService(reg, journalStore, repo.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	m := &Model{
		repository:        repo,
		credentialService: svc,
		formState: &nodeFormState{
			isEdit:         true,
			originalID:     nodeID,
			user:           "user4",
			address:        "192.168.1.40",
			port:           "22",
			authType:       "password",
			password:       "brand_new_secret",
			passwordAction: "replace",
			sudoMode:       "auto",
		},
	}

	completeConfigurationMutation(t, m, m.saveFormCmd())

	updatedIdent, ok := repo.View().Configuration.Identities.Get("user4@192.168.1.40")
	if !ok {
		t.Fatalf("identity not found after mutation")
	}
	if updatedIdent.Password != "" {
		t.Errorf("expected plain password to be cleared, got %q", updatedIdent.Password)
	}
	if updatedIdent.LoginPasswordRef == nil || updatedIdent.LoginPasswordRef.IsEmpty() {
		t.Fatalf("expected LoginPasswordRef to be set, got %v", updatedIdent.LoginPasswordRef)
	}
	if updatedIdent.LoginPasswordRef.StoreID != "mem" {
		t.Errorf("expected StoreID=mem, got %q", updatedIdent.LoginPasswordRef.StoreID)
	}

	sec, err := memStore.Get(context.Background(), *updatedIdent.LoginPasswordRef)
	if err != nil {
		t.Fatalf("get secret from memory store failed: %v", err)
	}
	if string(sec.Value) != "brand_new_secret" {
		t.Errorf("expected secret value 'brand_new_secret', got %q", string(sec.Value))
	}
}

func TestNodeFormCredentialReplace_FailurePreservesLegacySecret(t *testing.T) {
	cfg := newFormCredentialTestConfiguration("legacy-password")
	repo := newTestRepository(t, cfg)
	store := &failingCredentialStore{memoryCredentialStore: newMemoryCredentialStore(), failPut: true}
	service := newFormCredentialTestService(t, repo, store)
	m := newPasswordReplaceFormModel(repo, service, "new-password")
	if cmd := m.saveFormCmd(); cmd != nil {
		cmd()
	} else {
		t.Fatal("expected configuration mutation command")
	}

	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil {
		t.Fatalf("resolve connection failed: %v", err)
	}
	if snapshot.Identity.Password != "legacy-password" {
		t.Fatalf("legacy password = %q, want preserved value", snapshot.Identity.Password)
	}
}

func TestNodeFormCredentialReplace_RejectsConcurrentCredentialMutation(t *testing.T) {
	cfg := newFormCredentialTestConfiguration("")
	repo := newTestRepository(t, cfg)
	store := &failingCredentialStore{memoryCredentialStore: newMemoryCredentialStore()}
	concurrentRef := credential.Ref{StoreID: "mem", ItemID: "concurrent-item"}
	store.onPut = func() error {
		_, _, err := repo.UpdateNodeCredentialRefAtVersionContext(t.Context(), formCredentialTestNodeID, "", credential.KindLoginPassword, &concurrentRef)
		return err
	}
	service := newFormCredentialTestService(t, repo, store)
	m := newPasswordReplaceFormModel(repo, service, "new-password")
	if cmd := m.saveFormCmd(); cmd != nil {
		cmd()
	} else {
		t.Fatal("expected configuration mutation command")
	}

	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil {
		t.Fatalf("resolve connection failed: %v", err)
	}
	if snapshot.Identity.LoginPasswordRef == nil || *snapshot.Identity.LoginPasswordRef != concurrentRef {
		t.Fatalf("credential reference = %v, want concurrent ref %v", snapshot.Identity.LoginPasswordRef, concurrentRef)
	}
}

func TestNodeFormCredentialDelete_ServiceFailurePreservesReference(t *testing.T) {
	cfg := newFormCredentialTestConfiguration("")
	oldRef := credential.Ref{StoreID: "mem", ItemID: "old-item"}
	identity, _ := cfg.Identities.Get("user@192.168.1.50")
	identity.LoginPasswordRef = oldRef.Clone()
	cfg.Identities.Set("user@192.168.1.50", identity)
	repo := newTestRepository(t, cfg)
	m := newPasswordReplaceFormModel(repo, nil, "")
	m.formState.passwordAction = "delete"
	m.formState.existingPasswordRef = oldRef.Clone()

	cmd := m.saveFormCmd()
	if cmd == nil {
		t.Fatal("expected configuration mutation command")
	}
	msg, ok := cmd().(configurationMutationMsg)
	if !ok || msg.err == nil {
		t.Fatalf("delete without credential service = %#v, want error", msg)
	}
	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil {
		t.Fatalf("resolve connection failed: %v", err)
	}
	if snapshot.Identity.LoginPasswordRef == nil || *snapshot.Identity.LoginPasswordRef != oldRef {
		t.Fatalf("credential ref = %v, want preserved %v", snapshot.Identity.LoginPasswordRef, oldRef)
	}
}

func TestNodeFormCredentialDelete_RemovesLegacyPlaintext(t *testing.T) {
	repo := newTestRepository(t, newFormCredentialTestConfiguration("legacy-password"))
	model := newPasswordReplaceFormModel(repo, newFormCredentialTestService(t, repo, newMemoryCredentialStore()), "")
	model.formState.passwordAction = "delete"
	completeConfigurationMutation(t, model, model.saveFormCmd())

	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil {
		t.Fatalf("resolve connection: %v", err)
	}
	if snapshot.Identity.Password != "" {
		t.Fatalf("legacy password = %q, want empty after delete", snapshot.Identity.Password)
	}
}

const formCredentialTestNodeID = "user@192.168.1.50:22"

func newFormCredentialTestConfiguration(password string) *config.Configuration {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{DefaultStore: "mem"},
	}
	cfg.Nodes.Set(formCredentialTestNodeID, models.Node{HostRef: "192.168.1.50:22", IdentityRef: "user@192.168.1.50", SudoMode: models.SudoModeAuto})
	cfg.Hosts.Set("192.168.1.50:22", models.Host{Address: "192.168.1.50", Port: 22})
	cfg.Identities.Set("user@192.168.1.50", models.Identity{User: "user", AuthType: "password", Password: password})
	return cfg
}

func newFormCredentialTestService(t *testing.T, repo *config.Repository, store credential.Store) *credential.Service {
	t.Helper()
	registry := credential.NewRegistry()
	if err := registry.Register("mem", store); err != nil {
		t.Fatalf("register credential store: %v", err)
	}
	journal, err := credential.NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatalf("create journal store: %v", err)
	}
	service, err := credential.NewService(registry, journal, repo.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatalf("create credential service: %v", err)
	}
	return service
}

func newPasswordReplaceFormModel(repo *config.Repository, service *credential.Service, password string) *Model {
	snapshot, _ := repo.ResolveConnection(formCredentialTestNodeID)
	return &Model{repository: repo, credentialService: service, formState: &nodeFormState{
		isEdit: true, originalID: formCredentialTestNodeID, user: "user", address: "192.168.1.50", port: "22",
		authType: "password", password: password, passwordAction: "replace", existingPlainPassword: snapshot.Identity.Password,
		existingPasswordRef: snapshot.Identity.LoginPasswordRef.Clone(), sudoMode: "auto",
	}}
}
