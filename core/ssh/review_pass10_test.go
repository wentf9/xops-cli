package ssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

type pass10KeyStore struct {
	mu      sync.Mutex
	configs map[string]*ClientConfig
	tamper  func(nodeID string, cfg *ClientConfig)
}

func (s *pass10KeyStore) GetConfig(nodeID string) (*ClientConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, ok := s.configs[nodeID]
	if !ok || cfg == nil {
		return nil, nil
	}
	cp := *cfg
	cp.KeyPaths = slices.Clone(cfg.KeyPaths)
	return &cp, nil
}

func (s *pass10KeyStore) UpdateAuth(_ context.Context, nodeID, authUpdateToken, password, keyPath, passphrase string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.configs[nodeID]
	nextToken := authUpdateToken + "-next"
	cfg.AuthUpdateToken = nextToken
	cfg.AuthType = "key"
	if keyPath != "" {
		cfg.KeyPath = keyPath
		if !slices.Contains(cfg.KeyPaths, keyPath) {
			cfg.KeyPaths = append([]string{keyPath}, cfg.KeyPaths...)
		}
	}
	if password != "" {
		cfg.Password = password
	}
	if passphrase != "" {
		cfg.Passphrase = passphrase
	}
	if s.tamper != nil {
		s.tamper(nodeID, cfg)
	}
	return nextToken, nil
}

func (s *pass10KeyStore) UpdateSudo(_ context.Context, _, sudoUpdateToken string, _ SudoMode, _ string) (string, error) {
	return sudoUpdateToken, nil
}

func TestPass10_H1_KeyProjectionCompatibilityUnitAndConnect(t *testing.T) {
	t.Run("isCompatibleRecordedKeyProjection_matrix", func(t *testing.T) {
		if !isCompatibleRecordedKeyProjection("/k1", []string{"/k1", "/k2"}, "/k2", "/k1", []string{"/k1", "/k2"}) {
			t.Fatal("expected CLI multi-key primary preservation to be compatible")
		}
		if !isCompatibleRecordedKeyProjection("%d/.ssh/k2", []string{"%d/.ssh/k2"}, "/home/a/.ssh/k2", "%d/.ssh/k2", []string{"%d/.ssh/k2", "/home/a/.ssh/k2"}) {
			t.Fatal("expected template expansion insertion to be compatible")
		}
		if !isCompatibleRecordedKeyProjection("~/.ssh/k1", []string{"~/.ssh/k1", "~/.ssh/k2"}, "/home/a/.ssh/k2", "/home/a/.ssh/k2", []string{"/home/a/.ssh/k2", "~/.ssh/k1", "~/.ssh/k2"}) {
			t.Fatal("expected ssh_config managed-key promotion to be compatible")
		}
		if !isCompatibleRecordedKeyProjection("/old", []string{"/k1", "/k2", "/old"}, "/k2", "/k2", []string{"/k1", "/k2"}) {
			t.Fatal("expected single managed key replacement to be compatible")
		}
		if isCompatibleRecordedKeyProjection("/k1", []string{"/k1", "/k2"}, "/k2", "/evil", []string{"/evil", "/k1", "/k2"}) {
			t.Fatal("expected unrelated primary key drift to be rejected")
		}
		if isCompatibleRecordedKeyProjection("/k1", []string{"/k1", "/k2"}, "/k2", "/k2", []string{"/k2", "/evil", "/k1"}) {
			t.Fatal("expected unrelated extra key in KeyPaths to be rejected")
		}
	})

	fix := newPhase3CertFixture(t)
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	k1 := filepath.Join(sshDir, "id_wrong")
	k2 := filepath.Join(sshDir, "id_right")
	writeEd25519KeyFile(t, k1, "")
	_, pub2 := writeEd25519KeyFile(t, k2, "pass2")
	port, _ := startPhase3CertSSHServer(t, fix.hostSigner, nil, pub2, nil)

	t.Run("multi_key_fallback_remember_succeeds", func(t *testing.T) {
		opts := newPhase3TrustAllOptions(t, dir)
		_ = opts.Set(OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew)
		store := &pass10KeyStore{
			configs: map[string]*ClientConfig{
				"multi-key-rem": {
					NodeID:          "multi-key-rem",
					Address:         "127.0.0.1",
					Port:            port,
					User:            "alice",
					AuthType:        "auto",
					KeyPath:         k1,
					KeyPaths:        []string{k1, k2},
					AuthUpdateToken: "v1",
					Options:         opts,
				},
			},
		}
		env := fixtureEnvironment()
		env.HomeDir = dir
		prompter := &spyInteractionPrompter{passphrase: "pass2"}
		conn := NewConnector(store, WithCredentialRecorder(store), WithEnvironment(env), WithInteractionHandler(prompter))
		t.Cleanup(func() { _ = conn.CloseAll() })

		cli, err := conn.Connect(t.Context(), "multi-key-rem")
		if err != nil {
			t.Fatalf("Connect(multi-key-rem) failed: %v", err)
		}
		if got := cli.ConnectionConfig().AuthUpdateToken; got != "v1-next" {
			t.Errorf("AuthUpdateToken = %q, want v1-next", got)
		}
	})

	t.Run("template_token_key_remember_succeeds", func(t *testing.T) {
		opts := newPhase3TrustAllOptions(t, dir)
		_ = opts.Set(OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew)
		store := &pass10KeyStore{
			configs: map[string]*ClientConfig{
				"tpl-key": {
					NodeID:          "tpl-key",
					Address:         "127.0.0.1",
					Port:            port,
					User:            "alice",
					AuthType:        "auto",
					KeyPath:         "%d/.ssh/id_right",
					KeyPaths:        []string{"%d/.ssh/id_right"},
					AuthUpdateToken: "v1",
					Options:         opts,
				},
			},
		}
		env := fixtureEnvironment()
		env.HomeDir = dir
		prompter := &spyInteractionPrompter{passphrase: "pass2"}
		conn := NewConnector(store, WithCredentialRecorder(store), WithEnvironment(env), WithInteractionHandler(prompter))
		t.Cleanup(func() { _ = conn.CloseAll() })

		cli, err := conn.Connect(t.Context(), "tpl-key")
		if err != nil {
			t.Fatalf("Connect(tpl-key) failed: %v", err)
		}
		if got := cli.ConnectionConfig().AuthUpdateToken; got != "v1-next" {
			t.Errorf("AuthUpdateToken = %q, want v1-next", got)
		}
		if got := cli.ConnectionConfig().KeyPath; got != k2 {
			t.Errorf("synced KeyPath = %q, want %q", got, k2)
		}
	})

	t.Run("concurrent_tamper_still_fails_closed", func(t *testing.T) {
		opts := newPhase3TrustAllOptions(t, dir)
		_ = opts.Set(OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew)
		store := &pass10KeyStore{
			configs: map[string]*ClientConfig{
				"tamper-key": {
					NodeID:          "tamper-key",
					Address:         "127.0.0.1",
					Port:            port,
					User:            "alice",
					AuthType:        "auto",
					KeyPath:         k2,
					KeyPaths:        []string{k2},
					AuthUpdateToken: "v1",
					Options:         opts,
				},
			},
			tamper: func(_ string, cfg *ClientConfig) {
				cfg.KeyPaths = append(cfg.KeyPaths, "/evil/injected_key")
			},
		}
		env := fixtureEnvironment()
		env.HomeDir = dir
		prompter := &spyInteractionPrompter{passphrase: "pass2"}
		conn := NewConnector(store, WithCredentialRecorder(store), WithEnvironment(env), WithInteractionHandler(prompter))
		t.Cleanup(func() { _ = conn.CloseAll() })

		if _, err := conn.Connect(t.Context(), "tamper-key"); !errors.Is(err, ErrSnapshotMismatch) {
			t.Fatalf("expected ErrSnapshotMismatch on concurrent KeyPaths tamper, got: %v", err)
		}
	})
}
