package adapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptossh "golang.org/x/crypto/ssh"
)

func buildW17bM2Fixtures(t *testing.T, withConflict bool) (*config.Provider, *config.Repository) {
	t.Helper()

	sshCfg := strings.Join([]string{
		"Host ssh-jump",
		"  HostName 10.30.0.1",
		"  User juser",
		"  Port 2201",
		"",
		"Host app-shared",
		"  HostName 10.10.0.1",
		"  User vuser",
		"  Port 2222",
		"  ProxyJump ssh-jump",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-w17b-shared-%h-%p-%r-%j-%C",
	}, "\n") + "\n"

	makeCfg := func() (*config.Configuration, *config.OpenSSHParser) {
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.SSHOptions = ssh.MustOptions(
			ssh.OptionControlMaster, "auto",
			ssh.OptionControlPath, "/tmp/cm-w17b-%h-%p-%r-%j-%C",
		)

		cfg.Hosts.Set("h-bastion", models.Host{Address: "10.10.0.254", Port: 2222})
		cfg.Identities.Set("id-bastion", models.Identity{User: "jump", AuthType: "auto"})
		cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-bastion"})

		cfg.Hosts.Set("h-bastion-b", models.Host{Address: "10.10.0.253", Port: 2222})
		cfg.Identities.Set("id-bastion-b", models.Identity{User: "jump2", AuthType: "auto"})
		cfg.Nodes.Set("bastion-b", models.Node{HostRef: "h-bastion-b", IdentityRef: "id-bastion-b"})

		cfg.Hosts.Set("h-web1", models.Host{Address: "10.10.0.1", Port: 2222})
		cfg.Identities.Set("id-web1", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("web-01", models.Node{
			HostRef:     "h-web1",
			IdentityRef: "id-web1",
			ProxyJump:   "bastion",
		})
		if withConflict {
			cfg.Identities.Set("id-web2", models.Identity{User: "admin", AuthType: "auto"})
			cfg.Nodes.Set("web-02", models.Node{
				HostRef:     "h-web1",
				IdentityRef: "id-web2",
				ProxyJump:   "bastion-b",
			})
		}
		return cfg, parser
	}

	roCfg, roParser := makeCfg()
	roProv := config.NewProviderWithOpenSSHParser(roCfg, roParser)

	repoCfg, repoParser := makeCfg()
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(repoCfg, store, repoParser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return roProv, repo
}

func assertW17bM2ParityCase(
	t *testing.T,
	env ssh.Environment,
	target config.ConnectionTarget,
	overrideOrig, overrideHost, wantJump string,
) {
	t.Helper()
	roProv, repo := buildW17bM2Fixtures(t, false)
	req := ControlTargetRequest{
		Provider:                 roProv,
		Target:                   target,
		ApplyTargetNodeOverrides: true,
		OverrideOriginalHost:     overrideOrig,
		OverrideExpandedHost:     overrideHost,
		Environment:              &env,
	}
	ctrlSock, ctrlRes, err := ResolveControlSocketPath(req)
	if err != nil {
		t.Fatalf("ResolveControlSocketPath: %v", err)
	}
	if ctrlRes.Target.JumpHost != wantJump {
		t.Fatalf("control JumpHost = %q, want %q", ctrlRes.Target.JumpHost, wantJump)
	}
	dialTarget, dialSock, _, _ := resolveW16bDialBaseline(t, repo, env, target, overrideOrig, overrideHost, "")
	if ctrlRes.Target != dialTarget || ctrlSock != dialSock {
		t.Fatalf("control vs dial mismatch:\n  target: %+v vs %+v\n  sock:   %q vs %q", ctrlRes.Target, dialTarget, ctrlSock, dialSock)
	}
}

func assertW17bM2CycleFailClosed(t *testing.T, env ssh.Environment) {
	t.Helper()
	roProv, _ := buildW17bM2Fixtures(t, false)
	req := ControlTargetRequest{
		Provider: roProv,
		Target: config.ConnectionTarget{
			Selector: "web-01",
			User:     "jump",
			HasUser:  true,
		},
		ApplyTargetNodeOverrides: true,
		OverrideOriginalHost:     "web-01",
		OverrideExpandedHost:     "10.10.0.254",
		Environment:              &env,
	}
	if res, err := ResolveControlTarget(req); err == nil {
		t.Fatalf("ResolveControlTarget bypassed ProxyJump cycle check: res=%+v", res)
	}
	if sock, res, err := ResolveControlSocketPath(req); err == nil {
		t.Fatalf("ResolveControlSocketPath bypassed ProxyJump cycle check: sock=%q res=%+v", sock, res)
	}
	if ctrl, err := ResolveControlConfig(roProv, "", "web-01", SessionAuth{
		User:     "jump",
		HostName: "10.10.0.254",
	}, SessionControlOptions{}); err == nil {
		t.Fatalf("ResolveControlConfig bypassed ProxyJump cycle check: ctrl=%+v", ctrl)
	}
}

func assertW17bM2AmbiguousFailClosed(t *testing.T, env ssh.Environment) {
	t.Helper()
	roProv, _ := buildW17bM2Fixtures(t, true)
	req := ControlTargetRequest{
		Provider: roProv,
		Target: config.ConnectionTarget{
			Selector: "web-01",
			User:     "altuser",
			HasUser:  true,
		},
		ApplyTargetNodeOverrides: true,
		OverrideOriginalHost:     "web-01",
		OverrideExpandedHost:     "10.10.0.99",
		Environment:              &env,
	}
	if res, err := ResolveControlTarget(req); err == nil || !strings.Contains(strings.ToLower(err.Error()), "ambiguous proxy jump") {
		t.Fatalf("ResolveControlTarget = (%+v, %v), want ambiguous proxy jump error", res, err)
	}
	if sock, res, err := ResolveControlSocketPath(req); err == nil || !strings.Contains(strings.ToLower(err.Error()), "ambiguous proxy jump") {
		t.Fatalf("ResolveControlSocketPath = (%q, %+v, %v), want ambiguous proxy jump error", sock, res, err)
	}
	if ctrl, err := ResolveControlConfig(roProv, "", "web-01", SessionAuth{
		User:     "altuser",
		HostName: "10.10.0.99",
	}, SessionControlOptions{}); err == nil || !strings.Contains(strings.ToLower(err.Error()), "ambiguous proxy jump") {
		t.Fatalf("ResolveControlConfig = (%+v, %v), want ambiguous proxy jump error", ctrl, err)
	}

	reqWithJump := req
	reqWithJump.Target.ProxyJump = "bastion"
	reqWithJump.Target.HasProxyJump = true
	res, err := ResolveControlTarget(reqWithJump)
	if err != nil || res.Target.JumpHost != "bastion" {
		t.Fatalf("ResolveControlTarget(explicit -J bastion) = (%+v, %v), want JumpHost=bastion", res, err)
	}

	reqNone := req
	reqNone.Target.ProxyJump = "none"
	reqNone.Target.HasProxyJump = true
	resNone, err := ResolveControlTarget(reqNone)
	if err != nil || resNone.Target.JumpHost != "" {
		t.Fatalf("ResolveControlTarget(explicit -J none) = (%+v, %v), want empty JumpHost", resNone, err)
	}
}

func TestP7W17b_L3_17_M2_HostNameOverrideInheritedProxyJumpParity(t *testing.T) {
	t.Parallel()

	env := ssh.Environment{
		LocalUser: "localuser",
		LocalHost: "workstation",
		HomeDir:   "/home/localuser",
	}

	t.Run("saved_node_user_and_hostname_override_preserves_inherited_proxyjump_and_socket_parity", func(t *testing.T) {
		t.Parallel()
		assertW17bM2ParityCase(t, env, config.ConnectionTarget{Selector: "web-01", User: "altuser", HasUser: true}, "web-01", "10.10.0.99", "bastion")
	})
	t.Run("saved_node_port_mismatch_and_hostname_override_matches_dial_empty_jump", func(t *testing.T) {
		t.Parallel()
		assertW17bM2ParityCase(t, env, config.ConnectionTarget{Selector: "web-01", Port: 2299, HasPort: true}, "web-01", "10.10.0.99", "")
	})
	t.Run("openssh_derived_shared_host_inherits_saved_proxyjump_under_hostname_override", func(t *testing.T) {
		t.Parallel()
		assertW17bM2ParityCase(t, env, config.ConnectionTarget{Selector: "app-shared", User: "altuser", HasUser: true}, "app-shared", "10.10.0.99", "bastion")
	})
	t.Run("combined_user_and_hostname_override_pointing_to_inherited_bastion_fails_closed_cycle", func(t *testing.T) {
		t.Parallel()
		assertW17bM2CycleFailClosed(t, env)
	})
	t.Run("ambiguous_multi_node_proxyjump_fails_closed_under_hostname_override_unless_tier1_overrides", func(t *testing.T) {
		t.Parallel()
		assertW17bM2AmbiguousFailClosed(t, env)
	})
}

type failingDeleteCredentialStore struct {
	*adapterCredentialStore
	failDeleteID string
	deleteErr    error
}

func (s *failingDeleteCredentialStore) Delete(ctx context.Context, ref credential.Ref) error {
	if s.failDeleteID != "" && ref.ItemID == s.failDeleteID {
		return s.deleteErr
	}
	return s.adapterCredentialStore.Delete(ctx, ref)
}

func writeEncryptedEd25519KeyFixture(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := cryptossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}
	return keyPath
}

func setupW17bPersistAuthFixture(
	t *testing.T,
	cfg *config.Configuration,
	initialSecrets map[string]string,
	failDeleteID string,
) (*config.Repository, *SSHAdapter, *adapterCredentialStore) {
	t.Helper()
	cfg.SchemaVersion = 2
	cfg.Credential = &config.CredentialConfig{
		DefaultStore: "mem",
		Stores: map[string]config.StoreConfig{
			"mem": {Type: config.StoreTypeNone},
		},
	}
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "key"))
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	mem := &adapterCredentialStore{data: make(map[string]credential.Secret, len(initialSecrets))}
	for id, val := range initialSecrets {
		mem.data[id] = credential.NewSecret([]byte(val))
	}
	reg := credential.NewRegistry()
	var regStore credential.Source = mem
	if failDeleteID != "" {
		regStore = &failingDeleteCredentialStore{
			adapterCredentialStore: mem,
			failDeleteID:           failDeleteID,
			deleteErr:              errors.New("simulated vault delete failure"),
		}
	}
	if err := reg.Register("mem", regStore); err != nil {
		t.Fatalf("Register(mem): %v", err)
	}
	journal, err := credential.NewJournalStore(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatalf("NewJournalStore: %v", err)
	}
	svc, err := credential.NewService(reg, journal, repo.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatalf("credential.NewService: %v", err)
	}
	adp := NewSSHAdapter(repo, WithCredentialSource(reg), WithCredentialService(svc))
	return repo, adp, mem
}

func assertW17bKeyToPasswordCleanup(t *testing.T) {
	t.Helper()
	oldPassRef := &credential.Ref{StoreID: "mem", ItemID: "old-passphrase"}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.80.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{
		User:           "ops",
		AuthType:       "key",
		KeyPath:        "/tmp/old-key",
		KeyFingerprint: "SHA256:old-key-fp",
		PassphraseRef:  oldPassRef,
	})
	cfg.Nodes.Set("node1", models.Node{HostRef: "h1", IdentityRef: "id1"})

	repo, adp, mem := setupW17bPersistAuthFixture(t, cfg, map[string]string{"old-passphrase": "key-secret"}, "")
	snap, err := repo.ResolveConnection("node1")
	if err != nil {
		t.Fatalf("ResolveConnection: %v", err)
	}
	if _, err := adp.UpdateAuth(t.Context(), "node1", string(snap.UpdateRef.AuthVersion[:]), "new-login-pw", "", ""); err != nil {
		t.Fatalf("UpdateAuth(password): %v", err)
	}
	after, err := repo.ResolveConnection("node1")
	if err != nil {
		t.Fatalf("ResolveConnection(after): %v", err)
	}
	if after.Identity.AuthType != "password" || after.Identity.PassphraseRef != nil || after.Identity.LoginPasswordRef == nil {
		t.Fatalf("unexpected identity after password rotation: %+v", after.Identity)
	}
	if _, stillPresent := mem.data["old-passphrase"]; stillPresent {
		t.Fatal("displaced PassphraseRef secret leaked in vault after rotating non-hybrid node to password")
	}
	if _, ok := mem.data[after.Identity.LoginPasswordRef.ItemID]; !ok {
		t.Fatalf("new LoginPasswordRef %q missing from vault", after.Identity.LoginPasswordRef.ItemID)
	}
}

func assertW17bPasswordToKeyCleanup(t *testing.T) {
	t.Helper()
	keyPath := writeEncryptedEd25519KeyFixture(t, "new-key-pass")
	oldLoginRef := &credential.Ref{StoreID: "mem", ItemID: "old-login-pw"}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.80.0.2", Port: 22})
	cfg.Identities.Set("id1", models.Identity{
		User:             "ops",
		AuthType:         "password",
		LoginPasswordRef: oldLoginRef,
	})
	cfg.Nodes.Set("node1", models.Node{HostRef: "h1", IdentityRef: "id1"})

	repo, adp, mem := setupW17bPersistAuthFixture(t, cfg, map[string]string{"old-login-pw": "old-secret"}, "")
	snap, err := repo.ResolveConnection("node1")
	if err != nil {
		t.Fatalf("ResolveConnection: %v", err)
	}
	if _, err := adp.UpdateAuth(t.Context(), "node1", string(snap.UpdateRef.AuthVersion[:]), "", keyPath, "new-key-pass"); err != nil {
		t.Fatalf("UpdateAuth(passphrase): %v", err)
	}
	after, err := repo.ResolveConnection("node1")
	if err != nil {
		t.Fatalf("ResolveConnection(after): %v", err)
	}
	if after.Identity.AuthType != "key" || after.Identity.LoginPasswordRef != nil || after.Identity.PassphraseRef == nil {
		t.Fatalf("unexpected identity after passphrase rotation: %+v", after.Identity)
	}
	if _, stillPresent := mem.data["old-login-pw"]; stillPresent {
		t.Fatal("displaced LoginPasswordRef secret leaked in vault after rotating non-hybrid node to key passphrase")
	}
	if _, ok := mem.data[after.Identity.PassphraseRef.ItemID]; !ok {
		t.Fatalf("new PassphraseRef %q missing from vault", after.Identity.PassphraseRef.ItemID)
	}
}

func assertW17bHybridPreservesOppositeKind(t *testing.T) {
	t.Helper()
	passRef := &credential.Ref{StoreID: "mem", ItemID: "hybrid-passphrase"}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.80.0.3", Port: 22})
	cfg.Identities.Set("id1", models.Identity{
		User:           "ops",
		AuthType:       "auto",
		KeyPath:        "/tmp/hybrid-key",
		KeyFingerprint: "SHA256:hybrid-key-fp",
		PassphraseRef:  passRef,
	})
	cfg.Nodes.Set("node1", models.Node{HostRef: "h1", IdentityRef: "id1"})

	repo, adp, mem := setupW17bPersistAuthFixture(t, cfg, map[string]string{"hybrid-passphrase": "keep-me"}, "")
	snap, err := repo.ResolveConnection("node1")
	if err != nil {
		t.Fatalf("ResolveConnection: %v", err)
	}
	if _, err := adp.UpdateAuth(t.Context(), "node1", string(snap.UpdateRef.AuthVersion[:]), "hybrid-pw", "", ""); err != nil {
		t.Fatalf("UpdateAuth(hybrid): %v", err)
	}
	after, err := repo.ResolveConnection("node1")
	if err != nil {
		t.Fatalf("ResolveConnection(after): %v", err)
	}
	if after.Identity.AuthType != "auto" || after.Identity.PassphraseRef == nil || *after.Identity.PassphraseRef != *passRef {
		t.Fatalf("hybrid identity lost PassphraseRef: %+v", after.Identity)
	}
	if _, ok := mem.data["hybrid-passphrase"]; !ok {
		t.Fatal("hybrid PassphraseRef was wrongly deleted from vault")
	}
}

func assertW17bSharedRefRetained(t *testing.T) {
	t.Helper()
	sharedPassRef := &credential.Ref{StoreID: "mem", ItemID: "shared-passphrase"}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.80.0.4", Port: 22})
	cfg.Hosts.Set("h2", models.Host{Address: "10.80.0.5", Port: 22})
	cfg.Identities.Set("id1", models.Identity{
		User:           "ops",
		AuthType:       "key",
		KeyPath:        "/tmp/shared-key",
		KeyFingerprint: "SHA256:shared-key-fp",
		PassphraseRef:  sharedPassRef.Clone(),
	})
	cfg.Identities.Set("id2", models.Identity{
		User:           "ops2",
		AuthType:       "key",
		KeyPath:        "/tmp/shared-key",
		KeyFingerprint: "SHA256:shared-key-fp",
		PassphraseRef:  sharedPassRef.Clone(),
	})
	cfg.Nodes.Set("node1", models.Node{HostRef: "h1", IdentityRef: "id1"})
	cfg.Nodes.Set("node2", models.Node{HostRef: "h2", IdentityRef: "id2"})

	repo, adp, mem := setupW17bPersistAuthFixture(t, cfg, map[string]string{"shared-passphrase": "still-shared"}, "")
	snap, err := repo.ResolveConnection("node1")
	if err != nil {
		t.Fatalf("ResolveConnection: %v", err)
	}
	if _, err := adp.UpdateAuth(t.Context(), "node1", string(snap.UpdateRef.AuthVersion[:]), "node1-pw", "", ""); err != nil {
		t.Fatalf("UpdateAuth(shared): %v", err)
	}
	if _, ok := mem.data["shared-passphrase"]; !ok {
		t.Fatal("shared PassphraseRef was deleted from vault despite node2 still referencing it")
	}
}

func assertW17bCleanupErrorPreservesCommit(t *testing.T) {
	t.Helper()
	oldPassRef := &credential.Ref{StoreID: "mem", ItemID: "stuck-passphrase"}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.80.0.6", Port: 22})
	cfg.Identities.Set("id1", models.Identity{
		User:           "ops",
		AuthType:       "key",
		KeyPath:        "/tmp/old-key",
		KeyFingerprint: "SHA256:stuck-key-fp",
		PassphraseRef:  oldPassRef,
	})
	cfg.Nodes.Set("node1", models.Node{HostRef: "h1", IdentityRef: "id1"})

	repo, adp, _ := setupW17bPersistAuthFixture(t, cfg, map[string]string{"stuck-passphrase": "stuck-secret"}, "stuck-passphrase")
	snap, err := repo.ResolveConnection("node1")
	if err != nil {
		t.Fatalf("ResolveConnection: %v", err)
	}
	oldTok := string(snap.UpdateRef.AuthVersion[:])
	nextTok, err := adp.UpdateAuth(t.Context(), "node1", oldTok, "committed-pw", "", "")
	var cleanupErr *credential.CleanupError
	if !errors.As(err, &cleanupErr) {
		t.Fatalf("UpdateAuth error = %v, want *credential.CleanupError", err)
	}
	if cleanupErr.OldRef != *oldPassRef {
		t.Fatalf("CleanupError.OldRef = %+v, want %+v", cleanupErr.OldRef, *oldPassRef)
	}
	if nextTok == "" || nextTok == oldTok {
		t.Fatalf("expected updated auth version token on CleanupError, got %q (old=%q)", nextTok, oldTok)
	}
	after, err := repo.ResolveConnection("node1")
	if err != nil {
		t.Fatalf("ResolveConnection(after): %v", err)
	}
	if after.Identity.AuthType != "password" || after.Identity.PassphraseRef != nil || after.Identity.LoginPasswordRef == nil {
		t.Fatalf("committed config should remain intact on CleanupError: %+v", after.Identity)
	}
}

func TestP7W17b_L4_17_M2_PersistAuthenticationCrossKindVaultCleanup(t *testing.T) {
	t.Parallel()

	t.Run("non_hybrid_key_rotating_to_password_deletes_displaced_passphrase_from_vault", func(t *testing.T) {
		t.Parallel()
		assertW17bKeyToPasswordCleanup(t)
	})
	t.Run("non_hybrid_password_rotating_to_passphrase_deletes_displaced_login_password_from_vault", func(t *testing.T) {
		t.Parallel()
		assertW17bPasswordToKeyCleanup(t)
	})
	t.Run("hybrid_auth_preserves_opposite_kind_ref_and_vault_secret", func(t *testing.T) {
		t.Parallel()
		assertW17bHybridPreservesOppositeKind(t)
	})
	t.Run("shared_opposite_kind_ref_is_retained_in_vault_when_referenced_by_another_identity", func(t *testing.T) {
		t.Parallel()
		assertW17bSharedRefRetained(t)
	})
	t.Run("vault_cleanup_failure_returns_cleanup_error_while_preserving_committed_config_and_version", func(t *testing.T) {
		t.Parallel()
		assertW17bCleanupErrorPreservesCommit(t)
	})
	t.Run("finalize_pending_connection_deletes_vault_ref_displaced_by_lease_confirm", func(t *testing.T) {
		t.Parallel()
		assertW17bFinalizePendingConnectionDisplacedRefCleanup(t)
	})
}

type w17bUnlinkingPendingLease struct {
	nodeID  string
	confirm func(context.Context) error
}

func (l w17bUnlinkingPendingLease) NodeID() string                    { return l.nodeID }
func (l w17bUnlinkingPendingLease) Confirm(ctx context.Context) error { return l.confirm(ctx) }
func (l w17bUnlinkingPendingLease) Release()                          {}
func (l w17bUnlinkingPendingLease) Created() bool                     { return false }

func assertW17bFinalizePendingConnectionDisplacedRefCleanup(t *testing.T) {
	t.Helper()
	oldLoginRef := &credential.Ref{StoreID: "mem", ItemID: "pending-displaced-login"}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.80.0.7", Port: 22})
	cfg.Identities.Set("id1", models.Identity{
		User:             "ops",
		AuthType:         "password",
		LoginPasswordRef: oldLoginRef,
	})
	cfg.Nodes.Set("node1", models.Node{HostRef: "h1", IdentityRef: "id1"})

	repo, adp, mem := setupW17bPersistAuthFixture(t, cfg, map[string]string{
		"pending-displaced-login": "old-pw-secret",
	}, "")
	err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "node1"},
		ExistingUpdate: config.PendingNodeUpdate{
			Enabled:      true,
			RememberAuth: true,
			IdentityFile: "/tmp/unencrypted-key",
		},
	}, func(realLease config.PendingLease) error {
		if !repo.IsPendingNode(realLease.NodeID()) {
			t.Fatalf("expected %q to be pending before FinalizePendingConnection", realLease.NodeID())
		}
		lease := w17bUnlinkingPendingLease{
			nodeID: realLease.NodeID(),
			confirm: func(ctx context.Context) error {
				if err := realLease.Confirm(ctx); err != nil {
					return err
				}
				confirmedSnap, rErr := repo.ResolveConnection("node1")
				if rErr != nil {
					return rErr
				}
				_, _, err := repo.AsConfigUpdater().ApplyCredentialRefAtVersion(ctx, credential.Target{
					NodeID:   "node1",
					Kind:     credential.KindLoginPassword,
					AuthType: "key",
				}, string(confirmedSnap.UpdateRef.AuthVersion[:]), nil)
				return err
			},
		}
		return adp.FinalizePendingConnection(t.Context(), lease, nil)
	})
	if err != nil {
		t.Fatalf("WithPendingNode/FinalizePendingConnection: %v", err)
	}
	if _, stillPresent := mem.data["pending-displaced-login"]; stillPresent {
		t.Fatal("displaced LoginPasswordRef leaked in vault after FinalizePendingConnection")
	}

	// Verify that when lease.Confirm leaves a pre-confirm ref still referenced, DeleteAssets retains it.
	keepRef := &credential.Ref{StoreID: "mem", ItemID: "pending-retained-login"}
	keepCfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	keepCfg.Hosts.Set("h1", models.Host{Address: "10.80.0.8", Port: 22})
	keepCfg.Identities.Set("id1", models.Identity{
		User:             "ops",
		AuthType:         "auto",
		LoginPasswordRef: keepRef,
	})
	keepCfg.Nodes.Set("node1", models.Node{HostRef: "h1", IdentityRef: "id1"})
	keepRepo, keepAdp, keepMem := setupW17bPersistAuthFixture(t, keepCfg, map[string]string{
		"pending-retained-login": "keep-pw-secret",
	}, "")
	if err := keepRepo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "node1"},
		ExistingUpdate: config.PendingNodeUpdate{
			Enabled:      true,
			RememberAuth: true,
			IdentityFile: "/tmp/hybrid-key",
		},
	}, func(realLease config.PendingLease) error {
		return keepAdp.FinalizePendingConnection(t.Context(), realLease, nil)
	}); err != nil {
		t.Fatalf("WithPendingNode/FinalizePendingConnection(retained): %v", err)
	}
	if _, ok := keepMem.data["pending-retained-login"]; !ok {
		t.Fatal("still-referenced LoginPasswordRef was wrongly deleted during FinalizePendingConnection")
	}
}

func TestP7W17b_L3_17_L1_EffectivePolicyOriginalHostOverlay(t *testing.T) {
	t.Parallel()

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host app-virtual\n  HostName 10.90.0.2\n  User vuser\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.90.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("web-01", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
	})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	t.Run("saved_and_virtual_nodes_overlay_session_auth_original_host_and_unwrap_openssh_prefix", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name     string
			nodeID   string
			sessOrig string
			wantOrig string
		}{
			{"saved_openssh_prefixed_alias", "web-01", "openssh:override-alias", "override-alias"},
			{"saved_openssh_prefixed_user_port", "web-01", "openssh:ops@override-alias:2222", "override-alias"},
			{"saved_plain_alias", "web-01", "plain-override", "plain-override"},
			{"saved_empty_stays_empty", "web-01", "", ""},
			{"virtual_empty_keeps_openssh_alias", "openssh:app-virtual", "", "app-virtual"},
			{"virtual_overlay_overrides_openssh_alias", "openssh:app-virtual", "openssh:custom-alias", "custom-alias"},
		} {
			adp := NewSSHAdapter(prov, WithSessionAuthOverride(tc.nodeID, SessionAuth{
				OriginalHost: tc.sessOrig,
			}))
			pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: tc.nodeID})
			if err != nil {
				t.Fatalf("%s: Resolve: %v", tc.name, err)
			}
			clientCfg, err := pol.ClientConfig()
			if err != nil {
				t.Fatalf("%s: ClientConfig: %v", tc.name, err)
			}
			gotOrig := pol.OriginalHost()
			if gotOrig != tc.wantOrig {
				t.Fatalf("%s: pol.OriginalHost() = %q, want %q", tc.name, gotOrig, tc.wantOrig)
			}
			if clientCfg.OriginalHost != gotOrig {
				t.Fatalf("%s: ClientConfig().OriginalHost = %q != OriginalHost() = %q", tc.name, clientCfg.OriginalHost, gotOrig)
			}
			wantTargetOrig := gotOrig
			if wantTargetOrig == "" {
				wantTargetOrig = tc.nodeID
			}
			if gotTargetOrig := pol.TargetContext().OriginalHost; gotTargetOrig != wantTargetOrig {
				t.Fatalf("%s: TargetContext().OriginalHost = %q, want %q", tc.name, gotTargetOrig, wantTargetOrig)
			}
		}
	})

	t.Run("no_snapshot_overlays_openssh_alias_and_session_auth_original_host", func(t *testing.T) {
		t.Parallel()
		originProv := config.NewProviderWithOpenSSHParser(cfg, parser)
		originProv.SetNodeOpenSSHOrigin("ops@10.90.0.9:22", config.OpenSSHOrigin{
			Alias:         "origin-alias",
			CanonicalHost: "origin-alias.corp.example.com",
		})

		polOrigin, err := NewSSHAdapter(originProv).Resolve(t.Context(), ResolveRequest{NodeID: "ops@10.90.0.9:22"})
		if err != nil {
			t.Fatalf("Resolve(noSnap origin): %v", err)
		}
		if polOrigin.hasSnapshot {
			t.Fatal("expected !hasSnapshot")
		}
		if got := polOrigin.OriginalHost(); got != "origin-alias" {
			t.Fatalf("noSnap pol.OriginalHost() = %q, want %q", got, "origin-alias")
		}
		if gotTarget := polOrigin.TargetContext().OriginalHost; gotTarget != "origin-alias" {
			t.Fatalf("noSnap TargetContext().OriginalHost = %q, want %q", gotTarget, "origin-alias")
		}

		polSess, err := NewSSHAdapter(originProv, WithSessionAuthOverride("ops@10.90.0.9:22", SessionAuth{
			OriginalHost: "openssh:ops@sess-alias:2222",
		})).Resolve(t.Context(), ResolveRequest{NodeID: "ops@10.90.0.9:22"})
		if err != nil {
			t.Fatalf("Resolve(noSnap session): %v", err)
		}
		if got := polSess.OriginalHost(); got != "sess-alias" {
			t.Fatalf("noSnap session pol.OriginalHost() = %q, want %q", got, "sess-alias")
		}
		if gotTarget := polSess.TargetContext().OriginalHost; gotTarget != "sess-alias" {
			t.Fatalf("noSnap session TargetContext().OriginalHost = %q, want %q", gotTarget, "sess-alias")
		}
	})
}
