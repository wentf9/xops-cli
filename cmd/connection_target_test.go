package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

type memoryStore struct {
	cfg *config.Configuration
}

func (m *memoryStore) Load() (*config.Configuration, error) {
	return m.cfg, nil
}

func (m *memoryStore) Save(cfg *config.Configuration) error {
	m.cfg = cfg
	return nil
}

func setupTestRepository(t *testing.T) *config.Repository {
	t.Helper()
	cfg, err := config.NewProvider(nil)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}
	snapshot := cfg.Snapshot()
	snapshot.Hosts.Set("10.238.221.181:22", models.Host{
		Address: "10.238.221.181",
		Port:    22,
	})
	snapshot.Identities.Set("iaas@10.238.221.181", models.Identity{
		User:     "iaas",
		AuthType: "auto",
		Password: "secretPassword",
	})
	snapshot.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "10.238.221.181:22",
		IdentityRef: "iaas@10.238.221.181",
		ProxyJump:   "jump-01",
		Alias:       []string{"web-01"},
		Tags:        []string{"production"},
	})
	// 显式指定 none store，防止在 CI headless Linux 环境（无 D-Bus）中
	// credentialConfigOrDefault 尝试初始化 system store 失败
	snapshot.Credential = &config.CredentialConfig{
		DefaultStore: "none",
		Stores: map[string]config.StoreConfig{
			"none": {Type: config.StoreTypeNone},
		},
	}

	store := &memoryStore{cfg: snapshot}
	repo, err := config.NewRepositoryWithoutOpenSSH(snapshot, store)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	return repo
}

func TestCommands_Consistency_ExplicitUserReusesHost(t *testing.T) {
	ctx := context.Background()
	t.Run("ssh", func(t *testing.T) { testSSHExplicitUserReusesHost(t, ctx) })
	t.Run("sftp", func(t *testing.T) { testSFTPExplicitUserReusesHost(t, ctx) })
	t.Run("scp", func(t *testing.T) { testSCPExplicitUserReusesHost(t, ctx) })
	t.Run("exec", func(t *testing.T) { testExecExplicitUserReusesHost(t, ctx) })
}

func testSSHExplicitUserReusesHost(t *testing.T, ctx context.Context) {
	repo := setupTestRepository(t)
	sshOpt := NewSshOptions()
	sshOpt.args = []string{"test@10.238.221.181"}
	if err := sshOpt.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		if !repo.IsPendingNode(nodeID) || nodeID != "test@10.238.221.181:22" {
			t.Errorf("ssh got nodeID=%q, pending=%v, want test@10.238.221.181:22, true", nodeID, repo.IsPendingNode(nodeID))
		}
		snap := repo.Snapshot()
		if len(snap.Hosts.Keys()) != 1 {
			t.Errorf("expected host to be reused (1 host), got %d", len(snap.Hosts.Keys()))
		}
		node, _, ident, resolveErr := repo.Resolve(nodeID)
		if resolveErr != nil || node.ProxyJump != "jump-01" {
			t.Errorf("expected inherited ProxyJump 'jump-01', got %+v", node)
		}
		if len(node.Alias) != 0 || len(node.Tags) != 0 {
			t.Errorf("new node must not inherit alias/tags, got %+v", node)
		}
		if ident.User != "test" || ident.Password != "" {
			t.Errorf("new identity must exist and not inherit secretPassword, got %+v", ident)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingNode failed: %v", err)
	}
}

func testSFTPExplicitUserReusesHost(t *testing.T, ctx context.Context) {
	repo := setupTestRepository(t)
	sftpOpt := NewSftpOptions()
	sftpOpt.args = []string{"test@10.238.221.181"}
	if err := sftpOpt.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if err := sftpOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		if !repo.IsPendingNode(nodeID) || nodeID != "test@10.238.221.181:22" {
			t.Errorf("sftp got nodeID=%q, pending=%v, want test@10.238.221.181:22, true", nodeID, repo.IsPendingNode(nodeID))
		}
		snap := repo.Snapshot()
		if len(snap.Hosts.Keys()) != 1 {
			t.Errorf("expected host to be reused (1 host), got %d", len(snap.Hosts.Keys()))
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingNode failed: %v", err)
	}
}

func testSCPExplicitUserReusesHost(t *testing.T, ctx context.Context) {
	repo := setupTestRepository(t)
	scpOpt := NewScpOptions()
	scpOpt.Source = "local.txt"
	scpOpt.Dest = "test@10.238.221.181:/tmp/remote.txt"
	dst, err := parsePath(scpOpt.Dest)
	if err != nil {
		t.Fatalf("parsePath failed: %v", err)
	}
	if err := scpOpt.withTestPendingPath(ctx, repo, dst, "", func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		if !repo.IsPendingNode(nodeID) || nodeID != "test@10.238.221.181:22" {
			t.Errorf("scp got nodeID=%q, pending=%v, want test@10.238.221.181:22, true", nodeID, repo.IsPendingNode(nodeID))
		}
		snap := repo.Snapshot()
		if len(snap.Hosts.Keys()) != 1 {
			t.Errorf("expected host to be reused (1 host), got %d", len(snap.Hosts.Keys()))
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingPath failed: %v", err)
	}
}

func testExecExplicitUserReusesHost(t *testing.T, ctx context.Context) {
	repo := setupTestRepository(t)
	execOpt := NewExecOptions()
	execOpt.Host = "test@10.238.221.181"
	if err := execOpt.withTestPendingHostTasks(ctx, repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
		if len(hostErrs) > 0 {
			t.Fatalf("withTestPendingHostTasks hostErrs=%v", hostErrs)
		}
		if len(tasks) != 1 || tasks[0].nodeID != "test@10.238.221.181:22" {
			t.Errorf("exec got tasks=%+v, want 1 task with nodeID=test@10.238.221.181:22", tasks)
		}
		snap := repo.Snapshot()
		if len(snap.Hosts.Keys()) != 1 {
			t.Errorf("expected host to be reused (1 host), got %d", len(snap.Hosts.Keys()))
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingHostTasks failed: %v", err)
	}
}

func TestCommands_Consistency_AliasResolvesCanonicalNode(t *testing.T) {
	ctx := context.Background()

	// SSH test@web-01 -> test@10.238.221.181:22
	t.Run("ssh_alias", func(t *testing.T) {
		repo := setupTestRepository(t)
		sshOpt := NewSshOptions()
		sshOpt.args = []string{"test@web-01"}
		if err := sshOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
			nodeID := lease.NodeID()
			if !repo.IsPendingNode(nodeID) || nodeID != "test@10.238.221.181:22" {
				t.Errorf("got nodeID=%q, pending=%v, want test@10.238.221.181:22, true", nodeID, repo.IsPendingNode(nodeID))
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingNode failed: %v", err)
		}
	})

	// Exec test@web-01 -> test@10.238.221.181:22
	t.Run("exec_alias", func(t *testing.T) {
		repo := setupTestRepository(t)
		execOpt := NewExecOptions()
		execOpt.Host = "test@web-01"
		if err := execOpt.withTestPendingHostTasks(ctx, repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
			if len(hostErrs) > 0 {
				t.Fatalf("withTestPendingHostTasks hostErrs=%v", hostErrs)
			}
			if len(tasks) != 1 || tasks[0].nodeID != "test@10.238.221.181:22" {
				t.Errorf("exec got tasks=%+v, want test@10.238.221.181:22", tasks)
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingHostTasks failed: %v", err)
		}
	})
}

func TestCommands_Consistency_BareAddressSingleMatchesMultiAmbiguous(t *testing.T) {
	ctx := context.Background()

	// 1. Single node matches bare address
	t.Run("bare_single_matches", func(t *testing.T) {
		repo := setupTestRepository(t)
		sshOpt := NewSshOptions()
		sshOpt.args = []string{"10.238.221.181"}
		if err := sshOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
			nodeID := lease.NodeID()
			if repo.IsPendingNode(nodeID) || nodeID != "iaas@10.238.221.181:22" {
				t.Errorf("got nodeID=%q, pending=%v, want iaas@10.238.221.181:22, false", nodeID, repo.IsPendingNode(nodeID))
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingNode failed: %v", err)
		}
	})

	// 2. Add second user on same address -> bare address becomes ambiguous
	t.Run("bare_multi_ambiguous", func(t *testing.T) {
		repo := setupTestRepository(t)
		// create a second node for root
		_, err := repo.EnsureNodeContext(ctx, config.EnsureNodeOptions{
			Target: config.ConnectionTarget{
				Selector: "10.238.221.181",
				User:     "root",
				HasUser:  true,
			},
		})
		if err != nil {
			t.Fatalf("failed to create second node: %v", err)
		}

		sshOpt := NewSshOptions()
		sshOpt.args = []string{"10.238.221.181"}
		if err := sshOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		err = sshOpt.withTestPendingNode(ctx, repo, func(config.PendingLease) error { return nil })
		if err == nil {
			t.Fatalf("expected ambiguous error for multi-user bare address, got nil")
		}
		if !strings.Contains(err.Error(), "ambiguous") {
			t.Errorf("expected ambiguous error, got %v", err)
		}

		// Exec with bare address also returns error
		execOpt := NewExecOptions()
		execOpt.Host = "10.238.221.181"
		var execHostErrs []error
		err = execOpt.withTestPendingHostTasks(ctx, repo, func(_ []execHostTask, _ []config.PendingLease, hostErrs []error) error {
			execHostErrs = hostErrs
			return nil
		})
		if len(execHostErrs) == 0 && err == nil {
			t.Errorf("exec expected error for ambiguous bare address, got none")
		}
	})
}

func TestCommands_Consistency_ExplicitPort(t *testing.T) {
	ctx := context.Background()

	repo := setupTestRepository(t)
	sshOpt := NewSshOptions()
	sshOpt.Port = 2222
	sshOpt.args = []string{"test@10.238.221.181"}
	if err := sshOpt.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		if !repo.IsPendingNode(nodeID) || nodeID != "test@10.238.221.181:2222" {
			t.Errorf("got nodeID=%q, want test@10.238.221.181:2222", nodeID)
		}
		snap := repo.Snapshot()
		if len(snap.Hosts.Keys()) != 1 {
			t.Errorf("pending port must not create a saved host, got %d hosts", len(snap.Hosts.Keys()))
		}
		_, host, _, err := repo.Resolve(nodeID)
		if err != nil || host.Port != 2222 {
			t.Fatalf("pending connection port = %d, error = %v", host.Port, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingNode failed: %v", err)
	}
}

func TestCommands_SSH_FlagPrecedence(t *testing.T) {
	ctx := context.Background()

	t.Run("flag_user_overrides_positional_user", func(t *testing.T) {
		repo := setupTestRepository(t)
		sshOpt := NewSshOptions()
		sshOpt.User = "test"
		sshOpt.args = []string{"iaas@10.238.221.181"}
		if err := sshOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
			nodeID := lease.NodeID()
			// Must use test, not iaas
			if !repo.IsPendingNode(nodeID) || nodeID != "test@10.238.221.181:22" {
				t.Errorf("expected nodeID 'test@10.238.221.181:22', got %q (pending=%v)", nodeID, repo.IsPendingNode(nodeID))
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingNode failed: %v", err)
		}
	})

	t.Run("flag_port_overrides_positional_port", func(t *testing.T) {
		repo := setupTestRepository(t)
		sshOpt := NewSshOptions()
		sshOpt.Port = 2222
		sshOpt.args = []string{"test@10.238.221.181:22"}
		if err := sshOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
			nodeID := lease.NodeID()
			// Must use 2222, not 22
			if !repo.IsPendingNode(nodeID) || nodeID != "test@10.238.221.181:2222" {
				t.Errorf("expected nodeID 'test@10.238.221.181:2222', got %q", nodeID)
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingNode failed: %v", err)
		}
	})
}

func TestCommands_Exec_Sudo(t *testing.T) {
	ctx := context.Background()
	repo := setupTestRepository(t)

	execOpt := NewExecOptions()
	execOpt.Host = "test@10.238.221.181"
	execOpt.Sudo = true

	if err := execOpt.withTestPendingHostTasks(ctx, repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
		if len(hostErrs) > 0 {
			t.Fatalf("withTestPendingHostTasks hostErrs=%v", hostErrs)
		}
		if len(tasks) != 1 || tasks[0].nodeID != "test@10.238.221.181:22" {
			t.Fatalf("unexpected tasks: %+v", tasks)
		}
		node, _, _, resolveErr := repo.Resolve("test@10.238.221.181:22")
		if resolveErr != nil {
			t.Fatalf("node test@10.238.221.181:22 not found in snapshot")
		}
		if node.SudoMode != models.SudoModeSudo {
			t.Errorf("expected SudoMode=%q, got %q", models.SudoModeSudo, node.SudoMode)
		}
		if node.SuPwd != "" {
			t.Errorf("expected discovered sudo password to remain session-only, got %q", node.SuPwd)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingHostTasks failed: %v", err)
	}
}

func TestCommands_ExistingNodeCredentialsStayOutOfConfiguration(t *testing.T) {
	repo := setupTestRepository(t)
	sshOpt := NewSshOptions()
	sshOpt.Remember = "always"
	sshOpt.Password = "new-synthetic-password"
	sshOpt.Target = config.ConnectionTarget{Selector: "10.238.221.181", User: "iaas", HasUser: true}

	if err := sshOpt.withTestPendingNode(t.Context(), repo, func(lease config.PendingLease) error {
		if err := lease.Confirm(t.Context()); err != nil {
			t.Fatalf("lease.Confirm: %v", err)
		}
		snapshot, err := repo.ResolveConnection(lease.NodeID())
		if err != nil {
			t.Fatalf("resolve connection failed: %v", err)
		}
		if snapshot.Identity.Password == sshOpt.Password {
			t.Fatal("SSH option password was persisted in configuration")
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingNode failed: %v", err)
	}

	execOpt := NewExecOptions()
	execOpt.Remember = "always"
	execOpt.Interactive = true
	execOpt.Host = "iaas@10.238.221.181"
	if err := execOpt.withTestPendingHostTasks(t.Context(), repo, func(tasks []execHostTask, leases []config.PendingLease, hostErrs []error) error {
		if len(hostErrs) > 0 || len(tasks) != 1 {
			t.Fatalf("withTestPendingHostTasks: tasks=%v hostErrs=%v", tasks, hostErrs)
		}
		if err := leases[0].Confirm(t.Context()); err != nil {
			t.Fatalf("exec lease.Confirm: %v", err)
		}
		snapshot, err := repo.ResolveConnection(tasks[0].nodeID)
		if err != nil {
			t.Fatalf("resolve connection after exec update failed: %v", err)
		}
		if snapshot.Node.SuPwd != "" {
			t.Fatal("exec sudo password was persisted in configuration")
		}
		return nil
	}); err != nil {
		t.Fatalf("exec withTestPendingHostTasks failed: %v", err)
	}
}

func TestCommands_ExecUsesPerHostSessionPassword(t *testing.T) {
	repo := setupTestRepository(t)
	execOpt := NewExecOptions()
	execOpt.Remember = "never"
	tasks := []execHostTask{{
		nodeID: "iaas@10.238.221.181:22",
		host:   "10.238.221.181",
		pass:   "per-host-password",
	}}
	opts, err := execOpt.buildAdapterOptions(tasks, repo.Snapshot(), repo)
	if err != nil {
		t.Fatalf("build adapter options: %v", err)
	}
	secret, err := adapter.NewSSHAdapter(repo, opts...).ResolveSecret(t.Context(), ssh.SecretRequest{
		NodeID: tasks[0].nodeID,
		Kind:   ssh.SecretKindLoginPassword,
	})
	if err != nil {
		t.Fatalf("resolve session secret: %v", err)
	}
	if string(secret) != tasks[0].pass {
		t.Fatalf("resolved password = %q, want per-host session password", secret)
	}
}

func TestCommands_ExecTagUsesExplicitSessionCredentials(t *testing.T) {
	repo := setupTestRepository(t)
	execOpt := NewExecOptions()
	execOpt.Tag = "production"
	execOpt.Password = "tag-password"
	execOpt.Passphrase = "tag-passphrase"
	execOpt.Remember = "never"
	if err := execOpt.withTestPendingTagTasks(t.Context(), repo, func(tasks []execHostTask, _ []config.PendingLease) error {
		opts, err := execOpt.buildAdapterOptions(tasks, repo.Snapshot(), repo)
		if err != nil {
			t.Fatalf("build adapter options: %v", err)
		}
		adapter := adapter.NewSSHAdapter(repo, opts...)
		password, err := adapter.ResolveSecret(t.Context(), ssh.SecretRequest{NodeID: tasks[0].nodeID, Kind: ssh.SecretKindLoginPassword})
		if err != nil {
			t.Fatalf("resolve tag password: %v", err)
		}
		if string(password) != execOpt.Password {
			t.Fatalf("tag password = %q, want explicit password", password)
		}
		passphrase, err := adapter.ResolveSecret(t.Context(), ssh.SecretRequest{NodeID: tasks[0].nodeID, Kind: ssh.SecretKindPrivateKeyPassphrase})
		if err != nil {
			t.Fatalf("resolve tag passphrase: %v", err)
		}
		if string(passphrase) != execOpt.Passphrase {
			t.Fatalf("tag passphrase = %q, want explicit passphrase", passphrase)
		}
		return nil
	}); err != nil {
		t.Fatalf("build tag tasks: %v", err)
	}
}

func TestCommands_SSHSessionOnlyDoesNotInitializeSystemStore(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Credential = nil
	o := NewSshOptions()
	o.Remember = "never"
	if _, err := o.buildAdapterOptions("iaas@10.238.221.181:22", cfg, repo); err != nil {
		t.Fatalf("build session-only options: %v", err)
	}
}

func seedTestJumpNode(t *testing.T, repo *config.Repository, nodeID string) {
	t.Helper()
	if _, err := repo.CreateNodeContext(
		t.Context(),
		nodeID,
		models.Node{HostRef: "host-" + nodeID, IdentityRef: "id-" + nodeID},
		models.Host{Address: "10.238.221.1", Port: 22},
		models.Identity{User: "iaas", AuthType: "auto"},
	); err != nil {
		t.Fatalf("seed jump node %q: %v", nodeID, err)
	}
}

func TestCommands_SSHRememberNeverCoversProxyJump(t *testing.T) {
	repo := setupTestRepository(t)
	seedTestJumpNode(t, repo, "jump-01")
	o := NewSshOptions()
	o.Remember = "never"
	opts, err := o.buildAdapterOptions("final-node", repo.Snapshot(), repo)
	if err != nil {
		t.Fatalf("build adapter options: %v", err)
	}
	adp := adapter.NewSSHAdapter(repo, opts...)
	jumpID := "iaas@10.238.221.181:22"
	clientCfg, err := adp.GetConfig(jumpID)
	if err != nil {
		t.Fatalf("resolve jump config: %v", err)
	}
	if _, err := adp.UpdateAuth(t.Context(), jumpID, clientCfg.AuthUpdateToken, "jump-secret", "", ""); err != nil {
		t.Fatalf("update jump auth: %v", err)
	}
	snapshot, err := repo.ResolveConnection(jumpID)
	if err != nil {
		t.Fatalf("resolve jump node: %v", err)
	}
	if snapshot.Identity.Password == "jump-secret" {
		t.Fatal("--remember=never persisted a ProxyJump password")
	}
}

func TestCommands_SSHLegacyWithoutStoreKeepsDiscoveredCredentialsInSession(t *testing.T) {
	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Credential = nil
	o := NewSshOptions()
	// No override: v1 defaults to ask, but has nowhere to save the answer.
	opts, err := o.buildAdapterOptions("final-node", cfg, repo)
	if err != nil {
		t.Fatal(err)
	}
	adp := adapter.NewSSHAdapter(repo, opts...)
	nodeID := "iaas@10.238.221.181:22"
	before, err := repo.ResolveConnection(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adp.UpdateAuth(t.Context(), nodeID, string(before.UpdateRef.AuthVersion[:]), "session-secret", "", ""); err != nil {
		t.Fatalf("disabled persistence attempted a write: %v", err)
	}
	after, err := repo.ResolveConnection(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Identity.Password != before.Identity.Password || after.Identity.LoginPasswordRef != nil {
		t.Fatal("legacy authentication was changed without a writable default store")
	}
}

func TestCommands_SSHSessionOnlyUsesSelectedKey(t *testing.T) {
	repo := setupTestRepository(t)
	seedTestJumpNode(t, repo, "jump-01")
	o := NewSshOptions()
	o.Remember = "never"
	o.IdentityFile = t.TempDir()
	o.Target = config.ConnectionTarget{Selector: "10.238.221.181", User: "iaas", HasUser: true}
	if err := o.withTestPendingNode(t.Context(), repo, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		opts, err := o.buildAdapterOptions(nodeID, repo.Snapshot(), repo)
		if err != nil {
			t.Fatalf("build adapter options: %v", err)
		}
		clientCfg, err := adapter.NewSSHAdapter(repo, opts...).GetConfig(nodeID)
		if err != nil {
			t.Fatalf("get connection config: %v", err)
		}
		if clientCfg.KeyPath != o.IdentityFile {
			t.Fatalf("KeyPath = %q, want %q", clientCfg.KeyPath, o.IdentityFile)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingNode: %v", err)
	}
}

func TestCommands_ExecBatchNeverPromptsOrRecords(t *testing.T) {
	o := NewExecOptions()
	o.Remember = utils.RememberPolicyAlways
	if o.shouldRememberCredential("node", nil) {
		t.Fatal("batch execution must ignore --remember and remain session-only")
	}
}

func TestCommands_ExecRememberNeverCoversProxyJump(t *testing.T) {
	repo := setupTestRepository(t)
	seedTestJumpNode(t, repo, "jump-01")
	o := NewExecOptions()
	o.Interactive = true
	o.Remember = utils.RememberPolicyNever
	opts, err := o.buildAdapterOptions([]execHostTask{{nodeID: "final-node", host: "final"}}, repo.Snapshot(), repo)
	if err != nil {
		t.Fatalf("build adapter options: %v", err)
	}
	adp := adapter.NewSSHAdapter(repo, opts...)
	jumpID := "iaas@10.238.221.181:22"
	clientCfg, err := adp.GetConfig(jumpID)
	if err != nil {
		t.Fatalf("resolve jump config: %v", err)
	}
	if _, err := adp.UpdateAuth(t.Context(), jumpID, clientCfg.AuthUpdateToken, "jump-secret", "", ""); err != nil {
		t.Fatalf("update jump auth: %v", err)
	}
	snapshot, err := repo.ResolveConnection(jumpID)
	if err != nil {
		t.Fatalf("resolve jump node: %v", err)
	}
	if snapshot.Identity.Password == "jump-secret" {
		t.Fatal("--remember=never persisted an exec ProxyJump password")
	}
}

func TestCommands_ExecUsesSelectedSessionKey(t *testing.T) {
	repo := setupTestRepository(t)
	seedTestJumpNode(t, repo, "jump-01")
	o := NewExecOptions()
	o.Host = "iaas@10.238.221.181"
	o.IdentityFile = t.TempDir()
	o.Remember = utils.RememberPolicyNever
	if err := o.withTestPendingHostTasks(t.Context(), repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
		if len(hostErrs) != 0 {
			t.Fatalf("build tasks: hostErrs=%v", hostErrs)
		}
		opts, err := o.buildAdapterOptions(tasks, repo.Snapshot(), repo)
		if err != nil {
			t.Fatalf("build adapter options: %v", err)
		}
		clientCfg, err := adapter.NewSSHAdapter(repo, opts...).GetConfig(tasks[0].nodeID)
		if err != nil {
			t.Fatalf("get connection config: %v", err)
		}
		if clientCfg.KeyPath != o.IdentityFile {
			t.Fatalf("KeyPath = %q, want %q", clientCfg.KeyPath, o.IdentityFile)
		}
		return nil
	}); err != nil {
		t.Fatalf("build tasks: %v", err)
	}
}

func TestCommands_SCP_FlagPrecedence(t *testing.T) {
	ctx := context.Background()

	t.Run("scp_global_flags_override_saved_node_without_inline_user_or_port", func(t *testing.T) {
		for _, path := range []PathInfo{
			{Host: "10.238.221.181", IsRemote: true},
			{Host: "iaas@10.238.221.181:22", IsRemote: true},
		} {
			repo := setupTestRepository(t)
			scpOpt := NewScpOptions()
			scpOpt.User = "test"
			scpOpt.Port = 2222
			target, err := scpOpt.resolveTargetForPath(path)
			if err != nil {
				t.Fatalf("resolveTargetForPath(%+v) failed: %v", path, err)
			}
			res, err := repo.EnsureNodeContext(ctx, config.EnsureNodeOptions{Target: target})
			if err != nil {
				t.Fatalf("EnsureNodeContext(%+v) failed: %v", path, err)
			}
			if !res.Created || res.NodeID != "test@10.238.221.181:2222" {
				t.Errorf("path %+v: expected nodeID 'test@10.238.221.181:2222', got %q (created=%v)", path, res.NodeID, res.Created)
			}
		}
	})

	t.Run("scp_inline_user_and_port_override_global_flags", func(t *testing.T) {
		repo := setupTestRepository(t)
		scpOpt := NewScpOptions()
		scpOpt.User = "test"
		scpOpt.Port = 2222
		target, err := scpOpt.resolveTargetForPath(PathInfo{Host: "10.238.221.181", User: "alice", Port: 2223, IsRemote: true})
		if err != nil {
			t.Fatalf("resolveTargetForPath failed: %v", err)
		}
		res, err := repo.EnsureNodeContext(ctx, config.EnsureNodeOptions{Target: target})
		if err != nil {
			t.Fatalf("EnsureNodeContext failed: %v", err)
		}
		if !res.Created || res.NodeID != "alice@10.238.221.181:2223" {
			t.Errorf("expected nodeID 'alice@10.238.221.181:2223', got %q (created=%v)", res.NodeID, res.Created)
		}
	})
}

func TestCommands_SCPPortSelectionPreservesNumericFilename(t *testing.T) {
	for _, tc := range []struct {
		name        string
		storedPorts []uint16
		port        uint16
		wantPort    uint16
		ambiguous   bool
	}{
		{"unique configured port", []uint16{122}, 0, 122, false},
		{"multiple ports without flag", []uint16{22, 122}, 0, 0, true},
		{"explicit nondefault port", []uint16{22, 122}, 122, 122, false},
		{"explicit standard port", []uint16{22, 122}, 22, 22, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := config.NewProvider(nil)
			if err != nil {
				t.Fatal(err)
			}
			cfg := provider.Snapshot()
			cfg.Identities.Set("user", models.Identity{User: "user", AuthType: "auto"})
			for _, port := range tc.storedPorts {
				hostID := fmt.Sprintf("scp.fixture.invalid:%d", port)
				cfg.Hosts.Set(hostID, models.Host{Address: "scp.fixture.invalid", Port: port})
				cfg.Nodes.Set("user@"+hostID, models.Node{HostRef: hostID, IdentityRef: "user"})
			}
			repo, err := config.NewRepositoryWithoutOpenSSH(cfg, &memoryStore{cfg: cfg})
			if err != nil {
				t.Fatal(err)
			}
			path, err := parsePath("user@scp.fixture.invalid:22:file")
			if err != nil {
				t.Fatal(err)
			}
			if path.Path != "22:file" || path.Port != 0 {
				t.Fatalf("parsed path: %+v", path)
			}
			options := NewScpOptions()
			options.Port = tc.port
			target, err := options.resolveTargetForPath(path)
			if err != nil {
				t.Fatal(err)
			}
			if target.HasPort != (tc.port != 0) {
				t.Fatalf("HasPort = %v", target.HasPort)
			}
			err = repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{Target: target}, func(lease config.PendingLease) error {
				if want := fmt.Sprintf("user@scp.fixture.invalid:%d", tc.wantPort); repo.IsPendingNode(lease.NodeID()) || lease.NodeID() != want {
					t.Fatalf("resolved %q, pending=%v; want %q", lease.NodeID(), repo.IsPendingNode(lease.NodeID()), want)
				}
				return nil
			})
			if tc.ambiguous {
				var ambiguous *config.AmbiguousNodeError
				if !errors.As(err, &ambiguous) || len(ambiguous.Candidates) != 2 {
					t.Fatalf("expected ambiguity across two ports, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCommands_Exec_FlagPrecedence(t *testing.T) {
	ctx := context.Background()

	t.Run("exec_flag_user_overrides_host_user", func(t *testing.T) {
		repo := setupTestRepository(t)
		execOpt := NewExecOptions()
		execOpt.User = "test"
		execOpt.Host = "iaas@10.238.221.181"
		if err := execOpt.withTestPendingHostTasks(ctx, repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
			if len(hostErrs) > 0 {
				t.Fatalf("withTestPendingHostTasks hostErrs=%v", hostErrs)
			}
			if len(tasks) != 1 || tasks[0].nodeID != "test@10.238.221.181:22" {
				t.Fatalf("expected nodeID 'test@10.238.221.181:22', got %+v", tasks)
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingHostTasks failed: %v", err)
		}
	})

	t.Run("exec_flag_port_overrides_host_port", func(t *testing.T) {
		repo := setupTestRepository(t)
		execOpt := NewExecOptions()
		execOpt.Port = 2222
		execOpt.Host = "test@10.238.221.181:22"
		if err := execOpt.withTestPendingHostTasks(ctx, repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
			if len(hostErrs) > 0 {
				t.Fatalf("withTestPendingHostTasks hostErrs=%v", hostErrs)
			}
			if len(tasks) != 1 || tasks[0].nodeID != "test@10.238.221.181:2222" {
				t.Fatalf("expected nodeID 'test@10.238.221.181:2222', got %+v", tasks)
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingHostTasks failed: %v", err)
		}
	})
}

func assertStagedAndConfirmedProxyJump(t *testing.T, ctx context.Context, repo *config.Repository, lease config.PendingLease, expectedPJ string) {
	t.Helper()
	nodeID := lease.NodeID()
	if saved, ok := repo.Snapshot().Nodes.Get(nodeID); !ok || saved.ProxyJump != "jump-01" {
		t.Fatalf("expected saved ProxyJump unchanged pre-confirm, got %+v", saved)
	}
	node, _, _, resolveErr := repo.Resolve(nodeID)
	if resolveErr != nil || node.ProxyJump != expectedPJ {
		t.Fatalf("expected staged node.ProxyJump=%q, got %q (err=%v)", expectedPJ, node.ProxyJump, resolveErr)
	}
	if err := lease.Confirm(ctx); err != nil {
		t.Fatalf("lease.Confirm: %v", err)
	}
	if saved, ok := repo.Snapshot().Nodes.Get(nodeID); !ok || saved.ProxyJump != expectedPJ {
		t.Errorf("expected persisted node.ProxyJump=%q after Confirm, got %+v", expectedPJ, saved)
	}
}

func TestCommands_ExistingNode_ProxyJumpChainUpdate(t *testing.T) {
	ctx := context.Background()
	expectedPJ := config.OpenSSHNodePrefix + "10.0.0.1:22," + config.OpenSSHNodePrefix + "10.0.0.2:22"

	t.Run("ssh_updates_existing_node_multihop_proxyjump", func(t *testing.T) {
		repo := setupTestRepository(t)
		sshOpt := NewSshOptions()
		sshOpt.JumpHost = "10.0.0.1:22,10.0.0.2:22"
		sshOpt.args = []string{"iaas@10.238.221.181"}
		if err := sshOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
			if lease.NodeID() != "iaas@10.238.221.181:22" {
				t.Fatalf("expected existing nodeID 'iaas@10.238.221.181:22', got %s", lease.NodeID())
			}
			assertStagedAndConfirmedProxyJump(t, ctx, repo, lease, expectedPJ)
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingNode failed: %v", err)
		}
	})

	t.Run("scp_updates_existing_node_multihop_proxyjump", func(t *testing.T) {
		repo := setupTestRepository(t)
		scpOpt := NewScpOptions()
		scpOpt.JumpHost = "10.0.0.1:22,10.0.0.2:22"
		if err := scpOpt.withTestPendingPath(ctx, repo, PathInfo{Host: "10.238.221.181", User: "iaas", Port: 22}, "", func(lease config.PendingLease) error {
			assertStagedAndConfirmedProxyJump(t, ctx, repo, lease, expectedPJ)
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingPath failed: %v", err)
		}
	})

	t.Run("exec_updates_existing_node_multihop_proxyjump", func(t *testing.T) {
		repo := setupTestRepository(t)
		execOpt := NewExecOptions()
		execOpt.Interactive = true
		execOpt.JumpHost = "10.0.0.1:22,10.0.0.2:22"
		execOpt.Host = "iaas@10.238.221.181"
		if err := execOpt.withTestPendingHostTasks(ctx, repo, func(tasks []execHostTask, leases []config.PendingLease, hostErrs []error) error {
			if len(hostErrs) > 0 || len(tasks) != 1 {
				t.Fatalf("withTestPendingHostTasks failed: tasks=%d hostErrs=%v", len(tasks), hostErrs)
			}
			assertStagedAndConfirmedProxyJump(t, ctx, repo, leases[0], expectedPJ)
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingHostTasks failed: %v", err)
		}
	})
}

func setupMultiPortRepository(t *testing.T) *config.Repository {
	t.Helper()
	cfg, err := config.NewProvider(nil)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}
	snapshot := cfg.Snapshot()
	snapshot.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
	snapshot.Hosts.Set("10.0.0.1:2222", models.Host{Address: "10.0.0.1", Port: 2222})
	snapshot.Identities.Set("root@10.0.0.1", models.Identity{User: "root", AuthType: "auto"})
	snapshot.Identities.Set("root@10.0.0.1:2222", models.Identity{User: "root", AuthType: "auto"})
	snapshot.Nodes.Set("root@10.0.0.1:22", models.Node{
		HostRef:     "10.0.0.1:22",
		IdentityRef: "root@10.0.0.1",
	})
	snapshot.Nodes.Set("root@10.0.0.1:2222", models.Node{
		HostRef:     "10.0.0.1:2222",
		IdentityRef: "root@10.0.0.1:2222",
	})

	store := &memoryStore{cfg: snapshot}
	repo, err := config.NewRepositoryWithoutOpenSSH(snapshot, store)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	return repo
}

func TestCommands_Consistency_MultiPortDisambiguation(t *testing.T) {
	ctx := context.Background()

	t.Run("ssh_explicit_port_2222_resolves_existing_node", func(t *testing.T) {
		repo := setupMultiPortRepository(t)
		sshOpt := NewSshOptions()
		sshOpt.args = []string{"root@10.0.0.1:2222"}
		if err := sshOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
			nodeID := lease.NodeID()
			if repo.IsPendingNode(nodeID) || nodeID != "root@10.0.0.1:2222" {
				t.Errorf("got nodeID=%q, pending=%v, want root@10.0.0.1:2222, false", nodeID, repo.IsPendingNode(nodeID))
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingNode failed: %v", err)
		}
	})

	t.Run("sftp_explicit_port_2222_resolves_existing_node", func(t *testing.T) {
		repo := setupMultiPortRepository(t)
		sftpOpt := NewSftpOptions()
		sftpOpt.args = []string{"root@10.0.0.1:2222"}
		if err := sftpOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		if err := sftpOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
			nodeID := lease.NodeID()
			if repo.IsPendingNode(nodeID) || nodeID != "root@10.0.0.1:2222" {
				t.Errorf("got nodeID=%q, pending=%v, want root@10.0.0.1:2222, false", nodeID, repo.IsPendingNode(nodeID))
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingNode failed: %v", err)
		}
	})

	t.Run("scp_explicit_port_2222_resolves_existing_node", func(t *testing.T) {
		repo := setupMultiPortRepository(t)
		scpOpt := NewScpOptions()
		if err := scpOpt.withTestPendingPath(ctx, repo, PathInfo{Host: "10.0.0.1", User: "root", Port: 2222}, "", func(lease config.PendingLease) error {
			nodeID := lease.NodeID()
			if repo.IsPendingNode(nodeID) || nodeID != "root@10.0.0.1:2222" {
				t.Errorf("got nodeID=%q, pending=%v, want root@10.0.0.1:2222, false", nodeID, repo.IsPendingNode(nodeID))
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingPath failed: %v", err)
		}
	})

	t.Run("exec_explicit_port_2222_resolves_existing_node", func(t *testing.T) {
		repo := setupMultiPortRepository(t)
		execOpt := NewExecOptions()
		execOpt.Host = "root@10.0.0.1:2222"
		if err := execOpt.withTestPendingHostTasks(ctx, repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
			if len(hostErrs) > 0 || len(tasks) != 1 {
				t.Fatalf("withTestPendingHostTasks failed: tasks=%d hostErrs=%v", len(tasks), hostErrs)
			}
			if tasks[0].nodeID != "root@10.0.0.1:2222" {
				t.Errorf("got task nodeID=%q, want root@10.0.0.1:2222", tasks[0].nodeID)
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingHostTasks failed: %v", err)
		}
	})
}

func TestCommands_Consistency_SavedAliasWithPortProxyJump(t *testing.T) {
	ctx := context.Background()

	setupBastionRepo := func(t *testing.T) *config.Repository {
		t.Helper()
		cfg, err := config.NewProvider(nil)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}
		snapshot := cfg.Snapshot()
		snapshot.Hosts.Set("10.0.0.5:22", models.Host{Address: "10.0.0.5", Port: 22, Alias: []string{"bastion"}})
		snapshot.Identities.Set("root@10.0.0.5", models.Identity{User: "root", AuthType: "auto"})
		snapshot.Nodes.Set("root@10.0.0.5:22", models.Node{
			HostRef:     "10.0.0.5:22",
			IdentityRef: "root@10.0.0.5",
			Alias:       []string{"bastion"},
		})
		store := &memoryStore{cfg: snapshot}
		repo, rErr := config.NewRepositoryWithoutOpenSSH(snapshot, store)
		if rErr != nil {
			t.Fatalf("failed to create repo: %v", rErr)
		}
		return repo
	}

	t.Run("ssh_jump_bastion_port_resolves_to_saved_node", func(t *testing.T) {
		repo := setupBastionRepo(t)
		sshOpt := NewSshOptions()
		sshOpt.JumpHost = "bastion:22"
		sshOpt.args = []string{"test@10.238.221.181"}
		if err := sshOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
			node, _, _, resolveErr := repo.Resolve(lease.NodeID())
			if resolveErr != nil {
				t.Fatalf("node %s not found", lease.NodeID())
			}
			if node.ProxyJump != "root@10.0.0.5:22" {
				t.Errorf("got ProxyJump=%q, want root@10.0.0.5:22", node.ProxyJump)
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingNode failed: %v", err)
		}
	})

	t.Run("exec_jump_bastion_port_resolves_to_saved_node", func(t *testing.T) {
		repo := setupBastionRepo(t)
		execOpt := NewExecOptions()
		execOpt.JumpHost = "bastion:22"
		execOpt.Host = "test@10.238.221.181"
		if err := execOpt.withTestPendingHostTasks(ctx, repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
			if len(hostErrs) > 0 || len(tasks) != 1 {
				t.Fatalf("withTestPendingHostTasks failed: tasks=%d hostErrs=%v", len(tasks), hostErrs)
			}
			node, _, _, resolveErr := repo.Resolve(tasks[0].nodeID)
			if resolveErr != nil {
				t.Fatalf("node %s not found", tasks[0].nodeID)
			}
			if node.ProxyJump != "root@10.0.0.5:22" {
				t.Errorf("got ProxyJump=%q, want root@10.0.0.5:22", node.ProxyJump)
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingHostTasks failed: %v", err)
		}
	})
}

func setupNonDefaultPortWithProxyJumpRepo(t *testing.T) *config.Repository {
	t.Helper()
	cfg, err := config.NewProvider(nil)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}
	snapshot := cfg.Snapshot()
	snapshot.Hosts.Set("10.0.0.5:2222", models.Host{Address: "10.0.0.5", Port: 2222})
	snapshot.Identities.Set("root@10.0.0.5:2222", models.Identity{User: "root", AuthType: "auto"})
	snapshot.Nodes.Set("root@10.0.0.5:2222", models.Node{
		HostRef:     "10.0.0.5:2222",
		IdentityRef: "root@10.0.0.5:2222",
		ProxyJump:   "upstream",
		Alias:       []string{"bastion"},
	})
	store := &memoryStore{cfg: snapshot}
	repo, rErr := config.NewRepositoryWithoutOpenSSH(snapshot, store)
	if rErr != nil {
		t.Fatalf("failed to create repo: %v", rErr)
	}
	return repo
}

func TestCommands_SSH_ChangeUserPreservesPortAndProxyJump(t *testing.T) {
	ctx := context.Background()
	repo := setupNonDefaultPortWithProxyJumpRepo(t)
	sshOpt := NewSshOptions()
	sshOpt.args = []string{"test@10.0.0.5"}
	if err := sshOpt.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		if !repo.IsPendingNode(nodeID) || nodeID != "test@10.0.0.5:2222" {
			t.Errorf("got nodeID=%q, pending=%v, want test@10.0.0.5:2222, true", nodeID, repo.IsPendingNode(nodeID))
		}
		node, _, _, resolveErr := repo.Resolve(nodeID)
		if resolveErr != nil {
			t.Fatalf("node %s not found", nodeID)
		}
		if node.ProxyJump != "upstream" {
			t.Errorf("got ProxyJump=%q, want upstream", node.ProxyJump)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingNode failed: %v", err)
	}
}

func TestCommands_SFTP_ChangeUserPreservesPortAndProxyJump(t *testing.T) {
	ctx := context.Background()
	repo := setupNonDefaultPortWithProxyJumpRepo(t)
	sftpOpt := NewSftpOptions()
	sftpOpt.args = []string{"test@10.0.0.5"}
	if err := sftpOpt.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if err := sftpOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		if !repo.IsPendingNode(nodeID) || nodeID != "test@10.0.0.5:2222" {
			t.Errorf("got nodeID=%q, pending=%v, want test@10.0.0.5:2222, true", nodeID, repo.IsPendingNode(nodeID))
		}
		node, _, _, resolveErr := repo.Resolve(nodeID)
		if resolveErr != nil {
			t.Fatalf("node %s not found", nodeID)
		}
		if node.ProxyJump != "upstream" {
			t.Errorf("got ProxyJump=%q, want upstream", node.ProxyJump)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingNode failed: %v", err)
	}
}

func TestCommands_SCP_ChangeUserPreservesPortAndProxyJump(t *testing.T) {
	ctx := context.Background()
	repo := setupNonDefaultPortWithProxyJumpRepo(t)
	scpOpt := NewScpOptions()
	if err := scpOpt.withTestPendingPath(ctx, repo, PathInfo{Host: "10.0.0.5", User: "test"}, "", func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		if !repo.IsPendingNode(nodeID) || nodeID != "test@10.0.0.5:2222" {
			t.Errorf("got nodeID=%q, pending=%v, want test@10.0.0.5:2222, true", nodeID, repo.IsPendingNode(nodeID))
		}
		node, _, _, resolveErr := repo.Resolve(nodeID)
		if resolveErr != nil {
			t.Fatalf("node %s not found", nodeID)
		}
		if node.ProxyJump != "upstream" {
			t.Errorf("got ProxyJump=%q, want upstream", node.ProxyJump)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingPath failed: %v", err)
	}
}

func TestCommands_Exec_ChangeUserPreservesPortAndProxyJump(t *testing.T) {
	ctx := context.Background()
	repo := setupNonDefaultPortWithProxyJumpRepo(t)
	execOpt := NewExecOptions()
	execOpt.Host = "test@10.0.0.5"
	if err := execOpt.withTestPendingHostTasks(ctx, repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
		if len(hostErrs) > 0 || len(tasks) != 1 {
			t.Fatalf("withTestPendingHostTasks failed: tasks=%d hostErrs=%v", len(tasks), hostErrs)
		}
		if tasks[0].nodeID != "test@10.0.0.5:2222" {
			t.Errorf("got task nodeID=%q, want test@10.0.0.5:2222", tasks[0].nodeID)
		}
		node, _, _, resolveErr := repo.Resolve(tasks[0].nodeID)
		if resolveErr != nil {
			t.Fatalf("node %s not found", tasks[0].nodeID)
		}
		if node.ProxyJump != "upstream" {
			t.Errorf("got ProxyJump=%q, want upstream", node.ProxyJump)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingHostTasks failed: %v", err)
	}
}

func TestCommands_JumpAliasUserOverridePreservesPort(t *testing.T) {
	ctx := context.Background()

	t.Run("ssh_jump_alias_override_user_preserves_port", func(t *testing.T) {
		repo := setupNonDefaultPortWithProxyJumpRepo(t)
		sshOpt := NewSshOptions()
		sshOpt.JumpHost = "another@bastion"
		sshOpt.args = []string{"test@10.238.221.181"}
		if err := sshOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
			node, _, _, resolveErr := repo.Resolve(lease.NodeID())
			if resolveErr != nil {
				t.Fatalf("node %s not found", lease.NodeID())
			}
			expectedJump := config.OpenSSHNodePrefix + "another@10.0.0.5:2222"
			if node.ProxyJump != expectedJump {
				t.Errorf("got ProxyJump=%q, want %q", node.ProxyJump, expectedJump)
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingNode failed: %v", err)
		}
	})

	t.Run("exec_jump_alias_override_user_preserves_port", func(t *testing.T) {
		repo := setupNonDefaultPortWithProxyJumpRepo(t)
		execOpt := NewExecOptions()
		execOpt.JumpHost = "another@bastion"
		execOpt.Host = "test@10.238.221.181"
		if err := execOpt.withTestPendingHostTasks(ctx, repo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
			if len(hostErrs) > 0 || len(tasks) != 1 {
				t.Fatalf("withTestPendingHostTasks failed: tasks=%d hostErrs=%v", len(tasks), hostErrs)
			}
			node, _, _, resolveErr := repo.Resolve(tasks[0].nodeID)
			if resolveErr != nil {
				t.Fatalf("node %s not found", tasks[0].nodeID)
			}
			expectedJump := config.OpenSSHNodePrefix + "another@10.0.0.5:2222"
			if node.ProxyJump != expectedJump {
				t.Errorf("got ProxyJump=%q, want %q", node.ProxyJump, expectedJump)
			}
			return nil
		}); err != nil {
			t.Fatalf("withTestPendingHostTasks failed: %v", err)
		}
	})
}

func TestCommands_SSH_OpenSSHJumpNotOverriddenByLocalAlias(t *testing.T) {
	ctx := context.Background()
	sshConfig := `
Host remote
    HostName 10.0.0.10
    ProxyJump bastion

Host bastion
    HostName 10.0.0.20
    Port 22
`
	parser, pErr := config.NewOpenSSHParserFromReader(strings.NewReader(sshConfig))
	if pErr != nil {
		t.Fatalf("failed to create openssh parser: %v", pErr)
	}

	cfg, err := config.NewProvider(nil)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}
	snapshot := cfg.Snapshot()
	snapshot.Hosts.Set("10.0.0.99:22", models.Host{Address: "10.0.0.99", Port: 22})
	snapshot.Identities.Set("root@10.0.0.99", models.Identity{User: "root", AuthType: "auto"})
	snapshot.Nodes.Set("root@10.0.0.99:22", models.Node{
		HostRef:     "10.0.0.99:22",
		IdentityRef: "root@10.0.0.99",
		Alias:       []string{"bastion"},
	})

	store := &memoryStore{cfg: snapshot}
	repo, rErr := config.NewRepositoryWithOpenSSHParser(snapshot, store, parser)
	if rErr != nil {
		t.Fatalf("failed to create repo: %v", rErr)
	}

	sshOpt := NewSshOptions()
	sshOpt.args = []string{"test@remote"}
	if err := sshOpt.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if err := sshOpt.withTestPendingNode(ctx, repo, func(lease config.PendingLease) error {
		node, _, _, resolveErr := repo.Resolve(lease.NodeID())
		if resolveErr != nil {
			t.Fatalf("node %s not found", lease.NodeID())
		}
		expectedJump := config.OpenSSHNodePrefix + "bastion"
		if node.ProxyJump != expectedJump {
			t.Errorf("got ProxyJump=%q, want %q (must not be local node root@10.0.0.99:22)", node.ProxyJump, expectedJump)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingNode failed: %v", err)
	}
}
