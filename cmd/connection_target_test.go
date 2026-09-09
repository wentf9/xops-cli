package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
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
	nodeID, created, err := sshOpt.resolveNode(ctx, repo)
	if err != nil {
		t.Fatalf("resolveNode failed: %v", err)
	}
	if !created || nodeID != "test@10.238.221.181:22" {
		t.Errorf("ssh got nodeID=%q, created=%v, want test@10.238.221.181:22, true", nodeID, created)
	}
	snap := repo.Snapshot()
	if len(snap.Hosts.Keys()) != 1 {
		t.Errorf("expected host to be reused (1 host), got %d", len(snap.Hosts.Keys()))
	}
	node, ok := snap.Nodes.Get(nodeID)
	if !ok || node.ProxyJump != "jump-01" {
		t.Errorf("expected inherited ProxyJump 'jump-01', got %+v", node)
	}
	if len(node.Alias) != 0 || len(node.Tags) != 0 {
		t.Errorf("new node must not inherit alias/tags, got %+v", node)
	}
	ident, ok := snap.Identities.Get(node.IdentityRef)
	if !ok || ident.Password != "" {
		t.Errorf("new identity must exist and not inherit secretPassword, got %+v", ident)
	}
}

func testSFTPExplicitUserReusesHost(t *testing.T, ctx context.Context) {
	repo := setupTestRepository(t)
	sftpOpt := NewSftpOptions()
	sftpOpt.args = []string{"test@10.238.221.181"}
	if err := sftpOpt.Validate(); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	nodeID, created, err := sftpOpt.resolveNode(ctx, repo)
	if err != nil {
		t.Fatalf("resolveNode failed: %v", err)
	}
	if !created || nodeID != "test@10.238.221.181:22" {
		t.Errorf("sftp got nodeID=%q, created=%v, want test@10.238.221.181:22, true", nodeID, created)
	}
	snap := repo.Snapshot()
	if len(snap.Hosts.Keys()) != 1 {
		t.Errorf("expected host to be reused (1 host), got %d", len(snap.Hosts.Keys()))
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
	nodeID, created, err := scpOpt.getOrCreateNodeForPath(ctx, repo, dst, "")
	if err != nil {
		t.Fatalf("getOrCreateNodeForPath failed: %v", err)
	}
	if !created || nodeID != "test@10.238.221.181:22" {
		t.Errorf("scp got nodeID=%q, created=%v, want test@10.238.221.181:22, true", nodeID, created)
	}
	snap := repo.Snapshot()
	if len(snap.Hosts.Keys()) != 1 {
		t.Errorf("expected host to be reused (1 host), got %d", len(snap.Hosts.Keys()))
	}
}

func testExecExplicitUserReusesHost(t *testing.T, ctx context.Context) {
	repo := setupTestRepository(t)
	execOpt := NewExecOptions()
	execOpt.Host = "test@10.238.221.181"
	tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
	if err != nil || len(hostErrs) > 0 {
		t.Fatalf("buildTasksFromHosts failed: err=%v, hostErrs=%v", err, hostErrs)
	}
	if len(tasks) != 1 || tasks[0].nodeID != "test@10.238.221.181:22" {
		t.Errorf("exec got tasks=%+v, want 1 task with nodeID=test@10.238.221.181:22", tasks)
	}
	snap := repo.Snapshot()
	if len(snap.Hosts.Keys()) != 1 {
		t.Errorf("expected host to be reused (1 host), got %d", len(snap.Hosts.Keys()))
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
		nodeID, created, err := sshOpt.resolveNode(ctx, repo)
		if err != nil {
			t.Fatalf("resolveNode failed: %v", err)
		}
		if !created || nodeID != "test@10.238.221.181:22" {
			t.Errorf("got nodeID=%q, created=%v, want test@10.238.221.181:22, true", nodeID, created)
		}
	})

	// Exec test@web-01 -> test@10.238.221.181:22
	t.Run("exec_alias", func(t *testing.T) {
		repo := setupTestRepository(t)
		execOpt := NewExecOptions()
		execOpt.Host = "test@web-01"
		tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
		if err != nil || len(hostErrs) > 0 {
			t.Fatalf("buildTasksFromHosts failed: err=%v, hostErrs=%v", err, hostErrs)
		}
		if len(tasks) != 1 || tasks[0].nodeID != "test@10.238.221.181:22" {
			t.Errorf("exec got tasks=%+v, want test@10.238.221.181:22", tasks)
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
		nodeID, created, err := sshOpt.resolveNode(ctx, repo)
		if err != nil {
			t.Fatalf("resolveNode failed: %v", err)
		}
		if created || nodeID != "iaas@10.238.221.181:22" {
			t.Errorf("got nodeID=%q, created=%v, want iaas@10.238.221.181:22, false", nodeID, created)
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
		_, _, err = sshOpt.resolveNode(ctx, repo)
		if err == nil {
			t.Fatalf("expected ambiguous error for multi-user bare address, got nil")
		}
		if !strings.Contains(err.Error(), "ambiguous") {
			t.Errorf("expected ambiguous error, got %v", err)
		}

		// Exec with bare address also returns error
		execOpt := NewExecOptions()
		execOpt.Host = "10.238.221.181"
		_, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
		if len(hostErrs) == 0 && err == nil {
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
	nodeID, created, err := sshOpt.resolveNode(ctx, repo)
	if err != nil {
		t.Fatalf("resolveNode failed: %v", err)
	}
	if !created || nodeID != "test@10.238.221.181:2222" {
		t.Errorf("got nodeID=%q, want test@10.238.221.181:2222", nodeID)
	}
	snap := repo.Snapshot()
	if len(snap.Hosts.Keys()) != 2 {
		t.Errorf("expected 2 hosts (22 and 2222), got %d", len(snap.Hosts.Keys()))
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
		nodeID, created, err := sshOpt.resolveNode(ctx, repo)
		if err != nil {
			t.Fatalf("resolveNode failed: %v", err)
		}
		// Must use test, not iaas
		if !created || nodeID != "test@10.238.221.181:22" {
			t.Errorf("expected nodeID 'test@10.238.221.181:22', got %q (created=%v)", nodeID, created)
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
		nodeID, created, err := sshOpt.resolveNode(ctx, repo)
		if err != nil {
			t.Fatalf("resolveNode failed: %v", err)
		}
		// Must use 2222, not 22
		if !created || nodeID != "test@10.238.221.181:2222" {
			t.Errorf("expected nodeID 'test@10.238.221.181:2222', got %q", nodeID)
		}
	})
}

func TestCommands_Exec_SudoAndSuPwd(t *testing.T) {
	ctx := context.Background()
	repo := setupTestRepository(t)

	execOpt := NewExecOptions()
	execOpt.Host = "test@10.238.221.181"
	execOpt.Sudo = true
	execOpt.SuPwd = "mySuperSecretPassword"

	tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
	if err != nil || len(hostErrs) > 0 {
		t.Fatalf("buildTasksFromHosts failed: err=%v, hostErrs=%v", err, hostErrs)
	}
	if len(tasks) != 1 || tasks[0].nodeID != "test@10.238.221.181:22" {
		t.Fatalf("unexpected tasks: %+v", tasks)
	}

	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get("test@10.238.221.181:22")
	if !ok {
		t.Fatalf("node test@10.238.221.181:22 not found in snapshot")
	}
	if node.SudoMode != models.SudoModeSudo {
		t.Errorf("expected SudoMode=%q, got %q", models.SudoModeSudo, node.SudoMode)
	}
	if node.SuPwd != "" {
		t.Errorf("expected discovered sudo password to remain session-only, got %q", node.SuPwd)
	}
}

func TestCommands_ExistingNodeCredentialsStayOutOfConfiguration(t *testing.T) {
	repo := setupTestRepository(t)
	sshOpt := NewSshOptions()
	sshOpt.Remember = "always"
	sshOpt.Password = "new-synthetic-password"
	sshOpt.Target = config.ConnectionTarget{Selector: "10.238.221.181", User: "iaas", HasUser: true}

	nodeID, _, err := sshOpt.resolveNode(t.Context(), repo)
	if err != nil {
		t.Fatalf("resolveNode failed: %v", err)
	}
	snapshot, err := repo.ResolveConnection(nodeID)
	if err != nil {
		t.Fatalf("resolve connection failed: %v", err)
	}
	if snapshot.Identity.Password == sshOpt.Password {
		t.Fatal("SSH option password was persisted in configuration")
	}

	execOpt := NewExecOptions()
	execOpt.Remember = "always"
	execOpt.SuPwd = "new-synthetic-sudo-password"
	if _, err := execOpt.updateNodeFromHostInfo(t.Context(), nodeID, repo, utils.HostInfo{Host: "10.238.221.181"}); err != nil {
		t.Fatalf("updateNodeFromHostInfo failed: %v", err)
	}
	snapshot, err = repo.ResolveConnection(nodeID)
	if err != nil {
		t.Fatalf("resolve connection after exec update failed: %v", err)
	}
	if snapshot.Node.SuPwd == execOpt.SuPwd {
		t.Fatal("exec sudo password was persisted in configuration")
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
	tasks, err := execOpt.buildTasksFromTags(repo)
	if err != nil {
		t.Fatalf("build tag tasks: %v", err)
	}
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

func TestCommands_SSHRememberNeverCoversProxyJump(t *testing.T) {
	repo := setupTestRepository(t)
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

func TestCommands_SSHSessionOnlyUsesSelectedKey(t *testing.T) {
	repo := setupTestRepository(t)
	o := NewSshOptions()
	o.Remember = "never"
	o.IdentityFile = t.TempDir()
	o.Target = config.ConnectionTarget{Selector: "10.238.221.181", User: "iaas", HasUser: true}
	nodeID, _, err := o.resolveNode(t.Context(), repo)
	if err != nil {
		t.Fatalf("resolve node: %v", err)
	}
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
	o := NewExecOptions()
	o.Host = "iaas@10.238.221.181"
	o.IdentityFile = t.TempDir()
	o.Remember = utils.RememberPolicyNever
	tasks, hostErrs, err := o.buildTasksFromHosts(t.Context(), repo)
	if err != nil || len(hostErrs) != 0 {
		t.Fatalf("build tasks: err=%v hostErrs=%v", err, hostErrs)
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
}

func TestCommands_SCP_FlagPrecedence(t *testing.T) {
	ctx := context.Background()

	t.Run("scp_flag_user_overrides_path_user", func(t *testing.T) {
		repo := setupTestRepository(t)
		scpOpt := NewScpOptions()
		scpOpt.User = "test"
		target, err := scpOpt.resolveTargetForPath(PathInfo{Host: "10.238.221.181", User: "iaas", Port: 22})
		if err != nil {
			t.Fatalf("resolveTargetForPath failed: %v", err)
		}
		res, err := repo.EnsureNodeContext(ctx, config.EnsureNodeOptions{Target: target})
		if err != nil {
			t.Fatalf("EnsureNodeContext failed: %v", err)
		}
		if !res.Created || res.NodeID != "test@10.238.221.181:22" {
			t.Errorf("expected nodeID 'test@10.238.221.181:22', got %q", res.NodeID)
		}
	})

	t.Run("scp_flag_port_overrides_path_port", func(t *testing.T) {
		repo := setupTestRepository(t)
		scpOpt := NewScpOptions()
		scpOpt.Port = 2222
		target, err := scpOpt.resolveTargetForPath(PathInfo{Host: "10.238.221.181", User: "test", Port: 22})
		if err != nil {
			t.Fatalf("resolveTargetForPath failed: %v", err)
		}
		res, err := repo.EnsureNodeContext(ctx, config.EnsureNodeOptions{Target: target})
		if err != nil {
			t.Fatalf("EnsureNodeContext failed: %v", err)
		}
		if !res.Created || res.NodeID != "test@10.238.221.181:2222" {
			t.Errorf("expected nodeID 'test@10.238.221.181:2222', got %q", res.NodeID)
		}
	})
}

func TestCommands_Exec_FlagPrecedence(t *testing.T) {
	ctx := context.Background()

	t.Run("exec_flag_user_overrides_host_user", func(t *testing.T) {
		repo := setupTestRepository(t)
		execOpt := NewExecOptions()
		execOpt.User = "test"
		execOpt.Host = "iaas@10.238.221.181"
		tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
		if err != nil || len(hostErrs) > 0 {
			t.Fatalf("buildTasksFromHosts failed: err=%v, hostErrs=%v", err, hostErrs)
		}
		if len(tasks) != 1 || tasks[0].nodeID != "test@10.238.221.181:22" {
			t.Fatalf("expected nodeID 'test@10.238.221.181:22', got %+v", tasks)
		}
	})

	t.Run("exec_flag_port_overrides_host_port", func(t *testing.T) {
		repo := setupTestRepository(t)
		execOpt := NewExecOptions()
		execOpt.Port = 2222
		execOpt.Host = "test@10.238.221.181:22"
		tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
		if err != nil || len(hostErrs) > 0 {
			t.Fatalf("buildTasksFromHosts failed: err=%v, hostErrs=%v", err, hostErrs)
		}
		if len(tasks) != 1 || tasks[0].nodeID != "test@10.238.221.181:2222" {
			t.Fatalf("expected nodeID 'test@10.238.221.181:2222', got %+v", tasks)
		}
	})
}

func TestCommands_ExistingNode_ProxyJumpChainUpdate(t *testing.T) {
	ctx := context.Background()

	t.Run("ssh_updates_existing_node_multihop_proxyjump", func(t *testing.T) {
		repo := setupTestRepository(t)
		sshOpt := NewSshOptions()
		sshOpt.JumpHost = "10.0.0.1:22,10.0.0.2:22"
		sshOpt.args = []string{"iaas@10.238.221.181"}
		if err := sshOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		nodeID, mutated, err := sshOpt.resolveNode(ctx, repo)
		if err != nil {
			t.Fatalf("resolveNode failed: %v", err)
		}
		if nodeID != "iaas@10.238.221.181:22" {
			t.Fatalf("expected existing nodeID 'iaas@10.238.221.181:22', got %s", nodeID)
		}
		if !mutated {
			t.Fatalf("expected node to be updated (mutated=true)")
		}
		snap := repo.Snapshot()
		node, ok := snap.Nodes.Get(nodeID)
		if !ok {
			t.Fatalf("node not found: %s", nodeID)
		}
		expectedPJ := config.OpenSSHNodePrefix + "10.0.0.1:22," + config.OpenSSHNodePrefix + "10.0.0.2:22"
		if node.ProxyJump != expectedPJ {
			t.Errorf("expected node.ProxyJump=%q, got %q", expectedPJ, node.ProxyJump)
		}
	})

	t.Run("scp_updates_existing_node_multihop_proxyjump", func(t *testing.T) {
		repo := setupTestRepository(t)
		scpOpt := NewScpOptions()
		scpOpt.JumpHost = "10.0.0.1:22,10.0.0.2:22"
		nodeID, updated, err := scpOpt.getOrCreateNodeForPath(ctx, repo, PathInfo{Host: "10.238.221.181", User: "iaas", Port: 22}, "")
		if err != nil {
			t.Fatalf("getOrCreateNodeForPath failed: %v", err)
		}
		if !updated {
			t.Fatalf("expected existing node to be updated with new ProxyJump")
		}
		snap := repo.Snapshot()
		node, ok := snap.Nodes.Get(nodeID)
		if !ok {
			t.Fatalf("node not found: %s", nodeID)
		}
		expectedPJ := config.OpenSSHNodePrefix + "10.0.0.1:22," + config.OpenSSHNodePrefix + "10.0.0.2:22"
		if node.ProxyJump != expectedPJ {
			t.Errorf("expected node.ProxyJump=%q, got %q", expectedPJ, node.ProxyJump)
		}
	})

	t.Run("exec_updates_existing_node_multihop_proxyjump", func(t *testing.T) {
		repo := setupTestRepository(t)
		execOpt := NewExecOptions()
		execOpt.JumpHost = "10.0.0.1:22,10.0.0.2:22"
		execOpt.Host = "iaas@10.238.221.181"
		tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
		if err != nil || len(hostErrs) > 0 {
			t.Fatalf("buildTasksFromHosts failed: err=%v, hostErrs=%v", err, hostErrs)
		}
		if len(tasks) != 1 {
			t.Fatalf("expected 1 task, got %d", len(tasks))
		}
		snap := repo.Snapshot()
		node, ok := snap.Nodes.Get(tasks[0].nodeID)
		if !ok {
			t.Fatalf("node not found: %s", tasks[0].nodeID)
		}
		expectedPJ := config.OpenSSHNodePrefix + "10.0.0.1:22," + config.OpenSSHNodePrefix + "10.0.0.2:22"
		if node.ProxyJump != expectedPJ {
			t.Errorf("expected node.ProxyJump=%q, got %q", expectedPJ, node.ProxyJump)
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
		nodeID, created, err := sshOpt.resolveNode(ctx, repo)
		if err != nil {
			t.Fatalf("resolveNode failed: %v", err)
		}
		if created || nodeID != "root@10.0.0.1:2222" {
			t.Errorf("got nodeID=%q, created=%v, want root@10.0.0.1:2222, false", nodeID, created)
		}
	})

	t.Run("sftp_explicit_port_2222_resolves_existing_node", func(t *testing.T) {
		repo := setupMultiPortRepository(t)
		sftpOpt := NewSftpOptions()
		sftpOpt.args = []string{"root@10.0.0.1:2222"}
		if err := sftpOpt.Validate(); err != nil {
			t.Fatalf("validate failed: %v", err)
		}
		nodeID, created, err := sftpOpt.resolveNode(ctx, repo)
		if err != nil {
			t.Fatalf("resolveNode failed: %v", err)
		}
		if created || nodeID != "root@10.0.0.1:2222" {
			t.Errorf("got nodeID=%q, created=%v, want root@10.0.0.1:2222, false", nodeID, created)
		}
	})

	t.Run("scp_explicit_port_2222_resolves_existing_node", func(t *testing.T) {
		repo := setupMultiPortRepository(t)
		scpOpt := NewScpOptions()
		nodeID, created, err := scpOpt.getOrCreateNodeForPath(ctx, repo, PathInfo{Host: "10.0.0.1", User: "root", Port: 2222}, "")
		if err != nil {
			t.Fatalf("getOrCreateNodeForPath failed: %v", err)
		}
		if created || nodeID != "root@10.0.0.1:2222" {
			t.Errorf("got nodeID=%q, created=%v, want root@10.0.0.1:2222, false", nodeID, created)
		}
	})

	t.Run("exec_explicit_port_2222_resolves_existing_node", func(t *testing.T) {
		repo := setupMultiPortRepository(t)
		execOpt := NewExecOptions()
		execOpt.Host = "root@10.0.0.1:2222"
		tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
		if err != nil || len(hostErrs) > 0 {
			t.Fatalf("buildTasksFromHosts failed: err=%v, hostErrs=%v", err, hostErrs)
		}
		if len(tasks) != 1 {
			t.Fatalf("expected 1 task, got %d", len(tasks))
		}
		if tasks[0].nodeID != "root@10.0.0.1:2222" {
			t.Errorf("got task nodeID=%q, want root@10.0.0.1:2222", tasks[0].nodeID)
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
		nodeID, _, err := sshOpt.resolveNode(ctx, repo)
		if err != nil {
			t.Fatalf("resolveNode failed: %v", err)
		}
		snap := repo.Snapshot()
		node, ok := snap.Nodes.Get(nodeID)
		if !ok {
			t.Fatalf("node %s not found", nodeID)
		}
		if node.ProxyJump != "root@10.0.0.5:22" {
			t.Errorf("got ProxyJump=%q, want root@10.0.0.5:22", node.ProxyJump)
		}
	})

	t.Run("exec_jump_bastion_port_resolves_to_saved_node", func(t *testing.T) {
		repo := setupBastionRepo(t)
		execOpt := NewExecOptions()
		execOpt.JumpHost = "bastion:22"
		execOpt.Host = "test@10.238.221.181"
		tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
		if err != nil || len(hostErrs) > 0 {
			t.Fatalf("buildTasksFromHosts failed: err=%v, hostErrs=%v", err, hostErrs)
		}
		if len(tasks) != 1 {
			t.Fatalf("expected 1 task, got %d", len(tasks))
		}
		snap := repo.Snapshot()
		node, ok := snap.Nodes.Get(tasks[0].nodeID)
		if !ok {
			t.Fatalf("node %s not found", tasks[0].nodeID)
		}
		if node.ProxyJump != "root@10.0.0.5:22" {
			t.Errorf("got ProxyJump=%q, want root@10.0.0.5:22", node.ProxyJump)
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
	nodeID, created, err := sshOpt.resolveNode(ctx, repo)
	if err != nil {
		t.Fatalf("resolveNode failed: %v", err)
	}
	if !created || nodeID != "test@10.0.0.5:2222" {
		t.Errorf("got nodeID=%q, created=%v, want test@10.0.0.5:2222, true", nodeID, created)
	}
	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(nodeID)
	if !ok {
		t.Fatalf("node %s not found", nodeID)
	}
	if node.ProxyJump != "upstream" {
		t.Errorf("got ProxyJump=%q, want upstream", node.ProxyJump)
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
	nodeID, created, err := sftpOpt.resolveNode(ctx, repo)
	if err != nil {
		t.Fatalf("resolveNode failed: %v", err)
	}
	if !created || nodeID != "test@10.0.0.5:2222" {
		t.Errorf("got nodeID=%q, created=%v, want test@10.0.0.5:2222, true", nodeID, created)
	}
	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(nodeID)
	if !ok {
		t.Fatalf("node %s not found", nodeID)
	}
	if node.ProxyJump != "upstream" {
		t.Errorf("got ProxyJump=%q, want upstream", node.ProxyJump)
	}
}

func TestCommands_SCP_ChangeUserPreservesPortAndProxyJump(t *testing.T) {
	ctx := context.Background()
	repo := setupNonDefaultPortWithProxyJumpRepo(t)
	scpOpt := NewScpOptions()
	nodeID, created, err := scpOpt.getOrCreateNodeForPath(ctx, repo, PathInfo{Host: "10.0.0.5", User: "test"}, "")
	if err != nil {
		t.Fatalf("getOrCreateNodeForPath failed: %v", err)
	}
	if !created || nodeID != "test@10.0.0.5:2222" {
		t.Errorf("got nodeID=%q, created=%v, want test@10.0.0.5:2222, true", nodeID, created)
	}
	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(nodeID)
	if !ok {
		t.Fatalf("node %s not found", nodeID)
	}
	if node.ProxyJump != "upstream" {
		t.Errorf("got ProxyJump=%q, want upstream", node.ProxyJump)
	}
}

func TestCommands_Exec_ChangeUserPreservesPortAndProxyJump(t *testing.T) {
	ctx := context.Background()
	repo := setupNonDefaultPortWithProxyJumpRepo(t)
	execOpt := NewExecOptions()
	execOpt.Host = "test@10.0.0.5"
	tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
	if err != nil || len(hostErrs) > 0 {
		t.Fatalf("buildTasksFromHosts failed: err=%v, hostErrs=%v", err, hostErrs)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	if tasks[0].nodeID != "test@10.0.0.5:2222" {
		t.Errorf("got task nodeID=%q, want test@10.0.0.5:2222", tasks[0].nodeID)
	}
	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(tasks[0].nodeID)
	if !ok {
		t.Fatalf("node %s not found", tasks[0].nodeID)
	}
	if node.ProxyJump != "upstream" {
		t.Errorf("got ProxyJump=%q, want upstream", node.ProxyJump)
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
		nodeID, _, err := sshOpt.resolveNode(ctx, repo)
		if err != nil {
			t.Fatalf("resolveNode failed: %v", err)
		}
		snap := repo.Snapshot()
		node, ok := snap.Nodes.Get(nodeID)
		if !ok {
			t.Fatalf("node %s not found", nodeID)
		}
		expectedJump := config.OpenSSHNodePrefix + "another@10.0.0.5:2222"
		if node.ProxyJump != expectedJump {
			t.Errorf("got ProxyJump=%q, want %q", node.ProxyJump, expectedJump)
		}
	})

	t.Run("exec_jump_alias_override_user_preserves_port", func(t *testing.T) {
		repo := setupNonDefaultPortWithProxyJumpRepo(t)
		execOpt := NewExecOptions()
		execOpt.JumpHost = "another@bastion"
		execOpt.Host = "test@10.238.221.181"
		tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
		if err != nil || len(hostErrs) > 0 {
			t.Fatalf("buildTasksFromHosts failed: err=%v, hostErrs=%v", err, hostErrs)
		}
		if len(tasks) != 1 {
			t.Fatalf("expected 1 task, got %d", len(tasks))
		}
		snap := repo.Snapshot()
		node, ok := snap.Nodes.Get(tasks[0].nodeID)
		if !ok {
			t.Fatalf("node %s not found", tasks[0].nodeID)
		}
		expectedJump := config.OpenSSHNodePrefix + "another@10.0.0.5:2222"
		if node.ProxyJump != expectedJump {
			t.Errorf("got ProxyJump=%q, want %q", node.ProxyJump, expectedJump)
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
	nodeID, _, err := sshOpt.resolveNode(ctx, repo)
	if err != nil {
		t.Fatalf("resolveNode failed: %v", err)
	}
	snap := repo.Snapshot()
	node, ok := snap.Nodes.Get(nodeID)
	if !ok {
		t.Fatalf("node %s not found", nodeID)
	}
	expectedJump := config.OpenSSHNodePrefix + "bastion"
	if node.ProxyJump != expectedJump {
		t.Errorf("got ProxyJump=%q, want %q (must not be local node root@10.0.0.99:22)", node.ProxyJump, expectedJump)
	}
}
