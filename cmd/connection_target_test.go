package cmd

import (
	"context"
	"strings"
	"testing"

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
	if node.SuPwd != "mySuperSecretPassword" {
		t.Errorf("expected SuPwd='mySuperSecretPassword', got %q", node.SuPwd)
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
