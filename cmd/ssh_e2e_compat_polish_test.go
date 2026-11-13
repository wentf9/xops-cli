package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestCLI_IPv6TargetParsingAndNormalization(t *testing.T) {
	repo := setupTestRepository(t)

	cases := []struct {
		name     string
		args     []string
		portFlag uint16
		opts     []string
		wantUser string
		wantPort uint16
		wantID   string
	}{
		{
			name:     "user_bracketed_ipv6",
			args:     []string{"ops@[::1]"},
			wantUser: "ops",
			wantPort: 22,
			wantID:   "ops@[::1]:22",
		},
		{
			name:     "user_bracketed_ipv6_with_port",
			args:     []string{"ops@[::1]:34522"},
			wantUser: "ops",
			wantPort: 34522,
			wantID:   "ops@[::1]:34522",
		},
		{
			name:     "port_flag_with_unbracketed_ipv6",
			args:     []string{"ops@::1"},
			portFlag: 34522,
			wantUser: "ops",
			wantPort: 34522,
			wantID:   "ops@[::1]:34522",
		},
		{
			name:     "bare_bracketed_ipv6_with_login_option",
			args:     []string{"[::1]"},
			opts:     []string{"User=ops"},
			wantUser: "ops",
			wantPort: 22,
			wantID:   "ops@[::1]:22",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sshOpt := NewSshOptions()
			sshOpt.Port = tc.portFlag
			sshOpt.control.Options = tc.opts
			if err := sshOpt.Complete(nil, tc.args); err != nil {
				t.Fatalf("Complete(%v) failed: %v", tc.args, err)
			}
			if err := sshOpt.Validate(); err != nil {
				t.Fatalf("Validate(%v) failed: %v", tc.args, err)
			}
			if sshOpt.Host != "::1" {
				t.Fatalf("sshOpt.Host = %q, want \"::1\"", sshOpt.Host)
			}
			nodeID, _, err := sshOpt.resolveNode(t.Context(), repo)
			if err != nil {
				t.Fatalf("resolveNode failed: %v", err)
			}
			if nodeID != tc.wantID {
				t.Fatalf("nodeID = %q, want %q", nodeID, tc.wantID)
			}
			adpOpts, err := sshOpt.buildAdapterOptions(nodeID, repo.Snapshot(), repo)
			if err != nil {
				t.Fatalf("buildAdapterOptions failed: %v", err)
			}
			cfg, err := adapter.NewSSHAdapter(repo, adpOpts...).GetConfig(nodeID)
			if err != nil {
				t.Fatalf("GetConfig(%q) failed: %v", nodeID, err)
			}
			if cfg.Address != "::1" || cfg.Port != int(tc.wantPort) || cfg.User != tc.wantUser {
				t.Fatalf("GetConfig = Address:%q Port:%d User:%q, want ::1 / %d / %s", cfg.Address, cfg.Port, cfg.User, tc.wantPort, tc.wantUser)
			}
		})
	}
}

func TestCLI_ConnectionWideOptionsPropagateToJumpWithoutTargetLeak(t *testing.T) {
	sshCfgText := `
Host jump
    HostName 10.10.0.1
    User bastion
    Port 22

Host target
    HostName 10.10.0.2
    User app
    Port 22
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(newEmptyTestConfig(), store, parser)
	if err != nil {
		t.Fatal(err)
	}

	khPath := filepath.Join(t.TempDir(), "custom_known_hosts")
	sshOpt := NewSshOptions()
	sshOpt.control.AddressFamily = ssh.AddressFamilyInet
	sshOpt.JumpHost = "jump"
	sshOpt.control.Options = []string{
		"UserKnownHostsFile=" + khPath,
		"StrictHostKeyChecking=no",
		"ConnectTimeout=9",
		"HostName=10.10.0.99",
		"RemoteCommand=echo target-only",
		"ControlMaster=auto",
		"ControlPath=/tmp/target-%C",
		"ControlPersist=30",
		"LocalCommand=echo local",
		"PermitLocalCommand=yes",
		"ForwardAgent=yes",
		"RequestTTY=force",
		"EscapeChar=~",
	}
	if err := sshOpt.Complete(nil, []string{"target"}); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if err := sshOpt.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	nodeID, _, err := sshOpt.resolveNode(t.Context(), repo)
	if err != nil {
		t.Fatalf("resolveNode failed: %v", err)
	}
	adpOpts, err := sshOpt.buildAdapterOptions(nodeID, repo.Snapshot(), repo)
	if err != nil {
		t.Fatalf("buildAdapterOptions failed: %v", err)
	}
	adpOpts = append(adpOpts, adapter.WithLocalExecution(true))
	adp := adapter.NewSSHAdapter(repo, adpOpts...)

	jumpCfg, err := adp.GetConfig("openssh:jump")
	if err != nil {
		t.Fatalf("GetConfig(openssh:jump) failed: %v", err)
	}
	assertCLIJumpConfigIsolated(t, adp, jumpCfg, khPath)

	targetCfg, err := adp.GetConfig(nodeID)
	if err != nil {
		t.Fatalf("GetConfig(%q) failed: %v", nodeID, err)
	}
	if targetCfg.Address != "10.10.0.99" || targetCfg.Options.RemoteCommand() != "echo target-only" {
		t.Fatalf("target node missing target-scoped overrides: Address=%q RemoteCommand=%q", targetCfg.Address, targetCfg.Options.RemoteCommand())
	}
}

func assertCLIJumpConfigIsolated(t *testing.T, adp *adapter.SSHAdapter, jumpCfg *ssh.ClientConfig, khPath string) {
	t.Helper()
	if jumpCfg.Address != "10.10.0.1" {
		t.Fatalf("jump Address = %q, want 10.10.0.1 (HostName override must not leak to jump)", jumpCfg.Address)
	}
	if jumpCfg.Options.UserKnownHostsFile() != khPath ||
		jumpCfg.Options.StrictHostKeyChecking() != ssh.StrictHostKeyCheckingNo ||
		jumpCfg.Options.AddressFamily() != ssh.AddressFamilyInet {
		t.Fatalf("jump hop missing connection-wide CLI options: %+v", jumpCfg.Options)
	}
	if jumpCfg.Options.RemoteCommand() != "" || jumpCfg.Options.LocalCommand() != "" || jumpCfg.Options.PermitLocalCommand() {
		t.Fatalf("jump hop leaked command target options: %+v", jumpCfg.Options)
	}
	if jumpCfg.Options.ForwardAgent() != "" || jumpCfg.Options.RequestTTY() != "" || jumpCfg.Options.EscapeChar() != "" {
		t.Fatalf("jump hop leaked session target options: %+v", jumpCfg.Options)
	}
	if jumpCtrl, err := adp.GetControlConfig("openssh:jump"); err != nil || jumpCtrl != nil {
		t.Fatalf("jump hop leaked Control* override: ctrl=%+v err=%v", jumpCtrl, err)
	}
}

func TestCLI_OpenSSHVirtualNodeStripsPrefixInPercentN(t *testing.T) {
	sshCfgText := `
Host web-alias
    HostName 10.30.0.10
    User deploy
    Port 2222
    ControlPath /tmp/cm-%n-%p
    RemoteCommand echo host=%n
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(newEmptyTestConfig(), store, parser)
	if err != nil {
		t.Fatal(err)
	}

	sshOpt := NewSshOptions()
	if err := sshOpt.Complete(nil, []string{"web-alias"}); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if err := sshOpt.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	nodeID, _, err := sshOpt.resolveNode(t.Context(), repo)
	if err != nil {
		t.Fatalf("resolveNode failed: %v", err)
	}
	if nodeID != "openssh:web-alias" {
		t.Fatalf("nodeID = %q, want openssh:web-alias", nodeID)
	}

	sock, err := controlSocketPath(sshOpt, repo, nodeID)
	if err != nil {
		t.Fatalf("controlSocketPath failed: %v", err)
	}
	if sock != "/tmp/cm-web-alias-2222" {
		t.Fatalf("controlSocketPath = %q, want /tmp/cm-web-alias-2222", sock)
	}

	adpOpts, err := sshOpt.buildAdapterOptions(nodeID, repo.Snapshot(), repo)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := adapter.NewSSHAdapter(repo, adpOpts...).GetConfig(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	tCtx := controlTarget(sshOpt, repo, nodeID)
	expandedCmd, err := ssh.ExpandRemoteCommand(cfg.Options.RemoteCommand(), sshenv.Discover(), tCtx)
	if err != nil {
		t.Fatalf("ExpandRemoteCommand failed: %v", err)
	}
	if expandedCmd != "echo host=web-alias" {
		t.Fatalf("expanded RemoteCommand = %q, want %q", expandedCmd, "echo host=web-alias")
	}
}

func TestCLI_RememberNeverDoesNotPersistExistingNodeMutations(t *testing.T) {
	ctx := t.Context()

	t.Run("ssh_remember_never_does_not_persist_proxyjump_or_alias", func(t *testing.T) {
		assertSSHRememberNeverNoPersistence(t)
	})

	t.Run("scp_remember_never_does_not_persist_proxyjump", func(t *testing.T) {
		repo := setupTestRepository(t)
		scpOpt := NewScpOptions()
		scpOpt.Remember = "never"
		scpOpt.JumpHost = "10.0.0.1:22"
		nodeID, updated, err := scpOpt.getOrCreateNodeForPath(ctx, repo, PathInfo{Host: "10.238.221.181", User: "iaas", Port: 22}, "")
		if err != nil || updated {
			t.Fatalf("getOrCreateNodeForPath: updated=%v err=%v", updated, err)
		}
		assertExistingWeb01ProxyJumpUnchanged(t, repo, nodeID)
	})

	t.Run("exec_remember_never_does_not_persist_proxyjump", func(t *testing.T) {
		repo := setupTestRepository(t)
		execOpt := NewExecOptions()
		execOpt.Remember = "never"
		execOpt.JumpHost = "10.0.0.1:22"
		execOpt.Host = "iaas@10.238.221.181"
		tasks, hostErrs, err := execOpt.buildTasksFromHosts(ctx, repo)
		if err != nil || len(hostErrs) > 0 || len(tasks) != 1 {
			t.Fatalf("buildTasksFromHosts failed: tasks=%d err=%v hostErrs=%v", len(tasks), err, hostErrs)
		}
		assertExistingWeb01ProxyJumpUnchanged(t, repo, tasks[0].nodeID)
	})
}

func assertSSHRememberNeverNoPersistence(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	repo := setupTestRepository(t)
	sshOpt := NewSshOptions()
	sshOpt.Remember = "never"
	sshOpt.JumpHost = "10.0.0.1:22"
	sshOpt.Alias = "temp-alias"
	sshOpt.Sudo = true
	if err := sshOpt.Complete(nil, []string{"iaas@10.238.221.181"}); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if err := sshOpt.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	nodeID, mutated, err := sshOpt.resolveNode(ctx, repo)
	if err != nil || mutated {
		t.Fatalf("resolveNode: mutated=%v err=%v", mutated, err)
	}
	node := assertExistingWeb01ProxyJumpUnchanged(t, repo, nodeID)
	if len(node.Alias) != 1 || node.Alias[0] != "web-01" || node.SudoMode == models.SudoModeSudo {
		t.Fatalf("--remember=never persisted mutations on existing node: %+v", node)
	}

	adpOpts, err := sshOpt.buildAdapterOptions(nodeID, repo.Snapshot(), repo)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := adapter.NewSSHAdapter(repo, adpOpts...).GetConfig(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProxyJump != "openssh:10.0.0.1:22" {
		t.Fatalf("expected session ProxyJump override to remain active, got %q", cfg.ProxyJump)
	}
}

func assertExistingWeb01ProxyJumpUnchanged(t *testing.T, repo *config.Repository, nodeID string) models.Node {
	t.Helper()
	node, _, _, err := repo.Resolve(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if node.ProxyJump != "jump-01" {
		t.Fatalf("--remember=never mutated ProxyJump=%q on existing node (want jump-01)", node.ProxyJump)
	}
	return node
}
