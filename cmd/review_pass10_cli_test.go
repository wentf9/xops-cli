package cmd

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func buildAppliedDaemonSpecForTest(t *testing.T, opts *SshOptions, nodeID, sockPath string, master *ssh.MuxServer) (MuxDaemonSpec, *SshOptions) {
	t.Helper()
	spec := opts.buildMuxDaemonSpec(nodeID, sockPath, master)
	decoded := roundTripMuxDaemonSpecThroughPipe(t, spec)
	child := NewSshOptions()
	if err := child.applyMuxDaemonSpec(decoded); err != nil {
		t.Fatalf("applyMuxDaemonSpec: %v", err)
	}
	return decoded, child
}

func TestPass10_H3_MuxDaemonAuthoritativeControlAndIdentityOrder(t *testing.T) {
	t.Run("MM_overrides_ControlMaster_yes_without_downgrade", assertPass10MMNoDowngrade)
	t.Run("M_overrides_ControlMaster_no_and_auto_autoask_converge", assertPass10MAndAutoConverge)
	t.Run("leading_IdentityFile_none_preserves_order_and_no_duplication", assertPass10LeadingIdentityNoneOrder)
}

func assertPass10MMNoDowngrade(t *testing.T) {
	opts := NewSshOptions()
	sshCmd := newCmdSshWithOptions(opts)
	if err := sshCmd.ParseFlags([]string{"-M", "-M", "-o", "ControlMaster=yes", "-o", "ControlPersist=60s", "-o", "ClearAllForwardings=no", "edge"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := opts.Complete(sshCmd, []string{"edge"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	client, _ := newTunnelTestClient(t)
	sockPath := filepath.Join(t.TempDir(), "edge.sock")
	masterTarget := ssh.TargetContext{
		Host: "edge", Port: 22, User: "alice", OriginalHost: "edge",
		Control: &ssh.ControlConfig{Master: ssh.ControlMasterAsk, Path: sockPath, Persist: "60s"},
	}
	liveAskMaster, err := ssh.NewMuxServer(ssh.MuxServerOptions{
		ControlPath: sockPath, SSHClient: client.SSHClient(), Target: masterTarget,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	t.Cleanup(func() { _ = liveAskMaster.Shutdown() })
	for _, m := range []*ssh.MuxServer{nil, liveAskMaster} {
		_, child := buildAppliedDaemonSpecForTest(t, opts, "openssh:edge", sockPath, m)
		assertPass10MMDaemonOptions(t, child.control.Options, m != nil)
	}
}

func assertPass10MMDaemonOptions(t *testing.T, optVals []string, withMaster bool) {
	t.Helper()
	if slices.Contains(optVals, "ControlMaster=yes") {
		t.Fatalf("downgraded ControlMaster=yes leaked into daemon options (master=%v): %v", withMaster, optVals)
	}
	if !slices.Contains(optVals, "ControlMaster=ask") {
		t.Fatalf("expected authoritative ControlMaster=ask in daemon options (master=%v): %v", withMaster, optVals)
	}
	if slices.Contains(optVals, "ClearAllForwardings=no") {
		t.Fatalf("stale ClearAllForwardings=no leaked before ClearAllForwardings=yes: %v", optVals)
	}
	if count := countStrings(optVals, "ControlPersist=60s"); count != 1 {
		t.Fatalf("ControlPersist=60s count = %d, want 1 in %v", count, optVals)
	}
	ctrl, err := (&SSHControlFlags{Options: optVals}).ToSessionControlOptions()
	if err != nil {
		t.Fatalf("daemon ToSessionControlOptions: %v", err)
	}
	if ctrl.Master == nil || *ctrl.Master != ssh.ControlMasterAsk {
		t.Fatalf("daemon resolved Master = %v, want ask", ctrl.Master)
	}
}

func assertPass10MAndAutoConverge(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cliArgs    []string
		wantMaster ssh.ControlMasterMode
	}{
		{name: "M_with_ControlMaster_no", cliArgs: []string{"-M", "-o", "ControlMaster=no", "-o", "ControlPersist=60s", "edge"}, wantMaster: ssh.ControlMasterYes},
		{name: "ControlMaster_auto_with_persist", cliArgs: []string{"-o", "ControlMaster=auto", "-o", "ControlPersist=60s", "edge"}, wantMaster: ssh.ControlMasterYes},
		{name: "ControlMaster_autoask_with_persist", cliArgs: []string{"-o", "ControlMaster=autoask", "-o", "ControlPersist=60s", "edge"}, wantMaster: ssh.ControlMasterAsk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewSshOptions()
			c := newCmdSshWithOptions(opts)
			if err := c.ParseFlags(tc.cliArgs); err != nil {
				t.Fatalf("ParseFlags: %v", err)
			}
			if err := opts.Complete(c, []string{"edge"}); err != nil {
				t.Fatalf("Complete: %v", err)
			}
			spec, child := buildAppliedDaemonSpecForTest(t, opts, "openssh:edge", "/tmp/edge.sock", nil)
			if spec.ControlMaster != tc.wantMaster {
				t.Fatalf("spec.ControlMaster = %v, want %v", spec.ControlMaster, tc.wantMaster)
			}
			ctrl, err := (&SSHControlFlags{Options: child.control.Options}).ToSessionControlOptions()
			if err != nil {
				t.Fatalf("daemon ToSessionControlOptions: %v", err)
			}
			if ctrl.Master == nil || *ctrl.Master != tc.wantMaster {
				t.Fatalf("daemon resolved Master = %v, want %v (opts=%v)", ctrl.Master, tc.wantMaster, child.control.Options)
			}
		})
	}
}

func assertPass10LeadingIdentityNoneOrder(t *testing.T) {
	opts := NewSshOptions()
	c := newCmdSshWithOptions(opts)
	if err := c.ParseFlags([]string{"-o", "IdentityFile=none", "-o", "IdentityFile=/tmp/k2", "-o", "ControlPath=/tmp/stale.sock", "edge"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := opts.Complete(c, []string{"edge"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	spec, child := buildAppliedDaemonSpecForTest(t, opts, "openssh:edge", "/tmp/auth.sock", nil)
	if slices.Contains(child.control.Options, "ControlPath=/tmp/stale.sock") {
		t.Fatalf("stale ControlPath leaked into daemon options: %v", child.control.Options)
	}
	wantIDs := []string{"none"}
	if !slices.Equal(spec.IdentityFiles, wantIDs) {
		t.Fatalf("spec.IdentityFiles = %v, want %v", spec.IdentityFiles, wantIDs)
	}
	if !slices.Equal(child.IdentityFiles, wantIDs) {
		t.Fatalf("child.IdentityFiles = %v, want %v", child.IdentityFiles, wantIDs)
	}
}

func countStrings(items []string, target string) int {
	n := 0
	for _, it := range items {
		if it == target {
			n++
		}
	}
	return n
}

func TestPass10_M1_CLIReservedAliasAndDuplicateGuard(t *testing.T) {
	for _, bad := range []string{"openssh", "openssh:prod"} {
		t.Run("ssh_"+bad, func(t *testing.T) {
			opts := NewSshOptions()
			opts.Host = "127.0.0.1"
			opts.Alias = bad
			if err := opts.Validate(); err == nil {
				t.Fatalf("SshOptions.Validate accepted reserved alias %q", bad)
			}
		})
		t.Run("sftp_"+bad, func(t *testing.T) {
			opts := NewSftpOptions()
			opts.Host = "127.0.0.1"
			opts.Alias = bad
			if err := opts.Validate(); err == nil {
				t.Fatalf("SftpOptions.Validate accepted reserved alias %q", bad)
			}
		})
		t.Run("scp_"+bad, func(t *testing.T) {
			opts := NewScpOptions()
			opts.Source = "./a"
			opts.Dest = "web:/tmp/b"
			opts.Alias = bad
			if err := opts.Validate(); err == nil {
				t.Fatalf("ScpOptions.Validate accepted reserved alias %q", bad)
			}
		})
		t.Run("exec_"+bad, func(t *testing.T) {
			opts := NewExecOptions()
			opts.Host = "web"
			opts.Command = "id"
			opts.Alias = bad
			if err := opts.Validate(); err == nil {
				t.Fatalf("ExecOptions.Validate accepted reserved alias %q", bad)
			}
		})
	}

	dir := t.TempDir()
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, config.NewDefaultStore(filepath.Join(dir, "c.yaml"), filepath.Join(dir, "k")))
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	host := models.Host{Address: "10.0.0.10", Port: 22}
	ident := models.Identity{User: "ops", AuthType: "auto"}
	node := models.Node{HostRef: "h1", IdentityRef: "id1", Alias: []string{"web"}}
	if _, err := repo.CreateNodeContext(t.Context(), "node1", node, host, ident); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	optsDup := NewSshOptions()
	optsDup.Alias = "web"
	optsDup.Target = config.ConnectionTarget{Selector: "node1"}
	if err := optsDup.withTestPendingNode(t.Context(), repo, func(lease config.PendingLease) error {
		return lease.Confirm(t.Context())
	}); err != nil {
		t.Fatalf("withTestPendingNode(dup): %v", err)
	}
	gotNode, _, _, err := repo.Resolve("node1")
	if err != nil {
		t.Fatalf("Resolve(node1): %v", err)
	}
	if len(gotNode.Alias) != 1 || gotNode.Alias[0] != "web" {
		t.Fatalf("expected duplicate alias not to append; alias=%v", gotNode.Alias)
	}

	optsReserved := NewSshOptions()
	optsReserved.Alias = "openssh"
	optsReserved.Target = config.ConnectionTarget{Selector: "node1"}
	if err := optsReserved.withTestPendingNode(t.Context(), repo, func(config.PendingLease) error { return nil }); err == nil {
		t.Fatal("withTestPendingNode allowed reserved alias 'openssh'")
	}
}

func TestPass10_M2_EmptyStdioForwardAndTunnelDeviceRejected(t *testing.T) {
	t.Run("W_empty_and_whitespace_rejected", func(t *testing.T) {
		for _, val := range []string{"", "   "} {
			opts := NewSshOptions()
			c := newCmdSshWithOptions(opts)
			if err := c.ParseFlags([]string{"-W", val, "target"}); err != nil {
				t.Fatalf("ParseFlags(-W %q): %v", val, err)
			}
			if err := opts.Complete(c, []string{"target"}); err != nil {
				t.Fatalf("Complete(-W %q): %v", val, err)
			}
			if err := opts.Validate(); err == nil {
				t.Fatalf("expected error for -W %q, got nil", val)
			}
		}
	})

	t.Run("W_empty_with_O_proxy_exits_255", func(t *testing.T) {
		opts := NewSshOptions()
		c := newCmdSshWithOptions(opts)
		if err := c.ParseFlags([]string{"-O", "proxy", "-W", "", "target"}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		if err := opts.Complete(c, []string{"target"}); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		err := opts.Validate()
		var exitErr *ControlExitError
		if !errors.As(err, &exitErr) || exitErr.Code != 255 {
			t.Fatalf("expected ControlExitError(255) for -O proxy -W \"\", got %T (%v)", err, err)
		}
	})

	t.Run("w_empty_rejected_and_does_not_lock_tunnel_mode", func(t *testing.T) {
		opts := NewSshOptions()
		c := newCmdSshWithOptions(opts)
		if err := c.ParseFlags([]string{"-w", "", "target"}); err != nil {
			t.Fatalf("ParseFlags(-w \"\"): %v", err)
		}
		if opts.cliTunnelLockedByW || opts.cliTunnelMode != "" {
			t.Fatalf("empty -w mutated tunnel state: mode=%q locked=%v", opts.cliTunnelMode, opts.cliTunnelLockedByW)
		}
		if err := opts.Complete(c, []string{"target"}); err != nil {
			t.Fatalf("Complete(-w \"\"): %v", err)
		}
		err := opts.Validate()
		if err == nil || !strings.Contains(err.Error(), "tunnel device (-w)") {
			t.Fatalf("expected invalid tunnel device (-w) error, got %v", err)
		}

		opts.normalizeForMuxDaemon()
		if opts.stdioForwardSet || opts.tunnelDeviceSet || opts.cliTunnelLockedByW || opts.cliTunnelMode != "" {
			t.Fatalf("normalizeForMuxDaemon left stale -W/-w state: stdioSet=%v tunSet=%v locked=%v mode=%q",
				opts.stdioForwardSet, opts.tunnelDeviceSet, opts.cliTunnelLockedByW, opts.cliTunnelMode)
		}
	})
}
