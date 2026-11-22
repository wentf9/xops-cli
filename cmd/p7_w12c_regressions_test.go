package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func buildW12cLoopFixtureProvider(t *testing.T) (config.ConfigProvider, *config.Configuration) {
	t.Helper()
	const sshCfg = `
Host loop
    HostName 10.224.0.1
    User ops
    ProxyJump loop

Host ok-ssh
    HostName 10.224.0.2
    User ops
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-saved-loop", models.Host{Address: "10.224.0.3", Port: 22})
	cfg.Hosts.Set("h-saved-ok", models.Host{Address: "10.224.0.4", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-loop", models.Node{
		HostRef:     "h-saved-loop",
		IdentityRef: "id-ops",
		ProxyJump:   "openssh:loop",
		Tags:        []string{"prod"},
	})
	cfg.Nodes.Set("saved-ok", models.Node{
		HostRef:     "h-saved-ok",
		IdentityRef: "id-ops",
		Tags:        []string{"prod"},
	})
	return config.NewProviderWithOpenSSHParser(cfg, parser), cfg
}

func TestP7W12c_FG12M1_AllCLICommandsCancelLowerTierProxyJumpWithTier1ProxyCommand(t *testing.T) {
	t.Parallel()

	prov, cfg := buildW12cLoopFixtureProvider(t)

	cancelModes := []struct {
		name    string
		rawOpts []string
		cliJump string
	}{
		{"ProxyCommand_active", []string{"ProxyCommand=nc %h %p"}, ""},
		{"ProxyCommand_none", []string{"ProxyCommand=none"}, ""},
		{"ProxyJump_none_opt", []string{"ProxyJump=none"}, ""},
		{"ProxyCommand_before_cyclic_ProxyJump", []string{"ProxyCommand=nc %h %p", "ProxyJump=loop"}, ""},
	}

	for _, mode := range cancelModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			assertW12cSSHAndControlCancelCycle(t, prov, mode.rawOpts, mode.cliJump)
			assertW12cSFTPCancelCycle(t, prov, cfg, mode.rawOpts, mode.cliJump)
			assertW12cSCPCancelCycle(t, prov, mode.rawOpts, mode.cliJump)
			assertW12cExecCancelCycle(t, prov, mode.rawOpts, mode.cliJump)
		})
	}

	t.Run("control_without_override_fails_closed_with_ProxyCycleError", func(t *testing.T) {
		t.Parallel()
		var cycleErr *ssh.ProxyCycleError

		// ssh
		sshOpts := NewSshOptions()
		sshOpts.args = []string{"loop"}
		if err := sshOpts.Validate(); err != nil {
			t.Fatalf("ssh Validate: %v", err)
		}
		if _, err := sshOpts.buildPendingEnsureOptions(t.Context(), prov); !errors.As(err, &cycleErr) {
			t.Errorf("ssh buildPendingEnsureOptions(loop, no override) = %v, want *ssh.ProxyCycleError", err)
		}

		// scp
		scpOpts := NewScpOptions()
		scpOpts.Source = "./local.txt"
		scpOpts.Dest = "loop:/tmp/remote.txt"
		if _, err := scpOpts.planTransfer(t.Context(), prov); !errors.As(err, &cycleErr) {
			t.Errorf("scp planTransfer(loop, no override) = %v, want *ssh.ProxyCycleError", err)
		}

		// exec
		execOpts := NewExecOptions()
		execOpts.Host = "loop"
		execOpts.Command = "uptime"
		if err := execOpts.runWithProvider(t.Context(), cfg, prov); !errors.As(err, &cycleErr) {
			t.Errorf("exec runWithProvider(loop, no override) = %v, want *ssh.ProxyCycleError", err)
		}
	})
}

func assertW12cSSHAndControlCancelCycle(t *testing.T, prov config.ConfigProvider, rawOpts []string, cliJump string) {
	t.Helper()
	for _, selector := range []string{"loop", "saved-loop"} {
		o := NewSshOptions()
		o.args = []string{selector}
		o.JumpHost = cliJump
		o.control.Options = append(append([]string(nil), rawOpts...), "ControlMaster=auto", "ControlPath=/tmp/cm-w12c-cli-%h-%p-%r-%j")
		if err := o.Validate(); err != nil {
			t.Fatalf("ssh Validate(%s): %v", selector, err)
		}
		connTarget := effectiveConnectionTarget(o, "")
		if !connTarget.HasProxyJump || connTarget.ProxyJump != "none" {
			t.Fatalf("effectiveConnectionTarget(%s) = %+v, want ProxyJump=none HasProxyJump=true", selector, connTarget)
		}
		if err := o.applyHostnameCanonicalization(t.Context(), prov, nil); err != nil {
			t.Fatalf("applyHostnameCanonicalization(%s): %v", selector, err)
		}
		req, err := o.buildPendingEnsureOptions(t.Context(), prov)
		if err != nil {
			t.Fatalf("buildPendingEnsureOptions(%s): %v", selector, err)
		}
		if err := config.WithPendingNode(t.Context(), prov, req, func(lease config.PendingLease) error {
			if lease.NodeID() == "" {
				t.Errorf("empty lease NodeID for %s", selector)
			}
			return nil
		}); err != nil {
			t.Fatalf("WithPendingNode(%s): %v", selector, err)
		}
		nodeID, err := resolveControlNodeID(prov, effectiveConnectionTarget(o, ""))
		if err != nil {
			t.Fatalf("resolveControlNodeID(%s): %v", selector, err)
		}
		tgt, err := controlTarget(o, prov, nodeID)
		if err != nil || tgt.JumpHost != "" {
			t.Fatalf("controlTarget(%s) = (%+v, %v), want empty JumpHost", selector, tgt, err)
		}
		sock, err := controlSocketPath(o, prov, nodeID)
		if err != nil || sock == "" {
			t.Fatalf("controlSocketPath(%s) = (%q, %v), want non-empty socket", selector, sock, err)
		}
	}
}

func assertW12cSFTPCancelCycle(t *testing.T, prov config.ConfigProvider, cfg *config.Configuration, rawOpts []string, cliJump string) {
	t.Helper()
	o := NewSftpOptions()
	o.args = []string{"loop"}
	o.JumpHost = cliJump
	o.control.Options = append([]string(nil), rawOpts...)
	if err := o.Validate(); err != nil {
		t.Fatalf("sftp Validate: %v", err)
	}
	req, err := o.buildPendingEnsureOptions(t.Context(), prov)
	if err != nil {
		t.Fatalf("sftp buildPendingEnsureOptions(loop): %v", err)
	}
	if err := config.WithPendingNode(t.Context(), prov, req, func(lease config.PendingLease) error {
		if lease.NodeID() != "openssh:loop" {
			t.Errorf("sftp lease.NodeID() = %q, want openssh:loop", lease.NodeID())
		}
		return nil
	}); err != nil {
		t.Fatalf("sftp WithPendingNode(loop): %v", err)
	}
	// Run sftp.runWithProvider with an already-canceled dial context after pending prep:
	// verify pre-dial preparation never fails with *ssh.ProxyCycleError.
	oProg := NewSftpOptions()
	oProg.Host = "loop"
	oProg.JumpHost = cliJump
	oProg.control.Options = append([]string(nil), rawOpts...)
	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	var cycleErr *ssh.ProxyCycleError
	if runErr := oProg.runWithProvider(canceledCtx, cfg, prov, true); errors.As(runErr, &cycleErr) {
		t.Fatalf("sftp runWithProvider(loop) returned *ssh.ProxyCycleError: %v", runErr)
	}
}

func assertW12cSCPCancelCycle(t *testing.T, prov config.ConfigProvider, rawOpts []string, cliJump string) {
	t.Helper()

	// 1. Single-target upload to cyclic OpenSSH host loop.
	oSingle := NewScpOptions()
	oSingle.Source = "./local.txt"
	oSingle.Dest = "loop:/tmp/remote.txt"
	oSingle.JumpHost = cliJump
	oSingle.control.Options = append([]string(nil), rawOpts...)
	plan, err := oSingle.planTransfer(t.Context(), prov)
	if err != nil || len(plan.targets) != 1 {
		t.Fatalf("scp planTransfer(loop): plan=%+v err=%v", plan, err)
	}
	if err := config.WithPendingNode(t.Context(), prov, plan.targets[0].ensureReq, func(lease config.PendingLease) error {
		if lease.NodeID() != "openssh:loop" {
			t.Errorf("scp single lease.NodeID() = %q, want openssh:loop", lease.NodeID())
		}
		return nil
	}); err != nil {
		t.Fatalf("scp single WithPendingNode(loop): %v", err)
	}

	// 2. Batch --host loop,ok-ssh with --exclude loop.
	oBatch := NewScpOptions()
	oBatch.Host = "loop,ok-ssh"
	oBatch.Exclude = []string{"loop"}
	oBatch.Source = "./local.txt"
	oBatch.Dest = "/tmp/remote.txt"
	oBatch.JumpHost = cliJump
	oBatch.control.Options = append([]string(nil), rawOpts...)
	batchPlan, err := oBatch.planTransfer(t.Context(), prov)
	if err != nil || len(batchPlan.targets) != 1 || batchPlan.targets[0].label != "ok-ssh" {
		t.Fatalf("scp batch planTransfer(--exclude loop) = (%+v, %v), want only ok-ssh", batchPlan, err)
	}

	// 3. Batch --tag prod containing saved-loop (Tier-2 -> Tier-4 cycle).
	oTag := NewScpOptions()
	oTag.Tag = "prod"
	oTag.Source = "./local.txt"
	oTag.Dest = "/tmp/remote.txt"
	oTag.JumpHost = cliJump
	oTag.control.Options = append([]string(nil), rawOpts...)
	tagPlan, err := oTag.planTransfer(t.Context(), prov)
	if err != nil || len(tagPlan.targets) != 2 {
		t.Fatalf("scp tag planTransfer(prod) = (%+v, %v), want 2 targets", tagPlan, err)
	}
}

func assertW12cExecCancelCycle(t *testing.T, prov config.ConfigProvider, rawOpts []string, cliJump string) {
	t.Helper()

	// 1. --host loop
	oHost := NewExecOptions()
	oHost.Host = "loop"
	oHost.Command = "uptime"
	oHost.JumpHost = cliJump
	oHost.control.Options = append([]string(nil), rawOpts...)
	tasks, hostErrs, err := oHost.planTasksFromHosts(t.Context(), prov)
	if err != nil || len(hostErrs) != 0 || len(tasks) != 1 {
		t.Fatalf("exec planTasksFromHosts(loop) = (len=%d, hostErrs=%v, err=%v)", len(tasks), hostErrs, err)
	}
	if err := oHost.withPendingExecTasks(t.Context(), prov, tasks, func(mat []execHostTask, _ []config.PendingLease, matErrs []error) error {
		if len(matErrs) != 0 || len(mat) != 1 || mat[0].nodeID != "openssh:loop" {
			t.Fatalf("exec withPendingExecTasks(loop) = (%+v, errs=%v)", mat, matErrs)
		}
		return nil
	}); err != nil {
		t.Fatalf("exec withPendingExecTasks(loop): %v", err)
	}

	// 2. --tag prod (includes saved-loop)
	oTag := NewExecOptions()
	oTag.Tag = "prod"
	oTag.Command = "uptime"
	oTag.JumpHost = cliJump
	oTag.control.Options = append([]string(nil), rawOpts...)
	tagTasks, err := oTag.planTasksFromTags(t.Context(), prov)
	if err != nil || len(tagTasks) != 2 {
		t.Fatalf("exec planTasksFromTags(prod) = (len=%d, err=%v), want 2", len(tagTasks), err)
	}

	// 3. --host loop,ok-ssh --exclude loop
	oExcl := NewExecOptions()
	oExcl.Host = "loop,ok-ssh"
	oExcl.Exclude = []string{"loop"}
	oExcl.Command = "uptime"
	oExcl.JumpHost = cliJump
	oExcl.control.Options = append([]string(nil), rawOpts...)
	exclTasks, exclHostErrs, err := oExcl.planTasksFromHosts(t.Context(), prov)
	if err != nil || len(exclHostErrs) != 0 || len(exclTasks) != 2 {
		t.Fatalf("exec planTasksFromHosts(--exclude loop) = (len=%d, hostErrs=%v, err=%v)", len(exclTasks), exclHostErrs, err)
	}
}

func TestP7W12c_DE12L1_CLIFlagsRejectRawPaddedOpenSSHJump(t *testing.T) {
	t.Parallel()

	badJumps := []string{
		" openssh:web",
		"\u00a0openssh:web",
		"bastion1, openssh:web",
		"openssh:openssh:web",
		"openssh:web ",
	}

	for _, bad := range badJumps {
		if err := validateCLIProxyJumpSyntax(bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("validateCLIProxyJumpSyntax(%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
		o := NewSshOptions()
		if err := ApplyGeneralOptions(o, []string{"ProxyJump=" + bad}, nil); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ApplyGeneralOptions(ProxyJump=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
		sshCmd := newCmdSshWithOptions(NewSshOptions())
		if err := sshCmd.Flags().Parse([]string{"-J", bad}); err != nil {
			t.Fatalf("Flags().Parse(-J %q): %v", bad, err)
		}
		if err := validateExplicitNonEmptyFlags(sshCmd.Flags()); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("validateExplicitNonEmptyFlags(-J %q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}
}
