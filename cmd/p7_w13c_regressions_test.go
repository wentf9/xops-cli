package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W13c_L4_13_L2_ValidateCommonSSHBaseOptionsRejectsRawOpenSSHJumpTokens(t *testing.T) {
	t.Parallel()

	badJumps := []string{
		" openssh:web",
		"\u00a0openssh:web",
		"bastion1, openssh:web",
		"openssh:openssh:web",
		"openssh:web ",
		" OPENSSH:web",
	}

	for _, bad := range badJumps {
		o := NewSshOptions()
		o.JumpHost = bad
		if err := validateCommonSSHBaseOptions(o); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("validateCommonSSHBaseOptions(JumpHost=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}

		execOpts := NewExecOptions()
		execOpts.Host = "app"
		execOpts.Command = "uptime"
		execOpts.JumpHost = bad
		if err := execOpts.Validate(); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ExecOptions.Validate(JumpHost=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}

		scpOpts := NewScpOptions()
		scpOpts.Source = "./local.txt"
		scpOpts.Dest = "app:/tmp/remote.txt"
		scpOpts.JumpHost = bad
		if err := scpOpts.Validate(); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ScpOptions.Validate(JumpHost=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}

		sftpOpts := NewSftpOptions()
		sftpOpts.args = []string{"app"}
		sftpOpts.JumpHost = bad
		if err := sftpOpts.Validate(); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("SftpOptions.Validate(JumpHost=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}

	for _, good := range []string{"openssh:web", "bastion1,openssh:web", "bastion1, 10.0.0.2"} {
		o := NewSshOptions()
		o.JumpHost = good
		if err := validateCommonSSHBaseOptions(o); err != nil {
			t.Errorf("validateCommonSSHBaseOptions(valid JumpHost=%q) unexpected error: %v", good, err)
		}
	}
}

func TestP7W13c_L3_13_M1_CLICommandsRespectTier3ProxyCommandShadowingTier4(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host loop
    HostName 10.236.0.1
    Port 22
    User ops
    ProxyJump loop
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	for _, proxyCmd := range []string{"nc %h %p", "none"} {
		t.Run("Tier3_ProxyCommand_"+proxyCmd, func(t *testing.T) {
			t.Parallel()
			cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
			t3 := &ssh.Options{}
			if setErr := t3.Set(ssh.OptionProxyCommand, proxyCmd); setErr != nil {
				t.Fatalf("Set ProxyCommand: %v", setErr)
			}
			cfg.SSHOptions = t3
			cfg.Hosts.Set("h-saved-loop", models.Host{Address: "10.236.0.2", Port: 22})
			cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
			cfg.Nodes.Set("saved-loop", models.Node{
				HostRef:     "h-saved-loop",
				IdentityRef: "id-ops",
				ProxyJump:   "openssh:loop",
			})
			prov := config.NewProviderWithOpenSSHParser(cfg, parser)

			// Tier-4 OpenSSH cyclic host succeeds under Tier-3 ProxyCommand across ssh, control, scp, sftp, exec.
			sshOpts := NewSshOptions()
			sshOpts.args = []string{"loop"}
			sshOpts.control.Options = []string{"ControlMaster=auto", "ControlPath=/tmp/cm-w13c-cli-%h-%p-%r-%j"}
			if err := sshOpts.Validate(); err != nil {
				t.Fatalf("ssh Validate: %v", err)
			}
			req, err := sshOpts.buildPendingEnsureOptions(t.Context(), prov)
			if err != nil {
				t.Fatalf("ssh buildPendingEnsureOptions(loop): %v", err)
			}
			if err := config.WithPendingNode(t.Context(), prov, req, func(lease config.PendingLease) error {
				if lease.NodeID() != "openssh:loop" {
					t.Errorf("lease.NodeID() = %q, want openssh:loop", lease.NodeID())
				}
				return nil
			}); err != nil {
				t.Fatalf("WithPendingNode(loop): %v", err)
			}
			nodeID, err := resolveControlNodeID(prov, effectiveConnectionTarget(sshOpts, ""))
			if err != nil {
				t.Fatalf("resolveControlNodeID(loop): %v", err)
			}
			tgt, err := controlTarget(sshOpts, prov, nodeID)
			if err != nil || tgt.JumpHost != "" {
				t.Fatalf("controlTarget(loop) = (%+v, %v), want empty JumpHost", tgt, err)
			}
			sock, err := controlSocketPath(sshOpts, prov, nodeID)
			if err != nil || sock == "" {
				t.Fatalf("controlSocketPath(loop) = (%q, %v), want valid socket", sock, err)
			}

			scpOpts := NewScpOptions()
			scpOpts.Source = "./local.txt"
			scpOpts.Dest = "loop:/tmp/remote.txt"
			if plan, pErr := scpOpts.planTransfer(t.Context(), prov); pErr != nil || len(plan.targets) != 1 {
				t.Fatalf("scp planTransfer(loop) = (%+v, %v), want 1 target", plan, pErr)
			}

			execOpts := NewExecOptions()
			execOpts.Host = "loop"
			execOpts.Command = "uptime"
			if tasks, hostErrs, eErr := execOpts.planTasksFromHosts(t.Context(), prov); eErr != nil || len(hostErrs) != 0 || len(tasks) != 1 {
				t.Fatalf("exec planTasksFromHosts(loop) = (len=%d, errs=%v, err=%v), want 1 task", len(tasks), hostErrs, eErr)
			}

			// Tier-2 saved-loop MUST still fail closed with *ssh.ProxyCycleError (Tier 2 > Tier 3).
			var cycleErr *ssh.ProxyCycleError
			sshSaved := NewSshOptions()
			sshSaved.args = []string{"saved-loop"}
			if err := sshSaved.Validate(); err != nil {
				t.Fatalf("ssh Validate(saved-loop): %v", err)
			}
			if _, err := sshSaved.buildPendingEnsureOptions(t.Context(), prov); !errors.As(err, &cycleErr) {
				t.Fatalf("ssh buildPendingEnsureOptions(saved-loop) = %v, want *ssh.ProxyCycleError", err)
			}
		})
	}
}
