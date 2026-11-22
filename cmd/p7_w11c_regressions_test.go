package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func buildW11cBatchCycleExcludeProvider(t *testing.T) config.ConfigProvider {
	t.Helper()
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.222.0.1", Port: 22})
	cfg.Hosts.Set("h-web01", models.Host{Address: "10.222.0.2", Port: 22})
	cfg.Hosts.Set("h-web02", models.Host{Address: "10.222.0.3", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops", Tags: []string{"prod"}})
	cfg.Nodes.Set("web-01", models.Node{HostRef: "h-web01", IdentityRef: "id-ops", Tags: []string{"prod"}})
	cfg.Nodes.Set("web-02", models.Node{HostRef: "h-web02", IdentityRef: "id-ops", Tags: []string{"other"}})
	return config.NewProviderWithoutOpenSSH(cfg)
}

func TestP7W11c_FG11M2_ScpExcludeBeforeCLIProxyJumpCycleValidation(t *testing.T) {
	t.Parallel()

	prov := buildW11cBatchCycleExcludeProvider(t)

	t.Run("tag_with_J_bastion_and_exclude_bastion_succeeds_and_plans_only_web01", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name string
			init func(*ScpOptions)
		}{
			{"flag_J", func(o *ScpOptions) { o.JumpHost = "bastion" }},
			{"opt_ProxyJump", func(o *ScpOptions) { o.control.Options = []string{"ProxyJump=bastion"} }},
		} {
			o := NewScpOptions()
			o.Tag = "prod"
			o.Exclude = []string{"bastion"}
			o.Source = "./file"
			o.Dest = "/tmp/file"
			tc.init(o)

			plan, err := o.planTransfer(t.Context(), prov)
			if err != nil {
				t.Fatalf("%s planTransfer failed: %v", tc.name, err)
			}
			if len(plan.targets) != 1 || plan.targets[0].label != "web-01" {
				t.Fatalf("%s plan.targets = %+v, want single web-01", tc.name, plan.targets)
			}
			if plan.targets[0].ensureReq.Target.ProxyJump != "bastion" {
				t.Fatalf("%s target ProxyJump = %q, want bastion", tc.name, plan.targets[0].ensureReq.Target.ProxyJump)
			}
			// Verify adapter override collection also succeeds without tripping on excluded bastion.
			var adpOpts []adapter.Option
			if err := o.appendScpSessionAuthOverrides(&adpOpts, prov, false, true); err != nil {
				t.Fatalf("%s appendScpSessionAuthOverrides failed: %v", tc.name, err)
			}
			if paths, pErr := o.collectTargetPaths(prov); pErr != nil || len(paths) != 1 || paths[0].Host != "web-01" {
				t.Fatalf("%s collectTargetPaths = (%+v, %v), want [web-01]", tc.name, paths, pErr)
			}
		}
	})

	t.Run("host_list_with_J_bastion_and_exclude_bastion_succeeds", func(t *testing.T) {
		t.Parallel()
		o := NewScpOptions()
		o.Host = "bastion,web-01"
		o.JumpHost = "bastion"
		o.Exclude = []string{"bastion"}
		o.Source = "./file"
		o.Dest = "/tmp/file"

		plan, err := o.planTransfer(t.Context(), prov)
		if err != nil {
			t.Fatalf("planTransfer(--host bastion,web-01 --exclude bastion) failed: %v", err)
		}
		if len(plan.targets) != 1 || plan.targets[0].label != "web-01" {
			t.Fatalf("plan.targets = %+v, want single web-01", plan.targets)
		}
	})

	t.Run("surviving_bastion_and_malformed_or_duplicate_J_still_fail_closed", func(t *testing.T) {
		t.Parallel()

		var cycleErr *ssh.ProxyCycleError
		// Non-excluded bastion in --tag must fail closed with *ssh.ProxyCycleError.
		oTagSurv := NewScpOptions()
		oTagSurv.Tag = "prod"
		oTagSurv.JumpHost = "bastion"
		oTagSurv.Exclude = []string{"web-01"}
		oTagSurv.Source = "./file"
		oTagSurv.Dest = "/tmp/file"
		if _, err := oTagSurv.planTransfer(t.Context(), prov); !errors.As(err, &cycleErr) {
			t.Errorf("scp --tag prod -J bastion --exclude web-01 err = %v, want *ssh.ProxyCycleError", err)
		}

		// Non-excluded bastion in --host must fail closed with *ssh.ProxyCycleError.
		oHostSurv := NewScpOptions()
		oHostSurv.Host = "bastion,web-01"
		oHostSurv.JumpHost = "bastion"
		oHostSurv.Exclude = []string{"web-01"}
		oHostSurv.Source = "./file"
		oHostSurv.Dest = "/tmp/file"
		if _, err := oHostSurv.planTransfer(t.Context(), prov); !errors.As(err, &cycleErr) {
			t.Errorf("scp --host bastion,web-01 -J bastion --exclude web-01 err = %v, want *ssh.ProxyCycleError", err)
		}

		// Duplicate -J hops must fail closed on surviving web-01.
		oDupJump := NewScpOptions()
		oDupJump.Tag = "prod"
		oDupJump.JumpHost = "bastion,bastion"
		oDupJump.Exclude = []string{"bastion"}
		oDupJump.Source = "./file"
		oDupJump.Dest = "/tmp/file"
		if _, err := oDupJump.planTransfer(t.Context(), prov); !errors.As(err, &cycleErr) {
			t.Errorf("scp --tag prod -J bastion,bastion --exclude bastion err = %v, want *ssh.ProxyCycleError", err)
		}

		// Malformed -J syntax must fail closed upfront even when bastion is excluded.
		oBadSyntax := NewScpOptions()
		oBadSyntax.Tag = "prod"
		oBadSyntax.JumpHost = "bastion,,hop2"
		oBadSyntax.Exclude = []string{"bastion"}
		oBadSyntax.Source = "./file"
		oBadSyntax.Dest = "/tmp/file"
		if _, err := oBadSyntax.planTransfer(t.Context(), prov); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("scp malformed -J err = %v, want ErrSSHOptionsValidation", err)
		}
	})
}

func TestP7W11c_FG11M2_ExecExcludeBeforeCLIProxyJumpCycleValidation(t *testing.T) {
	t.Parallel()

	prov := buildW11cBatchCycleExcludeProvider(t)

	t.Run("tag_and_host_with_J_bastion_and_exclude_bastion_do_not_abort_with_ProxyCycleError", func(t *testing.T) {
		t.Parallel()
		assertW11cExecExcludeBeforeJumpSucceeds(t, prov)
	})

	t.Run("runWithProvider_fails_closed_on_surviving_cycle_and_malformed_J_upfront", func(t *testing.T) {
		t.Parallel()
		assertW11cExecSurvivingCycleFailsClosed(t, prov)
	})
}

func assertW11cExecExcludeBeforeJumpSucceeds(t *testing.T, prov config.ConfigProvider) {
	t.Helper()
	for _, tc := range []struct {
		name string
		init func(*ExecOptions)
	}{
		{"tag_flag_J", func(o *ExecOptions) { o.Tag = "prod"; o.JumpHost = "bastion" }},
		{"tag_opt_ProxyJump", func(o *ExecOptions) { o.Tag = "prod"; o.control.Options = []string{"ProxyJump=bastion"} }},
		{"host_flag_J", func(o *ExecOptions) { o.Host = "bastion,web-01"; o.JumpHost = "bastion" }},
	} {
		o := NewExecOptions()
		o.Command = "uptime"
		o.Exclude = []string{"bastion"}
		tc.init(o)

		var (
			tasks    []execHostTask
			hostErrs []error
			err      error
		)
		if o.Tag != "" {
			tasks, err = o.planTasksFromTags(t.Context(), prov)
		} else {
			tasks, hostErrs, err = o.planTasksFromHosts(t.Context(), prov)
		}
		if err != nil || len(hostErrs) != 0 {
			t.Fatalf("%s pre-exclude plan failed: err=%v hostErrs=%v", tc.name, err, hostErrs)
		}
		if len(tasks) != 2 {
			t.Fatalf("%s pre-exclude tasks len = %d, want 2", tc.name, len(tasks))
		}

		candidates := make([]utils.ExcludeTargetInfo, 0, len(tasks))
		for _, task := range tasks {
			candidates = append(candidates, o.execTaskExcludeInfo(task))
		}
		parsedExcludes, exErr := o.validatedExcludes()
		if exErr != nil {
			t.Fatalf("%s validatedExcludes: %v", tc.name, exErr)
		}
		excludes, exErr := utils.ResolveExcludesForTargetsWithOptions(prov, parsedExcludes, candidates, o.control.Options, o.effectiveCLIJumpHost())
		if exErr != nil {
			t.Fatalf("%s ResolveExcludesForTargetsWithOptions: %v", tc.name, exErr)
		}
		var filtered []execHostTask
		for i, task := range tasks {
			if !utils.IsTargetExcluded(excludes, candidates[i]) {
				filtered = append(filtered, task)
			}
		}
		surviving, postHostErrs, postErr := o.validateSurvivingExecTasksJump(prov, filtered)
		if postErr != nil || len(postHostErrs) != 0 || len(surviving) != 1 || surviving[0].rawHost != "web-01" {
			t.Fatalf("%s surviving web-01 validation failed: surviving=%+v hostErrs=%v err=%v", tc.name, surviving, postHostErrs, postErr)
		}
		if matErr := o.withPendingExecTasks(t.Context(), prov, surviving, func(materialized []execHostTask, _ []config.PendingLease, matErrs []error) error {
			if len(matErrs) != 0 || len(materialized) != 1 || materialized[0].nodeID != "web-01" {
				t.Fatalf("%s withPendingExecTasks = (len=%d errs=%v)", tc.name, len(materialized), matErrs)
			}
			return nil
		}); matErr != nil {
			t.Fatalf("%s withPendingExecTasks failed: %v", tc.name, matErr)
		}
	}
}

func assertW11cExecSurvivingCycleFailsClosed(t *testing.T, prov config.ConfigProvider) {
	t.Helper()
	cfg := prov.Snapshot()
	var cycleErr *ssh.ProxyCycleError

	// Surviving bastion in --tag fails closed with *ssh.ProxyCycleError before dialing.
	oTagSurv := NewExecOptions()
	oTagSurv.Tag = "prod"
	oTagSurv.JumpHost = "bastion"
	oTagSurv.Exclude = []string{"web-01"}
	oTagSurv.Command = "uptime"
	if err := oTagSurv.runWithProvider(t.Context(), cfg, prov); !errors.As(err, &cycleErr) {
		t.Errorf("exec --tag prod -J bastion --exclude web-01 err = %v, want *ssh.ProxyCycleError", err)
	}

	// Surviving bastion in --host fails closed with *ssh.ProxyCycleError before dialing.
	oHostSurv := NewExecOptions()
	oHostSurv.Host = "bastion,web-01"
	oHostSurv.JumpHost = "bastion"
	oHostSurv.Exclude = []string{"web-01"}
	oHostSurv.Command = "uptime"
	if err := oHostSurv.runWithProvider(t.Context(), cfg, prov); !errors.As(err, &cycleErr) {
		t.Errorf("exec --host bastion,web-01 -J bastion --exclude web-01 err = %v, want *ssh.ProxyCycleError", err)
	}

	// Duplicate -J hops on surviving web-01 fails closed with *ssh.ProxyCycleError before dialing.
	oDupJump := NewExecOptions()
	oDupJump.Tag = "prod"
	oDupJump.JumpHost = "bastion,bastion"
	oDupJump.Exclude = []string{"bastion"}
	oDupJump.Command = "uptime"
	if err := oDupJump.runWithProvider(t.Context(), cfg, prov); !errors.As(err, &cycleErr) {
		t.Errorf("exec --tag prod -J bastion,bastion --exclude bastion err = %v, want *ssh.ProxyCycleError", err)
	}

	// Malformed -J syntax fails closed upfront even when all targets would be excluded.
	oBadSyntax := NewExecOptions()
	oBadSyntax.Tag = "prod"
	oBadSyntax.JumpHost = "bastion,,hop2"
	oBadSyntax.Exclude = []string{"bastion", "web-01"}
	oBadSyntax.Command = "uptime"
	if err := oBadSyntax.runWithProvider(t.Context(), cfg, prov); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
		t.Errorf("exec malformed -J err = %v, want ErrSSHOptionsValidation", err)
	}

	// Excluding all targets (including bastion) with valid -J bastion returns no-nodes-found, NOT ProxyCycleError.
	oAllExcl := NewExecOptions()
	oAllExcl.Tag = "prod"
	oAllExcl.JumpHost = "bastion"
	oAllExcl.Exclude = []string{"bastion", "web-01"}
	oAllExcl.Command = "uptime"
	errAll := oAllExcl.runWithProvider(t.Context(), cfg, prov)
	if errAll == nil || errors.As(errAll, &cycleErr) {
		t.Errorf("exec all-excluded with -J bastion err = %v, want no-nodes-found (not ProxyCycleError)", errAll)
	}
}

func TestP7W11c_FG11M1_ScpBatchCompositeSavedExcludeDoesNotCanonicalize(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host prod-db.corp.example.com
    HostName 10.223.9.9
    Port 99999

Host *
    CanonicalizeHostname always
    CanonicalDomains corp.example.com
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-db", models.Host{Address: "10.223.0.1", Port: 22})
	cfg.Hosts.Set("h-db-fqdn", models.Host{Address: "prod-db.corp.example.com", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("prod-db", models.Node{HostRef: "h-db", IdentityRef: "id-ops", Tags: []string{"db"}})
	cfg.Nodes.Set("prod-db-fqdn", models.Node{HostRef: "h-db-fqdn", IdentityRef: "id-ops", Tags: []string{"db"}})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	o := NewScpOptions()
	o.Tag = "db"
	o.Exclude = []string{"ops@prod-db"}
	o.Source = "./dump.sql"
	o.Dest = "/tmp/dump.sql"

	plan, err := o.planTransfer(t.Context(), prov)
	if err != nil {
		t.Fatalf("scp planTransfer(--tag db --exclude ops@prod-db) failed: %v", err)
	}
	if len(plan.targets) != 1 || plan.targets[0].label != "prod-db-fqdn" {
		t.Fatalf("plan.targets = %+v, want only prod-db-fqdn surviving", plan.targets)
	}
	if strings.Contains(plan.targets[0].label, "99999") {
		t.Fatalf("unexpected target label: %q", plan.targets[0].label)
	}
}
