package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func buildCmdW16bM1Fixtures(t *testing.T) (*config.Provider, *config.Repository) {
	t.Helper()

	sshCfg := strings.Join([]string{
		"Host jump-box",
		"  HostName 10.30.0.1",
		"  User juser",
		"  Port 2201",
		"",
		"Host app-virtual",
		"  HostName 10.30.0.20",
		"  User vuser",
		"  Port 2220",
		"  ProxyJump jump-box",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-w16b-app-%h-%p-%r-%n-%j-%C",
		"  ControlPersist 60s",
		"  RemoteCommand uptime",
		"",
		"Host app-notty",
		"  HostName 10.30.0.21",
		"  User vuser",
		"  Port 2221",
		"  SessionType none",
		"",
		"Host short",
		"  User ops",
		"",
		"Host *.corp.example.com",
		"  HostName 10.40.0.5",
		"  Port 2222",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-w16b-canon-%n-%h-%p-%r-%j-%C",
		"  RemoteCommand date",
		"",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n") + "\n"

	makeCfg := func() (*config.Configuration, *config.OpenSSHParser) {
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()

		cfg.Hosts.Set("h-bastion", models.Host{Address: "10.10.0.254", Port: 22})
		cfg.Identities.Set("id-bastion", models.Identity{User: "jump", AuthType: "auto"})
		cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-bastion"})

		webOpts := ssh.MustOptions(
			ssh.OptionControlMaster, "auto",
			ssh.OptionControlPath, "/tmp/cm-w16b-web01-%h-%p-%r-%n-%j-%C",
			ssh.OptionRemoteCommand, "echo web01",
			ssh.OptionSessionType, "none",
		)
		cfg.Hosts.Set("h-web1", models.Host{Address: "10.10.0.1", Port: 2222})
		cfg.Identities.Set("id-web1", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("web-01", models.Node{
			HostRef:     "h-web1",
			IdentityRef: "id-web1",
			Alias:       []string{"Prod Web 01"},
			ProxyJump:   "bastion",
			SSHOptions:  webOpts,
		})
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

func TestP7W16b_L3_16_M1_ControlCheckSocketParityOnOverriddenOpenSSHAlias(t *testing.T) {
	t.Parallel()

	env := sshenv.Discover()
	cases := []struct {
		name     string
		makeOpts func() *SshOptions
	}{
		{
			name: "openssh_alias_port_2299_no_global_controlpath",
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.Port = 2299
				o.args = []string{"app-virtual"}
				return o
			},
		},
		{
			name: "openssh_alias_user_altuser_no_global_controlpath",
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.User = "altuser"
				o.args = []string{"app-virtual"}
				return o
			},
		},
		{
			name: "openssh_alias_port_and_user_no_global_controlpath",
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.Port = 2299
				o.User = "altuser"
				o.args = []string{"app-virtual"}
				return o
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			roProv, repo := buildCmdW16bM1Fixtures(t)

			// Control plane: simulate `xops ssh -O check -p 2299 app-virtual` (zero global ControlPath).
			ctlOpts := tc.makeOpts()
			ctlOpts.control.CtlCmd = "check"
			if err := ctlOpts.ensureArgsParsed(); err != nil {
				t.Fatalf("ctlOpts.ensureArgsParsed: %v", err)
			}
			var stderr bytes.Buffer
			if err := prepareControlOptionsForContext(t.Context(), ctlOpts, roProv, &stderr); err != nil {
				t.Fatalf("prepareControlOptionsForContext: %v (stderr=%q)", err, stderr.String())
			}
			ctlNodeID, err := resolveControlNodeID(roProv, effectiveConnectionTarget(ctlOpts, ""))
			if err != nil {
				t.Fatalf("resolveControlNodeID: %v", err)
			}
			ctlTarget, err := controlTarget(ctlOpts, roProv, ctlNodeID)
			if err != nil {
				t.Fatalf("controlTarget: %v", err)
			}
			ctlSock, err := expandControlSocketPath(ctlOpts, roProv, ctlNodeID, ctlTarget, &stderr)
			if err != nil {
				t.Fatalf("expandControlSocketPath failed (must not reject with ControlPath required): %v (stderr=%q)", err, stderr.String())
			}

			// Dial plane: simulate `xops ssh -p 2299 app-virtual`.
			dialOpts := tc.makeOpts()
			dialOpts.Remember = "never"
			if err := dialOpts.ensureArgsParsed(); err != nil {
				t.Fatalf("dialOpts.ensureArgsParsed: %v", err)
			}
			var (
				dialTarget ssh.TargetContext
				dialSock   string
			)
			if err := dialOpts.withTestPendingNode(t.Context(), repo, func(lease config.PendingLease) error {
				dialNodeID := lease.NodeID()
				adpOpts, err := dialOpts.buildAdapterOptions(dialNodeID, repo.Snapshot(), repo)
				if err != nil {
					t.Fatalf("buildAdapterOptions: %v", err)
				}
				adp := adapter.NewSSHAdapter(repo, adpOpts...)
				clientCfg, err := adp.GetConfig(dialNodeID)
				if err != nil {
					t.Fatalf("GetConfig(%q): %v", dialNodeID, err)
				}
				dialCtrl, err := adp.GetControlConfig(dialNodeID)
				if err != nil {
					t.Fatalf("GetControlConfig(%q): %v", dialNodeID, err)
				}
				if !dialCtrl.IsEnabled() {
					t.Fatalf("expected enabled dial ControlConfig, got %+v", dialCtrl)
				}
				dialTarget = ssh.BuildClientTargetContext(dialNodeID, clientCfg, env, nil)
				var pathErr error
				dialSock, pathErr = dialCtrl.ResolvePath(env, dialTarget)
				if pathErr != nil {
					t.Fatalf("dial ResolvePath: %v", pathErr)
				}
				return nil
			}); err != nil {
				t.Fatalf("withTestPendingNode: %v", err)
			}

			if ctlTarget != dialTarget {
				t.Fatalf("TargetContext mismatch:\n  control = %+v\n  dial    = %+v", ctlTarget, dialTarget)
			}
			if ctlSock != dialSock {
				t.Fatalf("ControlPath mismatch:\n  control = %q\n  dial    = %q", ctlSock, dialSock)
			}
		})
	}
}

func assertCmdW16bBackgroundProbeCases(t *testing.T, roProv *config.Provider) {
	t.Helper()
	for _, tc := range []struct {
		name     string
		makeOpts func() *SshOptions
		want     bool
	}{
		{
			name: "openssh_alias_user_override_retains_remote_command",
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.BgRun = true
				o.User = "altuser"
				o.args = []string{"app-virtual"}
				return o
			},
			want: true,
		},
		{
			name: "openssh_alias_port_override_retains_remote_command",
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.BgRun = true
				o.Port = 2299
				o.args = []string{"app-virtual"}
				return o
			},
			want: true,
		},
		{
			name: "openssh_alias_port_override_retains_session_type_none",
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.BgRun = true
				o.Port = 2299
				o.args = []string{"app-notty"}
				return o
			},
			want: true,
		},
		{
			name: "openssh_canonical_port_override_retains_remote_command",
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.BgRun = true
				o.Port = 2299
				o.args = []string{"short"}
				return o
			},
			want: true,
		},
		{
			name: "saved_node_port_override_does_not_leak_tier2_remote_command_or_session_type",
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.BgRun = true
				o.Port = 2299
				o.args = []string{"web-01"}
				return o
			},
			want: false,
		},
		{
			name: "saved_node_user_override_does_not_leak_tier2_remote_command_or_session_type",
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.BgRun = true
				o.User = "altuser"
				o.args = []string{"web-01"}
				return o
			},
			want: false,
		},
		{
			name: "saved_node_alias_port_override_does_not_leak_tier2",
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.BgRun = true
				o.Port = 2299
				o.args = []string{"Prod Web 01"}
				return o
			},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := tc.makeOpts()
			if err := o.ensureArgsParsed(); err != nil {
				t.Fatalf("ensureArgsParsed: %v", err)
			}
			sessionOpts, err := o.toSessionControlOptions()
			if err != nil {
				t.Fatalf("toSessionControlOptions: %v", err)
			}
			got, err := o.probeTargetBackgroundSession(roProv, sessionOpts, false, false)
			if err != nil {
				t.Fatalf("probeTargetBackgroundSession: %v", err)
			}
			if got != tc.want {
				t.Fatalf("probeTargetBackgroundSession(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func assertCmdW16bControlProxyAndCheckOverrides(t *testing.T, roProv *config.Provider) {
	t.Helper()

	// 1. Overridden OpenSSH alias: `-O proxy -p 2299 app-virtual` retains Host app-virtual's RemoteCommand.
	appOpts := NewSshOptions()
	appOpts.control.CtlCmd = "proxy"
	appOpts.Port = 2299
	appOpts.args = []string{"app-virtual"}
	if err := appOpts.ensureArgsParsed(); err != nil {
		t.Fatalf("appOpts.ensureArgsParsed: %v", err)
	}
	appNodeID, err := resolveControlNodeID(roProv, effectiveConnectionTarget(appOpts, ""))
	if err != nil {
		t.Fatalf("resolveControlNodeID(app-virtual -p 2299): %v", err)
	}
	appTarget, err := controlTarget(appOpts, roProv, appNodeID)
	if err != nil {
		t.Fatalf("controlTarget(app-virtual -p 2299): %v", err)
	}
	appCfg, _ := buildControlProxyClientConfig(appTarget, roProv, appNodeID, appOpts)
	if appCfg == nil || appCfg.Options == nil || appCfg.Options.Get(ssh.OptionRemoteCommand) != "uptime" {
		t.Fatalf("control proxy(-p 2299 app-virtual) dropped RemoteCommand=uptime: cfg=%+v opts=%v", appCfg, appCfg.Options)
	}

	// 2. Overridden saved node: `-O check -p 2299 web-01` and `-O check -l altuser web-01` must NOT leak web-01's saved Tier-2 ControlPath.
	for _, tc := range []struct {
		name string
		port uint16
		user string
	}{
		{"port_2299", 2299, ""},
		{"user_altuser", 0, "altuser"},
	} {
		webOpts := NewSshOptions()
		webOpts.control.CtlCmd = "check"
		webOpts.Port = tc.port
		webOpts.User = tc.user
		webOpts.args = []string{"web-01"}
		if err := webOpts.ensureArgsParsed(); err != nil {
			t.Fatalf("webOpts(%s).ensureArgsParsed: %v", tc.name, err)
		}
		webNodeID, err := resolveControlNodeID(roProv, effectiveConnectionTarget(webOpts, ""))
		if err != nil {
			t.Fatalf("resolveControlNodeID(web-01 %s): %v", tc.name, err)
		}
		webTarget, err := controlTarget(webOpts, roProv, webNodeID)
		if err != nil {
			t.Fatalf("controlTarget(web-01 %s): %v", tc.name, err)
		}
		var stderr bytes.Buffer
		if sock, err := expandControlSocketPath(webOpts, roProv, webNodeID, webTarget, &stderr); err == nil || sock != "" {
			t.Fatalf("expandControlSocketPath(web-01 %s) leaked saved web-01 ControlPath: sock=%q err=%v", tc.name, sock, err)
		}
	}

	// 3. Direct probeCandidateBackgroundSession with empty nodeID (unmatched override) must also preserve OpenSSH and block saved Tier-2 leak.
	appProbe := NewSshOptions()
	appProbe.BgRun = true
	appProbe.User = "altuser"
	appProbe.args = []string{"app-virtual"}
	if err := appProbe.ensureArgsParsed(); err != nil {
		t.Fatalf("appProbe.ensureArgsParsed: %v", err)
	}
	if !appProbe.probeCandidateBackgroundSession(roProv, "", effectiveConnectionTarget(appProbe, ""), adapter.SessionControlOptions{}, false, false) {
		t.Fatal("probeCandidateBackgroundSession(empty nodeID, -l altuser app-virtual) failed to preserve Host app-virtual RemoteCommand")
	}

	webProbe := NewSshOptions()
	webProbe.BgRun = true
	webProbe.Port = 2299
	webProbe.args = []string{"web-01"}
	if err := webProbe.ensureArgsParsed(); err != nil {
		t.Fatalf("webProbe.ensureArgsParsed: %v", err)
	}
	if webProbe.probeCandidateBackgroundSession(roProv, "", effectiveConnectionTarget(webProbe, ""), adapter.SessionControlOptions{}, false, false) {
		t.Fatal("probeCandidateBackgroundSession(empty nodeID, -p 2299 web-01) leaked saved web-01 RemoteCommand/SessionType")
	}
}

func TestP7W16b_L3_16_M1_BackgroundProbeAndControlProxyParity(t *testing.T) {
	t.Parallel()

	roProv, _ := buildCmdW16bM1Fixtures(t)

	t.Run("background_probe_preserves_openssh_remote_command_and_session_type_on_overrides", func(t *testing.T) {
		t.Parallel()
		assertCmdW16bBackgroundProbeCases(t, roProv)
	})
	t.Run("control_proxy_and_control_check_overridden_targets", func(t *testing.T) {
		t.Parallel()
		assertCmdW16bControlProxyAndCheckOverrides(t, roProv)
	})
}

func parseCompleteValidateSshArgs(t *testing.T, args ...string) (*SshOptions, error) {
	t.Helper()
	opts := NewSshOptions()
	c := newCmdSshWithOptions(opts)
	if err := c.Flags().Parse(args); err != nil {
		return nil, err
	}
	if err := opts.Complete(c, c.Flags().Args()); err != nil {
		return nil, err
	}
	return opts, opts.Validate()
}

func TestP7W16b_L3_16_M1_EndToEndCLIBackgroundValidateAndControlResolve(t *testing.T) {
	home := setupTestEnvironment(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	sshCfgPath := filepath.Join(home, "w16b_ssh_config")
	sshCfgContent := strings.Join([]string{
		"Host jump-box",
		"  HostName 10.30.0.1",
		"  User juser",
		"  Port 2201",
		"",
		"Host app-virtual",
		"  HostName 10.30.0.20",
		"  User vuser",
		"  Port 2220",
		"  ProxyJump jump-box",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-w16b-e2e-%h-%p-%r-%n-%j-%C",
		"  RemoteCommand uptime",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfgContent), 0o600); err != nil {
		t.Fatalf("WriteFile(ssh_config): %v", err)
	}

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.Hosts.Set("h-web1", models.Host{Address: "10.10.0.1", Port: 2222})
	cfg.Identities.Set("id-web1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("web-01", models.Node{
		HostRef:     "h-web1",
		IdentityRef: "id-web1",
		SSHOptions: ssh.MustOptions(
			ssh.OptionControlMaster, "auto",
			ssh.OptionControlPath, "/tmp/cm-w16b-web01-%C",
			ssh.OptionRemoteCommand, "echo web01",
			ssh.OptionSessionType, "none",
		),
	})
	if err := config.NewDefaultStore(cfgPath, keyPath).Save(cfg); err != nil {
		t.Fatalf("Save config: %v", err)
	}

	if _, err := parseCompleteValidateSshArgs(t, "-f", "-l", "altuser", "-F", sshCfgPath, "app-virtual"); err != nil {
		t.Fatalf("xops ssh -f -l altuser app-virtual Validate() failed: %v", err)
	}
	if _, err := parseCompleteValidateSshArgs(t, "-f", "-p", "2299", "-F", sshCfgPath, "app-virtual"); err != nil {
		t.Fatalf("xops ssh -f -p 2299 app-virtual Validate() failed: %v", err)
	}
	if _, err := parseCompleteValidateSshArgs(t, "-f", "-p", "2299", "-F", sshCfgPath, "web-01"); err == nil {
		t.Fatal("xops ssh -f -p 2299 web-01 Validate() succeeded; leaked saved web-01 Tier-2 RemoteCommand/SessionType")
	}

	// End-to-end resolveControlContext for `xops ssh -O check -p 2299 -F <sshCfgPath> app-virtual`.
	ctlOpts, err := parseCompleteValidateSshArgs(t, "-O", "check", "-p", "2299", "-F", sshCfgPath, "app-virtual")
	if err != nil {
		t.Fatalf("prepare -O check -p 2299 app-virtual: %v", err)
	}
	var stderr bytes.Buffer
	gotSock, gotTarget, _, _, err := resolveControlContext(t.Context(), ctlOpts, &stderr)
	if err != nil {
		t.Fatalf("resolveControlContext(-O check -p 2299 app-virtual): %v (stderr=%q)", err, stderr.String())
	}
	wantPrefix := "/tmp/cm-w16b-e2e-10.30.0.20-2299-vuser-app-virtual-openssh:jump-box-"
	if !strings.HasPrefix(gotSock, wantPrefix) || gotTarget.Port != 2299 || gotTarget.Host != "10.30.0.20" {
		t.Fatalf("resolveControlContext(-O check -p 2299 app-virtual) = (sock=%q target=%+v), want prefix %q", gotSock, gotTarget, wantPrefix)
	}

	// End-to-end resolveControlContext for `xops ssh -O check -p 2299 -F <sshCfgPath> web-01` must NOT leak web-01's ControlPath.
	webCtlOpts, err := parseCompleteValidateSshArgs(t, "-O", "check", "-p", "2299", "-F", sshCfgPath, "web-01")
	if err != nil {
		t.Fatalf("prepare -O check -p 2299 web-01: %v", err)
	}
	var webStderr bytes.Buffer
	if sock, _, _, _, err := resolveControlContext(t.Context(), webCtlOpts, &webStderr); err == nil || sock != "" {
		t.Fatalf("resolveControlContext(-O check -p 2299 web-01) leaked web-01 ControlPath: sock=%q err=%v", sock, err)
	}
}
