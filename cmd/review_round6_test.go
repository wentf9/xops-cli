package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	xssh "github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound6_P2_7_And_P3_9_SavedMasterNodeDefaultsDisambiguationAndIPv6(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host app-v6",
		"  HostName 2001:0DB8::55",
		"  User ops",
		"",
		"Host ssh-only-alias",
		"  HostName 10.70.0.5",
		"  User alice",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	// Port omitted (0 -> default 22), User omitted ("" -> default local user).
	cfg.Hosts.Set("h-def", models.Host{Address: "10.70.0.1", Port: 0})
	cfg.Identities.Set("id-def", models.Identity{User: ""})
	cfg.Nodes.Set("web-default", models.Node{HostRef: "h-def", IdentityRef: "id-def"})

	// Two saved nodes sharing an IP for disambiguation testing.
	cfg.Hosts.Set("h-shared", models.Host{Address: "10.70.0.5", Port: 22})
	cfg.Identities.Set("id-alice", models.Identity{User: "alice"})
	cfg.Identities.Set("id-bob", models.Identity{User: "bob"})
	cfg.Nodes.Set("alice@10.70.0.5:22", models.Node{HostRef: "h-shared", IdentityRef: "id-alice"})
	cfg.Nodes.Set("bob@10.70.0.5:22", models.Node{HostRef: "h-shared", IdentityRef: "id-bob"})

	prov := config.NewProviderWithOpenSSHParser(cfg, parser)
	localUser := defaultLocalUser()

	// P2-7: Port 2222 must NOT falsely match Port==0 (default 22) saved node.
	if got := resolveSavedMasterNodeID(prov, "web-default", "10.70.0.1", localUser, 2222); got != "" {
		t.Fatalf("port 2222 falsely matched port-0 saved node: %q", got)
	}
	if got := resolveSavedMasterNodeID(prov, "web-default", "10.70.0.1", localUser, 22); got != "web-default" {
		t.Fatalf("port 22 failed to match port-0 saved node: got %q", got)
	}
	// Wrong user must NOT falsely match empty Identity.User saved node.
	if got := resolveSavedMasterNodeID(prov, "web-default", "10.70.0.1", localUser+"-other", 22); got != "" {
		t.Fatalf("wrong user falsely matched empty-user saved node: %q", got)
	}

	// Disambiguate shared-IP saved nodes via (user, port).
	if got := resolveSavedMasterNodeID(prov, "10.70.0.5", "10.70.0.5", "bob", 22); got != "bob@10.70.0.5:22" {
		t.Fatalf("shared-IP disambiguation = %q, want bob@10.70.0.5:22", got)
	}
	// OpenSSH-only alias sharing an IP with a saved node must NOT be hijacked into saved node.
	if got := resolveSavedMasterNodeID(prov, "ssh-only-alias", "10.70.0.5", "alice", 22); got != "" {
		t.Fatalf("OpenSSH-only alias hijacked by saved node: %q", got)
	}

	// P3-9: resolveMasterVirtualOpenSSHNodeID matches non-canonical IPv6 HostName.
	if got := resolveMasterVirtualOpenSSHNodeID(prov, "app-v6", "2001:db8::55", "ops", 22); got != "openssh:app-v6" {
		t.Fatalf("resolveMasterVirtualOpenSSHNodeID(IPv6) = %q, want openssh:app-v6", got)
	}
}

func TestRound6_P3_6_P3_7_P3_8_ControlProxyTunnelAndEnsureApplied(t *testing.T) {
	t.Parallel()

	// P3-8: repeated -o Tunnel=... before -w obeys OpenSSH first-match-wins (including snake_case).
	sshOpt := NewSshOptions()
	sshOpt.recordOptionFlag("tunnel=ethernet")
	sshOpt.recordOptionFlag("Tunnel=point-to-point")
	sshOpt.recordTunnelDeviceFlag()
	if sshOpt.cliTunnelMode != string(xssh.TunnelModeEthernet) {
		t.Fatalf("recordOptionFlag cliTunnelMode = %q, want ethernet (first-match-wins)", sshOpt.cliTunnelMode)
	}

	// P3-6: resolveAndCacheSessionOptions applies general options and strips OptionClassLocalExec
	// in mux-daemon mode even when provider == nil.
	daemonOpt := NewSshOptions()
	daemonOpt.muxDaemonMode = true
	daemonOpt.control.Options = []string{"PermitLocalCommand=yes", "LocalCommand=echo hi", "ProxyJump=bastion"}
	eff, err := daemonOpt.resolveAndCacheSessionOptions(nil, "")
	if err != nil {
		t.Fatalf("resolveAndCacheSessionOptions(nil): %v", err)
	}
	if daemonOpt.JumpHost != "bastion" {
		t.Fatalf("resolveAndCacheSessionOptions did not apply -o ProxyJump: JumpHost=%q", daemonOpt.JumpHost)
	}
	if eff.Get(xssh.OptionLocalCommand) != "" || eff.Get(xssh.OptionPermitLocalCommand) != "" {
		t.Fatalf("mux daemon leaked OptionClassLocalExec with nil provider: LocalCommand=%q Permit=%q",
			eff.Get(xssh.OptionLocalCommand), eff.Get(xssh.OptionPermitLocalCommand))
	}

	// P3-6: scp excludeTargetInfoForPath, rawHostTargetPaths, and appendScpSessionAuthOverrides
	// propagate invalid general option errors instead of swallowing them.
	badScp := NewScpOptions()
	badScp.Host = "10.0.0.1"
	badScp.control.Options = []string{"Port=0"}
	if _, err := badScp.excludeTargetInfoForPath(nil, "10.0.0.1", PathInfo{Host: "10.0.0.1", IsRemote: true}); err == nil {
		t.Fatal("excludeTargetInfoForPath swallowed invalid -o Port=0 error")
	}
	if _, err := badScp.rawHostTargetPaths(); err == nil {
		t.Fatal("rawHostTargetPaths did not surface invalid -o Port=0 error")
	}
	var adpOpts []adapter.Option
	if err := badScp.appendScpSessionAuthOverrides(&adpOpts, nil, false, false); err == nil {
		t.Fatal("appendScpSessionAuthOverrides did not surface invalid -o Port=0 error")
	}

	// P3-7: targetContextFromResolvedTarget & newControlProxyFallbackConfig propagate CanonicalHost.
	tc := targetContextFromResolvedTarget(config.ResolvedTarget{
		NodeID:        "openssh:short.corp.example.com",
		Host:          "10.80.0.1",
		Port:          22,
		User:          "ops",
		CanonicalHost: "short.corp.example.com",
	})
	if tc.CanonicalHost != "short.corp.example.com" {
		t.Fatalf("targetContextFromResolvedTarget CanonicalHost = %q, want short.corp.example.com", tc.CanonicalHost)
	}
	fb := newControlProxyFallbackConfig(tc, nil, nil, nil, NewSshOptions())
	if fb.CanonicalHost != "short.corp.example.com" {
		t.Fatalf("newControlProxyFallbackConfig CanonicalHost = %q, want short.corp.example.com", fb.CanonicalHost)
	}

	// P3-7: -O proxy buildControlProxyClientConfig recovers saved-node OpenSSH alias on read-only *Provider.
	proxyCfgStr := strings.Join([]string{
		"Host app-a",
		"  HostName 10.80.0.5",
		"  User ops",
		"  ServerAliveInterval 11",
		"",
		"Host app-b",
		"  HostName 10.80.0.5",
		"  User ops",
		"  ServerAliveInterval 99",
	}, "\n") + "\n"
	proxyParser, err := config.NewOpenSSHParserFromReader(strings.NewReader(proxyCfgStr))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	savedCfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	savedCfg.Hosts.Set("h5", models.Host{Address: "10.80.0.5", Port: 22})
	savedCfg.Identities.Set("id5", models.Identity{User: "ops"})
	savedCfg.Nodes.Set("ops@10.80.0.5:22", models.Node{
		HostRef:       "h5",
		IdentityRef:   "id5",
		OpenSSHAlias:  "app-a",
		CanonicalHost: "app-a.corp.example.com",
	})
	readOnlyProv := config.NewProviderWithOpenSSHParser(savedCfg, proxyParser)

	proxyOpt := NewSshOptions()
	proxyOpt.Host = "app-b"
	proxyOpt.User = "ops"
	proxyOpt.Target = config.ConnectionTarget{Selector: "app-b", User: "ops", HasUser: true}
	proxyTarget := xssh.TargetContext{Host: "10.80.0.5", Port: 22, User: "ops", OriginalHost: "ops@10.80.0.5:22"}
	resolvedCfg, _ := buildControlProxyClientConfig(proxyTarget, readOnlyProv, "ops@10.80.0.5:22", proxyOpt)
	if resolvedCfg == nil || resolvedCfg.Options.Get(xssh.OptionServerAliveInterval) != "99" {
		t.Fatalf("-O proxy resolved wrong alias ServerAliveInterval: got %q, want 99", resolvedCfg.Options.Get(xssh.OptionServerAliveInterval))
	}
	if resolvedCfg.CanonicalHost != "" {
		t.Fatalf("-O proxy leaked stale Node.CanonicalHost = %q when switching alias to app-b", resolvedCfg.CanonicalHost)
	}
}

func TestRound6_P3_12_ExecAndScpCanonicalHostPropagation(t *testing.T) {
	t.Parallel()

	// P3-12 coverage: real ExecOptions.planTasksFromHosts -> buildTaskSessionAuth & scp appendScpSessionAuthOverrides propagate CanonicalHost.
	execCanonCfg := strings.Join([]string{
		"Host edge",
		"  User ops",
		"Host *.corp.example.com",
		"  HostName 10.80.0.9",
		"  User ops",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n") + "\n"
	execParser, err := config.NewOpenSSHParserFromReader(strings.NewReader(execCanonCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader(exec): %v", err)
	}
	execProv := config.NewProviderWithOpenSSHParser(nil, execParser)
	execOpt := NewExecOptions()
	execOpt.Host = "edge"
	execOpt.canonicalResolver = &round4FakeCanonicalResolver{
		hosts: map[string][]string{"edge.corp.example.com": {"10.80.0.9"}},
	}
	tasks, hostErrs, err := execOpt.planTasksFromHosts(t.Context(), execProv)
	if err != nil || len(hostErrs) != 0 || len(tasks) != 1 {
		t.Fatalf("planTasksFromHosts(edge) = (len=%d, errs=%v, err=%v)", len(tasks), hostErrs, err)
	}
	if tasks[0].nodeID != "openssh:edge.corp.example.com" || tasks[0].canonicalHost != "edge.corp.example.com" || tasks[0].originalHost != "edge" {
		t.Fatalf("planned exec task unexpected: %+v", tasks[0])
	}
	taskAuth, err := execOpt.buildTaskSessionAuth(tasks[0], nil, false, false)
	if err != nil {
		t.Fatalf("exec buildTaskSessionAuth: %v", err)
	}
	if taskAuth.CanonicalHost != "edge.corp.example.com" || taskAuth.OriginalHost != "edge" {
		t.Fatalf("exec buildTaskSessionAuth = (orig=%q, canon=%q), want (edge, edge.corp.example.com)", taskAuth.OriginalHost, taskAuth.CanonicalHost)
	}

	scpCanonCfg := strings.Join([]string{
		"Host edge",
		"  User ops",
		"Host *.corp.example.com",
		"  HostName 10.80.0.9",
		"  User ops",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n") + "\n"
	scpParser, err := config.NewOpenSSHParserFromReader(strings.NewReader(scpCanonCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	scpProv := config.NewProviderWithOpenSSHParser(nil, scpParser)
	scpOpt := NewScpOptions()
	scpOpt.Source = filepath.Join(t.TempDir(), "a.txt")
	scpOpt.Dest = "edge:/tmp/a.txt"
	scpOpt.canonicalResolver = &round4FakeCanonicalResolver{
		hosts: map[string][]string{"edge.corp.example.com": {"10.80.0.9"}},
	}
	if err := scpOpt.canonicalizeEndpoints(t.Context(), scpProv); err != nil {
		t.Fatalf("scp canonicalizeEndpoints: %v", err)
	}
	var scpAdpOpts []adapter.Option
	if err := scpOpt.appendScpSessionAuthOverrides(&scpAdpOpts, scpProv, false, true); err != nil {
		t.Fatalf("scp appendScpSessionAuthOverrides: %v", err)
	}
	scpCfg, err := adapter.NewSSHAdapter(scpProv, scpAdpOpts...).GetConfig("openssh:edge.corp.example.com")
	if err != nil {
		t.Fatalf("scp adapter GetConfig: %v", err)
	}
	if scpCfg.CanonicalHost != "edge.corp.example.com" || scpCfg.OriginalHost != "edge" {
		t.Fatalf("scp propagated (orig=%q, canon=%q), want (edge, edge.corp.example.com)", scpCfg.OriginalHost, scpCfg.CanonicalHost)
	}
}
