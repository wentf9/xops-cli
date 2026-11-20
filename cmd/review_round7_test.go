package cmd

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	xssh "github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound7_P1_6_ExecAndScpEndToEndExcludePlanning(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host unrelated-alias",
		"  HostName 10.94.0.5",
		"  User ops",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-ov", models.Host{Address: "10.94.0.5", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops"})
	cfg.Nodes.Set("saved-ov", models.Node{HostRef: "h-ov", IdentityRef: "id-ops"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	verifyRound7ExecExcludePlanning(t, prov)
	verifyRound7ScpExcludeInfo(t, prov)
}

func verifyRound7ExecExcludePlanning(t *testing.T, prov config.ConfigProvider) {
	t.Helper()
	execOpt := NewExecOptions()
	execOpt.Host = "saved-ov,openssh:unrelated-alias"
	execOpt.control.Options = []string{"HostName=override.internal"}
	tasks, hostErrs, err := execOpt.planTasksFromHosts(t.Context(), prov)
	if err != nil || len(hostErrs) != 0 || len(tasks) != 2 {
		t.Fatalf("planTasksFromHosts = (len=%d, errs=%v, err=%v)", len(tasks), hostErrs, err)
	}
	execCands := make([]cmdutils.ExcludeTargetInfo, 0, len(tasks))
	for _, task := range tasks {
		execCands = append(execCands, execOpt.execTaskExcludeInfo(task))
	}
	if execCands[0].ResolvedHost != "10.94.0.5" || !slices.Contains(execCands[0].UnmanagedHosts, "10.94.0.5") {
		t.Fatalf("saved exec candidate lost ResolvedHost under HostName override: %+v", execCands[0])
	}
	if execCands[1].ResolvedHost != "10.94.0.5" || slices.Contains(execCands[1].UnmanagedHosts, "10.94.0.5") {
		t.Fatalf("openssh exec candidate leaked ResolvedHost into UnmanagedHosts: %+v", execCands[1])
	}

	exSavedOnly, err := cmdutils.ResolveExcludesForTargets(prov, []string{"saved-ov"}, execCands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(saved-ov): %v", err)
	}
	if !cmdutils.IsTargetExcluded(exSavedOnly, execCands[0]) || cmdutils.IsTargetExcluded(exSavedOnly, execCands[1]) {
		t.Fatalf("exec exclude saved-ov mismatch: saved=%v unrelated=%v",
			cmdutils.IsTargetExcluded(exSavedOnly, execCands[0]), cmdutils.IsTargetExcluded(exSavedOnly, execCands[1]))
	}

	exExplicitIP, err := cmdutils.ResolveExcludesForTargets(prov, []string{"10.94.0.5"}, execCands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(10.94.0.5): %v", err)
	}
	if !cmdutils.IsTargetExcluded(exExplicitIP, execCands[0]) || cmdutils.IsTargetExcluded(exExplicitIP, execCands[1]) {
		t.Fatalf("exec exclude 10.94.0.5 mismatch (saved node matches IP without hijacking concrete OpenSSH alias): saved=%v unrelated=%v",
			cmdutils.IsTargetExcluded(exExplicitIP, execCands[0]), cmdutils.IsTargetExcluded(exExplicitIP, execCands[1]))
	}
}

func verifyRound7ScpExcludeInfo(t *testing.T, prov config.ConfigProvider) {
	t.Helper()
	scpOpt := NewScpOptions()
	scpOpt.control.Options = []string{"HostName=override.internal"}
	savedScpInfo, err := scpOpt.excludeTargetInfoForPath(prov, "saved-ov", PathInfo{Host: "saved-ov", IsRemote: true})
	if err != nil {
		t.Fatalf("excludeTargetInfoForPath(saved-ov): %v", err)
	}
	aliasScpInfo, err := scpOpt.excludeTargetInfoForPath(prov, "openssh:unrelated-alias", PathInfo{Host: "openssh:unrelated-alias", IsRemote: true})
	if err != nil {
		t.Fatalf("excludeTargetInfoForPath(openssh:unrelated-alias): %v", err)
	}
	if savedScpInfo.ResolvedHost != "10.94.0.5" || !slices.Contains(savedScpInfo.UnmanagedHosts, "10.94.0.5") {
		t.Fatalf("saved scp candidate unexpected: %+v", savedScpInfo)
	}
	if aliasScpInfo.ResolvedHost != "10.94.0.5" || slices.Contains(aliasScpInfo.UnmanagedHosts, "10.94.0.5") {
		t.Fatalf("openssh scp candidate leaked ResolvedHost into UnmanagedHosts: %+v", aliasScpInfo)
	}
}

func TestRound7_P2_7_ControlLookupSwitchesAliasesAndDoesNotBackfillCanonicalHost(t *testing.T) {
	t.Parallel()

	proxyCfgStr := strings.Join([]string{
		"Host app-a",
		"  HostName 10.95.0.5",
		"  User ops",
		"  ServerAliveInterval 11",
		"",
		"Host app-b",
		"  HostName 10.95.0.5",
		"  User ops",
		"  ServerAliveInterval 99",
	}, "\n") + "\n"
	proxyParser, err := config.NewOpenSSHParserFromReader(strings.NewReader(proxyCfgStr))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	savedCfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	savedCfg.Hosts.Set("h5", models.Host{Address: "10.95.0.5", Port: 22})
	savedCfg.Identities.Set("id5", models.Identity{User: "ops"})
	savedCfg.Nodes.Set("ops@10.95.0.5:22", models.Node{
		HostRef:       "h5",
		IdentityRef:   "id5",
		OpenSSHAlias:  "app-a",
		CanonicalHost: "app-a.corp.example.com",
	})
	prov := config.NewProviderWithOpenSSHParser(savedCfg, proxyParser)

	// Case 1: Resolve app-b through resolveControlSessionLookup when saved node already stores app-a metadata.
	switchOpt := NewSshOptions()
	switchOpt.Host = "app-b"
	switchOpt.User = "ops"
	switchOpt.Target = config.ConnectionTarget{Selector: "app-b", User: "ops", HasUser: true}
	_, switchAuth := resolveControlSessionLookup(switchOpt, prov, "ops@10.95.0.5:22", switchOpt.Target, xssh.TargetContext{
		Host: "10.95.0.5",
		Port: 22,
		User: "ops",
	})
	if switchAuth.OriginalHost != "app-b" || switchAuth.CanonicalHost != "" {
		t.Fatalf("resolveControlSessionLookup(app-b) = (orig=%q, canon=%q), want (app-b, \"\")", switchAuth.OriginalHost, switchAuth.CanonicalHost)
	}

	// Case 2: Explicit non-canonical origHost passed without canonHost must NOT backfill stale snap.Node.CanonicalHost.
	explicitKey, explicitAuth, handled, _ := resolveSavedControlSessionLookup(
		prov,
		"ops@10.95.0.5:22",
		"ops@10.95.0.5:22",
		config.ConnectionTarget{Selector: "ops@10.95.0.5:22"},
		"custom-orig",
		"",
		"",
		"",
	)
	if !handled || explicitKey != "ops@10.95.0.5:22" || explicitAuth.OriginalHost != "custom-orig" || explicitAuth.CanonicalHost != "" {
		t.Fatalf("explicit OriginalHost leaked snap.Node.CanonicalHost: key=%q handled=%v auth=%+v", explicitKey, handled, explicitAuth)
	}
}

func TestRound7_P2_8_MuxDaemonSpecLiteralControlPathPreserved(t *testing.T) {
	// Not parallel: reads/writes process env var via t.Setenv.
	t.Setenv("KEEP", "expanded-should-not-happen")

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("hz", models.Host{Address: "fe80::1%eth0", Port: 22})
	cfg.Identities.Set("id", models.Identity{User: "root"})
	cfg.Nodes.Set("v6-zone", models.Node{HostRef: "hz", IdentityRef: "id"})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	literalSock := filepath.Join(t.TempDir(), "cm-root@fe80::1%eth0:22-${KEEP}")
	spec := MuxDaemonSpec{
		Version:            muxDaemonSpecVersion,
		TargetHost:         "v6-zone",
		Port:               22,
		User:               "root",
		ControlPath:        literalSock,
		ControlPathLiteral: true,
		ControlMaster:      xssh.ControlMasterYes,
		ControlPersist:     "10m",
	}
	rawJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("json.Marshal(spec): %v", err)
	}
	var decoded MuxDaemonSpec
	if err := json.Unmarshal(rawJSON, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(spec): %v", err)
	}
	if !decoded.ControlPathLiteral || decoded.ControlPath != literalSock {
		t.Fatalf("MuxDaemonSpec round-trip lost ControlPathLiteral: %+v", decoded)
	}

	// Legacy JSON without control_path_literal remains decodable and defaults to false.
	var legacy MuxDaemonSpec
	if err := json.Unmarshal([]byte(`{"version":1,"target_host":"v6-zone","control_path":"/tmp/%h","control_master":"yes"}`), &legacy); err != nil {
		t.Fatalf("json.Unmarshal(legacy): %v", err)
	}
	if legacy.ControlPathLiteral {
		t.Fatalf("legacy spec unexpectedly set ControlPathLiteral=true")
	}

	daemonOpt := NewSshOptions()
	if err := daemonOpt.applyMuxDaemonSpec(decoded); err != nil {
		t.Fatalf("applyMuxDaemonSpec: %v", err)
	}
	if !daemonOpt.control.controlPathLiteral {
		t.Fatalf("applyMuxDaemonSpec did not preserve controlPathLiteral")
	}
	sessionOpts, err := daemonOpt.control.ToSessionControlOptionsWithJump("")
	if err != nil {
		t.Fatalf("ToSessionControlOptionsWithJump: %v", err)
	}
	if !sessionOpts.LiteralPath || sessionOpts.Path == nil || *sessionOpts.Path != literalSock {
		t.Fatalf("sessionOpts = %+v, want LiteralPath=true Path=%q", sessionOpts, literalSock)
	}

	resolvedSock, err := controlSocketPath(daemonOpt, prov, "v6-zone")
	if err != nil || resolvedSock != literalSock {
		t.Fatalf("controlSocketPath = (%q, %v), want (%q, nil)", resolvedSock, err, literalSock)
	}

	expandedSock, err := expandControlSocketPath(daemonOpt, prov, "v6-zone", xssh.TargetContext{Host: "fe80::1%eth0", Port: 22, User: "root"}, nil)
	if err != nil || expandedSock != literalSock {
		t.Fatalf("expandControlSocketPath = (%q, %v), want (%q, nil)", expandedSock, err, literalSock)
	}
}
