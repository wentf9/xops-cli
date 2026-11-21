package cmd

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestCLIContract_RejectEmptyExplicitShortFlags(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XOPS_CONFIG_DIR", filepath.Join(home, ".xops"))

	sshEmpty := [][]string{
		{"-c", "", "web"},
		{"-e", "", "web"},
		{"-S", "", "web"},
		{"-F", "", "web"},
		{"-l", "", "-o", "User=fallback", "web"},
		{"-J", "", "-o", "ProxyJump=jump1", "web"},
		{"-i", "", "-o", "IdentityFile=/tmp/k", "web"},
		{"-O", "", "web"},
		{"-W", "", "web"},
	}
	for _, args := range sshEmpty {
		cmd := NewCmdSsh()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Errorf("xops ssh %v succeeded, want fail-closed empty-flag error", args)
		}
	}

	for _, args := range [][]string{
		{"-c", "", "web"},
		{"-S", "", "web"},
		{"-F", "", "web"},
		{"-J", "", "web"},
		{"-i", "", "web"},
	} {
		cmd := NewCmdSftp()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Errorf("xops sftp %v succeeded, want fail-closed empty-flag error", args)
		}
	}

	for _, args := range [][]string{
		{"-c", "", "./a", "web:/tmp/b"},
		{"-S", "", "./a", "web:/tmp/b"},
		{"-F", "", "./a", "web:/tmp/b"},
		{"-J", "", "./a", "web:/tmp/b"},
		{"-i", "", "./a", "web:/tmp/b"},
	} {
		cmd := NewCmdScp()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Errorf("xops scp %v succeeded, want fail-closed empty-flag error", args)
		}
	}

	for _, args := range [][]string{
		{"-S", "", "web", "id"},
		{"-F", "", "web", "id"},
		{"-l", "", "-o", "User=fallback", "web", "id"},
		{"-J", "", "-o", "ProxyJump=jump1", "web", "id"},
		{"-i", "", "-o", "IdentityFile=/tmp/k", "web", "id"},
		{"-c", "", "--host", "web"},
	} {
		cmd := NewCmdExec()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Errorf("xops exec %v succeeded, want fail-closed empty-flag error", args)
		}
	}
}

func TestCLIContract_RejectExplicitZeroPort(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XOPS_CONFIG_DIR", filepath.Join(home, ".xops"))

	execFail := func(name string, cmd *cobra.Command, args []string) {
		t.Helper()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Errorf("%s %v succeeded, want explicit port-0 error", name, args)
		}
	}

	for _, args := range [][]string{
		{"-p", "0", "web"},
		{"-o", "Port=0", "web"},
		{"web:0"},
		{"alice@web:0"},
	} {
		execFail("ssh", NewCmdSsh(), args)
	}

	for _, args := range [][]string{
		{"-P", "0", "web"},
		{"-o", "Port=0", "web"},
		{"web:0"},
		{"alice@web:0"},
	} {
		execFail("sftp", NewCmdSftp(), args)
	}

	for _, args := range [][]string{
		{"-P", "0", "./a", "web:/tmp/b"},
		{"-o", "Port=0", "./a", "web:/tmp/b"},
		{"./a", "alice@web:0:/tmp/b"},
	} {
		execFail("scp", NewCmdScp(), args)
	}

	for _, args := range [][]string{
		{"-p", "0", "--host", "web", "-c", "id"},
		{"-o", "Port=0", "--host", "web", "-c", "id"},
		{"web:0", "id"},
		{"--host", "alice@web:0", "-c", "id"},
	} {
		execFail("exec", NewCmdExec(), args)
	}

	execFail("host add -p 0", hostcmd.NewCmdInventoryAdd(), []string{"--skip-verify", "-p", "0", "web", "192.0.2.10"})
	execFail("host add :0", hostcmd.NewCmdInventoryAdd(), []string{"--skip-verify", "web", "alice@192.0.2.10:0"})

	seed := hostcmd.NewCmdInventoryAdd()
	seed.SetOut(io.Discard)
	seed.SetErr(io.Discard)
	seed.SetArgs([]string{"--skip-verify", "--user", "alice", "-a", "seednode", "192.0.2.10"})
	if err := seed.Execute(); err != nil {
		t.Fatalf("seed host add: %v", err)
	}
	execFail("host edit -p 0", hostcmd.NewCmdInventoryEdit(), []string{"seednode", "-p", "0"})
}

func TestCLIContract_OpenSSHNamespaceIsolation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgDir := filepath.Join(home, ".xops")
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)

	assertOpenSSHMalformedRejected(t)
	assertOpenSSHNotHijackedOrPersisted(t, home, cfgDir)
	assertOpenSSHCLISelectorSyntaxAccepted(t)
	assertHostCommandsRejectReservedOpenSSH(t)
}

func assertOpenSSHMalformedRejected(t *testing.T) {
	t.Helper()
	for _, bad := range []string{"openssh:", "openssh:user@", "openssh::22"} {
		for _, tc := range []struct {
			name string
			cmd  *cobra.Command
			args []string
		}{
			{"ssh", NewCmdSsh(), []string{bad}},
			{"sftp", NewCmdSftp(), []string{bad}},
			{"exec_pos", NewCmdExec(), []string{bad, "id"}},
			{"exec_host", NewCmdExec(), []string{"--host", bad, "-c", "id"}},
			{"scp_path", NewCmdScp(), []string{"./a", bad + ":/tmp/b"}},
			{"scp_host", NewCmdScp(), []string{"--host", bad, "--src", "./a", "--dest", "/tmp/b"}},
		} {
			tc.cmd.SetOut(io.Discard)
			tc.cmd.SetErr(io.Discard)
			tc.cmd.SetArgs(tc.args)
			if err := tc.cmd.Execute(); err == nil {
				t.Errorf("%s %v succeeded for malformed selector %q, want error", tc.name, tc.args, bad)
			}
		}
	}
}

func assertOpenSSHNotHijackedOrPersisted(t *testing.T, home, cfgDir string) {
	t.Helper()
	sshCfgPath := filepath.Join(home, "ssh_config")
	sshCfg := strings.Join([]string{
		"Host web",
		"  HostName 10.99.0.1",
		"  User sshuser",
		"  Port 2201",
		"Host *",
		"  SetEnv FROM_STAR=yes",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := setupTestRepository(t)
	savedCfg := repo.Snapshot()
	savedCfg.Hosts.Set("h-saved", models.Host{Address: "192.0.2.99", Port: 22})
	savedCfg.Identities.Set("id-saved", models.Identity{User: "saved", AuthType: "auto"})
	savedCfg.Nodes.Set("web-saved", models.Node{HostRef: "h-saved", IdentityRef: "id-saved", Alias: []string{"web"}})
	savedRepo, err := config.NewRepositoryWithoutOpenSSH(savedCfg, config.NewDefaultStore(filepath.Join(cfgDir, "xops_config.yaml"), filepath.Join(cfgDir, "xops.key")))
	if err != nil {
		t.Fatal(err)
	}
	prov, err := config.WithOpenSSHConfigOverride(savedRepo, sshCfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, sel := range []string{"openssh:web", "openssh:alice@web:2222"} {
		res, rErr := config.ResolveTarget(prov, config.ConnectionTarget{Selector: sel, RawSelector: sel})
		if rErr != nil {
			t.Fatalf("ResolveTarget(%q): %v", sel, rErr)
		}
		if res.Host != "10.99.0.1" || !strings.HasPrefix(res.NodeID, config.OpenSSHNodePrefix) {
			t.Fatalf("ResolveTarget(%q) hijacked or lost namespace: %+v", sel, res)
		}
		if err := savedRepo.ConfirmNodeContext(t.Context(), res.NodeID); err != nil {
			t.Fatalf("ConfirmNodeContext(%q): %v", res.NodeID, err)
		}
		if _, persisted := savedRepo.Snapshot().Nodes.Get(res.NodeID); persisted {
			t.Fatalf("openssh node %q persisted into saved config", res.NodeID)
		}
	}
}

func assertOpenSSHCLISelectorSyntaxAccepted(t *testing.T) {
	t.Helper()
	for _, sel := range []string{"openssh:web", "openssh:alice@web:2222"} {
		assertOpenSSHSingleCommandSelectorSyntax(t, sel)
	}
	assertScpOpenSSHPathSyntax(t)
}

func assertOpenSSHSingleCommandSelectorSyntax(t *testing.T, sel string) {
	t.Helper()
	so := NewSshOptions()
	sc := newCmdSshWithOptions(so)
	if err := sc.ParseFlags([]string{sel}); err != nil {
		t.Fatal(err)
	}
	so.args = []string{sel}
	if err := so.parseArgs(); err != nil {
		t.Fatalf("ssh parseArgs(%q): %v", sel, err)
	}
	if so.Host != "openssh:web" {
		t.Errorf("ssh parseArgs(%q).Host = %q, want openssh:web", sel, so.Host)
	}

	sfo := NewSftpOptions()
	if err := sfo.Complete(NewCmdSftp(), []string{sel}); err != nil {
		t.Fatalf("sftp Complete(%q): %v", sel, err)
	}
	if err := sfo.parseArgs(); err != nil {
		t.Fatalf("sftp parseArgs(%q): %v", sel, err)
	}
	if sfo.Host != "openssh:web" {
		t.Errorf("sftp parseArgs(%q).Host = %q, want openssh:web", sel, sfo.Host)
	}

	if h, _, _, _, eErr := parsePositionalHost([]string{sel, "id"}); eErr != nil || h != "openssh:web" {
		t.Errorf("exec parsePositionalHost(%q) = (%q, %v)", sel, h, eErr)
	}
	if hosts, hErr := utils.ParseHosts(sel, "", ""); hErr != nil || len(hosts) != 1 || hosts[0].Host != "openssh:web" {
		t.Errorf("ParseHosts(%q) = (%+v, %v)", sel, hosts, hErr)
	}
}

func assertScpOpenSSHPathSyntax(t *testing.T) {
	t.Helper()
	if pi, pErr := parsePath("openssh:alice@web:/tmp/f"); pErr != nil || !pi.IsRemote || pi.User != "alice" || pi.Host != "openssh:web" || pi.Path != "/tmp/f" {
		t.Errorf("scp parsePath(openssh:alice@web:/tmp/f) = (%+v, %v)", pi, pErr)
	}
	if pi, pErr := parsePath("openssh:web:/tmp/f"); pErr != nil || !pi.IsRemote || pi.Host != "openssh:web" || pi.Path != "/tmp/f" {
		t.Errorf("scp parsePath(openssh:web:/tmp/f) = (%+v, %v)", pi, pErr)
	}
}

func assertHostCommandsRejectReservedOpenSSH(t *testing.T) {
	t.Helper()
	seed := hostcmd.NewCmdInventoryAdd()
	seed.SetOut(io.Discard)
	seed.SetErr(io.Discard)
	seed.SetArgs([]string{"--skip-verify", "--user", "alice", "-a", "normal-alias", "192.0.2.10"})
	if err := seed.Execute(); err != nil {
		t.Fatalf("seed host add: %v", err)
	}
	for _, reserved := range []string{"openssh", "OpenSSH", "openssh:prod"} {
		addCmd := hostcmd.NewCmdInventoryAdd()
		addCmd.SetOut(io.Discard)
		addCmd.SetErr(io.Discard)
		addCmd.SetArgs([]string{"--skip-verify", "--user", "alice", "-a", reserved, "192.0.2.11"})
		if err := addCmd.Execute(); err == nil {
			t.Errorf("host add -a %q succeeded, want reserved namespace error", reserved)
		}

		editCmd := hostcmd.NewCmdInventoryEdit()
		editCmd.SetOut(io.Discard)
		editCmd.SetErr(io.Discard)
		editCmd.SetArgs([]string{"normal-alias", "-a", reserved})
		if err := editCmd.Execute(); err == nil {
			t.Errorf("host edit -a %q succeeded, want reserved namespace error", reserved)
		}
	}
}

func TestCLIContract_UserPortPrecedenceMatrix(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	assertSshAndSftpFlagsOverrideInline(t)
	assertSingleExecFlagsOverrideInline(t)
	assertScpInlineEndpointOverridesFlags(t)
	assertBatchExecInlineEndpointOverridesFlags(t)
}

func assertSshAndSftpFlagsOverrideInline(t *testing.T) {
	t.Helper()
	for _, cliArgs := range [][]string{
		{"-l", "flaguser", "-p", "2299", "inlineuser@web:2201"},
		{"-o", "User=flaguser", "-o", "Port=2299", "inlineuser@web:2201"},
	} {
		so := NewSshOptions()
		c := newCmdSshWithOptions(so)
		if err := c.ParseFlags(cliArgs); err != nil {
			t.Fatalf("ssh ParseFlags(%v): %v", cliArgs, err)
		}
		if err := so.Complete(c, c.Flags().Args()); err != nil {
			t.Fatalf("ssh Complete(%v): %v", cliArgs, err)
		}
		if err := so.parseArgs(); err != nil {
			t.Fatalf("ssh parseArgs(%v): %v", cliArgs, err)
		}
		if so.User != "flaguser" || so.Port != 2299 || so.Host != "web" {
			t.Errorf("ssh %v -> user=%q port=%d host=%q, want flaguser/2299/web", cliArgs, so.User, so.Port, so.Host)
		}
	}

	sftpCmd := NewCmdSftp()
	if err := sftpCmd.ParseFlags([]string{"-P", "2299", "-o", "User=sftpflag", "inline@web:2201"}); err != nil {
		t.Fatalf("sftp ParseFlags: %v", err)
	}
	sfo := NewSftpOptions()
	sfo.Port, _ = sftpCmd.Flags().GetUint16("port")
	sfo.control.Options, _ = sftpCmd.Flags().GetStringArray("option")
	if err := sfo.Complete(sftpCmd, sftpCmd.Flags().Args()); err != nil {
		t.Fatalf("sftp Complete: %v", err)
	}
	if err := sfo.parseArgs(); err != nil {
		t.Fatalf("sftp parseArgs: %v", err)
	}
	if sfo.User != "sftpflag" || sfo.Port != 2299 || sfo.Host != "web" {
		t.Errorf("sftp -> user=%q port=%d host=%q, want sftpflag/2299/web", sfo.User, sfo.Port, sfo.Host)
	}
}

func assertSingleExecFlagsOverrideInline(t *testing.T) {
	t.Helper()
	eo := NewExecOptions()
	ec := newCmdExecWithOptions(eo)
	if err := ec.ParseFlags([]string{"-l", "flaguser", "-p", "2299"}); err != nil {
		t.Fatal(err)
	}
	if err := eo.Complete(ec, []string{"inlineuser@web:2201", "id"}); err != nil {
		t.Fatal(err)
	}
	if eo.User != "flaguser" || eo.Port != 2299 || eo.Host != "web" {
		t.Errorf("single exec -> user=%q port=%d host=%q, want flaguser/2299/web", eo.User, eo.Port, eo.Host)
	}
}

func assertScpInlineEndpointOverridesFlags(t *testing.T) {
	t.Helper()
	scpCmd := NewCmdScp()
	if err := scpCmd.ParseFlags([]string{"-P", "2299", "-o", "User=globaluser"}); err != nil {
		t.Fatal(err)
	}
	scpOpts := NewScpOptions()
	scpOpts.Port, _ = scpCmd.Flags().GetUint16("port")
	scpOpts.control.Options, _ = scpCmd.Flags().GetStringArray("option")
	if err := scpOpts.Complete(scpCmd, []string{"alice@src:/a", "dst:/b"}); err != nil {
		t.Fatal(err)
	}
	srcPI, _ := parsePath(scpOpts.Source)
	dstPI, _ := parsePath(scpOpts.Dest)
	if su, _, sp, _ := scpOpts.resolveUserAndPort(srcPI); su != "alice" || sp != 2299 {
		t.Errorf("scp positional alice@src:/a = (%q, %d), want (alice, 2299)", su, sp)
	}
	if du, _, dp, _ := scpOpts.resolveUserAndPort(dstPI); du != "globaluser" || dp != 2299 {
		t.Errorf("scp inherited endpoint = (%q, %d), want (globaluser, 2299)", du, dp)
	}
	batchHosts, err := utils.ParseHosts("alice@src:2201,dst", "", "")
	if err != nil || len(batchHosts) != 2 {
		t.Fatalf("ParseHosts(alice@src:2201,dst): %v", err)
	}
	if bu0, _, bp0, _ := scpOpts.resolveUserAndPort(PathInfo{IsRemote: true, User: batchHosts[0].User, Host: batchHosts[0].Host, Port: batchHosts[0].Port}); bu0 != "alice" || bp0 != 2201 {
		t.Errorf("scp batch inline user@host:port = (%q, %d), want (alice, 2201)", bu0, bp0)
	}
	if bu1, _, bp1, _ := scpOpts.resolveUserAndPort(PathInfo{IsRemote: true, User: batchHosts[1].User, Host: batchHosts[1].Host, Port: batchHosts[1].Port}); bu1 != "globaluser" || bp1 != 2299 {
		t.Errorf("scp batch bare host = (%q, %d), want (globaluser, 2299)", bu1, bp1)
	}
	if tu, _, tp, _ := scpOpts.resolveUserAndPort(taggedNodePathInfo("bare-node")); tu != "globaluser" || tp != 2299 {
		t.Errorf("scp --tag endpoint = (%q, %d), want (globaluser, 2299)", tu, tp)
	}
}

func assertBatchExecInlineEndpointOverridesFlags(t *testing.T) {
	t.Helper()
	eo := NewExecOptions()
	eo.User = "globaluser"
	eo.Port = 2299
	if u, _, p, _, _ := eo.resolveExecEntryCredentials(utils.HostInfo{Host: "a", User: "alice", Port: 2201}, true); u != "alice" || p != 2201 {
		t.Errorf("batch exec inline = (%q, %d), want (alice, 2201)", u, p)
	}
	if u, _, p, _, _ := eo.resolveExecEntryCredentials(utils.HostInfo{Host: "b"}, true); u != "globaluser" || p != 2299 {
		t.Errorf("batch exec bare = (%q, %d), want (globaluser, 2299)", u, p)
	}
	if u, _, p, _, _ := eo.resolveExecEntryCredentials(utils.HostInfo{Host: "a", User: "alice", Port: 2201}, false); u != "globaluser" || p != 2299 {
		t.Errorf("single-host --host exec = (%q, %d), want (globaluser, 2299)", u, p)
	}
}

func TestCLIContract_DuplicateDashOFirstWins(t *testing.T) {
	// 1. Control & trust options via ParseSessionOptions: first occurrence wins (StrictHostKeyChecking never downgraded).
	ctrlOpts, err := adapter.ParseSessionOptions([]string{
		"StrictHostKeyChecking=yes",
		"StrictHostKeyChecking=no",
		"ControlMaster=ask",
		"ControlMaster=no",
		"ControlPersist=60s",
		"ControlPersist=no",
		"ControlPath=/tmp/first.sock",
		"ControlPath=/tmp/second.sock",
	}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}
	if got := ctrlOpts.Options.StrictHostKeyChecking(); got != "yes" {
		t.Errorf("StrictHostKeyChecking = %q, want yes (first wins)", got)
	}
	if ctrlOpts.Master == nil || *ctrlOpts.Master != ssh.ControlMasterAsk {
		t.Errorf("ControlMaster = %v, want ask (first wins)", ctrlOpts.Master)
	}
	if ctrlOpts.Persist == nil || *ctrlOpts.Persist != "60s" {
		t.Errorf("ControlPersist = %v, want 60s (first wins)", ctrlOpts.Persist)
	}
	if ctrlOpts.Path == nil || *ctrlOpts.Path != "/tmp/first.sock" {
		t.Errorf("ControlPath = %v, want /tmp/first.sock (first wins)", ctrlOpts.Path)
	}

	// 2. General options: User / Port / HostName first wins, IdentityFile accumulates both with nil and non-nil flags.
	optsNil := NewSshOptions()
	if err := ApplyGeneralOptions(optsNil, []string{
		"User=first",
		"User=second",
		"Port=2201",
		"Port=2202",
		"HostName=first.internal",
		"HostName=second.internal",
		"IdentityFile=/tmp/k1",
		"IdentityFile=/tmp/k2",
	}, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions(nil): %v", err)
	}
	if optsNil.User != "first" || optsNil.Port != 2201 || optsNil.cliHostName != "first.internal" {
		t.Errorf("nil flags first-wins = user:%q port:%d hostName:%q", optsNil.User, optsNil.Port, optsNil.cliHostName)
	}
	if !slices.Equal(optsNil.IdentityFiles, []string{"/tmp/k1", "/tmp/k2"}) {
		t.Errorf("nil flags IdentityFiles = %v, want [/tmp/k1 /tmp/k2]", optsNil.IdentityFiles)
	}

	so := NewSshOptions()
	sc := newCmdSshWithOptions(so)
	if err := sc.ParseFlags([]string{"-i", "/tmp/k0", "-o", "IdentityFile=/tmp/k1", "-o", "IdentityFile=/tmp/k2", "web"}); err != nil {
		t.Fatal(err)
	}
	if err := so.Complete(sc, []string{"web"}); err != nil {
		t.Fatal(err)
	}
	wantAbs0 := filepath.Join("/", "tmp", "k0")
	if !slices.Equal(so.IdentityFiles, []string{wantAbs0, "/tmp/k1", "/tmp/k2"}) {
		t.Errorf("-i + -o IdentityFile = %v, want [%s /tmp/k1 /tmp/k2]", so.IdentityFiles, wantAbs0)
	}
}

func TestCLIContract_ExcludeFailClosedMatrix(t *testing.T) {
	_, openSSHProv, sshCfgPath := newPass6TaggedExcludeFixtureRepo(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshCfgMixed := filepath.Join(home, "mixed_ssh_config")
	mixedBody := strings.Join([]string{
		"Host bastion *.corp",
		"  User ops",
		"Host ssh-web",
		"  HostName 10.238.221.181",
		"  User iaas",
		"  Port 22",
		"Host *",
		"  ServerAliveInterval 15",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgMixed, []byte(mixedBody), 0o600); err != nil {
		t.Fatal(err)
	}

	savedRepo, _, _ := newPass6TaggedExcludeFixtureRepo(t)
	mixedProv, err := config.WithOpenSSHConfigOverride(savedRepo, sshCfgMixed)
	if err != nil {
		t.Fatal(err)
	}

	// Unmatched typos and wildcard-only hosts must fail closed despite Host * and Host bastion *.corp.
	for _, typo := range []string{"typo", "root@typo", "api.corp", "openssh:api.corp"} {
		cands := []utils.ExcludeTargetInfo{
			{NodeID: "iaas@10.238.221.181:22", MatchedNodeID: "iaas@10.238.221.181:22", OpenSSHAlias: "ssh-web", User: "iaas", Port: 22},
		}
		if _, err := utils.ResolveExcludesForTargets(mixedProv, []string{typo}, cands); err == nil {
			t.Errorf("ResolveExcludesForTargets(%q) succeeded with mixed wildcard ssh_config, want fail-closed error", typo)
		}
	}

	// Valid excludes with user/port overrides accurately exclude scp --tag and exec --tag targets.
	oScp := newPass6TaggedScpOptions(t, sshCfgPath, "iaas", 2222, "iaas@prod-web")
	if got := oScp.distinctRemoteHosts(openSSHProv); !slices.Equal(got, []string{"10.238.221.182"}) {
		t.Errorf("scp --tag --exclude iaas@prod-web with -P 2222 remaining hosts = %v, want [10.238.221.182]", got)
	}

	oExec := NewExecOptions()
	oExec.Tag = "prod"
	oExec.Port = 2222
	oExec.Remember = "never"
	oExec.control.ConfigFile = sshCfgPath
	tasks, err := oExec.buildTasksFromTags(t.Context(), openSSHProv)
	if err != nil {
		t.Fatalf("exec buildTasksFromTags: %v", err)
	}
	infos := make([]utils.ExcludeTargetInfo, 0, len(tasks))
	for _, task := range tasks {
		infos = append(infos, oExec.execTaskExcludeInfo(task))
	}
	excl, err := utils.ResolveExcludesForTargets(openSSHProv, []string{"iaas@ssh-web:2222"}, infos)
	if err != nil {
		t.Fatalf("exec ResolveExcludesForTargets: %v", err)
	}
	var kept []string
	for _, info := range infos {
		if !utils.IsTargetExcluded(excl, info) {
			kept = append(kept, info.User+"@"+info.OpenSSHAlias)
		}
	}
	if len(kept) != 1 {
		t.Errorf("exec --tag after excluding iaas@ssh-web:2222 left %d tasks (%v), want 1", len(kept), kept)
	}
}

func TestCLIContract_MuxDaemonArgsPreservation(t *testing.T) {
	opts := NewSshOptions()
	c := newCmdSshWithOptions(opts)
	cliFlags := []string{
		"-M", "-M",
		"-i", "/tmp/k1",
		"-o", "IdentityFile=none",
		"-o", "IdentityFile=/tmp/k2",
		"-o", "ProxyCommand=none",
		"-o", "ControlPersist=5m",
		"openssh:app.corp.example.com",
	}
	if err := c.ParseFlags(cliFlags); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := opts.Complete(c, []string{"openssh:app.corp.example.com"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	client, _ := newTunnelTestClient(t)
	sockPath := filepath.Join(t.TempDir(), "contract.sock")
	master, err := ssh.NewMuxServer(ssh.MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   client.SSHClient(),
		Target: ssh.TargetContext{
			Host:         "fe80::1%eth0",
			Port:         2222,
			User:         "ops",
			OriginalHost: "app.corp.example.com",
			Control: &ssh.ControlConfig{
				Master:  ssh.ControlMasterAsk,
				Path:    sockPath,
				Persist: "5m",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	t.Cleanup(func() { _ = master.Shutdown() })

	spec := opts.buildMuxDaemonSpec("openssh:app.corp.example.com", sockPath, master)
	decoded := roundTripMuxDaemonSpecThroughPipe(t, spec)

	if decoded.TargetHost != "app.corp.example.com" || !decoded.OpenSSHNamespace || decoded.Port != 2222 || decoded.User != "ops" {
		t.Errorf("buildMuxDaemonSpec dropped target host/port/user/namespace: %+v", decoded)
	}
	if decoded.DialHost != "fe80::1%eth0" {
		t.Errorf("buildMuxDaemonSpec dropped or altered IPv6 zone DialHost: %+v", decoded)
	}
	if !slices.Contains(decoded.Options, "ProxyCommand=none") {
		t.Errorf("buildMuxDaemonSpec dropped ProxyCommand=none: %v", decoded.Options)
	}
	if decoded.ControlMaster != ssh.ControlMasterAsk || decoded.ControlPersist != "5m" {
		t.Errorf("buildMuxDaemonSpec dropped authoritative ControlMaster=ask / ControlPersist=5m: %+v", decoded)
	}
	wantIDs := []string{filepath.Join("/", "tmp", "k1"), "none"}
	if !slices.Equal(decoded.IdentityFiles, wantIDs) {
		t.Errorf("buildMuxDaemonSpec identity order broken: got %v, want %v", decoded.IdentityFiles, wantIDs)
	}

	childOpts := NewSshOptions()
	if err := childOpts.applyMuxDaemonSpec(decoded); err != nil {
		t.Fatalf("applyMuxDaemonSpec: %v", err)
	}
	if effHost, err := childOpts.effectiveHostName(); err != nil || effHost != "fe80::1%eth0" {
		t.Errorf("effectiveHostName = (%q, %v), want %q", effHost, err, "fe80::1%eth0")
	}
	if !slices.Contains(childOpts.control.Options, "ControlMaster=ask") || !slices.Contains(childOpts.control.Options, "ControlPersist=5m") {
		t.Errorf("childOpts lost authoritative control options: %v", childOpts.control.Options)
	}
}
