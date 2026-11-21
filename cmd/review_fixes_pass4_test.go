package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestPass4_S3_1_ScpAndExecExcludeOpenSSHAlias(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host web",
		"  HostName 10.0.0.5",
		"  User ops",
		"Host role-a",
		"  HostName 10.0.0.5",
		"  User ops",
		"Host role-b",
		"  HostName 10.0.0.5",
		"  User ops",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	repo := setupTestRepository(t)
	prov, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}

	// 1. scp: --exclude web must exclude OpenSSH alias "web" (and disambiguated "role-b").
	oScp := NewScpOptions()
	oScp.Host = "web"
	oScp.Exclude = []string{"web"}
	oScp.Source = "./a"
	oScp.Dest = "/tmp/b"
	oScp.Remember = "never"
	oScp.control.ConfigFile = sshCfgPath
	oScp.control.Options = []string{"UserKnownHostsFile=none"}
	if err := oScp.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(scp): %v", err)
	}
	if err := oScp.runBatch(t.Context(), prov, nil); err != nil {
		t.Fatalf("scp runBatch with --exclude web should skip cleanly without dialing, got: %v", err)
	}

	// 2. scp: pre-canonicalized short name "web" excluded via --exclude web.
	excludesWeb := map[string]struct{}{config.OpenSSHNodePrefix + "web": {}}
	excluded, err := oScp.isBatchHostExcluded(prov, excludesWeb, "web", PathInfo{
		Host:         "web.corp.example.com",
		OriginalHost: "web",
		User:         "ops",
		Port:         22,
		IsRemote:     true,
	})
	if err != nil || !excluded {
		t.Fatalf("isBatchHostExcluded(pre-canon web) = (%v, %v), want (true, nil)", excluded, err)
	}

	// 3. exec: --exclude role-b must exclude disambiguated "openssh:ops@role-b:22" before dialing.
	oExec := NewExecOptions()
	oExec.Host = "role-b"
	oExec.Exclude = []string{"role-b"}
	oExec.Command = "id"
	oExec.Remember = "never"
	oExec.control.ConfigFile = sshCfgPath
	oExec.control.Options = []string{"UserKnownHostsFile=none"}
	if err := oExec.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete(exec): %v", err)
	}
	if err := oExec.RunContext(t.Context()); err == nil || !strings.Contains(err.Error(), "node") && !strings.Contains(err.Error(), "节点") {
		// When all hosts are excluded, RunContext returns err_no_nodes_found without dialing.
		t.Fatalf("expected no-nodes-found error after excluding role-b, got: %v", err)
	}
}

func TestPass4_S3_2_ControlPersistDisambiguatedOpenSSH(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if got := config.UnwrapOpenSSHSelector("openssh:ops@role-b:22"); got != "role-b" {
		t.Fatalf("UnwrapOpenSSHSelector(disambiguated) = %q, want role-b", got)
	}
	if got := config.UnwrapOpenSSHSelector("openssh:web"); got != "web" {
		t.Fatalf("UnwrapOpenSSHSelector(alias) = %q, want web", got)
	}
	if got := config.UnwrapOpenSSHSelector("10.0.0.5"); got != "10.0.0.5" {
		t.Fatalf("UnwrapOpenSSHSelector(plain) = %q, want 10.0.0.5", got)
	}
	if got := config.UnwrapOpenSSHSelector("openssh:"); got != "" {
		t.Fatalf("UnwrapOpenSSHSelector(bare prefix) = %q, want empty", got)
	}
	if got := config.UnwrapOpenSSHSelector("openssh:   "); got != "" {
		t.Fatalf("UnwrapOpenSSHSelector(blank prefix) = %q, want empty", got)
	}
}

func TestPass4_S3_2_MuxDaemonTargetAndNodeIDMatching(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	o := NewSshOptions()
	o.User = "ops"
	o.Port = 22
	// Test resolveMuxDaemonTarget on disambiguated nodeID without master.
	host, port, user := o.resolveMuxDaemonTarget("openssh:ops@role-b:22", nil)
	if host != "role-b" || port != 22 || user != "ops" {
		t.Fatalf("resolveMuxDaemonTarget = (%q, %d, %q), want (role-b, 22, ops)", host, port, user)
	}

	// Test matchesAnyTargetNodeID & matchesTargetSelector with disambiguated targetID.
	if !matchesAnyTargetNodeID("openssh:role-b", nil, []string{"openssh:ops@role-b:22"}) {
		t.Fatal("expected matchesAnyTargetNodeID to match openssh:role-b against openssh:ops@role-b:22")
	}
	if !matchesTargetSelector("openssh:role-b", nil, "openssh:ops@role-b:22", "") {
		t.Fatal("expected matchesTargetSelector to match openssh:role-b against openssh:ops@role-b:22")
	}
}

func TestPass4_S3_3_ExecSavedNodeOriginalHostAndExpandHost(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("web-h", models.Host{Address: "10.238.221.181", Port: 22})
	cfg.Identities.Set("iaas-i", models.Identity{User: "iaas", AuthType: "auto"})
	cfg.Nodes.Set("iaas@10.238.221.181:22", models.Node{
		HostRef:     "web-h",
		IdentityRef: "iaas-i",
		Alias:       []string{"Prod Web 01"},
	})
	savedRepo, err := config.NewRepositoryWithoutOpenSSH(cfg, config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key")))
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}

	o := NewExecOptions()
	o.Host = "Prod Web 01"
	o.Command = "id"
	o.Remember = "never"
	o.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdExec(), nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := o.withTestPendingHostTasks(t.Context(), savedRepo, func(tasks []execHostTask, _ []config.PendingLease, hostErrs []error) error {
		if len(hostErrs) != 0 || len(tasks) != 1 {
			t.Fatalf("withTestPendingHostTasks = (%v, %v)", tasks, hostErrs)
		}
		if tasks[0].originalHost != "" {
			t.Fatalf("saved node task.originalHost = %q, want empty string", tasks[0].originalHost)
		}
		auth, err := o.buildTaskSessionAuth(tasks[0], nil, false, false)
		if err != nil {
			t.Fatalf("buildTaskSessionAuth: %v", err)
		}
		if auth.OriginalHost != "" {
			t.Fatalf("saved node SessionAuth.OriginalHost = %q, want empty string", auth.OriginalHost)
		}
		if auth.HostName != "10.238.221.181.internal" {
			t.Fatalf("saved node SessionAuth.HostName = %q, want 10.238.221.181.internal", auth.HostName)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingHostTasks: %v", err)
	}

	// Verify ScpOptions uses the exact same shared helper on saved Node.Alias "Prod Web 01".
	oScp := NewScpOptions()
	oScp.Host = "Prod Web 01"
	oScp.Source = "./a"
	oScp.Dest = "/tmp/b"
	oScp.Remember = "never"
	oScp.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
	if err := oScp.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(scp): %v", err)
	}
	nodeIDs, originals, expandHosts := oScp.resolvedTargetNodeIDsWithHosts(savedRepo)
	if len(nodeIDs) != 1 || nodeIDs[0] != "iaas@10.238.221.181:22" {
		t.Fatalf("scp nodeIDs = %v, want [iaas@10.238.221.181:22]", nodeIDs)
	}
	if originals["iaas@10.238.221.181:22"] != "" {
		t.Fatalf("scp originals[iaas@10.238.221.181:22] = %q, want empty", originals["iaas@10.238.221.181:22"])
	}
	if expandHosts["iaas@10.238.221.181:22"] != "10.238.221.181" {
		t.Fatalf("scp expandHosts[iaas@10.238.221.181:22] = %q, want 10.238.221.181", expandHosts["iaas@10.238.221.181:22"])
	}
}

func TestPass4_S3_4_ScpCanonicalizePathInfoIdempotent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	repo := setupTestRepository(t)
	o := NewScpOptions()
	o.control.Options = []string{
		"CanonicalizeHostname=yes",
		"CanonicalDomains=corp.example.com",
		"CanonicalizeFallbackLocal=no",
		"UserKnownHostsFile=none",
	}

	// Simulate an already-canonicalized PathInfo (e.g. CNAME target "web01.internal"
	// with OriginalHost="web") passed from runBatch into connectSftpForPath.
	// It must short-circuit without invoking CanonicalizeHost a second time.
	in := PathInfo{
		Host:         "web01.internal",
		OriginalHost: "web",
		User:         "ops",
		Port:         22,
		IsRemote:     true,
	}
	out, err := o.canonicalizePathInfo(t.Context(), repo, in)
	if err != nil {
		t.Fatalf("canonicalizePathInfo on already-canonicalized PathInfo failed: %v", err)
	}
	if out.Host != "web01.internal" || out.OriginalHost != "web" {
		t.Fatalf("canonicalizePathInfo = %+v, want unchanged", out)
	}
}

func TestPass4_S3_5_ScpExcludeFiltersBeforeStaticHostNameCheck(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Hosts.Set("h2", models.Host{Address: "10.0.0.2", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@10.0.0.1:22", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		Alias:       []string{"web1"},
		Tags:        []string{"prod"},
	})
	cfg.Nodes.Set("ops@10.0.0.2:22", models.Node{
		HostRef:     "h2",
		IdentityRef: "id1",
		Alias:       []string{"web2"},
		Tags:        []string{"prod"},
	})
	savedRepo, err := config.NewRepositoryWithoutOpenSSH(cfg, config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key")))
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}

	o := NewScpOptions()
	o.Host = "web1,web2"
	o.Exclude = []string{"web2"}
	o.Source = "./a"
	o.Dest = "/tmp/b"
	o.Remember = "never"
	o.control.Options = []string{"HostName=10.0.0.9", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	distinct := o.distinctRemoteHosts(savedRepo)
	if len(distinct) != 1 || distinct[0] != "10.0.0.1" {
		t.Fatalf("distinctRemoteHosts after --exclude web2 = %v, want [10.0.0.1]", distinct)
	}
	if _, err := o.credentialConnector(savedRepo, savedRepo.Snapshot()); err != nil {
		t.Fatalf("credentialConnector with single remaining target after --exclude should succeed, got: %v", err)
	}

	// Also verify --tag prod --exclude web2 -o HostName=10.0.0.9 succeeds.
	oTag := NewScpOptions()
	oTag.Tag = "prod"
	oTag.Exclude = []string{"web2"}
	oTag.Source = "./a"
	oTag.Dest = "/tmp/b"
	oTag.Remember = "never"
	oTag.control.Options = []string{"HostName=10.0.0.9", "UserKnownHostsFile=none"}
	if err := oTag.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete(tag): %v", err)
	}
	if _, err := oTag.credentialConnector(savedRepo, savedRepo.Snapshot()); err != nil {
		t.Fatalf("credentialConnector(--tag prod --exclude web2) should succeed, got: %v", err)
	}
}
