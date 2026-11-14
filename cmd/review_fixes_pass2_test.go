package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestH9_ScpHostNamePositionalUpload(t *testing.T) {
	scpCmd := NewCmdScp()
	o := NewScpOptions()
	o.control.Options = []string{"HostName=%h.corp.example.com", "UserKnownHostsFile=none"}
	if err := o.Complete(scpCmd, []string{"./local/file.txt", "web:/tmp/file.txt"}); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if o.cliHostName != "%h.corp.example.com" {
		t.Fatalf("cliHostName = %q, want %%h.corp.example.com", o.cliHostName)
	}
	if o.HostName != "" {
		t.Fatalf("expected HostName to remain unexpanded before per-node resolution, got %q", o.HostName)
	}

	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	connector, err := o.credentialConnectorWithInteraction(repo, cfg, newCLIInteractionHandler())
	if err != nil {
		t.Fatalf("credentialConnectorWithInteraction: %v", err)
	}
	if connector == nil {
		t.Fatalf("expected non-nil connector")
	}
	if got, err := o.effectiveHostNameForHost("web"); err != nil || got != "web.corp.example.com" {
		t.Fatalf("effectiveHostNameForHost(web) = (%q, %v), want web.corp.example.com", got, err)
	}
}

func TestH9_ScpHostNameRemoteToRemote(t *testing.T) {
	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("src-h", models.Host{Address: "src", Port: 22})
	cfg.Identities.Set("src-i", models.Identity{User: "u1", AuthType: "auto"})
	cfg.Nodes.Set("src", models.Node{HostRef: "src-h", IdentityRef: "src-i"})
	cfg.Hosts.Set("dst-h", models.Host{Address: "dst", Port: 22})
	cfg.Identities.Set("dst-i", models.Identity{User: "u2", AuthType: "auto"})
	cfg.Nodes.Set("dst", models.Node{HostRef: "dst-h", IdentityRef: "dst-i"})

	scpCmd := NewCmdScp()
	o := NewScpOptions()
	o.Remember = "never"
	o.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
	if err := o.Complete(scpCmd, []string{"src:/data/in", "dst:/data/out"}); err != nil {
		t.Fatalf("Complete(%%h): %v", err)
	}
	connector, err := o.credentialConnectorWithInteraction(repo, cfg, newCLIInteractionHandler())
	if err != nil {
		t.Fatalf("credentialConnectorWithInteraction(%%h): %v", err)
	}
	if connector == nil {
		t.Fatalf("expected non-nil connector")
	}
	if got, err := o.effectiveHostNameForHost("src"); err != nil || got != "src.internal" {
		t.Fatalf("effectiveHostNameForHost(src) = (%q, %v), want src.internal", got, err)
	}
	if got, err := o.effectiveHostNameForHost("dst"); err != nil || got != "dst.internal" {
		t.Fatalf("effectiveHostNameForHost(dst) = (%q, %v), want dst.internal", got, err)
	}

	oStatic := NewScpOptions()
	oStatic.Remember = "never"
	oStatic.control.Options = []string{"HostName=10.0.0.5", "UserKnownHostsFile=none"}
	if err := oStatic.Complete(NewCmdScp(), []string{"src:/data/in", "dst:/data/out"}); err != nil {
		t.Fatalf("Complete(static): %v", err)
	}
	if _, err := oStatic.credentialConnectorWithInteraction(repo, cfg, newCLIInteractionHandler()); err == nil || !strings.Contains(err.Error(), "static HostName") {
		t.Fatalf("expected static HostName error for multi-host scp, got: %v", err)
	}
}

func TestH9_ScpHostNameBatchHostList(t *testing.T) {
	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	o := NewScpOptions()
	o.Host = "h1,h2"
	o.Source = "./a"
	o.Dest = "/tmp/b"
	o.Remember = "never"
	o.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := o.canonicalizeEndpoints(t.Context(), repo); err != nil {
		t.Fatalf("canonicalizeEndpoints: %v", err)
	}
	connector, err := o.credentialConnectorWithInteraction(repo, cfg, newCLIInteractionHandler())
	if err != nil {
		t.Fatalf("credentialConnectorWithInteraction: %v", err)
	}
	if connector == nil {
		t.Fatalf("expected non-nil connector")
	}
	if got, err := o.effectiveHostNameForHost("h1"); err != nil || got != "h1.internal" {
		t.Fatalf("effectiveHostNameForHost(h1) = (%q, %v), want h1.internal", got, err)
	}
}

func TestM14_ExecHostNameWithHostFileAndPositionalCmd(t *testing.T) {
	hostFile := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(hostFile, []byte("h1\nh2\n"), 0o600); err != nil {
		t.Fatalf("write hostfile: %v", err)
	}

	t.Run("-I hostfile with -c uptime", func(t *testing.T) {
		o := NewExecOptions()
		o.HostFile = hostFile
		o.Command = "uptime"
		o.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
		if err := o.Complete(NewCmdExec(), nil); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if err := o.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		auth1, err := o.buildTaskSessionAuth(execHostTask{nodeID: "n1", host: "h1", originalHost: "h1"}, nil, false, true)
		if err != nil || auth1.HostName != "h1.internal" {
			t.Fatalf("task 1 HostName = (%q, %v), want h1.internal", auth1.HostName, err)
		}
	})

	t.Run("-I hostfile with positional command containing tab/newline", func(t *testing.T) {
		o := NewExecOptions()
		o.HostFile = hostFile
		o.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
		if err := o.Complete(NewCmdExec(), []string{"printf \"a\tb\n\""}); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if err := o.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})
}

func TestM15_HasActiveProxyCommandInPath_JumpOverrideAndNilConnector(t *testing.T) {
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host bastion",
		"  HostName 127.0.0.1",
		"  User ops",
		"Host target",
		"  HostName 127.0.0.2",
		"  User ops",
		"  ProxyCommand nc %h %p",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	repo := setupTestRepository(t)
	provider, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}

	oNoJump := NewSshOptions()
	if !oNoJump.hasActiveProxyCommandInPath(provider, config.OpenSSHNodePrefix+"target", nil) {
		t.Fatalf("expected ProxyCommand to be active for target without -J")
	}

	oWithJump := NewSshOptions()
	oWithJump.JumpHost = "bastion"
	if oWithJump.hasActiveProxyCommandInPath(provider, config.OpenSSHNodePrefix+"target", nil) {
		t.Fatalf("expected CLI -J bastion to mask target's lower-tier ProxyCommand")
	}
}

func TestM16_MapControlProxySessionError_AlreadyReported(t *testing.T) {
	var stderr bytes.Buffer
	mapped := mapControlProxySessionError(&stderr, ssh.ErrEscapeDisconnect)
	if stderr.Len() != 0 {
		t.Fatalf("expected no duplicate stderr output for AlreadyReported error, got %q", stderr.String())
	}
	var exitErr *ControlExitError
	if !errors.As(mapped, &exitErr) {
		t.Fatalf("expected *ControlExitError, got %T (%v)", mapped, mapped)
	}
	if exitErr.Code != 255 || !exitErr.Reported {
		t.Fatalf("got Code=%d Reported=%v, want Code=255 Reported=true", exitErr.Code, exitErr.Reported)
	}
}

func TestL6_SftpRejectsBgRunAndClearsStdinScript(t *testing.T) {
	o := NewSftpOptions()
	o.stdinScript = true
	o.control.Options = []string{"ForkAfterAuthentication=yes"}
	if err := o.Complete(NewCmdSftp(), []string{"web"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if o.stdinScript {
		t.Fatalf("expected SftpOptions.Complete to clear stdinScript")
	}
	if err := o.Validate(); err == nil {
		t.Fatalf("expected SftpOptions.Validate to reject ForkAfterAuthentication=yes")
	}
}

func TestH9_ScpTagCompositeNodeID(t *testing.T) {
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("web-01:2222", models.Host{Address: "web-01", Port: 2222})
	cfg.Identities.Set("ops@web-01:2222", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@web-01:2222", models.Node{
		HostRef:     "web-01:2222",
		IdentityRef: "ops@web-01:2222",
		Tags:        []string{"prod"},
	})
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}

	o := NewScpOptions()
	o.Tag = "prod"
	o.Source = "./a"
	o.Dest = "/tmp/b"
	o.Remember = "never"
	o.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdScp(), nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := o.canonicalizeEndpoints(t.Context(), repo); err != nil {
		t.Fatalf("canonicalizeEndpoints: %v", err)
	}
	nodeIDs, originals, expandHosts := o.resolvedTargetNodeIDsWithHosts(repo)
	if len(nodeIDs) == 0 || expandHosts["ops@web-01:2222"] != "web-01" {
		t.Fatalf("resolvedTargetNodeIDsWithHosts = (%v, %v, %v), want expandHosts[ops@web-01:2222]=web-01", nodeIDs, originals, expandHosts)
	}
	if originals["ops@web-01:2222"] != "" {
		t.Fatalf("expected empty OriginalHost (%%n) for saved composite node when Canonicalized=false, got %q", originals["ops@web-01:2222"])
	}
	if got, err := o.effectiveHostNameForHost(expandHosts["ops@web-01:2222"]); err != nil || got != "web-01.internal" {
		t.Fatalf("effectiveHostNameForHost = (%q, %v), want web-01.internal", got, err)
	}
	if _, err := o.credentialConnectorWithInteraction(repo, cfg, newCLIInteractionHandler()); err != nil {
		t.Fatalf("credentialConnectorWithInteraction: %v", err)
	}

	// Saved named managed node (prod-web -> 10.0.0.1) must preserve empty OriginalHost (%n)
	// while still expanding -o HostName=%h.internal against 10.0.0.1.
	cfgNamed := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfgNamed.Hosts.Set("prod-web-h", models.Host{Address: "10.0.0.1", Port: 22})
	cfgNamed.Identities.Set("prod-web-i", models.Identity{User: "ops", AuthType: "auto"})
	cfgNamed.Nodes.Set("prod-web", models.Node{HostRef: "prod-web-h", IdentityRef: "prod-web-i"})
	namedRepo, err := config.NewRepositoryWithoutOpenSSH(cfgNamed, config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key")))
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH(named): %v", err)
	}
	oNamed := NewScpOptions()
	oNamed.Remember = "never"
	oNamed.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
	if err := oNamed.Complete(NewCmdScp(), []string{"prod-web:/tmp/a", "./b"}); err != nil {
		t.Fatalf("Complete(named): %v", err)
	}
	if err := oNamed.canonicalizeEndpoints(t.Context(), namedRepo); err != nil {
		t.Fatalf("canonicalizeEndpoints(named): %v", err)
	}
	_, namedOriginals, namedExpand := oNamed.resolvedTargetNodeIDsWithHosts(namedRepo)
	if namedOriginals["prod-web"] != "" {
		t.Fatalf("originals[prod-web] = %q, want empty string", namedOriginals["prod-web"])
	}
	if namedExpand["prod-web"] != "10.0.0.1" {
		t.Fatalf("expandHosts[prod-web] = %q, want 10.0.0.1", namedExpand["prod-web"])
	}
	if got, err := oNamed.effectiveHostNameForHost(namedExpand["prod-web"]); err != nil || got != "10.0.0.1.internal" {
		t.Fatalf("effectiveHostNameForHost(prod-web) = (%q, %v), want 10.0.0.1.internal", got, err)
	}
}

func TestL7_ScpDistinctOpenSSHAliasesOverrides(t *testing.T) {
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host role-a",
		"  HostName 10.0.0.5",
		"  User reader",
		"  IdentityFile ~/.ssh/id_a",
		"Host role-b",
		"  HostName 10.0.0.5",
		"  User writer",
		"  IdentityFile ~/.ssh/id_b",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	provider, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}

	o := NewScpOptions()
	o.Remember = "never"
	o.control.Options = []string{"HostName=%h.internal", "UserKnownHostsFile=none"}
	if err := o.Complete(NewCmdScp(), []string{"ops@role-a:/in", "ops@role-b:/out"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := o.canonicalizeEndpoints(t.Context(), provider); err != nil {
		t.Fatalf("canonicalizeEndpoints: %v", err)
	}
	_, originals := o.resolvedTargetNodeIDsWithOriginals(provider)
	if originals["ops@10.0.0.5:22"] != "role-a" {
		t.Fatalf("originals[ops@10.0.0.5:22] = %q, want role-a", originals["ops@10.0.0.5:22"])
	}
	if originals[config.OpenSSHNodePrefix+"ops@role-b:22"] != "role-b" {
		t.Fatalf("originals[openssh:ops@role-b:22] = %q, want role-b", originals[config.OpenSSHNodePrefix+"ops@role-b:22"])
	}
	if _, err := o.credentialConnectorWithInteraction(provider, cfg, newCLIInteractionHandler()); err != nil {
		t.Fatalf("credentialConnectorWithInteraction: %v", err)
	}
}
