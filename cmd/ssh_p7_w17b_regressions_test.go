package cmd

import (
	"bytes"
	"errors"
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

func buildW17bProxyTargetAndConfig(t *testing.T, prov config.ConfigProvider, o *SshOptions) (string, ssh.TargetContext, *ssh.ClientConfig) {
	t.Helper()
	if err := o.ensureArgsParsed(); err != nil {
		t.Fatalf("ensureArgsParsed: %v", err)
	}
	nodeID, err := resolveControlNodeID(prov, effectiveConnectionTarget(o, ""))
	if err != nil {
		t.Fatalf("resolveControlNodeID: %v", err)
	}
	target, err := controlTarget(o, prov, nodeID)
	if err != nil {
		t.Fatalf("controlTarget: %v", err)
	}
	clientCfg, _ := buildControlProxyClientConfig(target, prov, nodeID, o)
	return nodeID, target, clientCfg
}

func assertW17bSavedNodeUserOverrideProxy(t *testing.T, prov config.ConfigProvider) {
	t.Helper()
	o := NewSshOptions()
	o.control.CtlCmd = "proxy"
	o.User = "altuser"
	o.args = []string{"web-01"}
	nodeID, target, clientCfg := buildW17bProxyTargetAndConfig(t, prov, o)
	if nodeID != "" {
		t.Fatalf("expected unmatched nodeID for -l altuser web-01, got %q", nodeID)
	}
	if gotLookup := resolveControlProxyFallbackLookup(target, prov, o); gotLookup != "altuser@10.10.0.1:2222" {
		t.Fatalf("fallbackLookup = %q, want %q", gotLookup, "altuser@10.10.0.1:2222")
	}
	if clientCfg == nil || clientCfg.Options == nil {
		t.Fatalf("expected non-nil clientCfg and Options, got %+v", clientCfg)
	}
	if clientCfg.User != "altuser" || clientCfg.Port != 2222 {
		t.Fatalf("clientCfg endpoint = %s@%s:%d, want altuser@10.10.0.1:2222", clientCfg.User, clientCfg.Address, clientCfg.Port)
	}
	if clientCfg.Options.SessionType() == ssh.SessionTypeNone || clientCfg.Options.RemoteCommand() != "" ||
		clientCfg.Options.ForwardAgent() != "" || len(clientCfg.Options.LocalForwards()) > 0 {
		t.Fatalf("leaked web-01 Tier-2 options onto -O proxy -l altuser web-01: %v", clientCfg.Options)
	}
	if got := clientCfg.Options.Get(ssh.OptionServerAliveCountMax); got != "5" {
		t.Fatalf("expected Tier-3 ServerAliveCountMax=5 preserved, got %q", got)
	}
	if got := clientCfg.Options.Get(ssh.OptionServerAliveInterval); got != "41" {
		t.Fatalf("expected endpoint-scoped Tier-4 ServerAliveInterval=41 for 10.10.0.1:2222, got %q", got)
	}
}

func assertW17bSavedNodePortOverrideProxy(t *testing.T, prov config.ConfigProvider) {
	t.Helper()
	o := NewSshOptions()
	o.control.CtlCmd = "proxy"
	o.Port = 2299
	o.args = []string{"web-01"}
	_, target, clientCfg := buildW17bProxyTargetAndConfig(t, prov, o)
	if gotLookup := resolveControlProxyFallbackLookup(target, prov, o); gotLookup != "ops@10.10.0.1:2299" {
		t.Fatalf("fallbackLookup = %q, want %q", gotLookup, "ops@10.10.0.1:2299")
	}
	if clientCfg == nil || clientCfg.Options == nil || clientCfg.Port != 2299 {
		t.Fatalf("unexpected clientCfg for -p 2299 web-01: %+v", clientCfg)
	}
	if clientCfg.Options.SessionType() == ssh.SessionTypeNone || clientCfg.Options.RemoteCommand() != "" {
		t.Fatalf("leaked web-01 Tier-2 options onto -O proxy -p 2299 web-01: %v", clientCfg.Options)
	}
	if got := clientCfg.Options.Get(ssh.OptionServerAliveInterval); got != "92" {
		t.Fatalf("expected port-2299 Tier-4 ServerAliveInterval=92 (not port-2222 41), got %q", got)
	}
}

func TestP7W17b_L3_17_M1_ControlProxyOverriddenSavedNodeDoesNotLeakTier2(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host app-virtual",
		"  HostName 10.30.0.20",
		"  User vuser",
		"  Port 2220",
		"  RemoteCommand uptime",
		"",
		"Host 10.10.0.1",
		"  Port 2222",
		"  ServerAliveInterval 41",
		"",
		"Host web-2299",
		"  HostName 10.10.0.1",
		"  Port 2299",
		"  ServerAliveInterval 92",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SSHOptions = ssh.MustOptions(ssh.OptionServerAliveCountMax, "5")
	cfg.Hosts.Set("h-web1", models.Host{Address: "10.10.0.1", Port: 2222})
	cfg.Identities.Set("id-web1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("web-01", models.Node{
		HostRef:     "h-web1",
		IdentityRef: "id-web1",
		SSHOptions: ssh.MustOptions(
			ssh.OptionSessionType, "none",
			ssh.OptionRemoteCommand, "echo web01-secret",
			ssh.OptionForwardAgent, "yes",
			ssh.OptionLocalForward, "127.0.0.1:18080 127.0.0.1:80",
		),
	})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	t.Run("saved_node_user_override_blocks_tier2_options_and_keeps_tier3", func(t *testing.T) {
		t.Parallel()
		assertW17bSavedNodeUserOverrideProxy(t, prov)
	})
	t.Run("saved_node_port_override_blocks_tier2_and_scopes_tier4_to_2299", func(t *testing.T) {
		t.Parallel()
		assertW17bSavedNodePortOverrideProxy(t, prov)
	})
	t.Run("openssh_alias_port_override_still_retains_tier4_options", func(t *testing.T) {
		t.Parallel()
		o := NewSshOptions()
		o.control.CtlCmd = "proxy"
		o.Port = 2299
		o.args = []string{"app-virtual"}
		_, _, clientCfg := buildW17bProxyTargetAndConfig(t, prov, o)
		if clientCfg == nil || clientCfg.Options == nil || clientCfg.Options.RemoteCommand() != "uptime" {
			t.Fatalf("overridden OpenSSH alias lost RemoteCommand=uptime: cfg=%+v opts=%v", clientCfg, clientCfg.Options)
		}
	})
}

func assertW17bAdHocProxyPort2299(t *testing.T, prov config.ConfigProvider) {
	t.Helper()
	o := NewSshOptions()
	o.control.CtlCmd = "proxy"
	o.Port = 2299
	o.User = "adhocuser"
	o.args = []string{"10.55.66.77"}
	_, target, clientCfg := buildW17bProxyTargetAndConfig(t, prov, o)
	if gotLookup := resolveControlProxyFallbackLookup(target, prov, o); gotLookup != "adhocuser@10.55.66.77:2299" {
		t.Fatalf("ad-hoc fallbackLookup = %q, want %q", gotLookup, "adhocuser@10.55.66.77:2299")
	}
	if clientCfg == nil || clientCfg.Options == nil {
		t.Fatalf("expected non-nil clientCfg and Options, got %+v", clientCfg)
	}
	if got := clientCfg.Options.Get(ssh.OptionServerAliveInterval); got != "88" {
		t.Fatalf("ServerAliveInterval = %q, want 88 (port-2299 stanza, not port-22 77)", got)
	}
	if got := clientCfg.Options.Get(ssh.OptionConnectTimeout); got != "" {
		t.Fatalf("leaked port-22 ConnectTimeout=%q onto ad-hoc -O proxy -p 2299 10.55.66.77", got)
	}
}

func assertW17bAdHocProxyPort2298(t *testing.T, prov config.ConfigProvider) {
	t.Helper()
	o := NewSshOptions()
	o.control.CtlCmd = "proxy"
	o.Port = 2298
	o.args = []string{"10.55.66.77"}
	_, target, clientCfg := buildW17bProxyTargetAndConfig(t, prov, o)
	if gotLookup := resolveControlProxyFallbackLookup(target, prov, o); !strings.HasSuffix(gotLookup, "@10.55.66.77:2298") {
		t.Fatalf("ad-hoc -p 2298 fallbackLookup = %q, want suffix @10.55.66.77:2298", gotLookup)
	}
	if clientCfg == nil {
		t.Fatal("expected non-nil clientCfg")
	}
	if clientCfg.Options != nil {
		if got := clientCfg.Options.Get(ssh.OptionServerAliveInterval); got != "" {
			t.Fatalf("leaked port-22 ServerAliveInterval=%q onto ad-hoc -p 2298", got)
		}
		if got := clientCfg.Options.Get(ssh.OptionConnectTimeout); got != "" {
			t.Fatalf("leaked port-22 ConnectTimeout=%q onto ad-hoc -p 2298", got)
		}
	}
}

func TestP7W17b_L3_17_M1_ControlProxyAdHocPortUserEndpointScoping(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host host-22",
		"  HostName 10.55.66.77",
		"  Port 22",
		"  ServerAliveInterval 77",
		"  ConnectTimeout 19",
		"",
		"Host custom-2299",
		"  HostName 10.55.66.77",
		"  Port 2299",
		"  ServerAliveInterval 88",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(nil, parser)

	t.Run("adhoc_port_2299_matches_2299_stanza_not_port_22", func(t *testing.T) {
		t.Parallel()
		assertW17bAdHocProxyPort2299(t, prov)
	})
	t.Run("adhoc_port_2298_does_not_leak_port_22_stanza", func(t *testing.T) {
		t.Parallel()
		assertW17bAdHocProxyPort2298(t, prov)
	})
	t.Run("adhoc_port_22_still_matches_port_22_stanza", func(t *testing.T) {
		t.Parallel()
		o := NewSshOptions()
		o.control.CtlCmd = "proxy"
		o.Port = 22
		o.args = []string{"10.55.66.77"}
		_, _, clientCfg := buildW17bProxyTargetAndConfig(t, prov, o)
		if clientCfg == nil || clientCfg.Options == nil || clientCfg.Options.Get(ssh.OptionServerAliveInterval) != "77" {
			t.Fatalf("ad-hoc -p 22 failed to match port-22 stanza: cfg=%+v opts=%v", clientCfg, clientCfg.Options)
		}
	})
}

func buildW17bCmdM2BaseConfig() *config.Configuration {
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.SSHOptions = ssh.MustOptions(
		ssh.OptionControlMaster, "auto",
		ssh.OptionControlPath, "/tmp/cm-w17b-%h-%p-%r-%j-%C",
	)
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.10.0.254", Port: 2222})
	cfg.Identities.Set("id-bastion", models.Identity{User: "jump", AuthType: "auto"})
	cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-bastion"})

	cfg.Hosts.Set("h-web1", models.Host{Address: "10.10.0.1", Port: 2222})
	cfg.Identities.Set("id-web1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("web-01", models.Node{
		HostRef:     "h-web1",
		IdentityRef: "id-web1",
		ProxyJump:   "bastion",
	})
	return cfg
}

func resolveW17bCmdDialSocket(t *testing.T, emptySSHCfg string) (ssh.TargetContext, string) {
	t.Helper()
	env := sshenv.Discover()
	repoStore := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithoutOpenSSH(buildW17bCmdM2BaseConfig(), repoStore)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	dialOpts, err := parseCompleteValidateSshArgs(t, "-l", "altuser", "-o", "HostName=10.10.0.99", "-F", emptySSHCfg, "web-01")
	if err != nil {
		t.Fatalf("parseCompleteValidateSshArgs(dial): %v", err)
	}
	dialOpts.Remember = "never"
	var dialSock string
	var dialTarget ssh.TargetContext
	if err := dialOpts.withTestPendingNode(t.Context(), repo, func(lease config.PendingLease) error {
		adpOpts, err := dialOpts.buildAdapterOptions(lease.NodeID(), repo.Snapshot(), repo)
		if err != nil {
			t.Fatalf("buildAdapterOptions: %v", err)
		}
		adp := adapter.NewSSHAdapter(repo, adpOpts...)
		clientCfg, err := adp.GetConfig(lease.NodeID())
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}
		ctrl, err := adp.GetControlConfig(lease.NodeID())
		if err != nil {
			t.Fatalf("GetControlConfig: %v", err)
		}
		dialTarget = ssh.BuildClientTargetContext(lease.NodeID(), clientCfg, env, nil)
		dialSock, err = ctrl.ResolvePath(env, dialTarget)
		return err
	}); err != nil {
		t.Fatalf("withTestPendingNode: %v", err)
	}
	return dialTarget, dialSock
}

func assertW17bCmdControlRejects(t *testing.T, args []string, wantSubstring string) {
	t.Helper()
	opts, err := parseCompleteValidateSshArgs(t, args...)
	if err != nil {
		t.Fatalf("parseCompleteValidateSshArgs(%v): %v", args, err)
	}
	var stderr bytes.Buffer
	sock, _, _, _, err := resolveControlContext(t.Context(), opts, &stderr)
	if err == nil {
		t.Fatalf("expected resolveControlContext(%v) rejection, got sock=%q", args, sock)
	}
	var ctlErr *ControlExitError
	if !errors.As(err, &ctlErr) || ctlErr.Code != 255 {
		t.Fatalf("expected *ControlExitError{Code:255}, got %v", err)
	}
	if wantSubstring != "" && !strings.Contains(strings.ToLower(err.Error()), wantSubstring) {
		t.Fatalf("error = %v, want substring %q", err, wantSubstring)
	}
}

func TestP7W17b_L3_17_M2_EndToEndControlCheckHostNameAndUserOverrides(t *testing.T) {
	home := setupTestEnvironment(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	emptySSHCfg := filepath.Join(home, "empty_ssh_config")
	if err := os.WriteFile(emptySSHCfg, []byte(""), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// 1. Parity: `xops ssh -O check -l altuser -o HostName=10.10.0.99 web-01` preserves JumpHost=bastion
	// and produces exact %C/%j socket parity with dial-plane WithPendingNode.
	if err := config.NewDefaultStore(cfgPath, keyPath).Save(buildW17bCmdM2BaseConfig()); err != nil {
		t.Fatalf("Save config: %v", err)
	}
	ctlOpts, err := parseCompleteValidateSshArgs(t, "-O", "check", "-l", "altuser", "-o", "HostName=10.10.0.99", "-F", emptySSHCfg, "web-01")
	if err != nil {
		t.Fatalf("parseCompleteValidateSshArgs(parity): %v", err)
	}
	var stderr bytes.Buffer
	gotSock, gotTarget, _, _, err := resolveControlContext(t.Context(), ctlOpts, &stderr)
	if err != nil {
		t.Fatalf("resolveControlContext(-l altuser -o HostName=10.10.0.99 web-01): %v (stderr=%q)", err, stderr.String())
	}
	if gotTarget.JumpHost != "bastion" || gotTarget.Host != "10.10.0.99" || gotTarget.Port != 2222 || gotTarget.User != "altuser" {
		t.Fatalf("control TargetContext = %+v, want altuser@10.10.0.99:2222 via bastion", gotTarget)
	}
	dialTarget, dialSock := resolveW17bCmdDialSocket(t, emptySSHCfg)
	if gotTarget != dialTarget || gotSock != dialSock {
		t.Fatalf("control vs dial mismatch:\n  target: %+v vs %+v\n  sock:   %q vs %q", gotTarget, dialTarget, gotSock, dialSock)
	}

	// 2. Self-loop cycle fail-closed: `xops ssh -O check -l jump -o HostName=10.10.0.254 web-01`.
	assertW17bCmdControlRejects(t, []string{"-O", "check", "-l", "jump", "-o", "HostName=10.10.0.254", "-F", emptySSHCfg, "web-01"}, "")

	// 3. Ambiguous multi-node ProxyJump fail-closed under -l altuser -o HostName=10.10.0.99.
	ambCfg := buildW17bCmdM2BaseConfig()
	ambCfg.Hosts.Set("h-bastion-b", models.Host{Address: "10.10.0.253", Port: 2222})
	ambCfg.Identities.Set("id-bastion-b", models.Identity{User: "jump2", AuthType: "auto"})
	ambCfg.Nodes.Set("bastion-b", models.Node{HostRef: "h-bastion-b", IdentityRef: "id-bastion-b"})
	ambCfg.Identities.Set("id-web2", models.Identity{User: "admin", AuthType: "auto"})
	ambCfg.Nodes.Set("web-02", models.Node{
		HostRef:     "h-web1",
		IdentityRef: "id-web2",
		ProxyJump:   "bastion-b",
	})
	if err := config.NewDefaultStore(cfgPath, keyPath).Save(ambCfg); err != nil {
		t.Fatalf("Save ambiguous config: %v", err)
	}
	assertW17bCmdControlRejects(t, []string{"-O", "check", "-l", "altuser", "-o", "HostName=10.10.0.99", "-F", emptySSHCfg, "web-01"}, "ambiguous proxy jump")
}
