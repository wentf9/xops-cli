package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestPhase1Flags_RegistrationAndRouting(t *testing.T) {
	root := newRootCmd()
	initRootFlags(root)
	registerCommands(root)

	// -F is registered on ssh, scp, sftp, exec
	for _, sub := range []string{"ssh", "scp", "sftp", "exec"} {
		c, _, err := root.Find([]string{sub})
		if err != nil {
			t.Fatalf("find %s: %v", sub, err)
		}
		if f := c.Flags().ShorthandLookup("F"); f == nil || f.Name != "config-file" {
			t.Fatalf("%s missing -F/--config-file flag: %+v", sub, f)
		}
	}

	// -4 and -6 are registered on ssh, scp, sftp (not exec)
	for _, sub := range []string{"ssh", "scp", "sftp"} {
		c, _, err := root.Find([]string{sub})
		if err != nil {
			t.Fatalf("find %s: %v", sub, err)
		}
		if f := c.Flags().ShorthandLookup("4"); f == nil || f.Name != "ipv4" {
			t.Fatalf("%s missing -4/--ipv4 flag", sub)
		}
		if f := c.Flags().ShorthandLookup("6"); f == nil || f.Name != "ipv6" {
			t.Fatalf("%s missing -6/--ipv6 flag", sub)
		}
	}

	// -c is --cipher on ssh, and remains --cmd on exec
	sshCmd, _, _ := root.Find([]string{"ssh"})
	if f := sshCmd.Flags().ShorthandLookup("c"); f == nil || f.Name != "cipher" {
		t.Fatalf("ssh -c should be --cipher, got %+v", f)
	}
	execCmd, _, _ := root.Find([]string{"exec"})
	if f := execCmd.Flags().ShorthandLookup("c"); f == nil || f.Name != "cmd" {
		t.Fatalf("exec -c must remain --cmd, got %+v", f)
	}
	if f := execCmd.Flags().ShorthandLookup("4"); f != nil {
		t.Fatalf("exec must not register -4, got %+v", f)
	}

	// Argument routing preserves -F <file>, -c <cipher>, -4/-6, and -i <key> before remote command
	got := normalizeCommandArgs(root, []string{
		"ssh", "-F", "/tmp/ssh_cfg", "-c", "aes128-gcm@openssh.com", "-4", "-6", "-i", "/tmp/k1,comma", "-i", "/tmp/k2",
		"myhost", "uname", "-a",
	})
	want := []string{
		"ssh", "-F", "/tmp/ssh_cfg", "-c", "aes128-gcm@openssh.com", "-4", "-6", "-i", "/tmp/k1,comma", "-i", "/tmp/k2",
		"myhost", "--", "uname", "-a",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("normalizeCommandArgs() = %v, want %v", got, want)
	}
}

func TestPhase1Flags_AddressFamilyLastFlagWins(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "only -4", args: []string{"-4", "host"}, want: "inet"},
		{name: "only -6", args: []string{"-6", "host"}, want: "inet6"},
		{name: "-4 then -6", args: []string{"-4", "-6", "host"}, want: "inet6"},
		{name: "-6 then -4", args: []string{"-6", "-4", "host"}, want: "inet"},
		{name: "neither", args: []string{"host"}, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewSshOptions()
			c := newCmdSshWithOptions(opts)
			if err := c.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags(%v) error = %v", tc.args, err)
			}
			if opts.control.AddressFamily != tc.want {
				t.Fatalf("AddressFamily = %q, want %q", opts.control.AddressFamily, tc.want)
			}
		})
	}
}

func TestPhase1Flags_RepeatableIdentityPreservesCommas(t *testing.T) {
	opts := NewSshOptions()
	c := newCmdSshWithOptions(opts)
	if err := c.ParseFlags([]string{"-i", "/tmp/key,one", "-i", "/tmp/key_two", "host"}); err != nil {
		t.Fatalf("ParseFlags error = %v", err)
	}
	opts.syncIdentityFiles()
	want := []string{"/tmp/key,one", "/tmp/key_two"}
	if !slices.Equal(opts.IdentityFiles, want) {
		t.Fatalf("IdentityFiles = %v, want %v", opts.IdentityFiles, want)
	}
	if opts.IdentityFile != "/tmp/key,one" {
		t.Fatalf("IdentityFile = %q, want %q", opts.IdentityFile, "/tmp/key,one")
	}
}

func TestPhase1Flags_CipherSpecMapsToTier1Options(t *testing.T) {
	opts := NewSshOptions()
	opts.CipherSpec = "aes128-gcm@openssh.com"
	opts.control.Options = []string{"Ciphers=aes256-gcm@openssh.com"}

	sessionOpts, err := opts.toSessionControlOptions()
	if err != nil {
		t.Fatalf("toSessionControlOptions error = %v", err)
	}
	if sessionOpts.Options == nil || sessionOpts.Options.Get(ssh.OptionCiphers) != "aes128-gcm@openssh.com" {
		t.Fatalf("Ciphers = %q, want aes128-gcm@openssh.com", sessionOpts.Options.Get(ssh.OptionCiphers))
	}
}

func TestPhase1Flags_MuxDaemonForwardsFlags(t *testing.T) {
	opts := NewSshOptions()
	opts.control.ConfigFile = "/tmp/custom_ssh_cfg"
	opts.control.AddressFamily = "inet6"
	opts.CipherSpec = "chacha20-poly1305@openssh.com"
	opts.IdentityFiles = []string{"/tmp/id_one", "/tmp/id_two"}
	opts.syncIdentityFiles()

	spec := opts.buildMuxDaemonSpec("node1", "/tmp/mux.sock", nil)
	if spec.ConfigFile != "/tmp/custom_ssh_cfg" {
		t.Fatalf("ConfigFile = %q, want /tmp/custom_ssh_cfg", spec.ConfigFile)
	}
	if spec.CipherSpec != "chacha20-poly1305@openssh.com" {
		t.Fatalf("CipherSpec = %q, want chacha20-poly1305@openssh.com", spec.CipherSpec)
	}
	if spec.AddressFamily != "inet6" {
		t.Fatalf("AddressFamily = %q, want inet6", spec.AddressFamily)
	}
	if want := []string{"/tmp/id_one", "/tmp/id_two"}; !slices.Equal(spec.IdentityFiles, want) {
		t.Fatalf("IdentityFiles = %v, want %v", spec.IdentityFiles, want)
	}
}

func TestPhase1Flags_AddressFamilyOverridesOption(t *testing.T) {
	flags := SSHControlFlags{
		AddressFamily: "inet6",
		Options:       []string{"AddressFamily=inet"},
	}
	sessionOpts, err := flags.ToSessionControlOptions()
	if err != nil {
		t.Fatalf("ToSessionControlOptions failed: %v", err)
	}
	if got := sessionOpts.Options.AddressFamily(); got != "inet6" {
		t.Fatalf("AddressFamily = %q, want inet6 (-6 must override -o AddressFamily=inet)", got)
	}
}

func TestPhase1Flags_HostNameExpansionAndJumpIsolation(t *testing.T) {
	opts := NewSshOptions()
	opts.Host = "mybox"
	if err := ApplyGeneralOptions(opts, []string{"HostName=%h.corp.%%local"}, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions failed: %v", err)
	}
	got, err := opts.effectiveHostName()
	if err != nil {
		t.Fatalf("effectiveHostName failed: %v", err)
	}
	if got != "mybox.corp.%local" {
		t.Fatalf("effectiveHostName = %q, want %q", got, "mybox.corp.%local")
	}
	if targetOnly, err := isTargetOnlyMuxDaemonOption("HostName=10.0.0.5"); err != nil || !targetOnly {
		t.Fatalf("expected HostName to be target-specific so jump hosts never inherit it, got (%v, %v)", targetOnly, err)
	}
}

func TestPhase1Flags_GatewayPortsClientSpecified(t *testing.T) {
	flags := SSHControlFlags{
		Options: []string{"GatewayPorts=clientspecified"},
	}
	sessionOpts, err := flags.ToSessionControlOptions()
	if err != nil {
		t.Fatalf("ToSessionControlOptions failed: %v", err)
	}
	if got := sessionOpts.Options.GatewayPortsMode(); got != ssh.GatewayPortsClientSpecified {
		t.Fatalf("GatewayPortsMode = %q, want %q", got, ssh.GatewayPortsClientSpecified)
	}
}

func TestPhase1Flags_ConfigOverrideAdHocSSHAndSCP(t *testing.T) {
	baseCfg := &config.Configuration{}
	baseRepo, err := config.NewRepositoryWithoutOpenSSH(baseCfg, &memoryStore{cfg: baseCfg})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	overrideProvider, err := config.WithOpenSSHConfigOverride(baseRepo, "none")
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride(none) failed: %v", err)
	}

	// 1. ssh -F none ops@127.0.0.1 -> withTestPendingNode -> GetConfig succeeds
	sshOpts := NewSshOptions()
	sshOpts.Target = config.ConnectionTarget{Selector: "ops@127.0.0.1", User: "ops", HasUser: true}
	adp := adapter.NewSSHAdapter(overrideProvider)
	if err := sshOpts.withTestPendingNode(t.Context(), overrideProvider, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		clientCfg, err := adp.GetConfig(nodeID)
		if err != nil {
			t.Fatalf("GetConfig(%q) with -F none failed: %v", nodeID, err)
		}
		if clientCfg.Address != "127.0.0.1" || clientCfg.User != "ops" {
			t.Fatalf("unexpected clientCfg: Address=%q User=%q", clientCfg.Address, clientCfg.User)
		}
		return nil
	}); err != nil {
		t.Fatalf("ssh withTestPendingNode with -F none failed: %v", err)
	}

	// 2. scp -F none ops@127.0.0.1:/tmp/a -> withTestPendingPath succeeds
	scpOpts := NewScpOptions()
	if err := scpOpts.withTestPendingPath(t.Context(), overrideProvider, PathInfo{
		IsRemote: true,
		User:     "ops",
		Host:     "127.0.0.1",
		Path:     "/tmp/a",
	}, "", func(lease config.PendingLease) error {
		if _, err := adp.GetConfig(lease.NodeID()); err != nil {
			t.Fatalf("scp GetConfig(%q) with -F none failed: %v", lease.NodeID(), err)
		}
		return nil
	}); err != nil {
		t.Fatalf("scp withTestPendingPath with -F none failed: %v", err)
	}
	if len(baseRepo.ListNodes()) != 0 {
		t.Fatalf("expected baseRepo to remain unmutated, got %d nodes", len(baseRepo.ListNodes()))
	}
}

func TestPhase1Flags_ControlTargetAppliesHostNameOverride(t *testing.T) {
	cfg := &config.Configuration{}
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host mybox\n  HostName 10.0.0.1\n  User ops\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	opts := NewSshOptions()
	opts.Host = "mybox"
	opts.Target = config.ConnectionTarget{Selector: "mybox"}
	opts.control.ControlPath = "/tmp/mux-%h-%n.sock"
	if err := ApplyGeneralOptions(opts, []string{"HostName=%h.corp"}, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions failed: %v", err)
	}

	target := controlTarget(opts, provider, "openssh:mybox")
	if target.Host != "mybox.corp" {
		t.Fatalf("controlTarget.Host = %q, want %q", target.Host, "mybox.corp")
	}
	sockPath, err := controlSocketPath(opts, provider, "openssh:mybox")
	if err != nil {
		t.Fatalf("controlSocketPath failed: %v", err)
	}
	if !strings.Contains(sockPath, "mybox.corp") {
		t.Fatalf("controlSocketPath = %q, expected expanded HostName mybox.corp", sockPath)
	}
}

func TestPhase1Flags_IdentityPathPreservesTokensAndDeduplicates(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{raw: "%d/.ssh/id_ed25519", want: "%d/.ssh/id_ed25519"},
		{raw: "${KEYDIR}/k", want: "${KEYDIR}/k"},
		{raw: "none", want: "none"},
		{raw: "NONE", want: "NONE"},
	} {
		if got := normalizeCLIIdentityPath(tc.raw); got != tc.want {
			t.Fatalf("normalizeCLIIdentityPath(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	// Verify -o IdentityFile=rel_key is not duplicated in ClientConfig.KeyPaths
	baseCfg := &config.Configuration{}
	provider, err := config.WithOpenSSHConfigOverride(config.NewProviderWithoutOpenSSH(baseCfg), "none")
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride failed: %v", err)
	}
	opts := NewSshOptions()
	opts.Target = config.ConnectionTarget{Selector: "ops@127.0.0.1", User: "ops", HasUser: true}
	opts.control.Options = []string{"IdentityFile=rel_key"}
	if err := ApplyGeneralOptions(opts, opts.control.Options, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions failed: %v", err)
	}
	if err := opts.withTestPendingNode(t.Context(), provider, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		adpOpts, err := opts.buildAdapterOptions(nodeID, baseCfg, provider)
		if err != nil {
			t.Fatalf("buildAdapterOptions failed: %v", err)
		}
		clientCfg, err := adapter.NewSSHAdapter(provider, adpOpts...).GetConfig(nodeID)
		if err != nil {
			t.Fatalf("GetConfig failed: %v", err)
		}
		wd, _ := os.Getwd()
		wantAbs := filepath.Join(wd, "rel_key")
		if !slices.Equal(clientCfg.KeyPaths, []string{wantAbs}) {
			t.Fatalf("KeyPaths = %v, want single deduplicated [%q]", clientCfg.KeyPaths, wantAbs)
		}
		return nil
	}); err != nil {
		t.Fatalf("withTestPendingNode failed: %v", err)
	}
}
