package adapter

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestSplitOptionKeyValue(t *testing.T) {
	validSplitCases := []struct {
		input   string
		wantKey string
		wantVal string
	}{
		{"LocalForward=8080:127.0.0.1:80", "LocalForward", "8080:127.0.0.1:80"},
		{"LocalForward 8080 127.0.0.1:80", "LocalForward", "8080 127.0.0.1:80"},
		{"LocalForward\t8080 127.0.0.1:80", "LocalForward", "8080 127.0.0.1:80"},
		{"LocalForward = 8080:127.0.0.1:80", "LocalForward", "8080:127.0.0.1:80"},
		{"Tunnel ethernet", "Tunnel", "ethernet"},
		{"Tunnel=ethernet", "Tunnel", "ethernet"},
		{"Tunnel = ethernet", "Tunnel", "ethernet"},
		{"Tunnel = ", "Tunnel", ""},
		{"ControlPath=", "ControlPath", ""},
		{"ControlPath = ", "ControlPath", ""},
		{"", "", ""},
		{"   ", "", ""},
	}

	for _, tc := range validSplitCases {
		k, v, err := SplitOptionKeyValue(tc.input)
		if err != nil {
			t.Errorf("SplitOptionKeyValue(%q) unexpected error: %v", tc.input, err)
			continue
		}
		if k != tc.wantKey || v != tc.wantVal {
			t.Errorf("SplitOptionKeyValue(%q) = (%q, %q), want (%q, %q)", tc.input, k, v, tc.wantKey, tc.wantVal)
		}
	}

	invalidSplitCases := []string{
		"ControlMaster",
		"NoEqualsSign",
		"=Value",
		"= Value",
		"=",
		" = ",
	}
	for _, input := range invalidSplitCases {
		k, v, err := SplitOptionKeyValue(input)
		if err == nil {
			t.Errorf("SplitOptionKeyValue(%q) expected error, got (%q, %q)", input, k, v)
			continue
		}
		if !strings.Contains(err.Error(), "invalid -o option format") {
			t.Errorf("SplitOptionKeyValue(%q) error %q does not contain 'invalid -o option format'", input, err.Error())
		}
	}
}

func TestParseOptionStrings_MultiValueAndForwardOptions(t *testing.T) {
	opts, err := ParseOptionStrings([]string{
		"LocalForward=8080 127.0.0.1:80",
		"LocalForward 9090 remote:90",
		"RemoteForward=8081 127.0.0.1:81",
		"RemoteForward 9091 remote:91",
		"DynamicForward=1080",
		"DynamicForward 1081",
		"Tunnel ethernet",
		"TunnelDevice 0:1",
		"RequestTTY force",
		"ExitOnForwardFailure yes",
		"ClearAllForwardings yes",
		"GatewayPorts yes",
		"StreamLocalBindUnlink yes",
		"StreamLocalBindMask 0117",
		"ForkAfterAuthentication yes",
		"StdinNull yes",
		"SessionType none",
	})
	if err != nil {
		t.Fatalf("ParseOptionStrings failed: %v", err)
	}

	sshOpts := opts.ToSSHOptions()
	if sshOpts == nil {
		t.Fatalf("expected non-nil sshOpts")
	}

	assertParsedForwardOptions(t, sshOpts)

	for _, bad := range []string{
		"ControlMaster",
		"ControlPath=",
		"NoSuchOption=foo",
	} {
		if _, err := ParseOptionStrings([]string{bad}); err == nil {
			t.Errorf("ParseOptionStrings(%q) expected error, got nil", bad)
		}
	}
}

func assertParsedForwardOptions(t *testing.T, sshOpts *ssh.Options) {
	t.Helper()
	if len(sshOpts.LocalForwards()) != 2 {
		t.Errorf("LocalForwards count = %d, want 2: %v", len(sshOpts.LocalForwards()), sshOpts.LocalForwards())
	}
	if len(sshOpts.RemoteForwards()) != 2 {
		t.Errorf("RemoteForwards count = %d, want 2: %v", len(sshOpts.RemoteForwards()), sshOpts.RemoteForwards())
	}
	if len(sshOpts.DynamicForwards()) != 2 {
		t.Errorf("DynamicForwards count = %d, want 2: %v", len(sshOpts.DynamicForwards()), sshOpts.DynamicForwards())
	}
	if sshOpts.Tunnel() != "ethernet" {
		t.Errorf("Tunnel = %q, want ethernet", sshOpts.Tunnel())
	}
	if dev, ok := sshOpts.TunnelDevice(); !ok || dev.String() != "0:1" {
		t.Errorf("TunnelDevice = %v, want 0:1", dev)
	}
	if sshOpts.RequestTTY() != ssh.RequestTTYForce {
		t.Errorf("RequestTTY = %q, want force", sshOpts.RequestTTY())
	}
	if exitFail, ok := sshOpts.ExitOnForwardFailure(); !ok || !exitFail {
		t.Errorf("ExitOnForwardFailure = (%v, %v), want (true, true)", exitFail, ok)
	}
	if clearFwd, ok := sshOpts.ClearAllForwardings(); !ok || !clearFwd {
		t.Errorf("ClearAllForwardings = (%v, %v), want (true, true)", clearFwd, ok)
	}
	assertParsedStreamLocalAndSessionOptions(t, sshOpts)
}

func assertParsedStreamLocalAndSessionOptions(t *testing.T, sshOpts *ssh.Options) {
	t.Helper()
	if !sshOpts.EffectiveGatewayPorts() {
		t.Errorf("EffectiveGatewayPorts = false, want true")
	}
	if !sshOpts.EffectiveStreamLocalBindUnlink() {
		t.Errorf("EffectiveStreamLocalBindUnlink = false, want true")
	}
	if mask, ok := sshOpts.StreamLocalBindMask(); !ok || mask != 0o117 {
		t.Errorf("StreamLocalBindMask = (%04o, %v), want (0117, true)", mask, ok)
	}
	if fork, ok := sshOpts.ForkAfterAuthentication(); !ok || !fork {
		t.Errorf("ForkAfterAuthentication = (%v, %v), want (true, true)", fork, ok)
	}
	if stdinNull, ok := sshOpts.StdinNull(); !ok || !stdinNull {
		t.Errorf("StdinNull = (%v, %v), want (true, true)", stdinNull, ok)
	}
	if sshOpts.SessionType() != ssh.SessionTypeNone {
		t.Errorf("SessionType = %q, want %q", sshOpts.SessionType(), ssh.SessionTypeNone)
	}
}

func TestResolveSSHOptions_Tier4Filtering_ManagedVsVirtual(t *testing.T) {
	adp := newTier4FilteringTestAdapter(t)

	// 1. Managed node "srv": Tier 4 OptionClassForward and OptionClassSession must be filtered out
	managedOpts, err := adp.ResolveSSHOptions("srv", SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveSSHOptions(srv) failed: %v", err)
	}
	if managedOpts == nil {
		t.Fatalf("expected non-nil managedOpts")
	}
	assertManagedTier4Filtered(t, managedOpts)

	// 2. Virtual node "openssh:srv": Tier 4 OptionClassForward and OptionClassSession are fully preserved
	virtualOpts, err := adp.ResolveSSHOptions(config.OpenSSHNodePrefix+"srv", SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveSSHOptions(openssh:srv) failed: %v", err)
	}
	if virtualOpts == nil {
		t.Fatalf("expected non-nil virtualOpts")
	}
	assertVirtualTier4Preserved(t, virtualOpts)

	// 3. Managed node with Tier 1 CLI overrides: Tier 1 can explicitly set forwards
	cliOpts, err := ParseOptionStrings([]string{"LocalForward 9999 127.0.0.1:99"})
	if err != nil {
		t.Fatalf("ParseOptionStrings failed: %v", err)
	}
	managedWithCLIOpts, err := adp.ResolveSSHOptions("srv", cliOpts)
	if err != nil {
		t.Fatalf("ResolveSSHOptions with CLI opts failed: %v", err)
	}
	if len(managedWithCLIOpts.LocalForwards()) != 1 || managedWithCLIOpts.LocalForwards()[0] != "9999 127.0.0.1:99" {
		t.Errorf("expected Tier 1 LocalForward on managed node, got %v", managedWithCLIOpts.LocalForwards())
	}
}

func newTier4FilteringTestAdapter(t *testing.T) *SSHAdapter {
	t.Helper()
	openSSHContent := `
Host srv
    HostName 192.168.1.100
    Port 2222
    User bob
    ConnectTimeout 15
    Tunnel ethernet
    TunnelDevice 0:1
    RequestTTY force
    ExitOnForwardFailure yes
    ClearAllForwardings yes
    GatewayPorts yes
    StreamLocalBindUnlink yes
    StreamLocalBindMask 0117
    ForkAfterAuthentication yes
    StdinNull yes
    SessionType none
    LocalForward 8080 127.0.0.1:80
    RemoteForward 9090 127.0.0.1:90
    DynamicForward 1080
    SendEnv LANG LC_*
    SetEnv FOO=bar
    RemoteCommand echo %h
    EscapeChar ^
    CertificateFile ~/.ssh/id_test-cert.pub
    IdentityAgent /tmp/test-agent.sock
    ForwardAgent yes
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("host1", models.Host{Address: "192.168.1.100", Port: 2222})
	cfg.Identities.Set("id1", models.Identity{User: "bob", AuthType: "auto"})
	cfg.Nodes.Set("srv", models.Node{
		HostRef:     "host1",
		IdentityRef: "id1",
	})

	provider := config.NewProviderWithOpenSSHParser(cfg, parser)
	return NewSSHAdapter(provider)
}

func assertManagedTier4Filtered(t *testing.T, managedOpts *ssh.Options) {
	t.Helper()
	if managedOpts.Get(ssh.OptionConnectTimeout) != "15" {
		t.Errorf("expected ConnectTimeout=15 on managed node, got %q", managedOpts.Get(ssh.OptionConnectTimeout))
	}
	if len(managedOpts.LocalForwards()) != 0 {
		t.Errorf("LocalForwards should be filtered for managed node, got %v", managedOpts.LocalForwards())
	}
	if len(managedOpts.RemoteForwards()) != 0 {
		t.Errorf("RemoteForwards should be filtered for managed node, got %v", managedOpts.RemoteForwards())
	}
	if len(managedOpts.DynamicForwards()) != 0 {
		t.Errorf("DynamicForwards should be filtered for managed node, got %v", managedOpts.DynamicForwards())
	}
	if managedOpts.Tunnel() != "" {
		t.Errorf("Tunnel should be filtered for managed node, got %q", managedOpts.Tunnel())
	}
	if _, ok := managedOpts.TunnelDevice(); ok {
		t.Errorf("TunnelDevice should be filtered for managed node")
	}
	if managedOpts.RequestTTY() != "" {
		t.Errorf("RequestTTY should be filtered for managed node, got %q", managedOpts.RequestTTY())
	}
	if _, ok := managedOpts.ExitOnForwardFailure(); ok {
		t.Errorf("ExitOnForwardFailure should be filtered for managed node")
	}
	if _, ok := managedOpts.ClearAllForwardings(); ok {
		t.Errorf("ClearAllForwardings should be filtered for managed node")
	}
	if managedOpts.EffectiveGatewayPorts() {
		t.Errorf("GatewayPorts should be filtered for managed node")
	}
	if managedOpts.EffectiveStreamLocalBindUnlink() {
		t.Errorf("StreamLocalBindUnlink should be filtered for managed node")
	}
	if _, ok := managedOpts.StreamLocalBindMask(); ok {
		t.Errorf("StreamLocalBindMask should be filtered for managed node")
	}
	if _, ok := managedOpts.ForkAfterAuthentication(); ok {
		t.Errorf("ForkAfterAuthentication should be filtered for managed node")
	}
	if _, ok := managedOpts.StdinNull(); ok {
		t.Errorf("StdinNull should be filtered for managed node")
	}
	if managedOpts.SessionType() != "" {
		t.Errorf("SessionType should be filtered for managed node, got %q", managedOpts.SessionType())
	}
	if len(managedOpts.SendEnvPatterns()) != 0 {
		t.Errorf("SendEnv should be filtered for managed node, got %v", managedOpts.SendEnvPatterns())
	}
	if len(managedOpts.SetEnvDirectives()) != 0 {
		t.Errorf("SetEnv should be filtered for managed node, got %v", managedOpts.SetEnvDirectives())
	}
	if managedOpts.RemoteCommand() != "" {
		t.Errorf("RemoteCommand should be filtered for managed node, got %q", managedOpts.RemoteCommand())
	}
	if managedOpts.EscapeChar() != "" {
		t.Errorf("EscapeChar should be filtered for managed node, got %q", managedOpts.EscapeChar())
	}
	assertManagedTier4Phase3Filtered(t, managedOpts)
}

func assertManagedTier4Phase3Filtered(t *testing.T, managedOpts *ssh.Options) {
	t.Helper()
	if len(managedOpts.CertificateFiles()) != 0 {
		t.Errorf("CertificateFiles should be filtered for managed node, got %v", managedOpts.CertificateFiles())
	}
	if managedOpts.IdentityAgent() != "" {
		t.Errorf("IdentityAgent should be filtered for managed node, got %q", managedOpts.IdentityAgent())
	}
	if managedOpts.ForwardAgent() != "" {
		t.Errorf("ForwardAgent should be filtered for managed node, got %q", managedOpts.ForwardAgent())
	}
}

func assertVirtualTier4Preserved(t *testing.T, virtualOpts *ssh.Options) {
	t.Helper()
	if virtualOpts.Get(ssh.OptionConnectTimeout) != "15" {
		t.Errorf("expected ConnectTimeout=15 on virtual node, got %q", virtualOpts.Get(ssh.OptionConnectTimeout))
	}
	if len(virtualOpts.LocalForwards()) != 1 || virtualOpts.LocalForwards()[0] != "8080 127.0.0.1:80" {
		t.Errorf("expected LocalForward preserved on virtual node, got %v", virtualOpts.LocalForwards())
	}
	if len(virtualOpts.RemoteForwards()) != 1 || virtualOpts.RemoteForwards()[0] != "9090 127.0.0.1:90" {
		t.Errorf("expected RemoteForward preserved on virtual node, got %v", virtualOpts.RemoteForwards())
	}
	if len(virtualOpts.DynamicForwards()) != 1 || virtualOpts.DynamicForwards()[0] != "1080" {
		t.Errorf("expected DynamicForward preserved on virtual node, got %v", virtualOpts.DynamicForwards())
	}
	if virtualOpts.Tunnel() != "ethernet" {
		t.Errorf("expected Tunnel=ethernet on virtual node, got %q", virtualOpts.Tunnel())
	}
	if dev, ok := virtualOpts.TunnelDevice(); !ok || dev.String() != "0:1" {
		t.Errorf("expected TunnelDevice=0:1 on virtual node, got %v", dev)
	}
	if virtualOpts.RequestTTY() != ssh.RequestTTYForce {
		t.Errorf("expected RequestTTY=force on virtual node, got %q", virtualOpts.RequestTTY())
	}
	if exitFail, ok := virtualOpts.ExitOnForwardFailure(); !ok || !exitFail {
		t.Errorf("expected ExitOnForwardFailure=true on virtual node, got (%v, %v)", exitFail, ok)
	}
	if clearFwd, ok := virtualOpts.ClearAllForwardings(); !ok || !clearFwd {
		t.Errorf("expected ClearAllForwardings=true on virtual node, got (%v, %v)", clearFwd, ok)
	}
	assertParsedStreamLocalAndSessionOptions(t, virtualOpts)
	assertVirtualTier4SessionOptions(t, virtualOpts)
}

func assertVirtualTier4SessionOptions(t *testing.T, virtualOpts *ssh.Options) {
	t.Helper()
	if len(virtualOpts.SendEnvPatterns()) != 2 || virtualOpts.SendEnvPatterns()[0] != "LANG" || virtualOpts.SendEnvPatterns()[1] != "LC_*" {
		t.Errorf("expected SendEnv preserved on virtual node, got %v", virtualOpts.SendEnvPatterns())
	}
	if len(virtualOpts.SetEnvDirectives()) != 1 || virtualOpts.SetEnvDirectives()[0] != "FOO=bar" {
		t.Errorf("expected SetEnv preserved on virtual node, got %v", virtualOpts.SetEnvDirectives())
	}
	if virtualOpts.RemoteCommand() != "echo %h" {
		t.Errorf("expected RemoteCommand preserved on virtual node, got %q", virtualOpts.RemoteCommand())
	}
	if virtualOpts.EscapeChar() != "^" {
		t.Errorf("expected EscapeChar preserved on virtual node, got %q", virtualOpts.EscapeChar())
	}
	if len(virtualOpts.CertificateFiles()) != 1 || virtualOpts.CertificateFiles()[0] != "~/.ssh/id_test-cert.pub" {
		t.Errorf("expected CertificateFiles preserved on virtual node, got %v", virtualOpts.CertificateFiles())
	}
	if virtualOpts.IdentityAgent() != "/tmp/test-agent.sock" {
		t.Errorf("expected IdentityAgent preserved on virtual node, got %q", virtualOpts.IdentityAgent())
	}
	if virtualOpts.ForwardAgent() != "yes" {
		t.Errorf("expected ForwardAgent preserved on virtual node, got %q", virtualOpts.ForwardAgent())
	}
}

func TestResolveSSHOptions_WithSessionAndForwardOptionsDisabled(t *testing.T) {
	openSSHContent := `
Host srv
    HostName 192.168.1.100
    Port 2222
    User bob
    ConnectTimeout 15
    RequestTTY force
    LocalForward 8080 127.0.0.1:80
    SendEnv LANG
    SetEnv FOO=bar
    RemoteCommand echo %h
    EscapeChar ^
    CertificateFile ~/.ssh/id_test-cert.pub
    IdentityAgent /tmp/test-agent.sock
    ForwardAgent yes
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(nil, parser)
	adp := NewNonInteractiveSSHAdapter(
		provider,
		WithControlMultiplexing(false),
		WithHostTrustOverrides(false),
		WithSessionAndForwardOptions(false),
	)

	cliOpts, err := ParseOptionStrings([]string{
		"SendEnv=LC_ALL",
		"SetEnv=BAZ=qux",
		"RemoteCommand=ls",
		"EscapeChar=~",
		"LocalForward=9999 127.0.0.1:99",
	})
	if err != nil {
		t.Fatalf("ParseOptionStrings failed: %v", err)
	}

	opts, err := adp.ResolveSSHOptions(config.OpenSSHNodePrefix+"srv", cliOpts)
	if err != nil {
		t.Fatalf("ResolveSSHOptions() error = %v", err)
	}
	if opts == nil || opts.Get(ssh.OptionConnectTimeout) != "15" {
		t.Fatalf("expected transport option ConnectTimeout=15 preserved, got %+v", opts)
	}
	if len(opts.LocalForwards()) != 0 || opts.RequestTTY() != "" || len(opts.SendEnvPatterns()) != 0 ||
		len(opts.SetEnvDirectives()) != 0 || opts.RemoteCommand() != "" || opts.EscapeChar() != "" {
		t.Fatalf("Gate 4 violation: expected all forward and session options stripped, got %+v", opts)
	}
}

func TestResolveSSHOptions_NonInteractiveStripsForwardAgent(t *testing.T) {
	openSSHContent := `
Host play-target
    HostName 192.168.1.200
    Port 22
    User ops
    ForwardAgent yes
    LocalForward 8080 127.0.0.1:80
    SendEnv LANG
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(nil, parser)
	cliOpts, err := ParseOptionStrings([]string{"ForwardAgent=yes"})
	if err != nil {
		t.Fatalf("ParseOptionStrings failed: %v", err)
	}

	// 1. Default NewNonInteractiveSSHAdapter strips ForwardAgent
	adp := NewNonInteractiveSSHAdapter(provider)
	opts, err := adp.ResolveSSHOptions(config.OpenSSHNodePrefix+"play-target", cliOpts)
	if err != nil {
		t.Fatalf("ResolveSSHOptions() error = %v", err)
	}
	if opts.ForwardAgent() != "" {
		t.Fatalf("expected NewNonInteractiveSSHAdapter to strip ForwardAgent, got %q", opts.ForwardAgent())
	}

	// 2. Playbook adapter (WithNonInteractive(true), WithForwardOptions(false)) strips ForwardAgent and LocalForward while keeping SendEnv
	playAdp := NewNonInteractiveSSHAdapter(provider, WithForwardOptions(false))
	playOpts, err := playAdp.ResolveSSHOptions(config.OpenSSHNodePrefix+"play-target", cliOpts)
	if err != nil {
		t.Fatalf("ResolveSSHOptions() error = %v", err)
	}
	if playOpts.ForwardAgent() != "" || len(playOpts.LocalForwards()) != 0 {
		t.Fatalf("expected play adapter to strip ForwardAgent and LocalForward, got forward=%q local=%v",
			playOpts.ForwardAgent(), playOpts.LocalForwards())
	}
	if len(playOpts.SendEnvPatterns()) != 1 || playOpts.SendEnvPatterns()[0] != "LANG" {
		t.Fatalf("expected play adapter to keep SendEnv, got %v", playOpts.SendEnvPatterns())
	}
}

func TestResolveSSHOptions_Phase4TrustGateAndHashKnownHosts(t *testing.T) {
	openSSHContent := `
Host srv-hash-yes
    HostName 192.168.1.210
    User ops
    HashKnownHosts yes
    GlobalKnownHostsFile /etc/ssh/custom_known_hosts
    VerifyHostKeyDNS yes

Host srv-hash-no
    HostName 192.168.1.211
    User ops
    HashKnownHosts no
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHContent))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "192.168.1.210", Port: 22})
	cfg.Hosts.Set("h2", models.Host{Address: "192.168.1.211", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	tier2Yes, _ := ssh.NewOptions()
	_ = tier2Yes.Set(ssh.OptionHashKnownHosts, "yes")
	cfg.Nodes.Set("srv-hash-yes", models.Node{HostRef: "h1", IdentityRef: "id1"})
	cfg.Nodes.Set("srv-hash-no", models.Node{HostRef: "h2", IdentityRef: "id1", SSHOptions: tier2Yes})

	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	// 1. Managed node inherits one-way HashKnownHosts=yes from Tier 4, never GlobalKnownHostsFile or VerifyHostKeyDNS
	adp := NewSSHAdapter(provider)
	managedOpts, err := adp.ResolveSSHOptions("srv-hash-yes", SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveSSHOptions(srv-hash-yes) error = %v", err)
	}
	if !managedOpts.HashKnownHosts() {
		t.Fatalf("expected one-way HashKnownHosts=yes inherited on managed node")
	}
	if managedOpts.GlobalKnownHostsFile() != "" || managedOpts.VerifyHostKeyDNS() != "" {
		t.Fatalf("Gate 2 violation: GlobalKnownHostsFile/VerifyHostKeyDNS leaked to managed node: %+v", managedOpts)
	}

	// 2. Tier 4 HashKnownHosts=no never downgrades Tier 2 HashKnownHosts=yes
	managedNoDowngrade, err := adp.ResolveSSHOptions("srv-hash-no", SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveSSHOptions(srv-hash-no) error = %v", err)
	}
	if !managedNoDowngrade.HashKnownHosts() {
		t.Fatalf("expected Tier 4 HashKnownHosts=no NOT to downgrade Tier 2 HashKnownHosts=yes")
	}

	// 3. Gate 1 & Gate 4 assertions
	assertPhase4VirtualAndMCPTrustGate(t, adp, provider)
}

func assertPhase4VirtualAndMCPTrustGate(t *testing.T, adp *SSHAdapter, provider config.ConfigProvider) {
	t.Helper()
	virtualOpts, err := adp.ResolveSSHOptions(config.OpenSSHNodePrefix+"srv-hash-yes", SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveSSHOptions(openssh:srv-hash-yes) error = %v", err)
	}
	if !virtualOpts.HashKnownHosts() || virtualOpts.GlobalKnownHostsFile() != "" || virtualOpts.VerifyHostKeyDNS() != "" {
		t.Fatalf("Gate 1 mismatch on virtual node: got hash=%v global=%q dns=%q",
			virtualOpts.HashKnownHosts(), virtualOpts.GlobalKnownHostsFile(), virtualOpts.VerifyHostKeyDNS())
	}

	// 4. Tier 1 CLI -o GlobalKnownHostsFile / VerifyHostKeyDNS is preserved for CLI,
	// and stripped by Gate 4 MCP (WithHostTrustOverrides(false)).
	cliTrustOpts, err := ParseOptionStrings([]string{
		"GlobalKnownHostsFile=/etc/ssh/custom_known_hosts",
		"VerifyHostKeyDNS=yes",
	})
	if err != nil {
		t.Fatalf("ParseOptionStrings() error = %v", err)
	}
	cliResolved, err := adp.ResolveSSHOptions(config.OpenSSHNodePrefix+"srv-hash-yes", cliTrustOpts)
	if err != nil {
		t.Fatalf("ResolveSSHOptions(cli) error = %v", err)
	}
	if cliResolved.GlobalKnownHostsFile() != "/etc/ssh/custom_known_hosts" || cliResolved.VerifyHostKeyDNS() != ssh.VerifyHostKeyDNSYes {
		t.Fatalf("expected Tier 1 trust options preserved for CLI, got global=%q dns=%q",
			cliResolved.GlobalKnownHostsFile(), cliResolved.VerifyHostKeyDNS())
	}

	mcpAdp := NewNonInteractiveSSHAdapter(provider, WithHostTrustOverrides(false))
	mcpOpts, err := mcpAdp.ResolveSSHOptions(config.OpenSSHNodePrefix+"srv-hash-yes", cliTrustOpts)
	if err != nil {
		t.Fatalf("ResolveSSHOptions(mcp) error = %v", err)
	}
	if mcpOpts != nil && (mcpOpts.HashKnownHosts() || mcpOpts.GlobalKnownHostsFile() != "" || mcpOpts.VerifyHostKeyDNS() != "") {
		t.Fatalf("Gate 4 violation: MCP WithHostTrustOverrides(false) leaked trust options: %+v", mcpOpts)
	}
}

func TestGetConfig_PropagatesOriginalHost(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "web.corp.example.com", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("web.corp.example.com", models.Node{HostRef: "h1", IdentityRef: "id1"})

	provider := config.NewProviderWithOpenSSHParser(cfg, nil)
	adp := NewNonInteractiveSSHAdapter(provider, WithSessionAuthOverride("web.corp.example.com", SessionAuth{
		HostName:     "10.20.30.40",
		OriginalHost: "web",
	}))
	clientCfg, err := adp.GetConfig("web.corp.example.com")
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if clientCfg.Address != "10.20.30.40" {
		t.Fatalf("ClientConfig.Address = %q, want %q", clientCfg.Address, "10.20.30.40")
	}
	if clientCfg.OriginalHost != "web" {
		t.Fatalf("ClientConfig.OriginalHost = %q, want %q", clientCfg.OriginalHost, "web")
	}
}
