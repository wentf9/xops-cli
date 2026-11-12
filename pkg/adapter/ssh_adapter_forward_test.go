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
}
