package config

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func assertParsedScalarForwardOptions(t *testing.T, opts *ssh.Options) {
	t.Helper()
	if opts.Tunnel() != "ethernet" {
		t.Errorf("Tunnel = %q, want ethernet", opts.Tunnel())
	}
	if opts.EffectiveTunnelMode() != ssh.TunnelModeEthernet {
		t.Errorf("EffectiveTunnelMode = %q, want ethernet", opts.EffectiveTunnelMode())
	}
	devSpec, ok := opts.TunnelDevice()
	if !ok {
		t.Fatalf("expected TunnelDevice to be configured")
	}
	if devSpec.LocalUnit != 0 || devSpec.RemoteUnit != 1 || devSpec.String() != "0:1" {
		t.Errorf("TunnelDevice = %v (%s), want 0:1", devSpec, devSpec.String())
	}
	if opts.RequestTTY() != ssh.RequestTTYForce {
		t.Errorf("RequestTTY = %q, want force", opts.RequestTTY())
	}
	if exitFail, ok := opts.ExitOnForwardFailure(); !ok || !exitFail {
		t.Errorf("ExitOnForwardFailure = (%v, %v), want (true, true)", exitFail, ok)
	}
	if clearFwd, ok := opts.ClearAllForwardings(); !ok || !clearFwd {
		t.Errorf("ClearAllForwardings = (%v, %v), want (true, true)", clearFwd, ok)
	}
	assertParsedStreamLocalAndSessionOptions(t, opts)
}

func assertParsedStreamLocalAndSessionOptions(t *testing.T, opts *ssh.Options) {
	t.Helper()
	if !opts.EffectiveGatewayPorts() {
		t.Errorf("EffectiveGatewayPorts = false, want true")
	}
	if !opts.EffectiveStreamLocalBindUnlink() {
		t.Errorf("EffectiveStreamLocalBindUnlink = false, want true")
	}
	mask, ok := opts.StreamLocalBindMask()
	if !ok || mask != 0o117 {
		t.Errorf("StreamLocalBindMask = (%04o, %v), want (0117, true)", mask, ok)
	}
	if fork, ok := opts.ForkAfterAuthentication(); !ok || !fork {
		t.Errorf("ForkAfterAuthentication = (%v, %v), want (true, true)", fork, ok)
	}
	if stdinNull, ok := opts.StdinNull(); !ok || !stdinNull {
		t.Errorf("StdinNull = (%v, %v), want (true, true)", stdinNull, ok)
	}
	if opts.SessionType() != ssh.SessionTypeNone {
		t.Errorf("SessionType = %q, want %q", opts.SessionType(), ssh.SessionTypeNone)
	}
}

func assertParsedMultiForwardOptions(t *testing.T, opts *ssh.Options) {
	t.Helper()
	lf := opts.LocalForwards()
	if len(lf) != 2 || lf[0] != "8080 127.0.0.1:80" || lf[1] != "8081 127.0.0.1:81" {
		t.Fatalf("unexpected LocalForwards: %v", lf)
	}
	rf := opts.RemoteForwards()
	if len(rf) != 3 ||
		rf[0] != "9090 127.0.0.1:90" ||
		rf[1] != "/run/user/1000/gnupg/S.gpg-agent /run/user/1000/gnupg/S.gpg-agent.extra" ||
		rf[2] != "2080" {
		t.Fatalf("unexpected RemoteForward: %v", rf)
	}
	df := opts.DynamicForwards()
	if len(df) != 2 || df[0] != "1080" || df[1] != "1081" {
		t.Fatalf("unexpected DynamicForwards: %v", df)
	}
}

func TestOpenSSHParser_ForwardOptionsAndMultiValue(t *testing.T) {
	cfgText := `
Host srv1
    HostName 10.0.0.1
    User testuser
    Port 2200
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
    RemoteForward /run/user/1000/gnupg/S.gpg-agent /run/user/1000/gnupg/S.gpg-agent.extra
    RemoteForward 2080
    # Malformed multi-value entry should be leniently skipped without error:
    RemoteForward invalid:port:extra:bad:5
    DynamicForward 1080

Host *
    LocalForward 8081 127.0.0.1:81
    DynamicForward 1081
    # Duplicate entry to test deduplication:
    LocalForward 8080 127.0.0.1:80
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfgText))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}

	opts, err := parser.GetSSHOptions("srv1")
	if err != nil {
		t.Fatalf("GetSSHOptions failed: %v", err)
	}
	if opts == nil {
		t.Fatalf("expected non-nil options")
	}

	assertParsedScalarForwardOptions(t, opts)
	assertParsedMultiForwardOptions(t, opts)

	node, host, identity, err := parser.GetVirtualNode("srv1")
	if err != nil {
		t.Fatalf("GetVirtualNode failed: %v", err)
	}
	if host.Address != "10.0.0.1" || host.Port != 2200 || identity.User != "testuser" {
		t.Errorf("unexpected host/identity: %+v, %+v", host, identity)
	}
	if node.SSHOptions == nil || len(node.SSHOptions.LocalForwards()) != 2 || len(node.SSHOptions.RemoteForwards()) != 3 || len(node.SSHOptions.DynamicForwards()) != 2 {
		t.Errorf("node.SSHOptions did not preserve forwards: %+v", node.SSHOptions)
	}
}
