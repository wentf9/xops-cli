package config

import (
	"strings"
	"testing"
)

func TestParseOpenSSHHosts(t *testing.T) {
	t.Parallel()

	const input = `
Host *
    ServerAliveInterval 30

Host jump
    HostName bastion.example.com
    User ops
    Port 2222
    IdentityFile /keys/ops

Host web-*
    User deploy

Host app
    HostName 10.0.0.10
    User deploy
    ProxyJump jump

Host app
    HostName ignored.example.com
`

	hosts, err := ParseOpenSSHHosts(strings.NewReader(input), "local-user")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts() error = %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("ParseOpenSSHHosts() returned %d hosts, want 2", len(hosts))
	}

	jump := hosts[0]
	if jump.Name != "jump" || jump.Host.Address != "bastion.example.com" || jump.Host.Port != 2222 {
		t.Errorf("unexpected jump host: %#v", jump)
	}
	if jump.Identity.User != "ops" || jump.Identity.AuthType != "auto" || jump.Identity.KeyPath != "/keys/ops" {
		t.Errorf("unexpected jump identity: %#v", jump.Identity)
	}

	app := hosts[1]
	if app.Name != "app" || app.Host.Address != "10.0.0.10" || app.Host.Port != 22 {
		t.Errorf("unexpected app host: %#v", app)
	}
	if app.Node.ProxyJump != "jump" {
		t.Errorf("app ProxyJump = %q, want %q", app.Node.ProxyJump, "jump")
	}
	if len(app.Node.Tags) != 1 || app.Node.Tags[0] != "openssh" {
		t.Errorf("app tags = %v, want [openssh]", app.Node.Tags)
	}
}

func TestParseOpenSSHHosts_InvalidPort(t *testing.T) {
	t.Parallel()

	_, err := ParseOpenSSHHosts(strings.NewReader("Host broken\n  Port invalid\n"), "user")
	if err == nil {
		t.Fatal("ParseOpenSSHHosts() error = nil, want invalid port error")
	}
}

func TestParseOpenSSHHosts_ControlConfig(t *testing.T) {
	t.Parallel()

	const input = `
Host app
    HostName 10.0.0.10
    User deploy

Host custom
    HostName 10.0.0.20
    ControlMaster yes
    ControlPath /tmp/custom.sock
    ControlPersist 0

Host disabled
    HostName 10.0.0.30
    ControlPath none

Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 10m
`

	hosts, err := ParseOpenSSHHosts(strings.NewReader(input), "local-user")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts() error = %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(hosts))
	}

	// 1. app inherits wildcard control options
	app := hosts[0]
	if app.Name != "app" {
		t.Fatalf("expected first host to be 'app', got %s", app.Name)
	}
	if app.Node.Control == nil {
		t.Fatal("expected app.Node.Control to be non-nil")
	}
	if app.Node.Control.Master != "auto" ||
		app.Node.Control.Path != "~/.ssh/sockets/%r@%h-%p" ||
		app.Node.Control.Persist != "10m" {
		t.Fatalf("app control mismatch: %+v", app.Node.Control)
	}

	// 2. custom has explicit control options
	custom := hosts[1]
	if custom.Name != "custom" {
		t.Fatalf("expected second host to be 'custom', got %s", custom.Name)
	}
	if custom.Node.Control == nil {
		t.Fatal("expected custom.Node.Control to be non-nil")
	}
	if custom.Node.Control.Master != "yes" ||
		custom.Node.Control.Path != "/tmp/custom.sock" ||
		custom.Node.Control.Persist != "0" {
		t.Fatalf("custom control mismatch: %+v", custom.Node.Control)
	}

	// 3. disabled overrides path to none
	disabled := hosts[2]
	if disabled.Name != "disabled" {
		t.Fatalf("expected third host to be 'disabled', got %s", disabled.Name)
	}
	if disabled.Node.Control == nil {
		t.Fatal("expected disabled.Node.Control to be non-nil")
	}
	if disabled.Node.Control.Path != "none" {
		t.Fatalf("disabled control mismatch: %+v", disabled.Node.Control)
	}
	if disabled.Node.Control.IsEnabled() {
		t.Fatal("disabled control should have IsEnabled() == false")
	}
}

func TestParseOpenSSHHosts_InvalidControl(t *testing.T) {
	t.Parallel()

	// 1. Invalid ControlMaster
	_, err := ParseOpenSSHHosts(strings.NewReader("Host bad\n  ControlMaster unknown_mode\n"), "user")
	if err == nil || !strings.Contains(err.Error(), "invalid ControlMaster") {
		t.Fatalf("expected invalid ControlMaster error, got: %v", err)
	}

	// 2. Invalid ControlPersist
	_, err = ParseOpenSSHHosts(strings.NewReader("Host bad\n  ControlPersist 10invalid\n"), "user")
	if err == nil || !strings.Contains(err.Error(), "invalid ControlPersist") {
		t.Fatalf("expected invalid ControlPersist error, got: %v", err)
	}
}
