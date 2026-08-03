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
