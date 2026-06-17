package firewall

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestUfwBuildRuleCmd_AllowPort(t *testing.T) {
	exec := newMockExecutor()
	b := NewUfwBackend(exec)
	rule := Rule{Port: "80", Action: ActionAllow, Protocol: ProtocolAny}
	cmd := b.buildRuleCmd(rule, false)

	if !strings.Contains(cmd, "allow") {
		t.Errorf("expected 'allow', got: %s", cmd)
	}
	if !strings.Contains(cmd, "to any port 80") {
		t.Errorf("expected 'to any port 80', got: %s", cmd)
	}
	// protocol=any 不应追加 proto
	if strings.Contains(cmd, "proto") {
		t.Errorf("protocol=any should not add proto, got: %s", cmd)
	}
}

func TestUfwBuildRuleCmd_DenyWithSource(t *testing.T) {
	exec := newMockExecutor()
	b := NewUfwBackend(exec)
	rule := Rule{
		Port:     "22",
		Action:   ActionDeny,
		Protocol: ProtocolTCP,
		Source:   "10.0.0.0/8",
	}
	cmd := b.buildRuleCmd(rule, false)

	if !strings.Contains(cmd, "deny") {
		t.Errorf("expected 'deny', got: %s", cmd)
	}
	if !strings.Contains(cmd, "from 10.0.0.0/8") {
		t.Errorf("expected source, got: %s", cmd)
	}
	if !strings.Contains(cmd, "to any port 22") {
		t.Errorf("expected port 22, got: %s", cmd)
	}
	if !strings.Contains(cmd, "proto tcp") {
		t.Errorf("expected proto tcp, got: %s", cmd)
	}
}

func TestUfwBuildRuleCmd_AllowService(t *testing.T) {
	exec := newMockExecutor()
	b := NewUfwBackend(exec)
	rule := Rule{Service: "http", Action: ActionAllow}
	cmd := b.buildRuleCmd(rule, false)

	if !strings.Contains(cmd, "allow") {
		t.Errorf("expected 'allow', got: %s", cmd)
	}
	if !strings.Contains(cmd, "http") {
		t.Errorf("expected service name 'http', got: %s", cmd)
	}
}

func TestUfwBuildRuleCmd_WithProtocol(t *testing.T) {
	exec := newMockExecutor()
	b := NewUfwBackend(exec)
	rule := Rule{Port: "443", Action: ActionAllow, Protocol: ProtocolTCP}
	cmd := b.buildRuleCmd(rule, false)

	if !strings.Contains(cmd, "proto tcp") {
		t.Errorf("expected 'proto tcp', got: %s", cmd)
	}
}

func TestUfwBuildRuleCmd_Delete(t *testing.T) {
	exec := newMockExecutor()
	b := NewUfwBackend(exec)
	rule := Rule{Port: "80", Action: ActionAllow}
	cmd := b.buildRuleCmd(rule, true)

	if !strings.Contains(cmd, "delete") {
		t.Errorf("expected 'delete', got: %s", cmd)
	}
}

func TestUfwName(t *testing.T) {
	exec := newMockExecutor()
	b := NewUfwBackend(exec)
	if b.Name() != "ufw" {
		t.Errorf("Name() = %q, want 'ufw'", b.Name())
	}
}

// --- Firewalld Rule Args ---

func TestFirewalldBuildRuleArgs_AddPort(t *testing.T) {
	exec := newMockExecutor()
	b := NewFirewalldBackend(exec, "")
	rule := Rule{Port: "80", Action: ActionAllow, Protocol: ProtocolTCP}
	args := b.buildRuleArgs(rule, false)

	if args != "--add-port=80/tcp" {
		t.Errorf("got %q, want '--add-port=80/tcp'", args)
	}
}

func TestFirewalldBuildRuleArgs_RemoveService(t *testing.T) {
	exec := newMockExecutor()
	b := NewFirewalldBackend(exec, "")
	rule := Rule{Service: "http", Action: ActionAllow}
	args := b.buildRuleArgs(rule, true)

	if args != "--remove-service=http" {
		t.Errorf("got %q, want '--remove-service=http'", args)
	}
}

func TestFirewalldBuildRuleArgs_RichRuleWithSource(t *testing.T) {
	exec := newMockExecutor()
	b := NewFirewalldBackend(exec, "")
	rule := Rule{
		Port:     "22",
		Action:   ActionDeny,
		Protocol: ProtocolTCP,
		Source:   "192.168.1.0/24",
	}
	args := b.buildRuleArgs(rule, false)

	if !strings.Contains(args, "--add-rich-rule") {
		t.Errorf("source rule should use rich-rule, got: %s", args)
	}
	if !strings.Contains(args, "source address='192.168.1.0/24'") {
		t.Errorf("expected source address, got: %s", args)
	}
	if !strings.Contains(args, "drop") {
		t.Errorf("ActionDeny should map to 'drop', got: %s", args)
	}
}

func TestFirewalldBuildRuleArgs_IPv6(t *testing.T) {
	exec := newMockExecutor()
	b := NewFirewalldBackend(exec, "")
	rule := Rule{
		Port:   "80",
		Action: ActionAllow,
		Source: "::1",
	}
	args := b.buildRuleArgs(rule, false)

	if !strings.Contains(args, "family='ipv6'") {
		t.Errorf("IPv6 source should use family='ipv6', got: %s", args)
	}
}

func TestFirewalldDefaultZone(t *testing.T) {
	exec := newMockExecutor()
	b := NewFirewalldBackend(exec, "")
	if b.zone != "public" {
		t.Errorf("default zone = %q, want 'public'", b.zone)
	}
}

// --- Iptables Rule Cmd ---

func TestIptablesBuildRuleCmd_AddAccept(t *testing.T) {
	exec := newMockExecutor()
	b := NewIptablesBackend(exec)
	rule := Rule{Port: "80", Action: ActionAllow, Protocol: ProtocolTCP}
	cmd := b.buildRuleCmd(rule, "-A")

	expected := "iptables -A INPUT -p tcp --dport 80 -j ACCEPT"
	if cmd != expected {
		t.Errorf("got %q, want %q", cmd, expected)
	}
}

func TestIptablesBuildRuleCmd_DeleteDrop(t *testing.T) {
	exec := newMockExecutor()
	b := NewIptablesBackend(exec)
	rule := Rule{Port: "22", Action: ActionDrop, Protocol: ProtocolTCP, Source: "10.0.0.0/8"}
	cmd := b.buildRuleCmd(rule, "-D")

	if !strings.Contains(cmd, "-D INPUT") {
		t.Errorf("expected -D INPUT, got: %s", cmd)
	}
	if !strings.Contains(cmd, "-s 10.0.0.0/8") {
		t.Errorf("expected source, got: %s", cmd)
	}
	if !strings.Contains(cmd, "-j DROP") {
		t.Errorf("expected -j DROP, got: %s", cmd)
	}
}

// --- Backend Name ---

func TestBackendNames(t *testing.T) {
	exec := newMockExecutor()
	tests := []struct {
		name    string
		backend Firewall
	}{
		{"ufw", NewUfwBackend(exec)},
		{"firewalld", NewFirewalldBackend(exec, "")},
		{"iptables", NewIptablesBackend(exec)},
		{"nftables", NewNftablesBackend(exec)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.backend.Name(); got != tt.name {
				t.Errorf("Name() = %q, want %q", got, tt.name)
			}
		})
	}
}

// --- BackendError ---

func TestBackendError(t *testing.T) {
	err := &BackendError{Backend: "ufw", Err: fmt.Errorf("timeout")}
	expected := "[ufw] firewall error: timeout"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestIsOpen(t *testing.T) {
	t.Run("ufw", testUfwIsOpen)
	t.Run("firewalld", testFirewalldIsOpen)
	t.Run("nftables", testNftablesIsOpen)
	t.Run("iptables", testIptablesIsOpen)
}

func testUfwIsOpen(t *testing.T) {
	exec := newMockExecutor()
	exec.responses["ufw status"] = "Status: active\nTo                         Action      From\n--"
	b := NewUfwBackend(exec)
	open, err := b.IsOpen(context.Background())
	if err != nil || !open {
		t.Errorf("UFW expected open, got open=%v, err=%v", open, err)
	}

	exec.responses["ufw status"] = "Status: inactive"
	open, err = b.IsOpen(context.Background())
	if err != nil || open {
		t.Errorf("UFW expected closed, got open=%v, err=%v", open, err)
	}
}

func testFirewalldIsOpen(t *testing.T) {
	exec := newMockExecutor()
	exec.responses["firewall-cmd --state"] = "running\n"
	b := NewFirewalldBackend(exec, "")
	open, err := b.IsOpen(context.Background())
	if err != nil || !open {
		t.Errorf("Firewalld expected open, got open=%v, err=%v", open, err)
	}

	exec.errors["firewall-cmd --state"] = fmt.Errorf("command failed: exit status 2, output: not running\n")
	exec.responses["firewall-cmd --state"] = "not running\n"
	open, err = b.IsOpen(context.Background())
	if err != nil || open {
		t.Errorf("Firewalld expected closed, got open=%v, err=%v", open, err)
	}
}

func testNftablesIsOpen(t *testing.T) {
	exec := newMockExecutor()
	exec.responses["systemctl is-active nftables"] = "active\n"
	b := NewNftablesBackend(exec)
	open, err := b.IsOpen(context.Background())
	if err != nil || !open {
		t.Errorf("Nftables expected open, got open=%v, err=%v", open, err)
	}

	exec.errors["systemctl is-active nftables"] = fmt.Errorf("command failed: exit status 3, output: inactive\n")
	exec.responses["systemctl is-active nftables"] = "inactive\n"
	open, err = b.IsOpen(context.Background())
	if err != nil || open {
		t.Errorf("Nftables expected closed, got open=%v, err=%v", open, err)
	}
}

func testIptablesIsOpen(t *testing.T) {
	exec := newMockExecutor()
	exec.responses["iptables -L -n"] = "Chain INPUT (policy ACCEPT)"
	b := NewIptablesBackend(exec)
	open, err := b.IsOpen(context.Background())
	if err != nil || !open {
		t.Errorf("Iptables expected open, got open=%v, err=%v", open, err)
	}

	exec.errors["iptables -L -n"] = fmt.Errorf("permission denied")
	_, err = b.IsOpen(context.Background())
	if err == nil {
		t.Errorf("Iptables expected error, got nil")
	}
}
