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

func TestClearRules(t *testing.T) {
	t.Run("ufw", testUfwClear)
	t.Run("firewalld", testFirewalldClear)
	t.Run("nftables", testNftablesClear)
	t.Run("iptables", testIptablesClear)
}

func testUfwClear(t *testing.T) {
	exec := newMockExecutor()
	exec.responses["ufw status numbered"] = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 80/tcp                     ALLOW IN    Anywhere
[ 2] http                       ALLOW IN    Anywhere
[ 3] 22/tcp                     ALLOW IN    192.168.1.100
[ 4] 8080                       ALLOW IN    Anywhere
`
	exec.responses["ufw --force delete 1"] = "Deleted"
	exec.responses["ufw --force delete 4"] = "Deleted"
	exec.responses["ufw --force delete 2"] = "Deleted"
	exec.responses["ufw --force delete 3"] = "Deleted"

	b := NewUfwBackend(exec)

	_, err := b.ClearPorts(context.Background())
	if err != nil {
		t.Fatalf("ClearPorts err: %v", err)
	}
	if exec.lastCmd != "ufw --force delete 1" {
		t.Errorf("ClearPorts expected last cmd 'ufw --force delete 1', got: %s", exec.lastCmd)
	}

	_, err = b.ClearServices(context.Background())
	if err != nil {
		t.Fatalf("ClearServices err: %v", err)
	}
	if exec.lastCmd != "ufw --force delete 2" {
		t.Errorf("ClearServices expected last cmd 'ufw --force delete 2', got: %s", exec.lastCmd)
	}

	_, err = b.ClearRules(context.Background())
	if err != nil {
		t.Fatalf("ClearRules err: %v", err)
	}
	if exec.lastCmd != "ufw --force delete 3" {
		t.Errorf("ClearRules expected last cmd 'ufw --force delete 3', got: %s", exec.lastCmd)
	}
}

func testFirewalldClear(t *testing.T) {
	exec := newMockExecutor()
	exec.responses["firewall-cmd --zone=public --list-ports"] = "80/tcp 8080/udp"
	exec.responses["firewall-cmd --zone=public --list-services"] = "ssh http https"
	exec.responses["firewall-cmd --zone=public --list-rich-rules"] = "rule family=\"ipv4\" source address=\"192.168.1.100\" accept\nrule family=\"ipv4\" source address=\"10.0.0.1\" drop"

	exec.responses["firewall-cmd --permanent --zone=public --remove-port=80/tcp"] = "success"
	exec.responses["firewall-cmd --permanent --zone=public --remove-port=8080/udp"] = "success"
	exec.responses["firewall-cmd --permanent --zone=public --remove-service=http"] = "success"
	exec.responses["firewall-cmd --permanent --zone=public --remove-service=https"] = "success"
	exec.responses["firewall-cmd --permanent --zone=public --remove-rich-rule='rule family=\"ipv4\" source address=\"192.168.1.100\" accept'"] = "success"
	exec.responses["firewall-cmd --permanent --zone=public --remove-rich-rule='rule family=\"ipv4\" source address=\"10.0.0.1\" drop'"] = "success"

	b := NewFirewalldBackend(exec, "public")

	_, err := b.ClearPorts(context.Background())
	if err != nil {
		t.Fatalf("ClearPorts err: %v", err)
	}
	if exec.lastCmd != "firewall-cmd --permanent --zone=public --remove-port=8080/udp" {
		t.Errorf("ClearPorts expected last cmd, got: %s", exec.lastCmd)
	}

	_, err = b.ClearServices(context.Background())
	if err != nil {
		t.Fatalf("ClearServices err: %v", err)
	}
	if exec.lastCmd != "firewall-cmd --permanent --zone=public --remove-service=https" {
		t.Errorf("ClearServices expected last cmd, got: %s", exec.lastCmd)
	}

	_, err = b.ClearRules(context.Background())
	if err != nil {
		t.Fatalf("ClearRules err: %v", err)
	}
	expected := "firewall-cmd --permanent --zone=public --remove-rich-rule='rule family=\"ipv4\" source address=\"10.0.0.1\" drop'"
	if exec.lastCmd != expected {
		t.Errorf("ClearRules expected last cmd '%s', got: '%s'", expected, exec.lastCmd)
	}
}

func testNftablesClear(t *testing.T) {
	exec := newMockExecutor()
	exec.responses["nft -a list chain inet filter input"] = `table inet filter {
    chain input {
        type filter hook input priority filter; policy accept;
        ip saddr 192.168.1.100 tcp dport 22 accept # handle 4
        tcp dport 80 accept # handle 5
    }
}`
	exec.responses["nft delete rule inet filter input handle 5"] = "success"
	exec.responses["nft delete rule inet filter input handle 4"] = "success"

	b := NewNftablesBackend(exec)

	_, err := b.ClearPorts(context.Background())
	if err != nil {
		t.Fatalf("ClearPorts err: %v", err)
	}
	if exec.lastCmd != "nft delete rule inet filter input handle 5" {
		t.Errorf("ClearPorts expected last cmd, got: %s", exec.lastCmd)
	}

	_, err = b.ClearRules(context.Background())
	if err != nil {
		t.Fatalf("ClearRules err: %v", err)
	}
	if exec.lastCmd != "nft delete rule inet filter input handle 4" {
		t.Errorf("ClearRules expected last cmd, got: %s", exec.lastCmd)
	}
}

func testIptablesClear(t *testing.T) {
	exec := newMockExecutor()
	exec.responses["iptables -L INPUT --line-numbers -n"] = `Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  192.168.1.100        0.0.0.0/0            tcp dpt:22
2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80
3    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:http
`
	exec.responses["iptables -D INPUT 2"] = "success"
	exec.responses["iptables -D INPUT 3"] = "success"
	exec.responses["iptables -D INPUT 1"] = "success"

	b := NewIptablesBackend(exec)

	_, err := b.ClearPorts(context.Background())
	if err != nil {
		t.Fatalf("ClearPorts err: %v", err)
	}
	if exec.lastCmd != "iptables -D INPUT 2" {
		t.Errorf("ClearPorts expected last cmd, got: %s", exec.lastCmd)
	}

	_, err = b.ClearServices(context.Background())
	if err != nil {
		t.Fatalf("ClearServices err: %v", err)
	}
	if exec.lastCmd != "iptables -D INPUT 3" {
		t.Errorf("ClearServices expected last cmd, got: %s", exec.lastCmd)
	}

	_, err = b.ClearRules(context.Background())
	if err != nil {
		t.Fatalf("ClearRules err: %v", err)
	}
	if exec.lastCmd != "iptables -D INPUT 1" {
		t.Errorf("ClearRules expected last cmd, got: %s", exec.lastCmd)
	}
}
