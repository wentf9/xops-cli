package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestOpenSSHParser_ProxyJumpVsProxyCommandFirstMatchWins(t *testing.T) {
	openSSH := `
Host app-jump
    HostName 10.0.0.10
    ProxyJump bastion

Host app-cmd
    HostName 10.0.0.11
    ProxyCommand ssh -W %h:%p jump

Host app-jump-none
    HostName 10.0.0.12
    ProxyJump none

Host app-cmd-none
    HostName 10.0.0.13
    ProxyCommand none

Host *
    ProxyJump fallback-bastion
    ProxyCommand fallback-nc %h %p
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}

	nodeJump, _, _, err := parser.GetVirtualNode("app-jump")
	if err != nil {
		t.Fatalf("GetNode(app-jump) error = %v", err)
	}
	if nodeJump.ProxyJump != OpenSSHNodePrefix+"bastion" {
		t.Fatalf("app-jump ProxyJump = %q, want %q", nodeJump.ProxyJump, OpenSSHNodePrefix+"bastion")
	}
	if nodeJump.SSHOptions != nil && nodeJump.SSHOptions.ActiveProxyCommand() != "" {
		t.Fatalf("app-jump should not inherit fallback ProxyCommand, got %q", nodeJump.SSHOptions.ActiveProxyCommand())
	}

	nodeCmd, _, _, err := parser.GetVirtualNode("app-cmd")
	if err != nil {
		t.Fatalf("GetNode(app-cmd) error = %v", err)
	}
	if nodeCmd.ProxyJump != "" {
		t.Fatalf("app-cmd should not inherit fallback ProxyJump, got %q", nodeCmd.ProxyJump)
	}
	if nodeCmd.SSHOptions == nil || nodeCmd.SSHOptions.ActiveProxyCommand() != "ssh -W %h:%p jump" {
		t.Fatalf("app-cmd ProxyCommand = %v, want %q", nodeCmd.SSHOptions, "ssh -W %h:%p jump")
	}

	nodeJumpNone, _, _, err := parser.GetVirtualNode("app-jump-none")
	if err != nil {
		t.Fatalf("GetNode(app-jump-none) error = %v", err)
	}
	if nodeJumpNone.ProxyJump != "" {
		t.Fatalf("app-jump-none ProxyJump = %q, want empty (stopped by ProxyJump none)", nodeJumpNone.ProxyJump)
	}

	nodeCmdNone, _, _, err := parser.GetVirtualNode("app-cmd-none")
	if err != nil {
		t.Fatalf("GetNode(app-cmd-none) error = %v", err)
	}
	if nodeCmdNone.SSHOptions != nil && nodeCmdNone.SSHOptions.ActiveProxyCommand() != "" {
		t.Fatalf("app-cmd-none ActiveProxyCommand = %q, want empty (stopped by ProxyCommand none)", nodeCmdNone.SSHOptions.ActiveProxyCommand())
	}
}

func TestOpenSSHImport_Gate3StripsLocalExecOptions(t *testing.T) {
	openSSH := `
Host imported-node
    HostName 10.0.0.20
    User ops
    ProxyCommand nc -X connect -x 127.0.0.1:1080 %h %p
    LocalCommand echo imported
    PermitLocalCommand yes
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "ssh_config")
	if err := os.WriteFile(cfgPath, []byte(openSSH), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	parser, err := NewOpenSSHParserFromPath(cfgPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath() error = %v", err)
	}
	node, _, _, err := parser.GetVirtualNode("imported-node")
	if err != nil {
		t.Fatalf("GetNode() error = %v", err)
	}
	if node.SSHOptions == nil || node.SSHOptions.ActiveProxyCommand() == "" {
		t.Fatalf("expected virtual node to parse ProxyCommand before import filtering")
	}

	sanitized := node.SSHOptions.Clone()
	sanitized.StripClasses(ssh.OptionClassLocalExec, ssh.OptionClassTrust, ssh.OptionClassForward, ssh.OptionClassSession, ssh.OptionClassAuth)
	if sanitized.Get(ssh.OptionProxyCommand) != "" || sanitized.Get(ssh.OptionLocalCommand) != "" || sanitized.Get(ssh.OptionPermitLocalCommand) != "" {
		t.Fatalf("Gate 3 violation: local_exec options survived strip: %+v", sanitized)
	}
}
