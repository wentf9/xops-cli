package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestResolveTarget_IPv6LiteralsAndVirtualNodes(t *testing.T) {
	sshCfg := `
Host v6-bracketed
    HostName [::1]
    User ops
    Port 34522

Host v6-percent-h
    HostName [%h]
    User ops
    Port 2222
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	store := NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := NewRepositoryWithOpenSSHParser(&Configuration{}, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser failed: %v", err)
	}

	// 1. ssh_config HostName [::1] normalizes Address to unbracketed "::1" and HostRef to "[::1]:34522".
	node, host, ident, err := parser.GetVirtualNode("v6-bracketed")
	if err != nil {
		t.Fatalf("GetVirtualNode(v6-bracketed) failed: %v", err)
	}
	if host.Address != "::1" || host.Port != 34522 || ident.User != "ops" {
		t.Fatalf("unexpected virtual host/identity: host=%+v ident=%+v", host, ident)
	}
	if node.HostRef != "[::1]:34522" {
		t.Fatalf("node.HostRef = %q, want %q", node.HostRef, "[::1]:34522")
	}

	// 2. HostName [%h] expands %h and strips brackets cleanly.
	_, pctHost, _, err := parser.GetVirtualNode("::1")
	if err == nil && pctHost.Address != "::1" {
		t.Fatalf("pctHost.Address = %q, want ::1", pctHost.Address)
	}
	_, pctAliasHost, _, err := parser.GetVirtualNode("v6-percent-h")
	if err != nil {
		t.Fatalf("GetVirtualNode(v6-percent-h) failed: %v", err)
	}
	if pctAliasHost.Address != "v6-percent-h" {
		t.Fatalf("pctAliasHost.Address = %q, want %q", pctAliasHost.Address, "v6-percent-h")
	}

	// 3. Ad-hoc IPv6 targets resolve to unbracketed Host "::1" and bracketed FormatNodeID.
	cases := []struct {
		name     string
		target   ConnectionTarget
		wantUser string
		wantPort uint16
		wantID   string
	}{
		{
			name:     "user_bracketed_ipv6",
			target:   ConnectionTarget{Selector: "::1", RawSelector: "ops@[::1]", User: "ops", HasUser: true},
			wantUser: "ops",
			wantPort: 22,
			wantID:   "ops@[::1]:22",
		},
		{
			name:     "user_bracketed_ipv6_port",
			target:   ConnectionTarget{Selector: "::1", RawSelector: "ops@[::1]:34522", User: "ops", HasUser: true, Port: 34522, HasPort: true},
			wantUser: "ops",
			wantPort: 34522,
			wantID:   "ops@[::1]:34522",
		},
		{
			name:     "flag_port_unbracketed_ipv6",
			target:   ConnectionTarget{Selector: "::1", RawSelector: "ops@::1", User: "ops", HasUser: true, Port: 34522, HasPort: true},
			wantUser: "ops",
			wantPort: 34522,
			wantID:   "ops@[::1]:34522",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ResolveTarget(repo, tc.target)
			if err != nil {
				t.Fatalf("ResolveTarget failed: %v", err)
			}
			if res.Host != "::1" || res.User != tc.wantUser || res.Port != tc.wantPort || res.NodeID != tc.wantID {
				t.Fatalf("ResolveTarget = %+v, want Host=::1 User=%s Port=%d NodeID=%s", res, tc.wantUser, tc.wantPort, tc.wantID)
			}
		})
	}

	// 4. Existing IPv4 FormatNodeID behavior remains unchanged.
	if got := FormatNodeID("root", "10.0.0.5", 22); got != "root@10.0.0.5:22" {
		t.Fatalf("FormatNodeID IPv4 = %q, want root@10.0.0.5:22", got)
	}
}

func TestOpenSSHOverrideProvider_ConfirmNodeWithExecutionContextNoOp(t *testing.T) {
	dir := t.TempDir()
	sshCfgPath := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(sshCfgPath, []byte("Host demo\n  HostName 127.0.0.1\n  User ops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "key"))
	repo, err := NewRepositoryWithoutOpenSSH(&Configuration{}, store)
	if err != nil {
		t.Fatal(err)
	}
	override, err := WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride failed: %v", err)
	}
	preparer, ok := override.(interface {
		PrepareNodeContext(ctx interface{ Done() <-chan struct{} }, opts EnsureNodeOptions) (EnsureNodeResult, error)
	})
	_ = preparer
	_ = ok

	confirmer, ok := override.(interface {
		ConfirmNodeWithExecutionContext(ctx interface{}, nodeID string, exec *ssh.ExecutionConfig) error
	})
	_ = confirmer
	_ = ok

	probeRepo, ok := override.(*openSSHOverrideProvider)
	if !ok {
		t.Fatalf("expected *openSSHOverrideProvider, got %T", override)
	}
	prepared, err := probeRepo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "127.0.0.1", User: "ops", HasUser: true, Port: 2222, HasPort: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext failed: %v", err)
	}
	execCfg := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterSh}
	if err := probeRepo.ConfirmNodeWithExecutionContext(t.Context(), prepared.NodeID, execCfg); err != nil {
		t.Fatalf("ConfirmNodeWithExecutionContext returned error on -F override provider: %v", err)
	}
	if repo.Snapshot().Nodes.Count() != 0 {
		t.Fatalf("expected base repository to remain untouched under -F, got %d nodes", repo.Snapshot().Nodes.Count())
	}
}
