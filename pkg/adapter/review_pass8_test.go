package adapter

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestPass8_H3_DisambiguatedPendingAliasPreservesAllTier4ClassesAndGuardrails(t *testing.T) {
	dir := t.TempDir()
	keyA := filepath.Join(dir, "id_a")
	keyB1 := filepath.Join(dir, "id_b1")
	keyB2 := filepath.Join(dir, "id_b2")
	for _, p := range []string{keyA, keyB1, keyB2} {
		if err := os.WriteFile(p, []byte("dummy"), 0o600); err != nil {
			t.Fatalf("write key %s: %v", p, err)
		}
	}

	sshCfgPath := filepath.Join(dir, "ssh_config")
	sshCfg := strings.Join([]string{
		"Host role-a",
		"  HostName 10.0.0.5",
		"  Port 22",
		"  User reader",
		"  IdentityFile " + keyA,
		"",
		"Host role-b",
		"  HostName 10.0.0.5",
		"  Port 22",
		"  User writer",
		"  IdentityFile " + keyB1,
		"  IdentityFile " + keyB2,
		"  SendEnv LC_ALL",
		"  SetEnv APP_ROLE=b",
		"  LocalForward 18080 127.0.0.1:80",
		"  ProxyCommand nc %h %p",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	store := config.NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "xops.key"))
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	provider, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}

	if err := config.WithPendingNode(t.Context(), provider, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "role-a", User: "ops", HasUser: true},
	}, func(config.PendingLease) error {
		return config.WithPendingNode(t.Context(), provider, config.EnsureNodeOptions{
			Target: config.ConnectionTarget{Selector: "role-b", User: "ops", HasUser: true},
		}, func(leaseB config.PendingLease) error {
			resBID := leaseB.NodeID()
			if resBID != "openssh:ops@role-b:22" {
				t.Fatalf("resB.NodeID = %q, want openssh:ops@role-b:22", resBID)
			}

			restrictedAdp := NewSSHAdapter(provider, WithLocalExecution(false))
			if _, err := restrictedAdp.GetConfig(resBID); !errors.Is(err, ErrLocalExecutionDisabled) {
				t.Fatalf("expected ErrLocalExecutionDisabled with ProxyCommand on pending alias, got %v", err)
			}

			adp := NewSSHAdapter(provider, WithLocalExecution(true), WithSessionAndForwardOptions(true))
			clientCfg, err := adp.GetConfig(resBID)
			if err != nil {
				t.Fatalf("GetConfig(%q) error = %v", resBID, err)
			}
			if clientCfg.Options == nil {
				t.Fatal("expected non-nil clientCfg.Options")
			}
			if got := clientCfg.Options.ActiveProxyCommand(); got != "nc %h %p" {
				t.Errorf("ActiveProxyCommand = %q, want %q", got, "nc %h %p")
			}
			idFiles := clientCfg.Options.GetAll(ssh.OptionIdentityFile)
			if !slices.Contains(idFiles, keyB1) || !slices.Contains(idFiles, keyB2) {
				t.Errorf("IdentityFile list = %v, want both %s and %s", idFiles, keyB1, keyB2)
			}
			if !slices.Contains(clientCfg.Options.SendEnvPatterns(), "LC_ALL") {
				t.Errorf("SendEnvPatterns = %v, want LC_ALL", clientCfg.Options.SendEnvPatterns())
			}
			if !slices.Contains(clientCfg.Options.SetEnvDirectives(), "APP_ROLE=b") {
				t.Errorf("SetEnvDirectives = %v, want APP_ROLE=b", clientCfg.Options.SetEnvDirectives())
			}
			if lf := clientCfg.Options.LocalForwards(); len(lf) != 1 || !strings.Contains(lf[0], "18080") {
				t.Errorf("LocalForwards = %v, want 18080 127.0.0.1:80", lf)
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
}

func TestPass8_H4_ParseSessionOptionsFirstWinsAndProxyOrdering(t *testing.T) {
	verifyPass8ParseSessionOptionsFirstWins(t)
	verifyPass8ParseSessionOptionsProxyOrdering(t)
}

func verifyPass8ParseSessionOptionsFirstWins(t *testing.T) {
	t.Helper()
	parsed, err := ParseSessionOptions([]string{
		"StrictHostKeyChecking=yes",
		"StrictHostKeyChecking=no",
		"ControlMaster=yes",
		"ControlMaster=no",
		"ControlPath=/tmp/first-%C",
		"ControlPath=/tmp/second-%C",
		"ControlPersist=10m",
		"ControlPersist=no",
		"ConnectTimeout=5",
		"ConnectTimeout=20",
		"SetEnv=FOO=1",
		"SetEnv=BAR=2",
		"IdentityFile=/tmp/k1",
		"IdentityFile=/tmp/k2",
		"SendEnv=LC_ALL",
		"SendEnv=LANG",
	}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions failed: %v", err)
	}
	if parsed.Master == nil || *parsed.Master != ssh.ControlMasterYes {
		t.Errorf("ControlMaster = %v, want yes", parsed.Master)
	}
	if parsed.Path == nil || *parsed.Path != "/tmp/first-%C" {
		t.Errorf("ControlPath = %v, want /tmp/first-%%C", parsed.Path)
	}
	if parsed.Persist == nil || *parsed.Persist != "10m" {
		t.Errorf("ControlPersist = %v, want 10m", parsed.Persist)
	}
	sshOpts := parsed.ToSSHOptions()
	if got := sshOpts.Get(ssh.OptionStrictHostKeyChecking); got != "yes" {
		t.Errorf("StrictHostKeyChecking = %q, want yes", got)
	}
	if got := sshOpts.Get(ssh.OptionConnectTimeout); got != "5" {
		t.Errorf("ConnectTimeout = %q, want 5", got)
	}
	if got := sshOpts.SetEnvDirectives(); len(got) != 1 || got[0] != "FOO=1" {
		t.Errorf("SetEnvDirectives = %v, want [FOO=1]", got)
	}
	if got := sshOpts.GetAll(ssh.OptionIdentityFile); len(got) != 2 || got[0] != "/tmp/k1" || got[1] != "/tmp/k2" {
		t.Errorf("IdentityFile = %v, want [/tmp/k1 /tmp/k2]", got)
	}
	if got := sshOpts.SendEnvPatterns(); len(got) != 2 || got[0] != "LC_ALL" || got[1] != "LANG" {
		t.Errorf("SendEnvPatterns = %v, want [LC_ALL LANG]", got)
	}

	for _, bad := range [][]string{
		{"ConnectTimeout=5", "ConnectTimeout=not-a-number"},
		{"SetEnv=FOO=1", "SetEnv=INVALID_TOKEN"},
		{"HostName=valid.example.com", "HostName="},
	} {
		if _, err := ParseSessionOptions(bad, ""); err == nil {
			t.Errorf("ParseSessionOptions(%v) expected validation error on subsequent entry, got nil", bad)
		}
	}
}

func verifyPass8ParseSessionOptionsProxyOrdering(t *testing.T) {
	t.Helper()
	cases := []struct {
		name      string
		opts      []string
		wantProxy string
	}{
		{
			name:      "ProxyJump_blocks_later_ProxyCommand",
			opts:      []string{"ProxyJump=j1", "ProxyCommand=nc %h %p"},
			wantProxy: "",
		},
		{
			name:      "ProxyJump_none_preserves_later_ProxyCommand",
			opts:      []string{"ProxyJump=none", "ProxyCommand=nc %h %p"},
			wantProxy: "nc %h %p",
		},
		{
			name:      "ProxyCommand_before_ProxyJump_wins",
			opts:      []string{"ProxyCommand=nc %h %p", "ProxyJump=j1"},
			wantProxy: "nc %h %p",
		},
		{
			name:      "ProxyCommand_none_wins_over_later_ProxyCommand",
			opts:      []string{"ProxyCommand=none", "ProxyCommand=nc %h %p"},
			wantProxy: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseSessionOptions(tc.opts, "")
			if err != nil {
				t.Fatalf("ParseSessionOptions(%v) failed: %v", tc.opts, err)
			}
			got := ""
			if s := p.ToSSHOptions(); s != nil {
				got = s.ActiveProxyCommand()
			}
			if got != tc.wantProxy {
				t.Errorf("ActiveProxyCommand = %q, want %q", got, tc.wantProxy)
			}
		})
	}
}
