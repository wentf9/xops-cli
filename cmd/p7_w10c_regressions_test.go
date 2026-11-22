package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

type w10cCountingCanonicalResolver struct {
	hosts   map[string][]string
	lookups int
}

func (r *w10cCountingCanonicalResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	r.lookups++
	if addrs, ok := r.hosts[host]; ok {
		return addrs, nil
	}
	return nil, errors.New("nxdomain")
}

func (r *w10cCountingCanonicalResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return host + ".", nil
}

func TestP7W10c_DE10M1_SiblingInheritedBadJumpNoCanonicalHijack(t *testing.T) {
	const sshCfg = `
Host saved-open
    HostName 10.130.0.10
    Port 2222
    User ops

Host saved-open.corp.example.com
    HostName 198.51.100.123
    User attacker

Host *
    CanonicalizeHostname always
    CanonicalDomains corp.example.com
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	makeProv := func(siblingJump string) config.ConfigProvider {
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("h-open", models.Host{Address: "10.130.0.10", Port: 2222})
		cfg.Hosts.Set("h-j1", models.Host{Address: "10.130.0.21", Port: 22, Alias: []string{"dup-jump"}})
		cfg.Hosts.Set("h-j2", models.Host{Address: "10.130.0.22", Port: 22, Alias: []string{"dup-jump"}})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("jump-1", models.Node{HostRef: "h-j1", IdentityRef: "id-ops"})
		cfg.Nodes.Set("jump-2", models.Node{HostRef: "h-j2", IdentityRef: "id-ops"})
		cfg.Nodes.Set("ops@10.130.0.10:2222", models.Node{
			HostRef:     "h-open",
			IdentityRef: "id-ops",
			ProxyJump:   siblingJump,
		})
		return config.NewProviderWithOpenSSHParser(cfg, parser)
	}

	for _, tc := range []struct {
		name        string
		siblingJump string
		checkErr    func(*testing.T, error)
	}{
		{
			name:        "sibling_ambiguous_dup_jump",
			siblingJump: "dup-jump",
			checkErr: func(t *testing.T, err error) {
				t.Helper()
				var ambigErr *config.AmbiguousNodeError
				if !errors.As(err, &ambigErr) {
					t.Fatalf("err = %v, want *config.AmbiguousNodeError", err)
				}
			},
		},
		{
			name:        "sibling_unknown_single_label_jump",
			siblingJump: "unknown-single-label",
			checkErr: func(t *testing.T, err error) {
				t.Helper()
				if err == nil {
					t.Fatal("expected fail-closed error for unknown-single-label sibling jump, got nil")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prov := makeProv(tc.siblingJump)
			resolver := &w10cCountingCanonicalResolver{
				hosts: map[string][]string{"saved-open.corp.example.com": {"198.51.100.123"}},
			}
			o := NewSshOptions()
			o.Host = "saved-open"
			o.User = "deploy"
			o.Port = 2222
			o.Target = config.ConnectionTarget{
				Selector: "saved-open",
				User:     "deploy",
				HasUser:  true,
				Port:     2222,
				HasPort:  true,
			}
			o.canonicalResolver = resolver

			err := o.applyHostnameCanonicalization(t.Context(), prov, resolver)
			tc.checkErr(t, err)
			if resolver.lookups != 0 || o.canonicalized || o.Target.Selector != "saved-open" {
				t.Fatalf("sibling %s hijacked canonicalization: lookups=%d canonicalized=%v selector=%q",
					tc.siblingJump, resolver.lookups, o.canonicalized, o.Target.Selector)
			}

			oCtl := *o
			oCtl.control.CtlCmd = "check"
			var stderr bytes.Buffer
			if cErr := canonicalizeControlOptions(t.Context(), &oCtl, prov, &stderr); cErr == nil {
				t.Fatalf("canonicalizeControlOptions(%s) succeeded, want fail-closed error", tc.siblingJump)
			}
			if resolver.lookups != 0 {
				t.Fatalf("canonicalizeControlOptions(%s) performed DNS lookups=%d", tc.siblingJump, resolver.lookups)
			}

			if ok, bgErr := o.probeTargetBackgroundSession(prov, adapter.SessionControlOptions{}, false, false); bgErr == nil || ok {
				t.Fatalf("probeTargetBackgroundSession(%s) = (%v, %v), want (false, error)", tc.siblingJump, ok, bgErr)
			}
		})
	}
}

func TestP7W10c_DE10L2_SSHParseTargetRejectsMalformedHostFlag(t *testing.T) {
	t.Parallel()

	malformed := []string{
		"host:99999",
		"[::1",
		"host:0",
		"@host",
		"user@",
		"bad\nhost",
	}
	for _, bad := range malformed {
		o := NewSshOptions()
		o.Host = bad
		if err := o.parseTarget(false); err == nil {
			t.Errorf("parseTarget(--host %q) unexpectedly succeeded (Target=%+v), want error", bad, o.Target)
		}
	}

	for _, tc := range []struct {
		raw      string
		wantHost string
		wantUser string
		wantPort uint16
	}{
		{"ops@10.0.0.10:2222", "10.0.0.10", "ops", 2222},
		{"[::1]", "::1", "", 0},
		{"Prod Web 01", "Prod Web 01", "", 0},
		{"openssh:web", "openssh:web", "", 0},
	} {
		o := NewSshOptions()
		o.Host = tc.raw
		if err := o.parseTarget(false); err != nil {
			t.Errorf("parseTarget(--host %q) failed: %v", tc.raw, err)
			continue
		}
		if o.Host != tc.wantHost || o.User != tc.wantUser || o.Port != tc.wantPort {
			t.Errorf("parseTarget(--host %q) = (Host=%q User=%q Port=%d), want (%q %q %d)",
				tc.raw, o.Host, o.User, o.Port, tc.wantHost, tc.wantUser, tc.wantPort)
		}
	}
}

func setupW10cBrokenOpenSSHConfigEnv(t *testing.T) *config.Configuration {
	t.Helper()
	homeDir := t.TempDir()
	cfgDir := filepath.Join(homeDir, ".xops")
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatalf("MkdirAll cfgDir: %v", err)
	}
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll sshDir: %v", err)
	}
	// Write a syntactically broken ~/.ssh/config (unclosed quote).
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte("Host broken\n  IdentityFile \"/unterminated\n"), 0o600); err != nil {
		t.Fatalf("WriteFile broken ssh config: %v", err)
	}

	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bg", models.Host{Address: "10.131.0.1", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	nodeOpts := &ssh.Options{}
	if err := nodeOpts.Set(ssh.OptionSessionType, string(ssh.SessionTypeNone)); err != nil {
		t.Fatalf("Set SessionType=none: %v", err)
	}
	cfg.Nodes.Set("saved-bg", models.Node{
		HostRef:     "h-bg",
		IdentityRef: "id-ops",
		SSHOptions:  nodeOpts,
	})
	configPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath: %v", err)
	}
	store := config.NewDefaultStore(configPath, keyPath)
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	return cfg
}

func assertW10cSSHBackgroundUnderBrokenOpenSSH(t *testing.T) {
	t.Helper()
	oSaved := NewSshOptions()
	oSaved.BgRun = true
	oSaved.Host = "saved-bg"
	if err := oSaved.Validate(); err != nil {
		t.Fatalf("Validate(ssh -f saved-bg) failed under unrelated broken ~/.ssh/config: %v", err)
	}

	for _, badHost := range []string{"openssh:broken", "unmatched.example.com"} {
		oBad := NewSshOptions()
		oBad.BgRun = true
		oBad.Host = badHost
		if err := oBad.Validate(); err == nil || !strings.Contains(err.Error(), "load openssh config") {
			t.Fatalf("Validate(ssh -f %s) err = %v, want fail-closed openssh config error", badHost, err)
		}
	}
}

func assertW10cMCPRecoverUnderBrokenOpenSSH(t *testing.T, cfg *config.Configuration) {
	t.Helper()
	prov := config.NewProviderWithBrokenOpenSSHFallback(cfg)
	if _, h, _, err := prov.Resolve("saved-bg"); err != nil || h.Address != "10.131.0.1" {
		t.Fatalf("NewProviderWithBrokenOpenSSHFallback.Resolve(saved-bg) = (%+v, %v), want 10.131.0.1", h, err)
	}
	if _, _, _, err := prov.Resolve("openssh:broken"); err == nil || !strings.Contains(err.Error(), "load openssh config") {
		t.Fatalf("NewProviderWithBrokenOpenSSHFallback.Resolve(openssh:broken) err = %v, want load openssh config error", err)
	}

	for _, flag := range []string{"--verify", "--cleanup"} {
		cmd := newCmdMCPRecover()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{flag, "--id", "tx-nonexistent"})
		err := cmd.ExecuteContext(t.Context())
		if err != nil && (strings.Contains(err.Error(), "openssh") || strings.Contains(err.Error(), "ssh config") || strings.Contains(err.Error(), "unterminated quote")) {
			t.Fatalf("mcp recover %s aborted on unrelated broken ~/.ssh/config: %v (output=%s)", flag, err, out.String())
		}
	}
}

func TestP7W10c_FG10L1_BrokenDefaultOpenSSHConfigPreservesSavedNodeBackgroundAndMCPRecover(t *testing.T) {
	cfg := setupW10cBrokenOpenSSHConfigEnv(t)

	t.Run("ssh_background_saved_node_succeeds_while_openssh_fails_closed", func(t *testing.T) {
		assertW10cSSHBackgroundUnderBrokenOpenSSH(t)
	})

	t.Run("mcp_recover_verify_and_cleanup_succeed_under_broken_default_ssh_config", func(t *testing.T) {
		assertW10cMCPRecoverUnderBrokenOpenSSH(t, cfg)
	})
}
