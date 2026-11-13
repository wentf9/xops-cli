package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithOpenSSHConfigOverride(t *testing.T) {
	baseParser, err := NewOpenSSHParserFromReader(strings.NewReader(`
Host base-only
  HostName 10.0.0.1
  User baseuser
`))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	baseCfg := &Configuration{}
	base := NewProviderWithOpenSSHParser(baseCfg, baseParser)

	t.Run("empty path returns base unchanged", func(t *testing.T) {
		got, err := WithOpenSSHConfigOverride(base, "")
		if err != nil {
			t.Fatalf("WithOpenSSHConfigOverride(\"\") error = %v", err)
		}
		if got != base {
			t.Fatalf("expected base provider returned unchanged")
		}
	})

	t.Run("none skips openssh config", func(t *testing.T) {
		for _, val := range []string{"none", "NONE", " None "} {
			got, err := WithOpenSSHConfigOverride(base, val)
			if err != nil {
				t.Fatalf("WithOpenSSHConfigOverride(%q) error = %v", val, err)
			}
			if got == base {
				t.Fatalf("expected new read-only provider for %q", val)
			}
			if id := got.Find("base-only"); id != "" {
				t.Fatalf("expected base-only to be skipped with -F %q, got %q", val, id)
			}
		}
	})

	t.Run("explicit path loads custom config without mutating base", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "custom_ssh_config")
		content := "Host custom-alias\n  HostName 192.168.10.20\n  User customuser\n  Port 2222\n"
		if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
			t.Fatalf("write temp config: %v", err)
		}

		got, err := WithOpenSSHConfigOverride(base, cfgPath)
		if err != nil {
			t.Fatalf("WithOpenSSHConfigOverride(%q) error = %v", cfgPath, err)
		}
		nodeID := got.Find("custom-alias")
		if nodeID != OpenSSHNodePrefix+"custom-alias" {
			t.Fatalf("Find(custom-alias) = %q, want %q", nodeID, OpenSSHNodePrefix+"custom-alias")
		}
		_, host, ident, err := got.Resolve(nodeID)
		if err != nil {
			t.Fatalf("Resolve(%q) error = %v", nodeID, err)
		}
		if host.Address != "192.168.10.20" || host.Port != 2222 || ident.User != "customuser" {
			t.Fatalf("unexpected resolved target: host=%+v ident=%+v", host, ident)
		}
		if got.(openSSHParserSource).GetOpenSSHParser().HasHost("base-only") {
			t.Fatalf("expected base-only not to be present when overridden by custom config")
		}
		if !base.GetOpenSSHParser().HasHost("base-only") {
			t.Fatalf("expected base provider to remain unmutated")
		}
	})

	t.Run("missing file returns explicit error", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		if _, err := WithOpenSSHConfigOverride(base, missing); err == nil {
			t.Fatalf("expected explicit error for missing config file %q", missing)
		}
	})

	t.Run("directory path returns explicit error", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := WithOpenSSHConfigOverride(base, dir); err == nil {
			t.Fatalf("expected explicit error for directory path %q", dir)
		}
	})
}
