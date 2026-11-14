//go:build !windows

package sshenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	content := "# comment\nsearch example.com\nnameserver 192.0.2.53\nnameserver fe80::1%eth0\nnameserver not-an-ip\noptions edns0 trust-ad\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := parseResolvConf(path)
	if len(cfg.servers) != 2 || cfg.servers[0] != "192.0.2.53:53" || cfg.servers[1] != "[fe80::1%eth0]:53" {
		t.Fatalf("parseResolvConf servers = %v", cfg.servers)
	}
	if !cfg.trustAD {
		t.Fatal("expected trustAD=true when 'options edns0 trust-ad' is present")
	}

	noTrustPath := filepath.Join(dir, "resolv-no-trust.conf")
	noTrustContent := "nameserver 192.0.2.53\noptions edns0 # trust-ad\n; options trust-ad\n"
	if err := os.WriteFile(noTrustPath, []byte(noTrustContent), 0o600); err != nil {
		t.Fatal(err)
	}
	noTrustCfg := parseResolvConf(noTrustPath)
	if noTrustCfg.trustAD {
		t.Fatal("commented-out trust-ad must not set trustAD=true")
	}

	missingCfg := parseResolvConf(filepath.Join(dir, "missing"))
	if len(missingCfg.servers) != 1 || missingCfg.servers[0] != "127.0.0.1:53" || missingCfg.trustAD {
		t.Fatalf("missing resolv.conf fallback = %+v", missingCfg)
	}
}
