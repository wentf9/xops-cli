//go:build !windows

package sshenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	content := "# comment\nsearch example.com\nnameserver 192.0.2.53\nnameserver fe80::1%eth0\nnameserver not-an-ip\noptions edns0 trust-ad\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := parseResolvConf(path)
	if len(got) != 2 || got[0] != "192.0.2.53:53" || got[1] != "[fe80::1%eth0]:53" {
		t.Fatalf("parseResolvConf = %v", got)
	}
	if got := parseResolvConf(filepath.Join(t.TempDir(), "missing")); len(got) != 1 || got[0] != "127.0.0.1:53" {
		t.Fatalf("missing resolv.conf fallback = %v", got)
	}
}
