package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func requireSSHKeygenBinary(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skipf("ssh-keygen binary not found: %v", err)
	}
	return bin
}

func newDiffEd25519Key(t *testing.T) (cryptoSSH.Signer, cryptoSSH.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("cryptoSSH.NewSignerFromKey: %v", err)
	}
	return signer, signer.PublicKey()
}

func sshKeygenMatches(t *testing.T, keygenBin, khFile, query string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, keygenBin, "-F", query, "-f", khFile)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false
	}
	t.Fatalf("ssh-keygen -F %q -f %q failed unexpectedly (%v):\n%s", query, khFile, err, out)
	return false
}

func khDiffPutHostPort(host, port string) string {
	if port == "" || port == "22" {
		return host
	}
	return "[" + host + "]:" + port
}

func TestKnownHostsDifferentialOracle(t *testing.T) {
	keygenBin := requireSSHKeygenBinary(t)
	caSigner, hostKey := newDiffEd25519Key(t)
	_, revokedKey := newDiffEd25519Key(t)
	keyText := strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(hostKey)))
	revokedKeyText := strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(revokedKey)))

	t.Run("plain_wildcard_and_negation_parity", func(t *testing.T) {
		assertKnownHostsPlainWildcardParity(t, keygenBin, hostKey, keyText)
	})
	t.Run("hashed_entries_differential_parity", func(t *testing.T) {
		assertKnownHostsHashedParity(t, keygenBin, hostKey, keyText)
	})
	t.Run("uppercase_ipv6_hex_normalization", func(t *testing.T) {
		assertKnownHostsUppercaseIPv6(t, hostKey, keyText)
	})
	t.Run("cert_authority_and_revoked_markers", func(t *testing.T) {
		assertKnownHostsCARevokedMarkers(t, keygenBin, caSigner, hostKey, revokedKey, keyText, revokedKeyText)
	})
}

func assertKnownHostsPlainWildcardParity(t *testing.T, keygenBin string, hostKey cryptoSSH.PublicKey, keyText string) {
	t.Helper()
	patterns := []string{
		"app.corp", "[app.corp]:2222", "192.0.2.10", "[192.0.2.10]:2222",
		"2001:db8::1", "[2001:db8::1]:2222", "fe80::1%eth0", "*",
		"*.corp", "*:*", "[*.corp]:*", "app.corp:*", "*:22", "[app.corp]:22",
		"[sub.example.com]*", "host?.corp", "*,!bad.corp", "*,!*:22",
		"*,![bad.corp]:*", "*,!bad.corp:*", "*,![app.corp]:22", "*.corp,!bad.corp",
	}
	queries := []khAddr{
		{"app.corp", "22"}, {"app.corp", "2222"}, {"good.corp", "22"}, {"good.corp", "2222"},
		{"bad.corp", "22"}, {"bad.corp", "2222"}, {"sub.example.com", "22"}, {"sub.example.com", "2222"},
		{"host1.corp", "22"}, {"host1.corp", "2222"}, {"192.0.2.10", "22"}, {"192.0.2.10", "2222"},
		{"2001:db8::1", "22"}, {"2001:db8::1", "2222"}, {"fe80::1%eth0", "22"}, {"fe80::1%eth0", "2222"},
	}

	dir := t.TempDir()
	for i, pat := range patterns {
		khFile := filepath.Join(dir, fmt.Sprintf("kh_%d", i))
		if err := os.WriteFile(khFile, []byte(pat+" "+keyText+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %v", khFile, err)
		}
		db := newKnownHostsDB()
		if err := db.parseFileStrict(khFile); err != nil {
			t.Fatalf("parseFileStrict(%q): %v", pat, err)
		}
		for _, q := range queries {
			sshQuery := khDiffPutHostPort(q.host, q.port)
			want := sshKeygenMatches(t, keygenBin, khFile, sshQuery)
			hasCA, pinned := db.matchingHostKeyTypes(q)
			if hasCA {
				t.Fatalf("pattern %q unexpectedly marked as CA", pat)
			}
			gotTypes := slices.Contains(pinned, hostKey.Type())
			checkErr := db.check(net.JoinHostPort(q.host, q.port), &net.TCPAddr{IP: net.ParseIP("192.0.2.99"), Port: 2222}, hostKey)
			if gotTypes != want || (checkErr == nil) != want {
				t.Errorf("pattern=%q query=%s: ssh-keygen=%v, matchingHostKeyTypes=%v, check=%v (err=%v)",
					pat, sshQuery, want, gotTypes, checkErr == nil, checkErr)
			}
		}
	}
}

func assertKnownHostsHashedParity(t *testing.T, keygenBin string, hostKey cryptoSSH.PublicKey, keyText string) {
	t.Helper()
	dir := t.TempDir()
	khHashed := filepath.Join(dir, "kh_hashed")
	plain := strings.Join([]string{
		"app.corp " + keyText,
		"[app.corp]:2222 " + keyText,
		"2001:db8::1 " + keyText,
		"[2001:db8::1]:2222 " + keyText,
	}, "\n") + "\n"
	if err := os.WriteFile(khHashed, []byte(plain), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, keygenBin, "-H", "-f", khHashed).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -H failed (%v):\n%s", err, out)
	}
	db := newKnownHostsDB()
	if err := db.parseFileStrict(khHashed); err != nil {
		t.Fatalf("parseFileStrict(hashed): %v", err)
	}
	for _, q := range []khAddr{
		{"app.corp", "22"}, {"app.corp", "2222"}, {"app.corp", "2200"}, {"other.corp", "22"},
		{"2001:db8::1", "22"}, {"2001:db8::1", "2222"}, {"2001:db8::1", "2200"},
	} {
		sshQuery := khDiffPutHostPort(q.host, q.port)
		want := sshKeygenMatches(t, keygenBin, khHashed, sshQuery)
		_, pinned := db.matchingHostKeyTypes(q)
		gotTypes := slices.Contains(pinned, hostKey.Type())
		gotCheck := db.check(net.JoinHostPort(q.host, q.port), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, hostKey) == nil
		if gotTypes != want || gotCheck != want {
			t.Errorf("hashed query=%s: ssh-keygen=%v, matchingHostKeyTypes=%v, check=%v", sshQuery, want, gotTypes, gotCheck)
		}
	}

	khZone := filepath.Join(dir, "kh_zone")
	if err := appendKnownHost(khZone, "FE80::1%ETH0", hostKey, true); err != nil {
		t.Fatalf("appendKnownHost: %v", err)
	}
	dbZone := newKnownHostsDB()
	if err := dbZone.parseFileStrict(khZone); err != nil {
		t.Fatalf("parseFileStrict(khZone): %v", err)
	}
	for _, tc := range []struct {
		host      string
		wantMatch bool
	}{
		{"fe80::1%ETH0", true},
		{"FE80::1%ETH0", true},
		{"fe80::1%eth0", false},
	} {
		if got := dbZone.check(net.JoinHostPort(tc.host, "22"), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, hostKey) == nil; got != tc.wantMatch {
			t.Errorf("khZone check(%q) = %v, want %v", tc.host, got, tc.wantMatch)
		}
	}
	if !sshKeygenMatches(t, keygenBin, khZone, "fe80::1%ETH0") {
		t.Errorf("ssh-keygen -F fe80::1%%ETH0 expected match on hashed zone entry")
	}
	if sshKeygenMatches(t, keygenBin, khZone, "fe80::1%eth0") {
		t.Errorf("ssh-keygen -F fe80::1%%eth0 unexpectedly matched %%ETH0 hash")
	}
}

func assertKnownHostsUppercaseIPv6(t *testing.T, hostKey cryptoSSH.PublicKey, keyText string) {
	t.Helper()
	khFile := filepath.Join(t.TempDir(), "kh_v6case")
	if err := os.WriteFile(khFile, []byte("2001:db8::1 "+keyText+"\n[2001:db8::1]:2222 "+keyText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := newKnownHostsDB()
	if err := db.parseFileStrict(khFile); err != nil {
		t.Fatal(err)
	}
	for _, port := range []string{"22", "2222"} {
		if err := db.check(net.JoinHostPort("2001:DB8::1", port), &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 22}, hostKey); err != nil {
			t.Errorf("uppercase IPv6 query port %s failed: %v", port, err)
		}
	}
}

func assertKnownHostsCARevokedMarkers(
	t *testing.T,
	keygenBin string,
	caSigner cryptoSSH.Signer,
	hostKey, revokedKey cryptoSSH.PublicKey,
	keyText, revokedKeyText string,
) {
	t.Helper()
	khFile := filepath.Join(t.TempDir(), "kh_ca_revoked")
	lines := strings.Join([]string{
		"@cert-authority * " + keyText,
		"@cert-authority [*.corp]:* " + keyText,
		"@cert-authority *,!bad.corp " + keyText,
		"@revoked revoked.example " + revokedKeyText,
	}, "\n") + "\n"
	if err := os.WriteFile(khFile, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	db := newKnownHostsDB()
	if err := db.parseFileStrict(khFile); err != nil {
		t.Fatal(err)
	}

	for _, q := range []khAddr{
		{"app.corp", "22"}, {"app.corp", "2222"}, {"bad.corp", "22"}, {"bad.corp", "2222"},
	} {
		if hasCA, _ := db.matchingHostKeyTypes(q); !hasCA {
			t.Errorf("matchingHostKeyTypes(%+v) hasCA = false, want true", q)
		}
		if !db.isHostAuthority(caSigner.PublicKey(), net.JoinHostPort(q.host, q.port)) {
			t.Errorf("isHostAuthority(%+v) = false, want true", q)
		}
	}

	for _, tc := range []struct {
		line string
		host string
		port string
	}{
		{"@cert-authority [*.corp]:* " + keyText, "app.corp", "22"},
		{"@cert-authority [*.corp]:* " + keyText, "app.corp", "2222"},
		{"@cert-authority *,!bad.corp " + keyText, "good.corp", "22"},
		{"@cert-authority *,!bad.corp " + keyText, "bad.corp", "22"},
		{"@cert-authority *,!bad.corp " + keyText, "bad.corp", "2222"},
	} {
		f := filepath.Join(t.TempDir(), "ca_single")
		if err := os.WriteFile(f, []byte(tc.line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		singleDB := newKnownHostsDB()
		if err := singleDB.parseFileStrict(f); err != nil {
			t.Fatalf("parseFileStrict(%q): %v", tc.line, err)
		}
		want := sshKeygenMatches(t, keygenBin, f, khDiffPutHostPort(tc.host, tc.port))
		gotAuth := singleDB.isHostAuthority(hostKey, net.JoinHostPort(tc.host, tc.port))
		hasCA, _ := singleDB.matchingHostKeyTypes(khAddr{host: tc.host, port: tc.port})
		if gotAuth != want || hasCA != want {
			t.Errorf("CA line=%q query=(%s:%s): ssh-keygen=%v isHostAuthority=%v hasCA=%v", tc.line, tc.host, tc.port, want, gotAuth, hasCA)
		}
	}

	err := db.hostKeyCallback()("any.host:22", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, revokedKey)
	var revErr *knownhosts.RevokedError
	if !errors.As(err, &revErr) {
		t.Fatalf("expected RevokedError for @revoked key, got %v", err)
	}
}

func FuzzKnownHostsMatcher(f *testing.F) {
	keySample := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	seeds := []string{
		"",
		"# comment\n",
		"app.corp " + keySample + "\n",
		"[app.corp]:2222,[*.corp]:*,!bad.corp " + keySample + "\n",
		"[sub.example.com]* " + keySample + "\n",
		"@cert-authority * " + keySample + "\n",
		"@revoked bad.host " + keySample + "\n",
		"|1|c2FsdDEyMzQ1Njc4OTA=|aGFzaDEyMzQ1Njc4OTA= " + keySample + "\n",
		"fe80::1%ETH0 " + keySample + "\n",
		"[unclosed " + keySample + "\n",
		"*,! " + keySample + "\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	probePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	probeKey, err := cryptoSSH.NewPublicKey(probePub)
	if err != nil {
		f.Fatalf("NewPublicKey: %v", err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			return
		}
		db := newKnownHostsDB()
		_ = db.readLines(bytes.NewReader(data), "fuzz_known_hosts", nil)
		for _, q := range []khAddr{
			{host: "app.corp", port: "22"},
			{host: "app.corp", port: "2222"},
			{host: "fe80::1%ETH0", port: "22"},
		} {
			_, _ = db.matchingHostKeyTypes(q)
			_ = db.check(net.JoinHostPort(q.host, q.port), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, probeKey)
		}
	})
}
