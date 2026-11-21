package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/wentf9/xops-cli/core/fsx"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func FuzzForwardSpecRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"8080 127.0.0.1:80",
		"127.0.0.1:8080 10.0.0.1:80",
		"*:8080 [::1]:443",
		":8080 example.com:22",
		"8080:127.0.0.1:80",
		"127.0.0.1:8080:10.0.0.1:80",
		"[::1]:8080:[2001:db8::1]:443",
		"/tmp/local.sock 127.0.0.1:80",
		"8080 /var/run/app.sock",
		"/tmp/a.sock /tmp/b.sock",
		`"/tmp/my dir/a.sock" "/tmp/other dir/b.sock"`,
		`"/tmp/q\"s'\\b.sock" 127.0.0.1:80`,
		`C:\temp\a.sock 127.0.0.1:80`,
		"0 127.0.0.1:80",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		parsed, err := ParseForwardSpec(raw)
		if err != nil {
			return
		}
		wire := parsed.String()
		reparsed, err := ParseForwardSpec(wire)
		if err != nil {
			t.Fatalf("ParseForwardSpec(%q) succeeded (%+v), but re-parsing String() %q failed: %v", raw, parsed, wire, err)
		}
		if reparsed != parsed {
			t.Fatalf("ParseForwardSpec round-trip mismatch for raw=%q wire=%q:\nfirst:    %+v\nreparsed: %+v", raw, wire, parsed, reparsed)
		}
	})
}

func FuzzRemoteForwardSpecRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"1080",
		"0",
		"127.0.0.1:1080",
		"*:1080",
		":1080",
		"[::1]:1080",
		"/tmp/remote.sock",
		`"/tmp/remote dir/a.sock"`,
		"8080 127.0.0.1:80",
		"*:8080 [::1]:80",
		"8080:127.0.0.1:80",
		":8080:127.0.0.1:80",
		"/tmp/r.sock 127.0.0.1:80",
		"8080 /tmp/l.sock",
		`0\"0:0`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		parsed, err := ParseRemoteForwardSpec(raw)
		if err != nil {
			return
		}
		wire := parsed.String()
		reparsed, err := ParseRemoteForwardSpec(wire)
		if err != nil {
			t.Fatalf("ParseRemoteForwardSpec(%q) succeeded (%+v), but re-parsing String() %q failed: %v", raw, parsed, wire, err)
		}
		if reparsed != parsed {
			t.Fatalf("ParseRemoteForwardSpec round-trip mismatch for raw=%q wire=%q:\nfirst:    %+v\nreparsed: %+v", raw, wire, parsed, reparsed)
		}
	})
}

func FuzzDynamicForwardEndpointRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"1080",
		"0",
		"127.0.0.1:1080",
		"*:1080",
		":1080",
		"[::1]:1080",
		"[*]:1080",
		"/tmp/socks.sock",
		`"/tmp/my dir/socks.sock"`,
		`"/tmp/quote\"and'single\\end\"`,
		`C:\temp\socks.sock`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		parsed, err := ParseDynamicForwardEndpoint(raw)
		if err != nil {
			return
		}
		wire := parsed.String()
		reparsed, err := ParseDynamicForwardEndpoint(wire)
		if err != nil {
			t.Fatalf("ParseDynamicForwardEndpoint(%q) succeeded (%+v), but re-parsing String() %q failed: %v", raw, parsed, wire, err)
		}
		if reparsed != parsed {
			t.Fatalf("ParseDynamicForwardEndpoint round-trip mismatch for raw=%q wire=%q:\nfirst:    %+v\nreparsed: %+v", raw, wire, parsed, reparsed)
		}
	})
}

func assertIdentityPathSettingInvariants(t *testing.T, raw string, allowNone bool, setting IdentityPathSetting) {
	t.Helper()
	reparsed, err := ParseIdentityPathSetting(setting.Raw, allowNone)
	if err != nil || reparsed != setting {
		t.Fatalf("ParseIdentityPathSetting idempotence violated for raw=%q (allowNone=%t): first=%+v reparsed=(%+v, %v)", raw, allowNone, setting, reparsed, err)
	}
	if allowNone && IsNoneValue(raw) {
		if !setting.Disabled() || setting.Raw != "none" || setting.Enabled() || setting.Persistable() || setting.IsTemplate() {
			t.Fatalf("expected Disabled for %q, got %+v", raw, setting)
		}
		return
	}
	if setting.Disabled() || setting.Unset() || !setting.Enabled() {
		t.Fatalf("expected Enabled for %q (allowNone=%t), got %+v", raw, allowNone, setting)
	}
	hasTok := hasIdentityTemplateTokens(setting.Raw)
	if hasTok && (!setting.IsTemplate() || setting.Persistable()) {
		t.Fatalf("expected Template/non-Persistable for %q, got %+v", setting.Raw, setting)
	}
	if !hasTok && (setting.IsTemplate() || !setting.Persistable()) {
		t.Fatalf("expected Literal/Persistable for %q, got %+v", setting.Raw, setting)
	}
}

func FuzzIdentityPathSetting(f *testing.F) {
	for _, seed := range []struct {
		raw       string
		allowNone bool
	}{
		{"", true},
		{"", false},
		{"   ", true},
		{"none", true},
		{"NONE", true},
		{"none", false},
		{"~/.ssh/id_ed25519", true},
		{"/home/user/.ssh/id_%h_%p_%r_%n_%u_%l_%L_%i_%d_%j_%C_%%", true},
		{"${HOME}/.ssh/id_rsa", true},
		{"~/.ssh/id_%k", true},
		{"~/.ssh/id_%", true},
		{"${UNCLOSED", true},
		{"${1BAD}", true},
		{"/tmp/key\n", true},
		{"/tmp/key\u2028", true},
		{"\t/tmp/key", true},
		{"/tmp/key$1", false},
	} {
		f.Add(seed.raw, seed.allowNone)
	}
	f.Fuzz(func(t *testing.T, raw string, allowNone bool) {
		setting, err := ParseIdentityPathSetting(raw, allowNone)
		if hasControlOrLineSepChar(raw) {
			if err == nil {
				t.Fatalf("ParseIdentityPathSetting(%q, %t) accepted control/line-sep char", raw, allowNone)
			}
			return
		}
		if raw == "" {
			if err != nil || !setting.Unset() || setting.Enabled() || setting.Persistable() || setting.Raw != "" {
				t.Fatalf("ParseIdentityPathSetting(\"\", %t) = (%+v, %v), want Unset", allowNone, setting, err)
			}
			return
		}
		if strings.TrimSpace(raw) == "" {
			if err == nil {
				t.Fatalf("ParseIdentityPathSetting(%q, %t) accepted whitespace-only input", raw, allowNone)
			}
			return
		}
		if err != nil {
			return
		}
		assertIdentityPathSettingInvariants(t, raw, allowNone, setting)
	})
}

func FuzzShellQuote(f *testing.F) {
	for _, seed := range []string{
		"",
		"simple",
		"hello world",
		"it's a 'test'",
		"''",
		"'",
		"a\nb\tc",
		`$(whoami); rm -rf /`,
		`\back\slash\`,
		"unicode-中文-🚀",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		quoted := ShellQuote(raw)
		if len(quoted) < 2 || quoted[0] != '\'' || quoted[len(quoted)-1] != '\'' {
			t.Fatalf("ShellQuote(%q) = %q: must start and end with single quote", raw, quoted)
		}
		inner := quoted[1 : len(quoted)-1]
		var decoded strings.Builder
		for i := 0; i < len(inner); {
			if inner[i] == '\'' {
				if i+3 >= len(inner) || inner[i:i+4] != `'\''` {
					t.Fatalf("ShellQuote(%q) = %q: contains unescaped single quote at offset %d", raw, quoted, i)
				}
				decoded.WriteByte('\'')
				i += 4
				continue
			}
			decoded.WriteByte(inner[i])
			i++
		}
		if decoded.String() != raw {
			t.Fatalf("ShellQuote(%q) = %q decoded to %q", raw, quoted, decoded.String())
		}
	})
}

func assertSafeFilenameComponent(t *testing.T, raw, out string) {
	t.Helper()
	if out == "" {
		t.Fatalf("SanitizeFilenameComponent(%q) returned empty string", raw)
	}
	if out == "." || out == ".." || strings.Contains(out, "..") || out[0] == '.' || out[len(out)-1] == '.' {
		t.Fatalf("SanitizeFilenameComponent(%q) = %q: invalid dot segment", raw, out)
	}
	if strings.ContainsAny(out, `/\:`) {
		t.Fatalf("SanitizeFilenameComponent(%q) = %q: contains path/ADS separator", raw, out)
	}
	for _, r := range out {
		if !isSafeFilenameASCII(r) || unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			t.Fatalf("SanitizeFilenameComponent(%q) = %q: disallowed rune %U", raw, out, r)
		}
	}
	if err := fsx.ValidateLocalComponent(out); err != nil {
		t.Fatalf("SanitizeFilenameComponent(%q) = %q: rejected by fsx.ValidateLocalComponent: %v", raw, out, err)
	}
	if again := SanitizeFilenameComponent(out); again != out {
		t.Fatalf("SanitizeFilenameComponent is not idempotent: f(%q)=%q, f(f)=%q", raw, out, again)
	}
}

func FuzzSanitizeFilenameComponent(f *testing.F) {
	for _, seed := range []string{
		"",
		".",
		"..",
		"...",
		"a..b",
		"../etc/passwd",
		`..\..\windows\system32`,
		"[2001:db8::1]",
		"openssh:web1",
		"CON",
		"con.txt",
		"PRN",
		"AUX.log",
		"NUL",
		"COM1",
		"com9.sock",
		"LPT1",
		"lpt9.a.b",
		"web-01.prod.example.com",
		"foo.",
		".hidden",
		"bad\x00\n\r\t\u2028name",
		string([]byte{0xff, 0xfe, 'a', ':'}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		assertSafeFilenameComponent(t, raw, SanitizeFilenameComponent(raw))
	})
}

func TestP1_IdentityPathSetting_UnsetAndInvalid(t *testing.T) {
	t.Parallel()

	if s, err := ParseIdentityPathSetting("", true); err != nil || !s.Unset() || s.Enabled() || s.Persistable() {
		t.Fatalf("empty: got (%+v, %v)", s, err)
	}
	for _, bad := range []string{
		"   ",
		"\t~/.ssh/id_rsa",
		"~/.ssh/id_rsa\n",
		"~/.ssh/id_rsa\r",
		"~/.ssh/id_rsa\x00",
		"~/.ssh/id_rsa\u2028",
		"~/.ssh/id_rsa\u2029",
		"~/.ssh/id_%k",
		"~/.ssh/id_%z",
		"~/.ssh/id_%",
		"${UNCLOSED",
		"${}",
		"${1INVALID}",
	} {
		if _, err := ParseIdentityPathSetting(bad, true); err == nil {
			t.Errorf("ParseIdentityPathSetting(%q, true) unexpectedly succeeded", bad)
		}
	}
}

func TestP1_IdentityPathSetting_SentinelTemplateLiteral(t *testing.T) {
	t.Parallel()

	noneAllowed, err := ParseIdentityPathSetting("  NONE  ", true)
	if err != nil || !noneAllowed.Disabled() || noneAllowed.Raw != "none" || noneAllowed.Persistable() {
		t.Fatalf("NONE with allowNone=true: got (%+v, %v)", noneAllowed, err)
	}
	noneLiteral, err := ParseIdentityPathSetting("none", false)
	if err != nil || noneLiteral.Kind != IdentityPathLiteral || !noneLiteral.Persistable() || noneLiteral.Raw != "none" {
		t.Fatalf("none with allowNone=false: got (%+v, %v)", noneLiteral, err)
	}
	for _, tmpl := range []string{
		"~/.ssh/id_%h",
		"~/.ssh/id_%%_rsa",
		"${HOME}/.ssh/id_ed25519",
		"/keys/%r/%h/%p/%n/%u/%l/%L/%i/%d/%j/%C",
	} {
		s, err := ParseIdentityPathSetting(tmpl, true)
		if err != nil || !s.IsTemplate() || !s.Enabled() || s.Persistable() {
			t.Fatalf("template %q: got (%+v, %v)", tmpl, s, err)
		}
	}
	lit, err := ParseIdentityPathSetting(" ~/.ssh/id_ed25519 ", true)
	if err != nil || lit.Kind != IdentityPathLiteral || lit.Raw != "~/.ssh/id_ed25519" || !lit.Persistable() {
		t.Fatalf("literal: got (%+v, %v)", lit, err)
	}
}

func TestP1_IdentityPathSetting_OptionsDelegation(t *testing.T) {
	t.Parallel()

	opts := &Options{}
	if err := opts.Set(OptionIdentityFile, "NONE\n~/.ssh/id_%h"); err != nil {
		t.Fatalf("Set IdentityFile: %v", err)
	}
	if got := opts.IdentityFiles(); !slices.Equal(got, []string{"none"}) {
		t.Fatalf("IdentityFiles() = %v", got)
	}
	if err := opts.Set(OptionCertificateFile, "None\n${CERT_DIR}/id-cert.pub"); err != nil {
		t.Fatalf("Set CertificateFile: %v", err)
	}
	if got := opts.CertificateFiles(); !slices.Equal(got, []string{"none"}) {
		t.Fatalf("CertificateFiles() = %v", got)
	}
	if err := opts.Set(OptionIdentityFile, "~/.ssh/id_%k"); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("expected ErrSSHOptionsValidation for %%k IdentityFile, got %v", err)
	}
	if err := opts.Set(OptionCertificateFile, "${BAD-NAME}/cert.pub"); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("expected ErrSSHOptionsValidation for invalid env var in CertificateFile, got %v", err)
	}
}

func TestP1_SanitizeFilenameComponent_Table(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{"", "_"},
		{"web-01.prod.example.com", "web-01.prod.example.com"},
		{"192.168.1.10", "192.168.1.10"},
		{".", "_"},
		{"..", "__"},
		{"...", "___"},
		{"a..b", "a__b"},
		{"foo.", "foo_"},
		{".hidden", "_hidden"},
		{"../etc/passwd", "___etc_passwd"},
		{"openssh:web1", "openssh_web1"},
		{"[2001:db8::1]", "_2001_db8__1_"},
		{"CON", "_CON"},
		{"con.log", "_con.log"},
		{"PRN", "_PRN"},
		{"aux.txt", "_aux.txt"},
		{"NUL", "_NUL"},
		{"COM1", "_COM1"},
		{"com9.sock", "_com9.sock"},
		{"LPT1", "_LPT1"},
		{"lpt9.a.b", "_lpt9.a.b"},
		{"console", "console"},
		{"COM0", "COM0"},
	}
	for _, tc := range cases {
		if got := SanitizeFilenameComponent(tc.in); got != tc.want {
			t.Errorf("SanitizeFilenameComponent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestP1_SavePublicKey_RejectsDanglingAndLiveSymlinks(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()

	t.Run("creates new regular pub key and preserves existing regular file", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "id_ed25519")
		if err := savePublicKey(keyPath, pub); err != nil {
			t.Fatalf("savePublicKey initial: %v", err)
		}
		pubPath := keyPath + ".pub"
		want := cryptoSSH.MarshalAuthorizedKey(pub)
		got, err := os.ReadFile(pubPath)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("read saved pub key = (%q, %v), want %q", got, err, want)
		}
		sentinel := []byte("existing-content\n")
		if err := os.WriteFile(pubPath, sentinel, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := savePublicKey(keyPath, pub); err != nil {
			t.Fatalf("savePublicKey existing regular: %v", err)
		}
		got2, err := os.ReadFile(pubPath)
		if err != nil || !bytes.Equal(got2, sentinel) {
			t.Fatalf("existing pub key was unexpectedly modified: (%q, %v)", got2, err)
		}
	})

	t.Run("rejects dangling symlink without creating target", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires elevated privileges on Windows")
		}
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "id_dangling")
		pubPath := keyPath + ".pub"
		targetPath := filepath.Join(dir, "pwned.txt")
		if err := os.Symlink(targetPath, pubPath); err != nil {
			t.Skipf("os.Symlink unsupported: %v", err)
		}
		if err := savePublicKey(keyPath, pub); err == nil {
			t.Fatal("savePublicKey succeeded on dangling symlink, want rejection error")
		}
		if _, err := os.Lstat(targetPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("dangling symlink target %q was created (err=%v)", targetPath, err)
		}
	})

	t.Run("rejects live symlink without modifying target", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires elevated privileges on Windows")
		}
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "id_live")
		pubPath := keyPath + ".pub"
		targetPath := filepath.Join(dir, "victim.txt")
		orig := []byte("untouched")
		if err := os.WriteFile(targetPath, orig, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(targetPath, pubPath); err != nil {
			t.Skipf("os.Symlink unsupported: %v", err)
		}
		if err := savePublicKey(keyPath, pub); err == nil {
			t.Fatal("savePublicKey succeeded on live symlink, want rejection error")
		}
		got, err := os.ReadFile(targetPath)
		if err != nil || !bytes.Equal(got, orig) {
			t.Fatalf("live symlink target modified: (%q, %v)", got, err)
		}
	})
}

func TestP1_ForwardNilClientGuards(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	clients := []struct {
		name   string
		client *Client
	}{
		{"nil_client", nil},
		{"nil_sshClient", &Client{}},
		{"nil_sshClient_Conn", &Client{sshClient: &cryptoSSH.Client{}}},
	}

	bindEp := ForwardEndpoint{Host: "127.0.0.1", Port: 0, HasHost: true}
	destEp := ForwardEndpoint{Host: "127.0.0.1", Port: 80, HasHost: true}
	spec := ForwardSpec{Bind: bindEp, Dest: destEp}

	for _, tc := range clients {
		t.Run(tc.name, func(t *testing.T) {
			if fwd, err := tc.client.LocalForward(ctx, "127.0.0.1:0", "127.0.0.1:80"); err == nil || fwd != nil {
				t.Errorf("LocalForward = (%v, %v), want error", fwd, err)
			}
			if fwd, err := tc.client.LocalForwardEndpoint(ctx, bindEp, destEp, false); err == nil || fwd != nil {
				t.Errorf("LocalForwardEndpoint = (%v, %v), want error", fwd, err)
			}
			if fwd, err := tc.client.RemoteForward(ctx, "127.0.0.1:0", "127.0.0.1:80"); err == nil || fwd != nil {
				t.Errorf("RemoteForward = (%v, %v), want error", fwd, err)
			}
			if fwd, err := tc.client.RemoteForwardEndpoint(ctx, spec); err == nil || fwd != nil {
				t.Errorf("RemoteForwardEndpoint = (%v, %v), want error", fwd, err)
			}
			if conn, err := tc.client.dialSSH(ctx, "tcp", "127.0.0.1:80"); err == nil || conn != nil {
				t.Errorf("dialSSH = (%v, %v), want error", conn, err)
			}
			if ln, err := tc.client.listenRemoteContext(ctx, "tcp", "127.0.0.1:0", time.Second); err == nil || ln != nil {
				t.Errorf("listenRemoteContext = (%v, %v), want error", ln, err)
			}
			if fwd, err := tc.client.Socks5Forward(ctx, "127.0.0.1:0"); err == nil || fwd != nil {
				t.Errorf("Socks5Forward = (%v, %v), want error", fwd, err)
			}
			if fwd, err := tc.client.DynamicForwardEndpoint(ctx, bindEp, false); err == nil || fwd != nil {
				t.Errorf("DynamicForwardEndpoint = (%v, %v), want error", fwd, err)
			}
		})
	}
}

func TestP1_Socks5Handshake_RejectsNonZeroRSV(t *testing.T) {
	t.Parallel()

	cConn, sConn := net.Pipe()
	defer func() {
		_ = cConn.Close()
		_ = sConn.Close()
	}()

	srvErr := make(chan error, 1)
	go func() {
		_, err := handleSocks5Handshake(sConn)
		srvErr <- err
	}()

	if _, err := cConn.Write([]byte{0x01, 0x00}); err != nil {
		t.Fatalf("write methods: %v", err)
	}
	var authReply [2]byte
	if _, err := io.ReadFull(cConn, authReply[:]); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if authReply != [2]byte{0x05, 0x00} {
		t.Fatalf("auth reply = %x, want 0500", authReply)
	}

	// Send CONNECT request with non-zero RSV byte (0x01 instead of RFC 1928 0x00).
	if _, err := cConn.Write([]byte{0x05, 0x01, 0x01, 0x01}); err != nil {
		t.Fatalf("write request header: %v", err)
	}
	var errReply [10]byte
	if _, err := io.ReadFull(cConn, errReply[:]); err != nil {
		t.Fatalf("read RSV error reply: %v", err)
	}
	if errReply[0] != 0x05 || errReply[1] != 0x01 {
		t.Fatalf("RSV error reply = %x, want VER=0x05 REP=0x01", errReply)
	}
	err := <-srvErr
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("handleSocks5Handshake(RSV=0x01) err = %v, want reserved-byte error", err)
	}
}

type p1StallingAcceptNewChannel struct {
	entered   chan struct{}
	unblock   chan struct{}
	enterOnce sync.Once
	rejected  atomic.Bool
}

func (c *p1StallingAcceptNewChannel) Accept() (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	c.enterOnce.Do(func() { close(c.entered) })
	<-c.unblock
	return nil, nil, errors.New("stalled accept unblocked")
}

func (c *p1StallingAcceptNewChannel) Reject(_ cryptoSSH.RejectionReason, _ string) error {
	c.rejected.Store(true)
	return nil
}

func (c *p1StallingAcceptNewChannel) ChannelType() string { return agentForwardChannelType }
func (c *p1StallingAcceptNewChannel) ExtraData() []byte   { return nil }

type p1TrackCloseConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *p1TrackCloseConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestP1_AgentForward_DialTimeout(t *testing.T) {
	origTimeout := agentForwardDialTimeout
	agentForwardDialTimeout = 80 * time.Millisecond
	defer func() { agentForwardDialTimeout = origTimeout }()

	router := &sshAgentChannelRouter{}
	var sawDeadline atomic.Bool
	dialStalled := func(ctx context.Context, _ string) (net.Conn, error) {
		if _, ok := ctx.Deadline(); ok {
			sawDeadline.Store(true)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	lease, err := router.acquireLocalLease(t.Context(), "/tmp/stalled-agent.sock", dialStalled, nil)
	if err != nil {
		t.Fatalf("acquireLocalLease: %v", err)
	}
	defer lease.Release()

	if !router.tryAcquireChannelSlot() || !lease.tryBeginPump() {
		t.Fatal("failed to reserve channel slot and pump")
	}
	ch := &p1StallingAcceptNewChannel{
		entered: make(chan struct{}),
		unblock: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		defer lease.pumps.Done()
		defer close(done)
		router.serveLocalAgentChannel(lease, ch)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveLocalAgentChannel did not respect per-dial timeout")
	}
	if !sawDeadline.Load() {
		t.Fatal("dialAgentConn did not receive a bounded deadline context")
	}
	if !ch.rejected.Load() {
		t.Fatal("expected stalled dial to reject incoming agent channel")
	}
	if got := router.activeChannels.Load(); got != 0 {
		t.Fatalf("activeChannels = %d, want 0", got)
	}
}

func TestP1_AgentForward_StalledAcceptRelease(t *testing.T) {
	router := &sshAgentChannelRouter{}
	agentClosed := make(chan struct{})
	var peerEnd net.Conn
	dialFast := func(context.Context, string) (net.Conn, error) {
		cEnd, sEnd := net.Pipe()
		peerEnd = sEnd
		return &p1TrackCloseConn{Conn: cEnd, closed: agentClosed}, nil
	}
	lease, err := router.acquireLocalLease(t.Context(), "/tmp/accept-stall.sock", dialFast, nil)
	if err != nil {
		t.Fatalf("acquireLocalLease: %v", err)
	}
	defer func() {
		if peerEnd != nil {
			_ = peerEnd.Close()
		}
	}()

	if !router.tryAcquireChannelSlot() || !lease.tryBeginPump() {
		t.Fatal("failed to reserve channel slot and pump")
	}
	ch := &p1StallingAcceptNewChannel{
		entered: make(chan struct{}),
		unblock: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		defer lease.pumps.Done()
		defer close(done)
		router.serveLocalAgentChannel(lease, ch)
	}()

	select {
	case <-ch.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for serveLocalAgentChannel to enter Accept")
	}

	releaseDone := make(chan struct{})
	go func() {
		defer close(releaseDone)
		lease.releaseWithDeadline(time.Now().Add(50 * time.Millisecond))
	}()

	select {
	case <-agentClosed:
	case <-time.After(2 * time.Second):
		close(ch.unblock)
		t.Fatal("agentConn was leaked when lease.Release() ran during stalled Accept()")
	}

	close(ch.unblock)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveLocalAgentChannel did not exit after Accept unblocked")
	}
	<-releaseDone
	if got := router.activeChannels.Load(); got != 0 {
		t.Fatalf("activeChannels = %d, want 0", got)
	}
}

type p1RecordedExec struct {
	command string
	stdin   string
	hadPTY  bool
}

func startP1MockSudoSSHServer(t *testing.T, handler func(exec p1RecordedExec) (stdout string, exitStatus uint32)) (*cryptoSSH.Client, *[]p1RecordedExec, *sync.Mutex) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new host signer: %v", err)
	}
	srvCfg := &cryptoSSH.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock ssh: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var recorded []p1RecordedExec

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveP1MockSSHConn(conn, srvCfg, &mu, &recorded, handler)
		}
	}()

	rawCli, err := cryptoSSH.Dial("tcp", ln.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "root",
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial mock ssh: %v", err)
	}
	t.Cleanup(func() { _ = rawCli.Close() })
	return rawCli, &recorded, &mu
}

func serveP1MockSSHConn(
	nc net.Conn,
	srvCfg *cryptoSSH.ServerConfig,
	mu *sync.Mutex,
	recorded *[]p1RecordedExec,
	handler func(exec p1RecordedExec) (string, uint32),
) {
	sConn, chans, reqs, err := cryptoSSH.NewServerConn(nc, srvCfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	defer func() { _ = sConn.Close() }()
	go cryptoSSH.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go serveP1MockSession(ch, chReqs, mu, recorded, handler)
	}
}

func serveP1MockSession(
	c cryptoSSH.Channel,
	in <-chan *cryptoSSH.Request,
	mu *sync.Mutex,
	recorded *[]p1RecordedExec,
	handler func(exec p1RecordedExec) (string, uint32),
) {
	defer func() { _ = c.Close() }()
	hadPTY := false
	for req := range in {
		switch req.Type {
		case "pty-req":
			hadPTY = true
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			var payload struct{ Command string }
			_ = cryptoSSH.Unmarshal(req.Payload, &payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			var stdinBytes []byte
			if strings.Contains(payload.Command, "sudo -S") {
				stdinBytes, _ = io.ReadAll(io.LimitReader(c, 4096))
			}
			rec := p1RecordedExec{
				command: payload.Command,
				stdin:   string(stdinBytes),
				hadPTY:  hadPTY,
			}
			mu.Lock()
			*recorded = append(*recorded, rec)
			mu.Unlock()
			out, status := handler(rec)
			if out != "" {
				_, _ = io.WriteString(c, out)
			}
			_, _ = c.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{Status: status}))
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func TestP1_EmptyExecutionConfig_ConfiguredSudoAutoDetection(t *testing.T) {
	for _, initialMode := range []SudoMode{"", SudoModeAuto} {
		rawCli, recorded, mu := startP1MockSudoSSHServer(t, func(exec p1RecordedExec) (string, uint32) {
			if strings.Contains(exec.command, "id -u") {
				return "0\n", 0
			}
			return "ok\n", 0
		})
		client := &Client{
			sshClient: rawCli,
			connCfg: ConnectionConfig{
				SudoMode:  initialMode,
				Execution: &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX},
			},
		}
		opts, err := client.configuredSudoOptions(t.Context(), "echo ok", &ExecutionConfig{})
		if err != nil {
			t.Fatalf("initialMode=%q: configuredSudoOptions(&ExecutionConfig{}) failed: %v", initialMode, err)
		}
		if opts != nil {
			t.Fatalf("initialMode=%q: expected nil opts for empty ExecutionConfig, got %d", initialMode, len(opts))
		}
		if got := client.ConnectionConfig().SudoMode; got != SudoModeRoot {
			t.Fatalf("initialMode=%q: SudoMode = %q, want %q", initialMode, got, SudoModeRoot)
		}
		mu.Lock()
		seen := len(*recorded)
		mu.Unlock()
		if seen == 0 {
			t.Fatalf("initialMode=%q: expected maybeDetectSudoMode to probe remote host", initialMode)
		}
	}
}

func TestP1_EmptyExecutionConfig_RunAndInteractiveSudoAutoDetection(t *testing.T) {
	rawCli, recorded, mu := startP1MockSudoSSHServer(t, func(exec p1RecordedExec) (string, uint32) {
		if strings.Contains(exec.command, "id -u") {
			return "0\n", 0
		}
		return "exec-ok\n", 0
	})
	client := &Client{
		sshClient: rawCli,
		connCfg: ConnectionConfig{
			SudoMode:  SudoModeAuto,
			Execution: &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX},
		},
	}
	out, err := client.RunWithSudoExecution(t.Context(), "echo ok", &ExecutionConfig{})
	if err != nil || !strings.Contains(out, "exec-ok") {
		t.Fatalf("RunWithSudoExecution(&ExecutionConfig{}) = (%q, %v)", out, err)
	}
	if got := client.ConnectionConfig().SudoMode; got != SudoModeRoot {
		t.Fatalf("SudoMode after RunWithSudoExecution = %q, want %q", got, SudoModeRoot)
	}

	client.cfgMu.Lock()
	client.connCfg.SudoMode = SudoModeAuto
	client.cfgMu.Unlock()

	var stdout, stderr bytes.Buffer
	err = client.RunInteractiveWithSudoExecutionIO(
		t.Context(),
		"echo ok",
		&ExecutionConfig{},
		InteractiveIO{Stdout: &stdout, Stderr: &stderr},
	)
	if err != nil && (strings.Contains(err.Error(), "sudo mode") || strings.Contains(err.Error(), "fish")) {
		t.Fatalf("RunInteractiveWithSudoExecutionIO(&ExecutionConfig{}) hit privilege/interpreter error: %v", err)
	}
	if got := client.ConnectionConfig().SudoMode; got != SudoModeRoot {
		t.Fatalf("SudoMode after RunInteractiveWithSudoExecutionIO = %q, want %q", got, SudoModeRoot)
	}
	mu.Lock()
	for _, r := range *recorded {
		if strings.Contains(r.command, "fish") {
			mu.Unlock()
			t.Fatalf("empty ExecutionConfig unexpectedly fell back to fish interpreter: %q", r.command)
		}
	}
	mu.Unlock()
}

func TestP1_RunWithSudo_ScrubbablePasswordBuffer(t *testing.T) {
	var capturedStdin string
	var mu sync.Mutex
	rawCli, _, _ := startP1MockSudoSSHServer(t, func(exec p1RecordedExec) (string, uint32) {
		mu.Lock()
		capturedStdin = exec.stdin
		mu.Unlock()
		return "sudo-ran\n", 0
	})
	client := &Client{
		sshClient: rawCli,
		connCfg:   ConnectionConfig{SudoMode: SudoModeSudo},
	}
	pwd := []byte("my-sudo-secret")
	out, err := client.runWithSudo(t.Context(), "sh -c 'id'", pwd, strings.NewReader("payload\n"), DefaultRunConfig(), false)
	if err != nil || !strings.Contains(out, "sudo-ran") {
		t.Fatalf("runWithSudo = (%q, %v)", out, err)
	}
	mu.Lock()
	gotStdin := capturedStdin
	mu.Unlock()
	if gotStdin != "my-sudo-secret\npayload\n" {
		t.Fatalf("sudo stdin = %q, want %q", gotStdin, "my-sudo-secret\npayload\n")
	}
	if string(pwd) != "my-sudo-secret" {
		t.Fatalf("caller password slice was unexpectedly mutated: %q", string(pwd))
	}
}
