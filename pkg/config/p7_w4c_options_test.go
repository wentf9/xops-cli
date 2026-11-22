package config

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestP7W4c_D2_MalformedProxyAndEmptyDirectives_FailClosedAndDifferential(t *testing.T) {
	t.Parallel()

	t.Run("malformed ProxyJump and ProxyCommand fail closed across all entrypoints", testP7W4cMalformedProxyFailClosed)
	t.Run("ProxyJump none,none cancels jump and exposes lower ProxyCommand", testP7W4cProxyJumpNoneNone)
	t.Run("zero-token and empty-quoted directives fail closed without falling through to Host *", testP7W4cZeroAndEmptyDirectives)
	t.Run("firstSSHConfigKeyValueRawPasses stops at first matching empty directive without Host * fallthrough", testP7W4cFirstKeyValueNoFallthrough)
}

func testP7W4cMalformedProxyFailClosed(t *testing.T) {
	t.Parallel()

	badConfigs := []struct {
		name string
		cfg  string
	}{
		{"ProxyJump_double_comma", "Host app\n  HostName 10.0.0.1\n  ProxyJump a,,b\n"},
		{"ProxyJump_bare_comma", "Host app\n  HostName 10.0.0.1\n  ProxyJump ,\n"},
		{"ProxyJump_trailing_comma", "Host app\n  HostName 10.0.0.1\n  ProxyJump a,\n"},
		{"ProxyJump_leading_comma", "Host app\n  HostName 10.0.0.1\n  ProxyJump ,b\n"},
		{"ProxyJump_none_trailing_comma", "Host app\n  HostName 10.0.0.1\n  ProxyJump none,\n"},
		{"ProxyCommand_nul_byte", "Host app\n  HostName 10.0.0.1\n  ProxyCommand bad\x00cmd %h %p\n"},
		{"ProxyJump_wildcard_malformed", "Host app\n  HostName 10.0.0.1\nHost *\n  ProxyJump a,,b\n"},
		{"ProxyJump_with_canonicalize_enabled", "Host app\n  CanonicalizeHostname yes\n  CanonicalDomains corp.example\n  ProxyJump a,,b\n"},
	}

	for _, tc := range badConfigs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertP7W4cMalformedProxyRejected(t, tc.cfg)
		})
	}
}

func assertP7W4cMalformedProxyRejected(t *testing.T, cfg string) {
	t.Helper()
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
	if err != nil {
		// Parse-time rejection also satisfies fail-closed.
		return
	}
	if ps, err := parser.ResolveProxySetting("app"); err == nil {
		t.Errorf("ResolveProxySetting(app) = %q, want error", ps)
	}
	if ps, err := parser.ResolveProxySettingWithCanonical("app", "app.corp.example"); err == nil {
		t.Errorf("ResolveProxySettingWithCanonical(app) = %q, want error", ps)
	}
	if opts, err := parser.GetSSHOptions("app"); err == nil {
		t.Errorf("GetSSHOptions(app) = %+v, want error", opts)
	}
	if opts, err := parser.GetSSHOptionsWithCanonical("app", "app.corp.example"); err == nil {
		t.Errorf("GetSSHOptionsWithCanonical(app) = %+v, want error", opts)
	}
	if _, _, _, err := parser.GetVirtualNode("app"); err == nil {
		t.Error("GetVirtualNode(app) succeeded, want error")
	}
	if _, _, _, err := parser.GetVirtualNodeWithCanonical("app", "app.corp.example"); err == nil {
		t.Error("GetVirtualNodeWithCanonical(app) succeeded, want error")
	}
	prov := NewProviderWithOpenSSHParser(nil, parser)
	if _, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
		Provider: prov,
		Host:     "app",
		Resolver: &fakeCanonicalResolver{},
	}); err == nil {
		t.Error("CanonicalizeHost(app) succeeded on malformed ProxyJump/ProxyCommand, want error")
	}
	if _, err := ParseOpenSSHHosts(strings.NewReader(cfg), "ops"); err == nil {
		t.Error("ParseOpenSSHHosts succeeded on malformed ProxyJump/ProxyCommand, want error")
	}
}

func testP7W4cProxyJumpNoneNone(t *testing.T) {
	t.Parallel()

	cfg := strings.Join([]string{
		"Host app",
		"  HostName 10.0.0.1",
		"  ProxyJump none,none",
		"Host *",
		"  ProxyCommand nc %h %p",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	ps, err := parser.ResolveProxySetting("app")
	if err != nil {
		t.Fatalf("ResolveProxySetting(app): %v", err)
	}
	cmd, ok := ps.Command()
	if !ok || cmd != "nc %h %p" {
		t.Fatalf("ResolveProxySetting(app) = (%q, %v), want ProxyCommand=\"nc %%h %%p\"", ps, ok)
	}
	node, _, _, err := parser.GetVirtualNode("app")
	if err != nil {
		t.Fatalf("GetVirtualNode(app): %v", err)
	}
	if node.ProxyJump != "" || node.SSHOptions == nil || node.SSHOptions.ActiveProxyCommand() != "nc %h %p" {
		t.Fatalf("GetVirtualNode(app) proxy = (jump=%q cmd=%q), want (\"\", \"nc %%h %%p\")",
			node.ProxyJump, node.SSHOptions.ActiveProxyCommand())
	}
}

func assertLiveSSHGExit255(t *testing.T, sshBin, cfgPath, label string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, sshBin, "-F", cfgPath, "-G", "app").CombinedOutput()
	if err == nil {
		t.Errorf("live ssh -G unexpectedly accepted %s:\n%s", label, out)
		return
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 255 {
		t.Errorf("live ssh -G for %s exit = %v, want 255", label, err)
	}
}

func testP7W4cZeroAndEmptyDirectives(t *testing.T) {
	t.Parallel()

	fallbackBlock := strings.Join([]string{
		"Host *",
		"  HostName 10.99.99.99",
		"  User fallback-user",
		"  Port 2299",
		"  ProxyJump fallback-bastion",
		"  ProxyCommand fallback-cmd %h %p",
		"  IdentityFile ~/.ssh/id_fallback",
		"  Ciphers aes256-gcm@openssh.com",
		"  ControlMaster auto",
		"  PreferredAuthentications publickey",
	}, "\n") + "\n"

	cases := []struct {
		name         string
		line         string
		expectSSH255 bool
	}{
		{"zero_Ciphers", "Ciphers", true},
		{"zero_Ciphers_eq", "Ciphers =", true},
		{"zero_ControlMaster_eq", "ControlMaster =", true},
		{"zero_Port", "Port", true},
		{"zero_ProxyJump", "ProxyJump", true},
		{"zero_ProxyCommand", "ProxyCommand", true},
		{"zero_IdentityFile", "IdentityFile", true},
		{"zero_SendEnv", "SendEnv", true},
		{"zero_SetEnv", "SetEnv", true},
		{"zero_LocalForward", "LocalForward", true},
		{"zero_RemoteCommand", "RemoteCommand", true},
		{"zero_Host", "Host", true},
		{"zero_Match", "Match", true},
		{"zero_Include", "Include", true},
		{"empty_quoted_Ciphers", `Ciphers ""`, true},
		{"empty_quoted_ControlMaster", `ControlMaster ""`, true},
		{"empty_quoted_PreferredAuthentications", `PreferredAuthentications ""`, true},
		{"empty_quoted_Port", `Port ""`, true},
		{"empty_quoted_HostName", `HostName ""`, true},
		{"empty_quoted_User", `User ""`, true},
		{"empty_quoted_IdentityFile", `IdentityFile ""`, true},
		{"empty_quoted_Host", `Host ""`, true},
		{"empty_quoted_ProxyJump", `ProxyJump ""`, false},
		{"empty_quoted_ProxyCommand", `ProxyCommand ""`, false},
	}

	sshBin, _ := exec.LookPath("ssh")
	tmpDir := t.TempDir()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgText := "Host app\n  " + tc.line + "\n" + fallbackBlock
			if (strings.HasPrefix(tc.line, "Host") && !strings.HasPrefix(tc.line, "HostName")) ||
				strings.HasPrefix(tc.line, "Match") || strings.HasPrefix(tc.line, "Include") {
				cfgText = tc.line + "\n" + fallbackBlock
			}
			if _, err := NewOpenSSHParserFromReader(strings.NewReader(cfgText)); err == nil {
				t.Errorf("NewOpenSSHParserFromReader(%q) succeeded, want fail-closed parse error", tc.line)
			}
			if tc.expectSSH255 && sshBin != "" {
				cfgPath := filepath.Join(tmpDir, tc.name+".conf")
				writeCfgFile(t, cfgPath, cfgText)
				assertLiveSSHGExit255(t, sshBin, cfgPath, tc.line)
			}
		})
	}

	if sshBin != "" {
		for _, badPJ := range []string{"a,,b", ","} {
			cfgPath := filepath.Join(tmpDir, "bad_pj_"+strings.ReplaceAll(badPJ, ",", "_")+".conf")
			writeCfgFile(t, cfgPath, "Host app\n  ProxyJump "+badPJ+"\n")
			assertLiveSSHGExit255(t, sshBin, cfgPath, "ProxyJump "+badPJ)
		}
	}
}

func testP7W4cFirstKeyValueNoFallthrough(t *testing.T) {
	t.Parallel()
	doc := &sshConfigDoc{
		blocks: []*sshConfigBlock{
			{
				patterns: []sshHostPattern{newSSHHostPattern("app")},
				nodes: []sshConfigNode{
					&sshConfigDirective{line: 2, key: "User", lowerKey: "user", value: "", rawValue: ""},
				},
			},
			{
				patterns: []sshHostPattern{newSSHHostPattern("*")},
				nodes: []sshConfigNode{
					&sshConfigDirective{line: 4, key: "User", lowerKey: "user", value: "fallback", rawValue: "fallback"},
				},
			},
		},
	}
	if got := firstSSHConfigKeyValueRawPasses(doc, []string{"app"}, false, "User"); got != "" {
		t.Fatalf("firstSSHConfigKeyValueRawPasses fell through empty directive to %q, want empty", got)
	}
}

func TestP7W4c_ABM2_NullDeviceParityUnixAndWindows(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path    string
		goos    string
		wantHit bool
	}{
		{"/dev/null", "linux", true},
		{"/dev//null", "linux", true},
		{"/dev/null", "darwin", true},
		{"/dev/null", "windows", true},
		{"/DEV/NULL", "windows", true},
		{`\dev\null`, "windows", true},
		{"NUL", "windows", true},
		{"nul", "windows", true},
		{"Nul", "windows", true},
		{`\\.\NUL`, "windows", true},
		{`\\.\nul`, "windows", true},
		{`//./NUL`, "windows", true},
		{"NUL", "linux", false},
		{`\\.\NUL`, "linux", false},
		{"NUL.txt", "windows", false},
		{`C:\Users\alice\NUL`, "windows", false},
		{"/dev/zero", "linux", false},
		{"/dev/zero", "windows", false},
		{"", "windows", false},
		{"", "linux", false},
	}

	for _, tc := range cases {
		if got := isOpenSSHNullDevicePathForOS(tc.path, tc.goos); got != tc.wantHit {
			t.Errorf("isOpenSSHNullDevicePathForOS(%q, %q) = %v, want %v", tc.path, tc.goos, got, tc.wantHit)
		}
	}

	// Verify expandOpenSSHIncludePatternForOS treats null-device sentinels as skipped no-ops
	// BEFORE filepath.IsAbs and BEFORE prepending ~/.ssh/ or /etc/ssh/.
	for _, tc := range []struct {
		pat    string
		system bool
		goos   string
	}{
		{"/dev/null", false, "linux"},
		{"/dev/null", true, "linux"},
		{"/dev/null", false, "windows"},
		{"NUL", false, "windows"},
		{"nul", true, "windows"},
		{`\\.\NUL`, false, "windows"},
		{`\\.\nul`, true, "windows"},
	} {
		got, skip, err := expandOpenSSHIncludePatternForOS(tc.pat, tc.system, tc.goos)
		if err != nil || !skip || got != "" {
			t.Errorf("expandOpenSSHIncludePatternForOS(%q, system=%v, goos=%q) = (%q, skip=%v, err=%v), want (\"\", true, nil)",
				tc.pat, tc.system, tc.goos, got, skip, err)
		}
	}

	// Live Include /dev/null and -F /dev/null end-to-end checks.
	cfgWithNullInclude := "Include /dev/null\nHost app\n  HostName 10.2.3.4\n  User ops\n"
	pInc, err := NewOpenSSHParserFromReader(strings.NewReader(cfgWithNullInclude))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader(Include /dev/null): %v", err)
	}
	if !pInc.HasHost("app") {
		t.Fatal("expected Host app parsed cleanly after Include /dev/null")
	}

	pRoot, isNull, err := loadOpenSSHParserFromPath("/dev/null", true)
	if err != nil || !isNull || pRoot == nil {
		t.Fatalf("loadOpenSSHParserFromPath(/dev/null) = (%v, isNull=%v, err=%v), want empty parser + isNull=true", pRoot, isNull, err)
	}

	base := NewProviderWithOpenSSHParser(nil, pInc)
	ov, err := WithOpenSSHConfigOverride(base, "/dev/null")
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride(/dev/null): %v", err)
	}
	if ov.(openSSHParserSource).GetOpenSSHParser().HasHost("app") {
		t.Fatal("WithOpenSSHConfigOverride(/dev/null) leaked base OpenSSH config")
	}
}

func TestP7W4c_EFGM3_CaseInsensitiveOpenSSHPrefixAndDoublePrefixRejection(t *testing.T) {
	t.Parallel()

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(strings.Join([]string{
		"Host web",
		"  HostName 10.5.6.7",
		"  Port 2222",
		"  ProxyJump bastion",
		"  ConnectTimeout 9",
	}, "\n") + "\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	validCases := []struct {
		in       string
		wantOrig string
		wantHost bool
	}{
		{"openssh:web", "web", true},
		{"OPENSSH:web", "web", true},
		{"OpenSSH:web", "web", true},
		{"oPeNsSh:alice@web:2222", "web", true},
		{"OPENSSH:[2001:db8::1]:22", "2001:db8::1", false},
	}

	for _, tc := range validCases {
		assertP7W4cValidOpenSSHSelector(t, parser, tc.in, tc.wantOrig, tc.wantHost)
	}

	rejectedSelectors := []string{
		"openssh:",
		"OPENSSH:",
		"OPENSSH:   ",
		"openssh:openssh:web",
		"openssh:OPENSSH:web",
		"OPENSSH:openssh:web",
		"OPENSSH:OPENSSH:22",
		"openssh:  OPENSSH:web",
	}
	for _, bad := range rejectedSelectors {
		assertP7W4cRejectedOpenSSHSelector(t, parser, bad)
	}
}

func assertP7W4cValidOpenSSHSelector(t *testing.T, parser *OpenSSHParser, in, wantOrig string, wantHost bool) {
	t.Helper()
	if !IsOpenSSHNodeID(in) {
		t.Errorf("precondition: IsOpenSSHNodeID(%q) = false", in)
	}
	if got, ok := OpenSSHOriginalHost(in); !ok || got != wantOrig {
		t.Errorf("OpenSSHOriginalHost(%q) = (%q, %v), want (%q, true)", in, got, ok, wantOrig)
	}
	if got := UnwrapOpenSSHSelector(in); got != wantOrig {
		t.Errorf("UnwrapOpenSSHSelector(%q) = %q, want %q", in, got, wantOrig)
	}
	if got := parser.HasHost(in); got != wantHost {
		t.Errorf("HasHost(%q) = %v, want %v", in, got, wantHost)
	}
	if !wantHost {
		return
	}
	if hn, exp, err := parser.ResolveExplicitHostName(in); err != nil || !exp || hn != "10.5.6.7" {
		t.Errorf("ResolveExplicitHostName(%q) = (%q, %v, %v), want (10.5.6.7, true, nil)", in, hn, exp, err)
	}
	if port, exp, err := parser.ResolveExplicitPort(in); err != nil || !exp || port != 2222 {
		t.Errorf("ResolveExplicitPort(%q) = (%d, %v, %v), want (2222, true, nil)", in, port, exp, err)
	}
	if opts, err := parser.GetSSHOptions(in); err != nil || opts == nil || opts.Get(ssh.OptionConnectTimeout) != "9" {
		t.Errorf("GetSSHOptions(%q) = (%+v, %v), want ConnectTimeout=9", in, opts, err)
	}
	if ps, err := parser.ResolveProxySetting(in); err != nil || ps.Kind() != ssh.ProxyJump {
		t.Errorf("ResolveProxySetting(%q) = (%q, %v), want ProxyJump", in, ps, err)
	}
}

func assertP7W4cRejectedOpenSSHSelector(t *testing.T, parser *OpenSSHParser, bad string) {
	t.Helper()
	if got, ok := OpenSSHOriginalHost(bad); ok || got != "" {
		t.Errorf("OpenSSHOriginalHost(%q) = (%q, %v), want (\"\", false)", bad, got, ok)
	}
	if got := UnwrapOpenSSHSelector(bad); got != "" {
		t.Errorf("UnwrapOpenSSHSelector(%q) = %q, want \"\"", bad, got)
	}
	if parser.HasHost(bad) {
		t.Errorf("HasHost(%q) = true, want false", bad)
	}
	if _, err := ParseTargetRef(bad); err == nil {
		t.Errorf("ParseTargetRef(%q) succeeded, want error (parity check)", bad)
	}
	if _, err := parser.GetSSHOptions(bad); err == nil {
		t.Errorf("GetSSHOptions(%q) succeeded, want error", bad)
	}
	if _, err := parser.ResolveProxySetting(bad); err == nil {
		t.Errorf("ResolveProxySetting(%q) succeeded, want error", bad)
	}
}
