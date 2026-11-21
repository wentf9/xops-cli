package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

type p2OptionSample struct {
	val1    string
	val2    string
	invalid string
}

func p2AllOptionSamples() map[string]p2OptionSample {
	return map[string]p2OptionSample{
		ssh.OptionControlMaster:                {val1: "auto", val2: "yes", invalid: "bogus-master"},
		ssh.OptionControlPath:                  {val1: "~/.ssh/cm-%C", val2: "/tmp/alt-%h.sock", invalid: "/tmp/bad-%k.sock"},
		ssh.OptionControlPersist:               {val1: "10m", val2: "30s", invalid: "not-a-duration"},
		ssh.OptionAddressFamily:                {val1: "inet", val2: "inet6", invalid: "ipx"},
		ssh.OptionConnectTimeout:               {val1: "15", val2: "30", invalid: "forever"},
		ssh.OptionServerAliveInterval:          {val1: "30", val2: "60", invalid: "never"},
		ssh.OptionServerAliveCountMax:          {val1: "3", val2: "5", invalid: "-2"},
		ssh.OptionTCPKeepAlive:                 {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionStrictHostKeyChecking:        {val1: "accept-new", val2: "no", invalid: "sometimes"},
		ssh.OptionUserKnownHostsFile:           {val1: "~/.ssh/known_hosts /etc/ssh/extra", val2: "/tmp/kh", invalid: "/tmp/bad-%k"},
		ssh.OptionGlobalKnownHostsFile:         {val1: "/etc/ssh/ssh_known_hosts /etc/ssh/kh2", val2: "/etc/ssh/kh3", invalid: "/tmp/bad-%k"},
		ssh.OptionHashKnownHosts:               {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionVerifyHostKeyDNS:             {val1: "ask", val2: "yes", invalid: "bogus"},
		ssh.OptionCanonicalizeHostname:         {val1: "yes", val2: "always", invalid: "never"},
		ssh.OptionCanonicalDomains:             {val1: "dev.example.com corp.example.com", val2: "lab.example.com", invalid: "bad..domain!"},
		ssh.OptionCanonicalizeMaxDots:          {val1: "2", val2: "4", invalid: "-1"},
		ssh.OptionCanonicalizeFallbackLocal:    {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionCanonicalizePermittedCNAMEs:  {val1: "*.internal:*.prod.example.com *.dev:*.stage", val2: "*.a:*.b", invalid: "missingcolon"},
		ssh.OptionIdentityFile:                 {val1: "~/.ssh/id_ed25519", val2: "~/.ssh/id_rsa", invalid: "~/.ssh/bad-%k"},
		ssh.OptionCertificateFile:              {val1: "~/.ssh/id_ed25519-cert.pub", val2: "~/.ssh/id_rsa-cert.pub", invalid: "~/.ssh/bad-%k"},
		ssh.OptionIdentityAgent:                {val1: "SSH_AUTH_SOCK", val2: "none", invalid: "/tmp/bad-%k"},
		ssh.OptionPubkeyAuthentication:         {val1: "yes", val2: "no", invalid: "unbound"},
		ssh.OptionPasswordAuthentication:       {val1: "no", val2: "yes", invalid: "maybe"},
		ssh.OptionKbdInteractiveAuthentication: {val1: "no", val2: "yes", invalid: "maybe"},
		ssh.OptionIdentitiesOnly:               {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionPreferredAuthentications:     {val1: "publickey,password", val2: "password", invalid: "unsupported-auth-method"},
		ssh.OptionBatchMode:                    {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionHostKeyAlgorithms:            {val1: "ssh-ed25519", val2: "ecdsa-sha2-nistp256", invalid: "bogus-hostkey-algo"},
		ssh.OptionCiphers:                      {val1: "aes256-gcm@openssh.com", val2: "chacha20-poly1305@openssh.com", invalid: "bogus-cipher-algo"},
		ssh.OptionMACs:                         {val1: "hmac-sha2-256-etm@openssh.com", val2: "hmac-sha2-512-etm@openssh.com", invalid: "bogus-mac-algo"},
		ssh.OptionKexAlgorithms:                {val1: "curve25519-sha256", val2: "diffie-hellman-group14-sha256", invalid: "bogus-kex-algo"},
		ssh.OptionExitOnForwardFailure:         {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionClearAllForwardings:          {val1: "no", val2: "yes", invalid: "maybe"},
		ssh.OptionForwardAgent:                 {val1: "yes", val2: "no", invalid: "/tmp/bad-%k"},
		ssh.OptionGatewayPorts:                 {val1: "clientspecified", val2: "yes", invalid: "always"},
		ssh.OptionStreamLocalBindUnlink:        {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionStreamLocalBindMask:          {val1: "0177", val2: "0117", invalid: "9999"},
		ssh.OptionForkAfterAuthentication:      {val1: "no", val2: "yes", invalid: "maybe"},
		ssh.OptionStdinNull:                    {val1: "yes", val2: "no", invalid: "maybe"},
		ssh.OptionSessionType:                  {val1: "default", val2: "none", invalid: "bogus"},
		ssh.OptionTunnel:                       {val1: "point-to-point", val2: "ethernet", invalid: "bridge"},
		ssh.OptionTunnelDevice:                 {val1: "0:any", val2: "1:2", invalid: "bad:dev:spec"},
		ssh.OptionRequestTTY:                   {val1: "force", val2: "no", invalid: "sometimes"},
		ssh.OptionLocalForward:                 {val1: "127.0.0.1:8080 10.0.0.2:80", val2: "127.0.0.1:8081 10.0.0.3:81", invalid: "not-a-forward"},
		ssh.OptionRemoteForward:                {val1: "*:9090 127.0.0.1:9000", val2: "*:9091 127.0.0.1:9001", invalid: "not-a-forward"},
		ssh.OptionDynamicForward:               {val1: "127.0.0.1:1080", val2: "127.0.0.1:1081", invalid: "not-a-port:abc:def"},
		ssh.OptionSendEnv:                      {val1: "LANG LC_*", val2: "COLORTERM", invalid: "BAD=NAME"},
		ssh.OptionSetEnv:                       {val1: `FOO="hello world" BAR=baz`, val2: "BAZ=qux", invalid: "MISSING_EQUALS"},
		ssh.OptionRemoteCommand:                {val1: "tmux attach || tmux new", val2: "uname -a", invalid: "bad\x00cmd"},
		ssh.OptionEscapeChar:                   {val1: "^A", val2: "none", invalid: "toolong"},
		ssh.OptionProxyCommand:                 {val1: "nc %h %p", val2: "ssh -W %h:%p bastion", invalid: "bad\x00cmd"},
		ssh.OptionLocalCommand:                 {val1: "echo connected %h", val2: "echo done", invalid: "bad\x00cmd"},
		ssh.OptionPermitLocalCommand:           {val1: "yes", val2: "no", invalid: "maybe"},
	}
}

func TestP2_OpenSSHParserExhaustiveOptionSpecParity(t *testing.T) {
	t.Parallel()

	specs := ssh.RegisteredOptionSpecs()
	samples := p2AllOptionSamples()
	if len(specs) != len(samples) {
		t.Fatalf("RegisteredOptionSpecs count = %d, sample table count = %d", len(specs), len(samples))
	}
	for _, spec := range specs {
		if _, ok := samples[spec.CanonicalKey]; !ok {
			t.Fatalf("missing sample for registered option %q", spec.CanonicalKey)
		}
	}

	t.Run("ConfigSyntax", func(t *testing.T) {
		t.Parallel()
		for _, spec := range specs {
			assertOpenSSHDirectiveSyntaxParity(t, spec)
		}
		assertTargetAndUnknownDirectiveSyntax(t)
	})

	t.Run("Tier4Policy", func(t *testing.T) {
		t.Parallel()
		for _, spec := range specs {
			assertOpenSSHTier4PolicyParity(t, spec, samples[spec.CanonicalKey])
		}
	})

	t.Run("MergeMode", func(t *testing.T) {
		t.Parallel()
		for _, spec := range specs {
			assertOpenSSHMergeModeParity(t, spec, samples[spec.CanonicalKey])
		}
		assertTwoPassNoneTerminatedDedup(t)
	})

	t.Run("StrictInOpenSSHConfig", func(t *testing.T) {
		t.Parallel()
		for _, spec := range specs {
			assertOpenSSHStrictnessParity(t, spec, samples[spec.CanonicalKey])
		}
	})
}

func assertOpenSSHDirectiveSyntaxParity(t *testing.T, spec ssh.OptionSpec) {
	t.Helper()

	names := append([]string{spec.OpenSSHName, spec.CanonicalKey}, spec.Aliases...)
	for _, name := range names {
		assertSingleOpenSSHDirectiveSyntax(t, spec, name)
	}
}

func assertSingleOpenSSHDirectiveSyntax(t *testing.T, spec ssh.OptionSpec, name string) {
	t.Helper()

	lower := strings.ToLower(name)
	gotSyntax, known := ssh.LookupDirectiveSyntax(lower)
	if !known || gotSyntax != spec.ConfigSyntax {
		t.Fatalf("LookupDirectiveSyntax(%q) = (%v, %v), want (%v, true)", name, gotSyntax, known, spec.ConfigSyntax)
	}

	switch spec.ConfigSyntax {
	case ssh.OptionSyntaxWholeLineCommand:
		assertWholeLineCommandSyntax(t, spec, name, lower)
	case ssh.OptionSyntaxRawTokenList:
		assertRawTokenListSyntax(t, spec, name, lower)
	case ssh.OptionSyntaxMultiTokenList:
		assertMultiTokenListSyntax(t, spec, name, lower)
	case ssh.OptionSyntaxStrictScalar:
		assertStrictScalarSyntax(t, spec, name, lower)
	default:
		t.Fatalf("unexpected ConfigSyntax %v for %s", spec.ConfigSyntax, spec.CanonicalKey)
	}
}

func assertWholeLineCommandSyntax(t *testing.T, spec ssh.OptionSpec, name, lower string) {
	t.Helper()
	d, err := parseOpenSSHDirective(1, name, lower, `  cmd "a b" # keep comment  `)
	if err != nil {
		t.Fatalf("%s whole-line command parse failed: %v", name, err)
	}
	want := `cmd "a b" # keep comment`
	if d.value != want || d.rawValue != want || !spec.ConfigSyntax.PreservesRawValue() {
		t.Errorf("%s whole-line = (val=%q, raw=%q), want %q", name, d.value, d.rawValue, want)
	}
}

func assertRawTokenListSyntax(t *testing.T, spec ssh.OptionSpec, name, lower string) {
	t.Helper()
	d, err := parseOpenSSHDirective(1, name, lower, `  A="x y" B=z # trailing comment`)
	if err != nil {
		t.Fatalf("%s raw-token-list parse failed: %v", name, err)
	}
	want := `A="x y" B=z`
	if d.value != want || d.rawValue != want || !spec.ConfigSyntax.PreservesRawValue() {
		t.Errorf("%s raw-token-list = (val=%q, raw=%q), want %q", name, d.value, d.rawValue, want)
	}
}

func assertMultiTokenListSyntax(t *testing.T, spec ssh.OptionSpec, name, lower string) {
	t.Helper()
	d, err := parseOpenSSHDirective(1, name, lower, `  "first"   second # trailing comment`)
	if err != nil {
		t.Fatalf("%s multi-token-list parse failed: %v", name, err)
	}
	if d.value != "first second" || d.rawValue != `"first"   second` || spec.ConfigSyntax.PreservesRawValue() {
		t.Errorf("%s multi-token-list = (val=%q, raw=%q), want val=%q raw=%q",
			name, d.value, d.rawValue, "first second", `"first"   second`)
	}
}

func assertStrictScalarSyntax(t *testing.T, spec ssh.OptionSpec, name, lower string) {
	t.Helper()
	d, err := parseOpenSSHDirective(1, name, lower, `  "single_tok" # comment`)
	if err != nil {
		t.Fatalf("%s strict-scalar single token parse failed: %v", name, err)
	}
	if d.value != "single_tok" || spec.ConfigSyntax.PreservesRawValue() {
		t.Errorf("%s strict-scalar single token = %q, want %q", name, d.value, "single_tok")
	}
	if _, err := parseOpenSSHDirective(1, name, lower, `tok1 tok2`); err == nil || !strings.Contains(err.Error(), "garbage at end of line") {
		t.Errorf("%s strict-scalar multi-token err = %v, want garbage at end of line", name, err)
	}
}

func assertTargetAndUnknownDirectiveSyntax(t *testing.T) {
	t.Helper()

	for _, scalar := range []string{"Port", "User", "HostName"} {
		if _, err := parseOpenSSHDirective(1, scalar, strings.ToLower(scalar), "a b"); err == nil || !strings.Contains(err.Error(), "garbage at end of line") {
			t.Errorf("target directive %s with trailing garbage err = %v, want garbage error", scalar, err)
		}
	}

	pj, err := parseOpenSSHDirective(1, "ProxyJump", "proxyjump", `"jump1"   jump2 # comment`)
	if err != nil || pj.value != "jump1 jump2" {
		t.Fatalf("ProxyJump multi-token parse = (%+v, %v), want val=%q", pj, err, "jump1 jump2")
	}

	unkMulti, err := parseOpenSSHDirective(1, "UnknownFutureOption", "unknownfutureoption", `alpha beta # comment`)
	if err != nil || unkMulti.value != "alpha beta" || unkMulti.rawValue != "alpha beta" {
		t.Fatalf("unknown multi-token directive = (%+v, %v), want alpha beta", unkMulti, err)
	}
	unkSingle, err := parseOpenSSHDirective(1, "UnknownSingleOption", "unknownsingleoption", `"quoted" # comment`)
	if err != nil || unkSingle.value != "quoted" || unkSingle.rawValue != `"quoted"` {
		t.Fatalf("unknown single-token directive = (%+v, %v), want val=quoted raw=\"quoted\"", unkSingle, err)
	}
}

func assertOpenSSHTier4PolicyParity(t *testing.T, spec ssh.OptionSpec, sample p2OptionSample) {
	t.Helper()

	switch spec.Tier4Policy {
	case ssh.OptionTier4Deny:
		cfg := fmt.Sprintf("Host app\n  %s %s\n", spec.OpenSSHName, sample.val1)
		opts := mustGetOpenSSHOptions(t, cfg, "app")
		if opts != nil && opts.Has(spec.CanonicalKey) {
			t.Errorf("Tier4Deny option %s was inherited from ssh_config: %q", spec.CanonicalKey, opts.Get(spec.CanonicalKey))
		}

	case ssh.OptionTier4OneWayYes:
		for _, yesVal := range []string{"yes", "YES", "true", "True"} {
			cfg := fmt.Sprintf("Host app\n  %s %s\n", spec.OpenSSHName, yesVal)
			opts := mustGetOpenSSHOptions(t, cfg, "app")
			if opts == nil || opts.Get(spec.CanonicalKey) != "yes" {
				t.Errorf("Tier4OneWayYes option %s=%q got %v, want yes", spec.CanonicalKey, yesVal, opts)
			}
		}
		for _, noVal := range []string{"no", "NO", "false", "False"} {
			cfg := fmt.Sprintf("Host app\n  %s %s\n", spec.OpenSSHName, noVal)
			opts := mustGetOpenSSHOptions(t, cfg, "app")
			if opts != nil && opts.Has(spec.CanonicalKey) {
				t.Errorf("Tier4OneWayYes option %s=%q should not be inherited, got %q", spec.CanonicalKey, noVal, opts.Get(spec.CanonicalKey))
			}
		}

	case ssh.OptionTier4Inherit:
		cfg := fmt.Sprintf("Host app\n  %s %s\n", spec.OpenSSHName, sample.val1)
		opts := mustGetOpenSSHOptions(t, cfg, "app")
		if opts == nil || !opts.Has(spec.CanonicalKey) {
			t.Fatalf("Tier4Inherit option %s was not inherited from ssh_config", spec.CanonicalKey)
		}
		want, err := spec.Normalize(sample.val1)
		if err != nil {
			t.Fatalf("sample normalize failed for %s: %v", spec.CanonicalKey, err)
		}
		if got := opts.Get(spec.CanonicalKey); got != want {
			t.Errorf("Tier4Inherit option %s = %q, want %q", spec.CanonicalKey, got, want)
		}

	default:
		t.Fatalf("unexpected Tier4Policy %v for %s", spec.Tier4Policy, spec.CanonicalKey)
	}
}

func assertOpenSSHMergeModeParity(t *testing.T, spec ssh.OptionSpec, sample p2OptionSample) {
	t.Helper()

	if spec.Tier4Policy == ssh.OptionTier4Deny || spec.Tier4Policy == ssh.OptionTier4OneWayYes {
		return
	}

	cfg := fmt.Sprintf("Host app\n  %s %s\nHost *\n  %s %s\n",
		spec.OpenSSHName, sample.val1, spec.OpenSSHName, sample.val2)
	opts := mustGetOpenSSHOptions(t, cfg, "app")
	if opts == nil {
		t.Fatalf("%s: expected non-nil options", spec.CanonicalKey)
	}

	switch spec.MergeMode {
	case ssh.OptionMergeFirstWins:
		want, err := spec.Normalize(sample.val1)
		if err != nil {
			t.Fatalf("normalize %s: %v", spec.CanonicalKey, err)
		}
		if got := opts.Get(spec.CanonicalKey); got != want {
			t.Errorf("%s FirstWins = %q, want %q", spec.CanonicalKey, got, want)
		}

	case ssh.OptionMergeSingleDirectiveOrderedEnv:
		got := opts.GetAll(spec.CanonicalKey)
		if len(got) != 1 {
			t.Fatalf("%s SingleDirectivePerLayer got %v, want single first directive", spec.CanonicalKey, got)
		}
		// Invalid first directive must still shadow lower-block valid directive.
		badFirstCfg := fmt.Sprintf("Host app\n  %s %s\nHost *\n  %s %s\n",
			spec.OpenSSHName, sample.invalid, spec.OpenSSHName, sample.val2)
		badFirstOpts := mustGetOpenSSHOptions(t, badFirstCfg, "app")
		if badFirstOpts != nil && badFirstOpts.Has(spec.CanonicalKey) {
			t.Errorf("%s invalid first directive failed to shadow lower block: got %v",
				spec.CanonicalKey, badFirstOpts.GetAll(spec.CanonicalKey))
		}

	case ssh.OptionMergeAppendDedup, ssh.OptionMergeNoneTerminated, ssh.OptionMergeOrderedEnv:
		got := opts.GetAll(spec.CanonicalKey)
		if len(got) < 2 {
			t.Errorf("%s MultiValue (%v) expected >=2 entries across blocks, got %v",
				spec.CanonicalKey, spec.MergeMode, got)
		}

	default:
		t.Fatalf("unexpected MergeMode %v for %s", spec.MergeMode, spec.CanonicalKey)
	}
}

func assertTwoPassNoneTerminatedDedup(t *testing.T) {
	t.Helper()

	cfg := `
Host app
    IdentityFile ~/.ssh/shared_id
    CertificateFile ~/.ssh/shared-cert.pub
    SendEnv LANG

Host app.example.com
    IdentityFile ~/.ssh/shared_id
    IdentityFile ~/.ssh/canon_id
    CertificateFile ~/.ssh/shared-cert.pub
    CertificateFile ~/.ssh/canon-cert.pub
    SendEnv LANG
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("parse ssh config: %v", err)
	}
	opts, err := parser.GetSSHOptionsWithCanonical("app", "app.example.com")
	if err != nil {
		t.Fatalf("GetSSHOptionsWithCanonical: %v", err)
	}
	wantIDs := []string{"~/.ssh/shared_id", "~/.ssh/canon_id"}
	if got := opts.IdentityFiles(); !slices.Equal(got, wantIDs) {
		t.Errorf("IdentityFiles across two passes = %v, want %v", got, wantIDs)
	}
	wantCerts := []string{"~/.ssh/shared-cert.pub", "~/.ssh/canon-cert.pub"}
	if got := opts.CertificateFiles(); !slices.Equal(got, wantCerts) {
		t.Errorf("CertificateFiles across two passes = %v, want %v", got, wantCerts)
	}
	// SendEnv is NOT none-terminated, so distinct directives in Pass 1 and Pass 2 both appear.
	if got := opts.SendEnvPatterns(); !slices.Equal(got, []string{"LANG", "LANG"}) {
		t.Errorf("SendEnvPatterns across two passes = %v, want [LANG LANG]", got)
	}
}

func assertOpenSSHStrictnessParity(t *testing.T, spec ssh.OptionSpec, sample p2OptionSample) {
	t.Helper()

	if sample.invalid == "" {
		t.Fatalf("missing invalid sample for %s", spec.CanonicalKey)
	}
	cfg := fmt.Sprintf("Host app\n  %s %s\n", spec.OpenSSHName, sample.invalid)
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("parse config for %s: %v", spec.CanonicalKey, err)
	}
	opts, err := parser.GetSSHOptions("app")
	if spec.StrictInOpenSSHConfig {
		if err == nil {
			t.Errorf("StrictInOpenSSHConfig option %s accepted invalid value %q (got opts=%v)",
				spec.CanonicalKey, sample.invalid, opts)
		}
		return
	}
	if err != nil {
		t.Errorf("lenient option %s returned unexpected error for %q: %v",
			spec.CanonicalKey, sample.invalid, err)
	}
	if opts != nil && opts.Has(spec.CanonicalKey) {
		t.Errorf("lenient option %s stored invalid value %q as %q",
			spec.CanonicalKey, sample.invalid, opts.Get(spec.CanonicalKey))
	}
}

func mustGetOpenSSHOptions(t *testing.T, content, host string) *ssh.Options {
	t.Helper()

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(content))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	opts, err := parser.GetSSHOptions(host)
	if err != nil {
		t.Fatalf("GetSSHOptions(%q) failed: %v", host, err)
	}
	return opts
}

func TestP2_NormalizeConfigIdentityKeyPathDelegation(t *testing.T) {
	t.Parallel()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	nonPersistable := []string{
		"",
		"   ",
		"none",
		"NONE",
		"~/.ssh/%r_id",
		"~/.ssh/${USER}_id",
		"~/.ssh/bad%z",
		"/tmp/bad\x00key",
		"/tmp/bad\nkey",
		"~xops_definitely_nonexistent_user_p2/id_ed25519",
	}
	for _, raw := range nonPersistable {
		got, err := normalizeConfigIdentityKeyPath(raw)
		if err != nil || got != "" {
			t.Errorf("normalizeConfigIdentityKeyPath(%q) = (%q, %v), want (\"\", nil)", raw, got, err)
		}
	}

	gotConcrete, err := normalizeConfigIdentityKeyPath("  /tmp/my_key  ")
	if err != nil || gotConcrete != "/tmp/my_key" {
		t.Errorf("normalizeConfigIdentityKeyPath concrete = (%q, %v), want (/tmp/my_key, nil)", gotConcrete, err)
	}

	gotTilde, err := normalizeConfigIdentityKeyPath("~/.ssh/id_ed25519")
	wantTilde := filepath.Join(homeDir, ".ssh", "id_ed25519")
	if err != nil || gotTilde != wantTilde {
		t.Errorf("normalizeConfigIdentityKeyPath(~) = (%q, %v), want (%q, nil)", gotTilde, err, wantTilde)
	}
}
