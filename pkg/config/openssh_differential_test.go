package config

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
)

func requireOpenSSHBinary(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skipf("ssh binary not found: %v", err)
	}
	return bin
}

// runSSHConfigDump executes `ssh -F <configPath> -G [extraArgs...] <target>` strictly
// offline and parses stdout "<lowerkey> <value>" pairs in appearance order.
func runSSHConfigDump(t *testing.T, sshBin, configPath, target string, extraArgs ...string) map[string][]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	args := make([]string, 0, 4+len(extraArgs))
	args = append(args, "-F", configPath, "-G")
	args = append(args, extraArgs...)
	args = append(args, target)

	cmd := exec.CommandContext(ctx, sshBin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -F %s -G %v %q failed (%v):\n%s", configPath, extraArgs, target, err, out)
	}

	parsed := make(map[string][]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, " ")
		if !ok {
			parsed[strings.ToLower(line)] = append(parsed[strings.ToLower(line)], "")
			continue
		}
		key = strings.ToLower(key)
		parsed[key] = append(parsed[key], val)
	}
	return parsed
}

func sshDumpFirst(dump map[string][]string, key string) string {
	vals := dump[strings.ToLower(key)]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func normalizeOpenSSHBool(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes":
		return "yes"
	case "false", "no":
		return "no"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func normalizeOpenSSHProxyJumpValue(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "none") {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		p := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), OpenSSHNodePrefix))
		if p != "" && !strings.EqualFold(p, "none") {
			out = append(out, p)
		}
	}
	return out
}

func normalizeOpenSSHDurationSeconds(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return n, true
	}
	enabled, indef, d, err := ssh.ParseControlPersist(raw)
	if err != nil {
		return 0, false
	}
	if !enabled || indef {
		return 0, true
	}
	return int(d.Seconds()), true
}

type sshConfigDiffCase struct {
	name              string
	host              string
	checkForwardAgent bool
	checkProxy        bool
	checkIdentities   bool
	explicitIDs       []string
	expectIDNone      bool
	checkSendEnv      bool
	checkSetEnv       bool
	checkControl      bool
	checkTransport    bool
	checkSessionCmd   bool
	checkTrustBatch   bool
	checkAlgoAuth     bool
	checkCertAgent    bool
	checkForwardsExec bool
}

func TestOpenSSHConfigDifferentialOracle(t *testing.T) {
	sshBin := requireOpenSSHBinary(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	tmpDir := t.TempDir()
	mainCfgPath := setupOpenSSHDiffMainFixture(t, tmpDir)
	parser, err := NewOpenSSHParserFromPath(mainCfgPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath failed: %v", err)
	}

	t.Run("concrete_and_wildcard_host_resolution", func(t *testing.T) {
		assertOpenSSHDiffConcreteAndWildcard(t, parser)
	})

	for _, tc := range openSSHDiffCases() {
		t.Run(tc.name, func(t *testing.T) {
			runOpenSSHDiffCase(t, sshBin, mainCfgPath, parser, tc)
		})
	}

	t.Run("27_top_level_directives_before_first_host", func(t *testing.T) {
		assertOpenSSHDiffTopLevelBlock(t, sshBin, tmpDir)
	})
}

func setupOpenSSHDiffMainFixture(t *testing.T, tmpDir string) string {
	t.Helper()
	incDir := filepath.Join(tmpDir, "inc")
	globDir := filepath.Join(tmpDir, "glob.d")
	if err := os.MkdirAll(incDir, 0o700); err != nil {
		t.Fatalf("MkdirAll incDir: %v", err)
	}
	if err := os.MkdirAll(globDir, 0o700); err != nil {
		t.Fatalf("MkdirAll globDir: %v", err)
	}

	writeCfgFile(t, filepath.Join(incDir, "nested.conf"), `
Host inc-target
    Port 2244
    SendEnv NESTED_OK
    IdentityFile ~/.ssh/id_nested
`)
	writeCfgFile(t, filepath.Join(incDir, "z.conf"), fmt.Sprintf(`
Include %s/nested.conf

Host z-override
    User from-z
    Port 2209
    SendEnv Z_VAR
    SetEnv ENV_ORDER=from-z

Host inc-app
    SendEnv -FOO_* BAR
    SetEnv INC_KEY=from-inc DUP=inc
`, incDir))
	writeCfgFile(t, filepath.Join(incDir, "a.conf"), `
Host z-override
    User from-a
    Port 2210
    SendEnv A_VAR
    SetEnv ENV_ORDER=from-a
`)
	writeCfgFile(t, filepath.Join(globDir, "10-first.conf"), `
Host glob-host
    User glob-first
    Port 2211
    SendEnv GLOB_1
`)
	writeCfgFile(t, filepath.Join(globDir, "20-second.conf"), `
Host glob-host
    User glob-second
    Port 2212
    SendEnv GLOB_2
`)
	writeCfgFile(t, filepath.Join(incDir, "cond-only-other.conf"), `
Host cond-app
    User wrong-included-user
    Port 2299
    ProxyCommand evil-cond-cmd %h %p
`)
	writeCfgFile(t, filepath.Join(incDir, "cond-app.conf"), `
Host cond-app
    Port 2255
    SendEnv COND_INCLUDED
`)
	writeCfgFile(t, filepath.Join(incDir, "cond-bare.conf"), `
Port 2288
SendEnv FROM_COND_BARE
`)

	mainCfgPath := filepath.Join(tmpDir, "ssh_config")
	mainCfg := fmt.Sprintf(`
# Lead comment
Include %s/z.conf %s/a.conf %s/*.conf

Host exact-basic
    HostName 10.10.0.1
    User alice
    Port 2222
    IdentityFile ~/.ssh/id_custom
    ForwardAgent yes
    IdentitiesOnly yes
    HashKnownHosts yes
    Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
    ConnectTimeout 12
    ServerAliveInterval 20
    RequestTTY yes
    EscapeChar %%
    ControlMaster auto
    ControlPath ~/.ssh/cm-%%C
    ControlPersist 5m
    GatewayPorts yes

Host eq-and-tab
    HostName=10.10.0.2
    User = bob
    Port	2233
    ProxyCommand	/bin/sh -c "echo ok #keep-hash" # trailing

Host HASH-CASE
    HostName 10.10.0.3
    user caseuser
    pOrT 2234

Host multi-a multi-b
    HostName %%h.internal.example
    User multiuser
    Port 2235

Host *.corp.example !bad.corp.example
    User corpuser
    Port 2236

Host bad.corp.example
    HostName 10.10.0.99
    User baduser
    Port 2299

Host quoted-cmd
    HostName 10.10.0.4
    User qcmd
    ProxyCommand "/usr/bin/nc" "%%h" "%%p"
    SetEnv "FOO=hello world"
    SetEnv "FOO=ignored" "BAR=ignored"
    RemoteCommand echo "hi #keep"

Host quoted-setenv-multi
    HostName 10.10.0.5
    User qenv
    SetEnv "FOO=hello" "BAR=world"

Host quoted-sendenv
    HostName 10.10.0.6
    User qsenv
    SendEnv "LC_*" "LANG"

Host inc-app
    HostName 10.10.0.7
    User incapp
    SendEnv FOO_1 FOO_2
    Include %s/z.conf

Host inc-app
    SendEnv -BAR BAZ

Host outer-bare
    HostName 10.10.0.17
    User bareuser
    Include %s/cond-bare.conf

Host proxy-cmd-none-explicit
    HostName 10.10.0.9
    User pcmdnone
    ProxyCommand none

Host proxy-jump-none
    HostName 10.10.0.10
    User pjumpnone
    ProxyJump none

Host proxy-jump-first
    HostName 10.10.0.11
    User pjfirst
    ProxyJump bastion-a,ops@bastion-b:2222
    ProxyCommand overridden-cmd %%h %%p

Host proxy-cmd-first
    HostName 10.10.0.12
    User pcfirst
    ProxyCommand ssh -W %%h:%%p bastion-c
    ProxyJump overridden-jump

Host only-other-outer
    Include %s/cond-only-other.conf

Host cond-app
    HostName 10.10.0.13
    User conduser
    Include %s/cond-app.conf

Host fe80::1%%eth0 fe80::1%%hn0
    User v6zone

Host id-none
    HostName 10.10.0.14
    User idnone
    IdentityFile none

Host id-order
    HostName 10.10.0.15
    User idorder
    IdentityFile ~/.ssh/id_first
    IdentityFile ~/.ssh/id_second

Host canon-check
    HostName 10.10.0.16
    User canonuser
    CanonicalizeHostname no
    CanonicalDomains corp.example dev.example
    CanonicalizeMaxDots 2
    CanonicalizeFallbackLocal no

Host trust-batch
    HostName 10.10.0.18
    User trustuser
    StrictHostKeyChecking accept-new
    VerifyHostKeyDNS ask
    UserKnownHostsFile %s/kh_user_1 %s/kh_user_2
    GlobalKnownHostsFile %s/kh_global
    BatchMode yes

Host trust-batch-off
    HostName 10.10.0.19
    User trustoff
    StrictHostKeyChecking no
    VerifyHostKeyDNS no
    HashKnownHosts no
    BatchMode no

Host algo-auth
    HostName 10.10.0.20
    User algouser
    KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
    HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
    PreferredAuthentications publickey,keyboard-interactive,password
    PasswordAuthentication no
    PubkeyAuthentication yes
    KbdInteractiveAuthentication no

Host algo-auth-toggles
    HostName 10.10.0.21
    User algotoggle
    PasswordAuthentication yes
    PubkeyAuthentication no
    KbdInteractiveAuthentication yes

Host cert-agent
    HostName 10.10.0.22
    User certuser
    CertificateFile %s/id_a-cert.pub
    CertificateFile %s/id_b-cert.pub
    IdentityAgent %s/agent.sock

Host cert-agent-none
    HostName 10.10.0.23
    User certnone
    CertificateFile none
    IdentityAgent none

Host agent-env
    HostName 10.10.0.24
    User agentenv
    IdentityAgent SSH_AUTH_SOCK

Host fwd-localexec
    HostName 10.10.0.25
    User fwduser
    LocalForward 127.0.0.1:8080 10.0.0.1:80
    LocalForward 9090 [::1]:9000
    RemoteForward 127.0.0.1:8443 127.0.0.1:443
    RemoteForward 0
    DynamicForward 127.0.0.1:1080
    DynamicForward 1081
    PermitLocalCommand yes
    LocalCommand echo hi %%h %%p

Host *
    User fallback-user
    Port 2200
    ProxyJump fallback-bastion
    ProxyCommand fallback-cmd %%h %%p
    SendEnv FOO_1 GLOBAL
    SetEnv GLOBAL_ENV=fallback
    IdentityFile ~/.ssh/id_global
`, incDir, incDir, globDir, incDir, incDir, incDir, incDir, tmpDir, tmpDir, tmpDir, tmpDir, tmpDir, tmpDir)
	writeCfgFile(t, mainCfgPath, mainCfg)
	return mainCfgPath
}

func assertOpenSSHDiffConcreteAndWildcard(t *testing.T, parser *OpenSSHParser) {
	t.Helper()
	concreteHosts := []string{
		"exact-basic", "eq-and-tab", "HASH-CASE", "multi-a", "multi-b",
		"bad.corp.example", "z-override", "inc-target", "glob-host", "cond-app",
	}
	for _, h := range concreteHosts {
		if !parser.HasHost(h) {
			t.Errorf("HasHost(%q) = false, want true", h)
		}
	}
	for _, nonConcrete := range []string{"web.corp.example", "unknown-host"} {
		if parser.HasHost(nonConcrete) {
			t.Errorf("HasHost(%q) = true, want false (wildcard only)", nonConcrete)
		}
	}
}

func openSSHDiffCases() []sshConfigDiffCase {
	return []sshConfigDiffCase{
		{
			name:              "01_exact_basic_options",
			host:              "exact-basic",
			checkForwardAgent: true,
			checkControl:      true,
			checkTransport:    true,
			checkIdentities:   true,
			explicitIDs:       []string{"~/.ssh/id_custom", "~/.ssh/id_global"},
		},
		{name: "02_equals_tab_and_inline_hash_comment", host: "eq-and-tab", checkProxy: true, checkSendEnv: true},
		{name: "03_case_insensitive_keywords", host: "HASH-CASE"},
		{name: "04_multi_pattern_host_and_percent_h_first", host: "multi-a"},
		{name: "05_multi_pattern_host_second", host: "multi-b"},
		{name: "06_wildcard_with_negation_match", host: "app.corp.example"},
		{name: "07_wildcard_negation_falls_through_to_exact_block", host: "bad.corp.example"},
		{name: "08_wildcard_no_match_falls_back_to_star", host: "unlisted.example"},
		{name: "09_quoted_proxy_setenv_single_and_remote_cmd", host: "quoted-cmd", checkProxy: true, checkSetEnv: true, checkSessionCmd: true},
		{name: "10_quoted_setenv_multi_pair", host: "quoted-setenv-multi", checkSetEnv: true},
		{name: "11_quoted_sendenv", host: "quoted-sendenv", checkSendEnv: true},
		{name: "12_sendenv_and_setenv_across_include_top_down", host: "inc-app", checkSendEnv: true, checkSetEnv: true},
		{name: "13_multi_pattern_include_left_to_right_z_before_a", host: "z-override", checkSendEnv: true, checkSetEnv: true},
		{name: "14_nested_include", host: "inc-target", checkSendEnv: true},
		{name: "15_single_glob_lexical_order", host: "glob-host", checkSendEnv: true},
		{name: "16_proxy_command_none_blocks_lower_proxyjump", host: "proxy-cmd-none-explicit", checkProxy: true},
		{name: "17_proxy_jump_none_allows_lower_proxycommand", host: "proxy-jump-none", checkProxy: true},
		{name: "18_proxy_jump_first_wins_over_proxy_command", host: "proxy-jump-first", checkProxy: true},
		{name: "19_proxy_command_first_wins_over_proxy_jump", host: "proxy-cmd-first", checkProxy: true},
		{name: "20_conditional_include_inside_matching_and_nonmatching_host", host: "cond-app", checkProxy: true, checkSendEnv: true},
		{name: "21_ipv6_link_local_zone_no_percent_expansion_eth0", host: "fe80::1%eth0"},
		{name: "22_ipv6_link_local_zone_no_percent_expansion_hn0", host: "fe80::1%hn0"},
		{name: "23_identityfile_none_sentinel", host: "id-none", checkIdentities: true, expectIDNone: true},
		{
			name:            "24_identityfile_accumulation_order",
			host:            "id-order",
			checkIdentities: true,
			explicitIDs:     []string{"~/.ssh/id_first", "~/.ssh/id_second", "~/.ssh/id_global"},
		},
		{name: "25_canonicalize_directives_offline", host: "canon-check", checkTransport: true},
		{name: "26_conditional_include_bare_directives", host: "outer-bare", checkSendEnv: true},
		{name: "28_trust_and_batch_mode_tier4_policy_and_parity", host: "trust-batch", checkTrustBatch: true},
		{name: "29_trust_off_and_hash_known_hosts_one_way_yes", host: "trust-batch-off", checkTrustBatch: true},
		{name: "30_algorithms_and_auth_methods_parity", host: "algo-auth", checkAlgoAuth: true},
		{name: "31_auth_method_boolean_toggles", host: "algo-auth-toggles", checkAlgoAuth: true},
		{name: "32_certificate_files_and_identity_agent", host: "cert-agent", checkCertAgent: true},
		{name: "33_certificate_file_and_identity_agent_none", host: "cert-agent-none", checkCertAgent: true},
		{name: "34_identity_agent_ssh_auth_sock", host: "agent-env", checkCertAgent: true},
		{name: "35_forwards_and_local_command_parity", host: "fwd-localexec", checkForwardsExec: true},
	}
}

func runOpenSSHDiffCase(t *testing.T, sshBin, mainCfgPath string, parser *OpenSSHParser, tc sshConfigDiffCase) {
	t.Helper()
	dump := runSSHConfigDump(t, sshBin, mainCfgPath, tc.host)
	node, host, ident, err := parser.GetVirtualNode(tc.host)
	if err != nil {
		t.Fatalf("GetVirtualNode(%q) error = %v", tc.host, err)
	}
	opts, err := parser.GetSSHOptions(tc.host)
	if err != nil {
		t.Fatalf("GetSSHOptions(%q) error = %v", tc.host, err)
	}

	if wantHost := sshDumpFirst(dump, "hostname"); host.Address != wantHost {
		t.Errorf("host.Address = %q, ssh -G = %q", host.Address, wantHost)
	}
	if wantUser := sshDumpFirst(dump, "user"); ident.User != wantUser {
		t.Errorf("ident.User = %q, ssh -G = %q", ident.User, wantUser)
	}
	wantPort, convErr := strconv.Atoi(sshDumpFirst(dump, "port"))
	if convErr != nil {
		t.Fatalf("invalid ssh -G port %q: %v", sshDumpFirst(dump, "port"), convErr)
	}
	if int(host.Port) != wantPort {
		t.Errorf("host.Port = %d, ssh -G = %d", host.Port, wantPort)
	}
	assertOpenSSHDiffCaseOptions(t, dump, parser, node.ProxyJump, opts, tc)
}

func assertOpenSSHDiffCaseOptions(
	t *testing.T,
	dump map[string][]string,
	parser *OpenSSHParser,
	proxyJump string,
	opts *ssh.Options,
	tc sshConfigDiffCase,
) {
	t.Helper()
	if tc.checkProxy {
		assertDifferentialProxy(t, dump, proxyJump, opts)
	}
	expectedIDs := tc.explicitIDs
	expectedDumpIDs := tc.explicitIDs
	if tc.expectIDNone {
		// P5 Finding 4.2: core/ssh Options.Append truncates subsequent IdentityFile
		// entries within a single layer while preserving the "none" sentinel, whereas
		// raw `ssh -G` still dumps later Host * IdentityFile lines after "none".
		expectedIDs = []string{"none"}
		expectedDumpIDs = []string{"none", "~/.ssh/id_global"}
	}
	if tc.checkIdentities {
		assertDifferentialIdentityFiles(t, dump, opts, expectedIDs, expectedDumpIDs, tc.expectIDNone)
	}
	if tc.checkSendEnv {
		assertDifferentialSendEnv(t, dump, opts)
	}
	if tc.checkSetEnv {
		assertDifferentialSetEnv(t, dump, opts)
	}
	if tc.checkForwardAgent {
		wantFA := normalizeOpenSSHBool(sshDumpFirst(dump, "forwardagent"))
		if normalizeOpenSSHBool(opts.ForwardAgent()) != wantFA {
			t.Errorf("ForwardAgent = %q, ssh -G = %q", opts.ForwardAgent(), wantFA)
		}
	}
	if tc.checkControl {
		assertDifferentialControl(t, dump, parser, tc.host, opts)
	}
	if tc.checkTransport {
		assertDifferentialTransport(t, dump, opts, tc.host == "canon-check")
	}
	if tc.checkSessionCmd {
		wantRC := sshDumpFirst(dump, "remotecommand")
		if opts.RemoteCommand() != wantRC {
			t.Errorf("RemoteCommand = %q, ssh -G = %q", opts.RemoteCommand(), wantRC)
		}
	}
	if tc.checkTrustBatch {
		assertDifferentialTrustAndBatch(t, dump, opts, tc.host)
	}
	if tc.checkAlgoAuth {
		assertDifferentialAlgoAndAuth(t, dump, opts, tc.host)
	}
	if tc.checkCertAgent {
		assertDifferentialCertAndAgent(t, dump, opts, tc.host)
	}
	if tc.checkForwardsExec {
		assertDifferentialForwardsAndLocalExec(t, dump, opts)
	}
}

func assertOpenSSHDiffTopLevelBlock(t *testing.T, sshBin, tmpDir string) {
	t.Helper()
	topPath := filepath.Join(tmpDir, "top_level.conf")
	writeCfgFile(t, topPath, `
Port 2290
SendEnv TOP_SEND

Host named
    HostName 10.20.0.1
    User topuser

Host *
    User staruser
    Port 2201
`)
	p, err := NewOpenSSHParserFromPath(topPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath: %v", err)
	}
	for _, target := range []string{"named", "unlisted-top"} {
		dump := runSSHConfigDump(t, sshBin, topPath, target)
		_, host, ident, err := p.GetVirtualNode(target)
		if err != nil {
			t.Fatalf("GetVirtualNode(%q): %v", target, err)
		}
		opts, err := p.GetSSHOptions(target)
		if err != nil {
			t.Fatalf("GetSSHOptions(%q): %v", target, err)
		}
		wantPort, _ := strconv.Atoi(sshDumpFirst(dump, "port"))
		if int(host.Port) != wantPort {
			t.Errorf("%s port = %d, ssh -G = %d", target, host.Port, wantPort)
		}
		if ident.User != sshDumpFirst(dump, "user") {
			t.Errorf("%s user = %q, ssh -G = %q", target, ident.User, sshDumpFirst(dump, "user"))
		}
		if !slices.Contains(opts.SendEnvPatterns(), "TOP_SEND") {
			t.Errorf("%s missing top-level SendEnv TOP_SEND: %v", target, opts.SendEnvPatterns())
		}
	}
}

func assertDifferentialProxy(t *testing.T, dump map[string][]string, nodeJump string, opts *ssh.Options) {
	t.Helper()
	wantJump := normalizeOpenSSHProxyJumpValue(sshDumpFirst(dump, "proxyjump"))
	gotJump := normalizeOpenSSHProxyJumpValue(nodeJump)
	if !slices.Equal(gotJump, wantJump) {
		t.Errorf("ProxyJump = %v (raw %q), ssh -G = %v (raw %q)", gotJump, nodeJump, wantJump, sshDumpFirst(dump, "proxyjump"))
	}

	wantCmd := strings.TrimSpace(sshDumpFirst(dump, "proxycommand"))
	gotCmd := ""
	if opts != nil {
		gotCmd = strings.TrimSpace(opts.ActiveProxyCommand())
	}
	if strings.EqualFold(wantCmd, "none") {
		wantCmd = ""
	}
	if gotCmd != wantCmd {
		t.Errorf("ActiveProxyCommand = %q, ssh -G = %q", gotCmd, wantCmd)
	}
}

func assertDifferentialIdentityFiles(t *testing.T, dump map[string][]string, opts *ssh.Options, wantOpts, wantDump []string, expectNone bool) {
	t.Helper()
	dumpIDs := dump["identityfile"]
	if opts == nil {
		t.Fatalf("opts is nil, want identity files %v", wantOpts)
	}
	if !slices.Equal(opts.IdentityFiles(), wantOpts) {
		t.Errorf("opts.IdentityFiles() = %v, want %v", opts.IdentityFiles(), wantOpts)
	}
	if expectNone {
		if !slices.Equal(dumpIDs, wantDump) {
			t.Errorf("ssh -G identityfile for IdentityFile=none = %v, want %v", dumpIDs, wantDump)
		}
		return
	}
	if len(dumpIDs) < len(wantDump) || !slices.Equal(dumpIDs[:len(wantDump)], wantDump) {
		t.Errorf("ssh -G identityfile prefix = %v, want prefix %v", dumpIDs, wantDump)
	}
}

func assertDifferentialSendEnv(t *testing.T, dump map[string][]string, opts *ssh.Options) {
	t.Helper()
	wantSend := dump["sendenv"]
	sendOnly := opts.Clone()
	if sendOnly != nil {
		sendOnly.Delete(ssh.OptionSetEnv)
	}
	envKeys := []string{
		"FOO_1", "FOO_2", "BAR", "BAZ", "GLOBAL",
		"NESTED_OK", "Z_VAR", "A_VAR", "GLOB_1", "GLOB_2",
		"COND_INCLUDED", "FROM_COND_BARE", "LANG", "LC_ALL",
	}
	gotVars, err := ssh.ResolveSessionEnv(sendOnly, func() []string {
		out := make([]string, 0, len(envKeys))
		for _, k := range envKeys {
			out = append(out, k+"=1")
		}
		return out
	})
	if err != nil {
		t.Fatalf("ResolveSessionEnv(sendenv) error: %v", err)
	}
	var gotNames []string
	for _, ev := range gotVars {
		gotNames = append(gotNames, ev.Name)
	}
	var wantNames []string
	for _, k := range envKeys {
		matched := false
		for _, pat := range wantSend {
			if ok, _ := filepath.Match(pat, k); ok {
				matched = true
				break
			}
		}
		if matched {
			wantNames = append(wantNames, k)
		}
	}
	slices.Sort(gotNames)
	slices.Sort(wantNames)
	if !slices.Equal(gotNames, wantNames) {
		t.Errorf("resolved SendEnv names = %v (patterns=%v), ssh -G names = %v (dump=%v)", gotNames, opts.SendEnvPatterns(), wantNames, wantSend)
	}
}

func assertDifferentialSetEnv(t *testing.T, dump map[string][]string, opts *ssh.Options) {
	t.Helper()
	wantSet := dump["setenv"]
	gotVars, err := ssh.ResolveSessionEnv(opts, nil)
	if err != nil {
		t.Fatalf("ResolveSessionEnv(setenv) error: %v", err)
	}
	var gotSet []string
	for _, ev := range gotVars {
		gotSet = append(gotSet, ev.Name+"="+ev.Value)
	}
	if !slices.Equal(gotSet, wantSet) {
		t.Errorf("SetEnv resolved = %v (raw directives=%v), ssh -G = %v", gotSet, opts.SetEnvDirectives(), wantSet)
	}
}

func assertDifferentialControl(t *testing.T, dump map[string][]string, parser *OpenSSHParser, host string, opts *ssh.Options) {
	t.Helper()
	ctrl, err := parser.GetControlConfig(host)
	if err != nil {
		t.Fatalf("GetControlConfig(%q) error = %v", host, err)
	}
	if ctrl == nil {
		t.Fatalf("GetControlConfig(%q) = nil", host)
	}
	if got, want := string(ctrl.Master), strings.ToLower(sshDumpFirst(dump, "controlmaster")); got != want {
		t.Errorf("ControlMaster = %q, ssh -G = %q", got, want)
	}
	gotSec, ok1 := normalizeOpenSSHDurationSeconds(ctrl.Persist)
	wantSec, ok2 := normalizeOpenSSHDurationSeconds(sshDumpFirst(dump, "controlpersist"))
	if !ok1 || !ok2 || gotSec != wantSec {
		t.Errorf("ControlPersist = %q (%ds), ssh -G = %q (%ds)", ctrl.Persist, gotSec, sshDumpFirst(dump, "controlpersist"), wantSec)
	}
	if opts == nil {
		t.Fatal("opts is nil")
	}
	if opts.EscapeChar() != sshDumpFirst(dump, "escapechar") {
		t.Errorf("EscapeChar = %q, ssh -G = %q", opts.EscapeChar(), sshDumpFirst(dump, "escapechar"))
	}
	if got := normalizeOpenSSHBool(string(opts.RequestTTY())); got != normalizeOpenSSHBool(sshDumpFirst(dump, "requesttty")) {
		t.Errorf("RequestTTY = %q, ssh -G = %q", opts.RequestTTY(), sshDumpFirst(dump, "requesttty"))
	}
	if gp, ok := opts.GatewayPorts(); !ok || normalizeOpenSSHBool(strconv.FormatBool(gp)) != normalizeOpenSSHBool(sshDumpFirst(dump, "gatewayports")) {
		t.Errorf("GatewayPorts = (%v, %v), ssh -G = %q", gp, ok, sshDumpFirst(dump, "gatewayports"))
	}
}

func assertDifferentialTransport(t *testing.T, dump map[string][]string, opts *ssh.Options, isCanonCase bool) {
	t.Helper()
	if opts == nil {
		t.Fatal("opts is nil")
	}
	if isCanonCase {
		wantMode := normalizeOpenSSHBool(sshDumpFirst(dump, "canonicalizehostname"))
		if normalizeOpenSSHBool(opts.CanonicalizeHostname()) != wantMode {
			t.Errorf("CanonicalizeHostname = %q, ssh -G = %q", opts.CanonicalizeHostname(), wantMode)
		}
		wantDomains := strings.Fields(sshDumpFirst(dump, "canonicaldomains"))
		if !slices.Equal(opts.CanonicalDomains(), wantDomains) {
			t.Errorf("CanonicalDomains = %v, ssh -G = %v", opts.CanonicalDomains(), wantDomains)
		}
		wantDots, _ := strconv.Atoi(sshDumpFirst(dump, "canonicalizemaxdots"))
		if gotDots, ok := opts.CanonicalizeMaxDots(); !ok || gotDots != wantDots {
			t.Errorf("CanonicalizeMaxDots = (%d, %v), ssh -G = %d", gotDots, ok, wantDots)
		}
		wantFB := normalizeOpenSSHBool(sshDumpFirst(dump, "canonicalizefallbacklocal"))
		if gotFB, ok := opts.CanonicalizeFallbackLocal(); !ok || normalizeOpenSSHBool(strconv.FormatBool(gotFB)) != wantFB {
			t.Errorf("CanonicalizeFallbackLocal = (%v, %v), ssh -G = %q", gotFB, ok, wantFB)
		}
		return
	}

	if opts.Ciphers() != sshDumpFirst(dump, "ciphers") {
		t.Errorf("Ciphers = %q, ssh -G = %q", opts.Ciphers(), sshDumpFirst(dump, "ciphers"))
	}
	wantCT, _ := strconv.Atoi(sshDumpFirst(dump, "connecttimeout"))
	if int(opts.ConnectTimeout().Seconds()) != wantCT {
		t.Errorf("ConnectTimeout = %v, ssh -G = %ds", opts.ConnectTimeout(), wantCT)
	}
	wantSAI, _ := strconv.Atoi(sshDumpFirst(dump, "serveraliveinterval"))
	if int(opts.ServerAliveInterval().Seconds()) != wantSAI {
		t.Errorf("ServerAliveInterval = %v, ssh -G = %ds", opts.ServerAliveInterval(), wantSAI)
	}
	if !opts.IdentitiesOnly() || normalizeOpenSSHBool(sshDumpFirst(dump, "identitiesonly")) != "yes" {
		t.Errorf("IdentitiesOnly = %v, ssh -G = %q", opts.IdentitiesOnly(), sshDumpFirst(dump, "identitiesonly"))
	}
	if !opts.HashKnownHosts() || normalizeOpenSSHBool(sshDumpFirst(dump, "hashknownhosts")) != "yes" {
		t.Errorf("HashKnownHosts = %v, ssh -G = %q", opts.HashKnownHosts(), sshDumpFirst(dump, "hashknownhosts"))
	}
}

func assertDifferentialTrustAndBatch(t *testing.T, dump map[string][]string, opts *ssh.Options, host string) {
	t.Helper()
	if opts == nil {
		t.Fatal("opts is nil")
	}
	wantBatch := normalizeOpenSSHBool(sshDumpFirst(dump, "batchmode"))
	gotBatch := normalizeOpenSSHBool(opts.Get(ssh.OptionBatchMode))
	if gotBatch != wantBatch || opts.BatchMode() != (wantBatch == "yes") {
		t.Errorf("BatchMode = (%q, %v), ssh -G = %q", opts.Get(ssh.OptionBatchMode), opts.BatchMode(), wantBatch)
	}

	// Host-trust options carry OptionTier4Deny in core/ssh so ~/.ssh/config cannot
	// implicitly weaken host key trust; verify both the fail-closed Tier-4 denial
	// AND exact semantic parity when the same directives are supplied explicitly via CLI.
	if opts.StrictHostKeyChecking() != "" {
		t.Errorf("Tier-4 StrictHostKeyChecking must be denied (empty), got %q", opts.StrictHostKeyChecking())
	}
	if opts.VerifyHostKeyDNS() != "" {
		t.Errorf("Tier-4 VerifyHostKeyDNS must be denied (empty), got %q", opts.VerifyHostKeyDNS())
	}
	if opts.UserKnownHostsFile() != "" {
		t.Errorf("Tier-4 UserKnownHostsFile must be denied (empty), got %q", opts.UserKnownHostsFile())
	}
	if opts.GlobalKnownHostsFile() != "" {
		t.Errorf("Tier-4 GlobalKnownHostsFile must be denied (empty), got %q", opts.GlobalKnownHostsFile())
	}
	if host == "trust-batch-off" && opts.HashKnownHosts() {
		t.Error("Tier-4 HashKnownHosts=no must not enable HashKnownHosts")
	}

	cliDirectives := []string{
		"StrictHostKeyChecking=" + sshDumpFirst(dump, "stricthostkeychecking"),
		"VerifyHostKeyDNS=" + sshDumpFirst(dump, "verifyhostkeydns"),
	}
	if host == "trust-batch" {
		cliDirectives = append(cliDirectives,
			"UserKnownHostsFile="+sshDumpFirst(dump, "userknownhostsfile"),
			"GlobalKnownHostsFile="+sshDumpFirst(dump, "globalknownhostsfile"),
		)
	}
	cliOpts, err := ssh.ParseCLIOptions(cliDirectives)
	if err != nil {
		t.Fatalf("ParseCLIOptions(%v) failed: %v", cliDirectives, err)
	}
	if got, want := cliOpts.StrictHostKeyChecking(), normalizeOpenSSHBool(sshDumpFirst(dump, "stricthostkeychecking")); got != want {
		t.Errorf("CLI StrictHostKeyChecking = %q, ssh -G = %q", got, want)
	}
	if got, want := cliOpts.VerifyHostKeyDNS(), normalizeOpenSSHBool(sshDumpFirst(dump, "verifyhostkeydns")); got != want {
		t.Errorf("CLI VerifyHostKeyDNS = %q, ssh -G = %q", got, want)
	}
	if host == "trust-batch" {
		if got, want := cliOpts.UserKnownHostsFile(), sshDumpFirst(dump, "userknownhostsfile"); got != want {
			t.Errorf("CLI UserKnownHostsFile = %q, ssh -G = %q", got, want)
		}
		if got, want := cliOpts.GlobalKnownHostsFile(), sshDumpFirst(dump, "globalknownhostsfile"); got != want {
			t.Errorf("CLI GlobalKnownHostsFile = %q, ssh -G = %q", got, want)
		}
	}
}

func assertDifferentialAlgoAndAuth(t *testing.T, dump map[string][]string, opts *ssh.Options, host string) {
	t.Helper()
	if opts == nil {
		t.Fatal("opts is nil")
	}
	if host == "algo-auth" {
		if got, want := opts.KexAlgorithms(), sshDumpFirst(dump, "kexalgorithms"); got != want {
			t.Errorf("KexAlgorithms = %q, ssh -G = %q", got, want)
		}
		if got, want := opts.MACs(), sshDumpFirst(dump, "macs"); got != want {
			t.Errorf("MACs = %q, ssh -G = %q", got, want)
		}
		if got, want := opts.HostKeyAlgorithms(), sshDumpFirst(dump, "hostkeyalgorithms"); got != want {
			t.Errorf("HostKeyAlgorithms = %q, ssh -G = %q", got, want)
		}
		if got, want := strings.Join(opts.PreferredAuthentications(), ","), sshDumpFirst(dump, "preferredauthentications"); got != want {
			t.Errorf("PreferredAuthentications = %q, ssh -G = %q", got, want)
		}
	}
	assertDiffBoolGetter(t, "PasswordAuthentication", dump, "passwordauthentication", opts.PasswordAuthentication)
	assertDiffBoolGetter(t, "PubkeyAuthentication", dump, "pubkeyauthentication", opts.PubkeyAuthentication)
	assertDiffBoolGetter(t, "KbdInteractiveAuthentication", dump, "kbdinteractiveauthentication", opts.KbdInteractiveAuthentication)
}

func assertDiffBoolGetter(t *testing.T, name string, dump map[string][]string, dumpKey string, getter func() (bool, bool)) {
	t.Helper()
	got, ok := getter()
	want := normalizeOpenSSHBool(sshDumpFirst(dump, dumpKey))
	if !ok || normalizeOpenSSHBool(strconv.FormatBool(got)) != want {
		t.Errorf("%s = (%v, %v), ssh -G = %q", name, got, ok, sshDumpFirst(dump, dumpKey))
	}
}

func assertDifferentialCertAndAgent(t *testing.T, dump map[string][]string, opts *ssh.Options, host string) {
	t.Helper()
	if opts == nil {
		t.Fatal("opts is nil")
	}
	if got, want := opts.IdentityAgent(), sshDumpFirst(dump, "identityagent"); got != want {
		t.Errorf("IdentityAgent = %q, ssh -G = %q", got, want)
	}
	if host == "agent-env" {
		return
	}
	if got, want := opts.CertificateFiles(), dump["certificatefile"]; !slices.Equal(got, want) {
		t.Errorf("CertificateFiles = %v, ssh -G = %v", got, want)
	}
}

func normalizeSSHDumpLocalForwards(t *testing.T, raw []string) []string {
	t.Helper()
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		spec, err := ssh.ParseForwardSpec(entry)
		if err != nil {
			t.Fatalf("ParseForwardSpec(%q) from ssh -G: %v", entry, err)
		}
		out = append(out, spec.String())
	}
	return out
}

func normalizeSSHDumpRemoteForwards(t *testing.T, raw []string) []string {
	t.Helper()
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		trimmed := strings.TrimSpace(entry)
		// OpenSSH `ssh -G` formats reverse dynamic RemoteForward as "<bind> [socks]:0".
		if bind, ok := strings.CutSuffix(trimmed, " [socks]:0"); ok {
			trimmed = strings.TrimSpace(bind)
		}
		spec, err := ssh.ParseRemoteForwardSpec(trimmed)
		if err != nil {
			t.Fatalf("ParseRemoteForwardSpec(%q) from ssh -G: %v", entry, err)
		}
		out = append(out, spec.String())
	}
	return out
}

func normalizeSSHDumpDynamicForwards(t *testing.T, raw []string) []string {
	t.Helper()
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		norm, err := ssh.ParseDynamicForwardSpec(entry)
		if err != nil {
			t.Fatalf("ParseDynamicForwardSpec(%q) from ssh -G: %v", entry, err)
		}
		out = append(out, norm)
	}
	return out
}

func assertDifferentialForwardsAndLocalExec(t *testing.T, dump map[string][]string, opts *ssh.Options) {
	t.Helper()
	if opts == nil {
		t.Fatal("opts is nil")
	}
	wantLocal := normalizeSSHDumpLocalForwards(t, dump["localforward"])
	if got := opts.LocalForwards(); !slices.Equal(got, wantLocal) {
		t.Errorf("LocalForwards = %v, ssh -G normalized = %v (raw=%v)", got, wantLocal, dump["localforward"])
	}
	wantRemote := normalizeSSHDumpRemoteForwards(t, dump["remoteforward"])
	if got := opts.RemoteForwards(); !slices.Equal(got, wantRemote) {
		t.Errorf("RemoteForwards = %v, ssh -G normalized = %v (raw=%v)", got, wantRemote, dump["remoteforward"])
	}
	wantDyn := normalizeSSHDumpDynamicForwards(t, dump["dynamicforward"])
	if got := opts.DynamicForwards(); !slices.Equal(got, wantDyn) {
		t.Errorf("DynamicForwards = %v, ssh -G normalized = %v (raw=%v)", got, wantDyn, dump["dynamicforward"])
	}
	wantPermit := normalizeOpenSSHBool(sshDumpFirst(dump, "permitlocalcommand"))
	if normalizeOpenSSHBool(strconv.FormatBool(opts.PermitLocalCommand())) != wantPermit {
		t.Errorf("PermitLocalCommand = %v, ssh -G = %q", opts.PermitLocalCommand(), sshDumpFirst(dump, "permitlocalcommand"))
	}
	if got, want := opts.LocalCommand(), sshDumpFirst(dump, "localcommand"); got != want {
		t.Errorf("LocalCommand = %q, ssh -G = %q", got, want)
	}
}

func writeNestedIncludeChain(t *testing.T, dir string, hops int, leafHost string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
	for i := 0; i <= hops; i++ {
		curPath := filepath.Join(dir, fmt.Sprintf("lvl%02d.conf", i))
		if i < hops {
			nextPath := filepath.Join(dir, fmt.Sprintf("lvl%02d.conf", i+1))
			writeCfgFile(t, curPath, fmt.Sprintf("Include %s\n", nextPath))
			continue
		}
		writeCfgFile(t, curPath, fmt.Sprintf("Host %s\n    HostName 10.99.0.%d\n    User deepuser\n", leafHost, hops))
	}
	return filepath.Join(dir, "lvl00.conf")
}

// TestOpenSSHConfigDifferential_IncludeDepthFailClosed verifies that both real
// `ssh -F <cfg> -G` and `NewOpenSSHParserFromPath` accept depth == 16 and fail
// closed on a 17-level nested Include chain (depth > 16).
func TestOpenSSHConfigDifferential_IncludeDepthFailClosed(t *testing.T) {
	sshBin := requireOpenSSHBinary(t)
	tmpDir := t.TempDir()

	okCfg := writeNestedIncludeChain(t, filepath.Join(tmpDir, "depth16"), maxIncludeDepth, "depth-ok")
	okDump := runSSHConfigDump(t, sshBin, okCfg, "depth-ok")
	okParser, err := NewOpenSSHParserFromPath(okCfg)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath(depth=%d) failed: %v", maxIncludeDepth, err)
	}
	_, okHost, _, err := okParser.GetVirtualNode("depth-ok")
	if err != nil {
		t.Fatalf("GetVirtualNode(depth-ok): %v", err)
	}
	if want := sshDumpFirst(okDump, "hostname"); okHost.Address != want {
		t.Fatalf("depth-ok HostName = %q, ssh -G = %q", okHost.Address, want)
	}

	failCfg := writeNestedIncludeChain(t, filepath.Join(tmpDir, "depth17"), maxIncludeDepth+1, "depth-fail")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	out, sshErr := exec.CommandContext(ctx, sshBin, "-F", failCfg, "-G", "depth-fail").CombinedOutput()
	if sshErr == nil {
		t.Fatalf("expected ssh -F %s -G depth-fail (depth=%d) to fail closed, but it succeeded:\n%s", failCfg, maxIncludeDepth+1, out)
	}
	if _, parseErr := NewOpenSSHParserFromPath(failCfg); parseErr == nil || !strings.Contains(parseErr.Error(), "depth limit") {
		t.Fatalf("expected NewOpenSSHParserFromPath(depth=%d) to fail closed with depth limit error, got %v", maxIncludeDepth+1, parseErr)
	}
}

func effectiveOpenSSHRuntimeIdentityFiles(dumpIDs []string) []string {
	out := make([]string, 0, len(dumpIDs))
	for _, id := range dumpIDs {
		if ssh.IsNoneValue(id) {
			if len(out) == 0 {
				return []string{"none"}
			}
			return out
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

type multiLayerMergeFn func(t *testing.T, cli []string) (*ssh.Options, map[string][]string)

// TestOpenSSHConfigDifferential_MultiLayerCLIOverride compares real
// `ssh -F <cfg> -o <cliOpts...> -G <host>` against `ssh.ParseCLIOptions` +
// `ssh.MergeEffectiveOptions(cliOpts, parserOpts)` across scalar override,
// IdentityFile=none truncation, SendEnv/SetEnv ordering, ControlPath=none
// cross-layer disable, and trust/algorithm overrides.
func TestOpenSSHConfigDifferential_MultiLayerCLIOverride(t *testing.T) {
	sshBin := requireOpenSSHBinary(t)
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "multi_layer.conf")
	writeCfgFile(t, cfgPath, fmt.Sprintf(`
Host ml-host
    HostName 10.30.0.1
    User mluser
    ConnectTimeout 15
    ServerAliveInterval 30
    ServerAliveCountMax 5
    RequestTTY no
    IdentityFile %s/id_cfg_1
    IdentityFile %s/id_cfg_2
    SendEnv CFG_A CFG_B
    SetEnv K=cfg ONLY_CFG=1
    ControlMaster auto
    ControlPath %s/cm-%%C
    ControlPersist 10m
    KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
    HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
    PreferredAuthentications publickey,password
    StrictHostKeyChecking no
    VerifyHostKeyDNS no
`, tmpDir, tmpDir, tmpDir))

	parser, err := NewOpenSSHParserFromPath(cfgPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath: %v", err)
	}
	parserOpts, err := parser.GetSSHOptions("ml-host")
	if err != nil {
		t.Fatalf("GetSSHOptions(ml-host): %v", err)
	}

	mergeCLI := func(t *testing.T, cli []string) (*ssh.Options, map[string][]string) {
		t.Helper()
		cliOpts, parseErr := ssh.ParseCLIOptions(cli)
		if parseErr != nil {
			t.Fatalf("ParseCLIOptions(%v): %v", cli, parseErr)
		}
		eff, mergeErr := ssh.MergeEffectiveOptions(cliOpts, parserOpts)
		if mergeErr != nil {
			t.Fatalf("MergeEffectiveOptions(%v): %v", cli, mergeErr)
		}
		extraArgs := make([]string, 0, len(cli)*2)
		for _, opt := range cli {
			extraArgs = append(extraArgs, "-o", opt)
		}
		return eff, runSSHConfigDump(t, sshBin, cfgPath, "ml-host", extraArgs...)
	}

	t.Run("scalar_and_trust_and_algorithm_overrides", func(t *testing.T) {
		assertMultiLayerScalarTrustAlgo(t, tmpDir, mergeCLI)
	})
	t.Run("identityfile_none_truncation_and_prepend", func(t *testing.T) {
		assertMultiLayerIdentityFileNone(t, tmpDir, mergeCLI)
	})
	t.Run("sendenv_and_setenv_cross_layer_ordering", func(t *testing.T) {
		assertMultiLayerEnvOrdering(t, mergeCLI)
	})
	t.Run("controlpath_none_disables_config_multiplexing", func(t *testing.T) {
		assertMultiLayerControlPathNone(t, mergeCLI)
	})
}

func assertMultiLayerScalarTrustAlgo(t *testing.T, tmpDir string, mergeCLI multiLayerMergeFn) {
	t.Helper()
	cliKH := filepath.Join(tmpDir, "cli_kh")
	cliGKH := filepath.Join(tmpDir, "cli_gkh")
	eff, dump := mergeCLI(t, []string{
		"ConnectTimeout=5",
		"RequestTTY=force",
		"StrictHostKeyChecking=yes",
		"VerifyHostKeyDNS=ask",
		"UserKnownHostsFile=" + cliKH,
		"GlobalKnownHostsFile=" + cliGKH,
		"KexAlgorithms=curve25519-sha256",
		"MACs=hmac-sha2-512-etm@openssh.com",
		"HostKeyAlgorithms=ssh-ed25519",
		"PreferredAuthentications=publickey",
	})
	wantCT, _ := strconv.Atoi(sshDumpFirst(dump, "connecttimeout"))
	if int(eff.ConnectTimeout().Seconds()) != wantCT {
		t.Errorf("ConnectTimeout = %v, ssh -G = %ds", eff.ConnectTimeout(), wantCT)
	}
	wantSAI, _ := strconv.Atoi(sshDumpFirst(dump, "serveraliveinterval"))
	if int(eff.ServerAliveInterval().Seconds()) != wantSAI {
		t.Errorf("ServerAliveInterval = %v, ssh -G = %ds", eff.ServerAliveInterval(), wantSAI)
	}
	wantSCM, _ := strconv.Atoi(sshDumpFirst(dump, "serveralivecountmax"))
	if eff.ServerAliveCountMax() != wantSCM {
		t.Errorf("ServerAliveCountMax = %d, ssh -G = %d", eff.ServerAliveCountMax(), wantSCM)
	}
	assertMultiLayerStringParity(t, "RequestTTY", string(eff.RequestTTY()), strings.ToLower(sshDumpFirst(dump, "requesttty")))
	assertMultiLayerStringParity(t, "StrictHostKeyChecking", eff.StrictHostKeyChecking(), normalizeOpenSSHBool(sshDumpFirst(dump, "stricthostkeychecking")))
	assertMultiLayerStringParity(t, "VerifyHostKeyDNS", eff.VerifyHostKeyDNS(), normalizeOpenSSHBool(sshDumpFirst(dump, "verifyhostkeydns")))
	assertMultiLayerStringParity(t, "UserKnownHostsFile", eff.UserKnownHostsFile(), sshDumpFirst(dump, "userknownhostsfile"))
	assertMultiLayerStringParity(t, "GlobalKnownHostsFile", eff.GlobalKnownHostsFile(), sshDumpFirst(dump, "globalknownhostsfile"))
	assertMultiLayerStringParity(t, "KexAlgorithms", eff.KexAlgorithms(), sshDumpFirst(dump, "kexalgorithms"))
	assertMultiLayerStringParity(t, "MACs", eff.MACs(), sshDumpFirst(dump, "macs"))
	assertMultiLayerStringParity(t, "HostKeyAlgorithms", eff.HostKeyAlgorithms(), sshDumpFirst(dump, "hostkeyalgorithms"))
	assertMultiLayerStringParity(t, "PreferredAuthentications", strings.Join(eff.PreferredAuthentications(), ","), sshDumpFirst(dump, "preferredauthentications"))
}

func assertMultiLayerStringParity(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, ssh -G = %q", field, got, want)
	}
}

func assertMultiLayerIdentityFileNone(t *testing.T, tmpDir string, mergeCLI multiLayerMergeFn) {
	t.Helper()
	cliKey := filepath.Join(tmpDir, "id_cli_1")
	for _, tc := range []struct {
		name string
		cli  []string
		want []string
	}{
		{"cli_none_blocks_config", []string{"IdentityFile=none"}, []string{"none"}},
		{"cli_key_then_none_blocks_config", []string{"IdentityFile=" + cliKey, "IdentityFile=none"}, []string{cliKey}},
		{"cli_key_prepends_before_config", []string{"IdentityFile=" + cliKey}, []string{cliKey, filepath.Join(tmpDir, "id_cfg_1"), filepath.Join(tmpDir, "id_cfg_2")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, dump := mergeCLI(t, tc.cli)
			wantFromOracle := effectiveOpenSSHRuntimeIdentityFiles(dump["identityfile"])
			if !slices.Equal(eff.IdentityFiles(), tc.want) {
				t.Errorf("eff.IdentityFiles() = %v, want %v", eff.IdentityFiles(), tc.want)
			}
			if !slices.Equal(eff.IdentityFiles(), wantFromOracle) {
				t.Errorf("eff.IdentityFiles() = %v disagrees with ssh -G runtime effective %v (raw=%v)", eff.IdentityFiles(), wantFromOracle, dump["identityfile"])
			}
		})
	}
}

func assertMultiLayerEnvOrdering(t *testing.T, mergeCLI multiLayerMergeFn) {
	t.Helper()
	effAdd, dumpAdd := mergeCLI(t, []string{"SendEnv=CLI_C", "SetEnv=K=cli CLI_ONLY=2"})
	envKeys := []string{"CFG_A", "CFG_B", "CLI_C"}
	sendOnly := effAdd.Clone()
	sendOnly.Delete(ssh.OptionSetEnv)
	gotSendVars, err := ssh.ResolveSessionEnv(sendOnly, func() []string {
		return []string{"CFG_A=1", "CFG_B=1", "CLI_C=1"}
	})
	if err != nil {
		t.Fatalf("ResolveSessionEnv(send): %v", err)
	}
	var gotNames, wantNames []string
	for _, ev := range gotSendVars {
		gotNames = append(gotNames, ev.Name)
	}
	for _, k := range envKeys {
		if slices.Contains(dumpAdd["sendenv"], k) {
			wantNames = append(wantNames, k)
		}
	}
	slices.Sort(gotNames)
	slices.Sort(wantNames)
	if !slices.Equal(gotNames, wantNames) {
		t.Errorf("SendEnv resolved = %v, ssh -G = %v", gotNames, wantNames)
	}

	gotSetVars, err := ssh.ResolveSessionEnv(effAdd, nil)
	if err != nil {
		t.Fatalf("ResolveSessionEnv(set): %v", err)
	}
	gotSetMap := make(map[string]string, len(gotSetVars))
	for _, ev := range gotSetVars {
		gotSetMap[ev.Name] = ev.Value
	}
	for _, wantPair := range dumpAdd["setenv"] {
		if k, v, ok := strings.Cut(wantPair, "="); ok && gotSetMap[k] != v {
			t.Errorf("SetEnv[%q] = %q, ssh -G = %q", k, gotSetMap[k], v)
		}
	}
	if gotSetMap["ONLY_CFG"] != "1" {
		t.Errorf("layered SetEnv dropped non-conflicting config key ONLY_CFG: %v", gotSetMap)
	}

	effExcl, _ := mergeCLI(t, []string{"SendEnv=-CFG_A CLI_C"})
	exclSendOnly := effExcl.Clone()
	exclSendOnly.Delete(ssh.OptionSetEnv)
	exclVars, err := ssh.ResolveSessionEnv(exclSendOnly, func() []string {
		return []string{"CFG_A=1", "CFG_B=1", "CLI_C=1"}
	})
	if err != nil {
		t.Fatalf("ResolveSessionEnv(excl): %v", err)
	}
	var exclNames []string
	for _, ev := range exclVars {
		exclNames = append(exclNames, ev.Name)
	}
	slices.Sort(exclNames)
	if !slices.Equal(exclNames, []string{"CFG_B", "CLI_C"}) {
		t.Errorf("CLI SendEnv=-CFG_A resolved = %v, want [CFG_B CLI_C]", exclNames)
	}
}

func assertMultiLayerControlPathNone(t *testing.T, mergeCLI multiLayerMergeFn) {
	t.Helper()
	eff, dump := mergeCLI(t, []string{"ControlPath=none"})
	dumpCP := strings.TrimSpace(sshDumpFirst(dump, "controlpath"))
	if dumpCP != "" && !ssh.IsNoneValue(dumpCP) {
		t.Fatalf("expected ssh -G ControlPath=none to disable controlpath, got %q", dumpCP)
	}
	if !ssh.IsNoneValue(eff.ControlPath()) {
		t.Errorf("eff.ControlPath() = %q, want none", eff.ControlPath())
	}
	if eff.ControlMaster() != ssh.ControlMasterNo {
		t.Errorf("eff.ControlMaster() = %q, want no", eff.ControlMaster())
	}
	if eff.ControlPersist() != "" {
		t.Errorf("eff.ControlPersist() = %q, want empty", eff.ControlPersist())
	}
	if ctrl := eff.ControlConfig(); ctrl != nil && ctrl.IsEnabled() {
		t.Errorf("eff.ControlConfig().IsEnabled() = true, want false (%+v)", ctrl)
	}
}

func writeCfgFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.TrimLeft(content, "\n")), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}
