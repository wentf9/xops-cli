package ssh

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestP2_OptionRegistryCompleteness(t *testing.T) {
	t.Parallel()

	specs := RegisteredOptionSpecs()
	if len(specs) == 0 {
		t.Fatal("RegisteredOptionSpecs returned empty slice")
	}

	// Verify AST-discovered Option* constants in ssh_options.go match RegisteredOptionSpecs 1:1.
	astConstants := discoverOptionConstantsFromAST(t)
	expectedConstants := expectedRegisteredOptionSamples()
	if len(astConstants) != len(expectedConstants) {
		t.Fatalf("Option* constant count in ssh_options.go = %d, sample table has %d", len(astConstants), len(expectedConstants))
	}
	for _, key := range astConstants {
		if _, ok := expectedConstants[key]; !ok {
			t.Errorf("Option constant %q in ssh_options.go missing from TestP2 sample table", key)
		}
	}
	if len(specs) != len(astConstants) {
		t.Fatalf("RegisteredOptionSpecs count = %d, Option* constant count = %d", len(specs), len(astConstants))
	}

	assertOptionModeMethods(t)
	assertRegistryUniquenessAndMetadata(t, specs, expectedConstants)
	assertLookupDirectiveSyntaxCompleteness(t, specs)
	assertAllRegisteredOptionsRoundTrip(t, specs, expectedConstants)
}

func discoverOptionConstantsFromAST(t *testing.T) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "ssh_options.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ssh_options.go: %v", err)
	}
	targetLevel := map[string]bool{
		"OptionPort":      true,
		"OptionUser":      true,
		"OptionHostName":  true,
		"OptionProxyJump": true,
	}
	var keys []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			name := vs.Names[0].Name
			if !strings.HasPrefix(name, "Option") || targetLevel[name] {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			// Skip typed OptionClass string constants.
			if vs.Type != nil {
				continue
			}
			unquoted, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("unquote constant %s (%s): %v", name, lit.Value, err)
			}
			keys = append(keys, unquoted)
		}
	}
	return keys
}

func expectedRegisteredOptionSamples() map[string]string {
	return map[string]string{
		OptionControlMaster:                "no",
		OptionControlPath:                  "~/.ssh/cm-%C",
		OptionControlPersist:               "no",
		OptionAddressFamily:                "inet",
		OptionConnectTimeout:               "15s",
		OptionServerAliveInterval:          "30",
		OptionServerAliveCountMax:          "3",
		OptionTCPKeepAlive:                 "yes",
		OptionStrictHostKeyChecking:        "accept-new",
		OptionUserKnownHostsFile:           "~/.ssh/known_hosts /etc/ssh/extra_hosts",
		OptionGlobalKnownHostsFile:         "/etc/ssh/ssh_known_hosts",
		OptionHashKnownHosts:               "yes",
		OptionVerifyHostKeyDNS:             "ask",
		OptionCanonicalizeHostname:         "yes",
		OptionCanonicalDomains:             "dev.example.com corp.example.com",
		OptionCanonicalizeMaxDots:          "2",
		OptionCanonicalizeFallbackLocal:    "yes",
		OptionCanonicalizePermittedCNAMEs:  "*.internal:*.prod.example.com",
		OptionIdentityFile:                 "~/.ssh/id_ed25519",
		OptionCertificateFile:              "~/.ssh/id_ed25519-cert.pub",
		OptionIdentityAgent:                "SSH_AUTH_SOCK",
		OptionPubkeyAuthentication:         "yes",
		OptionPasswordAuthentication:       "no",
		OptionKbdInteractiveAuthentication: "no",
		OptionIdentitiesOnly:               "yes",
		OptionPreferredAuthentications:     "publickey,password",
		OptionBatchMode:                    "yes",
		OptionHostKeyAlgorithms:            "ssh-ed25519,ecdsa-sha2-nistp256",
		OptionCiphers:                      "aes256-gcm@openssh.com",
		OptionMACs:                         "hmac-sha2-256-etm@openssh.com",
		OptionKexAlgorithms:                "curve25519-sha256",
		OptionExitOnForwardFailure:         "yes",
		OptionClearAllForwardings:          "no",
		OptionForwardAgent:                 "yes",
		OptionGatewayPorts:                 "clientspecified",
		OptionStreamLocalBindUnlink:        "yes",
		OptionStreamLocalBindMask:          "0177",
		OptionForkAfterAuthentication:      "no",
		OptionStdinNull:                    "yes",
		OptionSessionType:                  "default",
		OptionTunnel:                       "point-to-point",
		OptionTunnelDevice:                 "0:any",
		OptionRequestTTY:                   "force",
		OptionLocalForward:                 "127.0.0.1:8080 10.0.0.2:80",
		OptionRemoteForward:                "*:9090 127.0.0.1:9000",
		OptionDynamicForward:               "127.0.0.1:1080",
		OptionSendEnv:                      "LANG",
		OptionSetEnv:                       `FOO="hello world" BAR=baz`,
		OptionRemoteCommand:                "tmux attach || tmux new",
		OptionEscapeChar:                   "^A",
		OptionProxyCommand:                 "nc %h %p",
		OptionLocalCommand:                 "echo connected %h",
		OptionPermitLocalCommand:           "yes",
	}
}

func assertOptionModeMethods(t *testing.T) {
	t.Helper()

	mergeCases := []struct {
		mode           OptionMergeMode
		multi          bool
		ordered        bool
		noneTerminated bool
		singlePerLayer bool
	}{
		{OptionMergeUnset, false, false, false, false},
		{OptionMergeFirstWins, false, false, false, true},
		{OptionMergeAppendDedup, true, false, false, false},
		{OptionMergeNoneTerminated, true, false, true, false},
		{OptionMergeOrderedEnv, true, true, false, false},
		{OptionMergeSingleDirectiveOrderedEnv, true, true, false, true},
	}
	for _, tc := range mergeCases {
		if tc.mode.IsMultiValue() != tc.multi ||
			tc.mode.IsOrderedOverride() != tc.ordered ||
			tc.mode.IsNoneTerminated() != tc.noneTerminated ||
			tc.mode.SingleDirectivePerLayer() != tc.singlePerLayer {
			t.Errorf("OptionMergeMode(%d) methods = (multi=%v, ordered=%v, noneTerm=%v, single=%v), want (%v, %v, %v, %v)",
				tc.mode,
				tc.mode.IsMultiValue(), tc.mode.IsOrderedOverride(), tc.mode.IsNoneTerminated(), tc.mode.SingleDirectivePerLayer(),
				tc.multi, tc.ordered, tc.noneTerminated, tc.singlePerLayer,
			)
		}
	}

	syntaxCases := []struct {
		syntax      OptionConfigSyntax
		preservesRV bool
	}{
		{OptionSyntaxUnset, false},
		{OptionSyntaxStrictScalar, false},
		{OptionSyntaxMultiTokenList, false},
		{OptionSyntaxRawTokenList, true},
		{OptionSyntaxWholeLineCommand, true},
	}
	for _, tc := range syntaxCases {
		if tc.syntax.PreservesRawValue() != tc.preservesRV {
			t.Errorf("OptionConfigSyntax(%d).PreservesRawValue() = %v, want %v",
				tc.syntax, tc.syntax.PreservesRawValue(), tc.preservesRV)
		}
	}
}

func assertRegistryUniquenessAndMetadata(t *testing.T, specs []OptionSpec, expectedSamples map[string]string) {
	t.Helper()

	seenCanonical := make(map[string]bool, len(specs))
	seenLookup := make(map[string]string, len(specs)*3)
	targetDirectives := map[string]bool{
		"port": true, "user": true, "hostname": true, "proxyjump": true, "proxy_jump": true,
	}

	for _, spec := range specs {
		if spec.CanonicalKey == "" || spec.OpenSSHName == "" {
			t.Errorf("spec missing key/name: %+v", spec)
		}
		if seenCanonical[spec.CanonicalKey] {
			t.Errorf("duplicate CanonicalKey %q", spec.CanonicalKey)
		}
		seenCanonical[spec.CanonicalKey] = true

		if _, ok := expectedSamples[spec.CanonicalKey]; !ok {
			t.Errorf("registered option %q not listed in expected sample table", spec.CanonicalKey)
		}

		// Verify lookup uniqueness across CanonicalKey, OpenSSHName, and Aliases.
		names := append([]string{spec.CanonicalKey, spec.OpenSSHName}, spec.Aliases...)
		localNames := make(map[string]bool, len(names))
		for _, name := range names {
			lower := strings.ToLower(name)
			if targetDirectives[lower] {
				t.Errorf("option %q collides with target-level directive %q", spec.CanonicalKey, name)
			}
			if prev, exists := seenLookup[lower]; exists && !localNames[lower] {
				t.Errorf("duplicate lookup token %q between %q and %q", name, prev, spec.CanonicalKey)
			}
			seenLookup[lower] = spec.CanonicalKey
			localNames[lower] = true
		}

		assertSingleSpecMetadata(t, spec)
	}
}

func assertSingleSpecMetadata(t *testing.T, spec OptionSpec) {
	t.Helper()

	if spec.Class == "" {
		t.Errorf("%s: Class is empty", spec.CanonicalKey)
	}
	if spec.MergeMode == OptionMergeUnset {
		t.Errorf("%s: MergeMode is unset", spec.CanonicalKey)
	}
	if spec.ConfigSyntax == OptionSyntaxUnset {
		t.Errorf("%s: ConfigSyntax is unset", spec.CanonicalKey)
	}
	if spec.Tier4Policy == OptionTier4Unset {
		t.Errorf("%s: Tier4Policy is unset", spec.CanonicalKey)
	}
	if spec.MuxPolicy == OptionMuxUnset {
		t.Errorf("%s: MuxPolicy is unset", spec.CanonicalKey)
	}
	if spec.Normalize == nil {
		t.Errorf("%s: Normalize is nil", spec.CanonicalKey)
	}
	if spec.MultiValue != spec.MergeMode.IsMultiValue() {
		t.Errorf("%s: MultiValue=%v disagrees with MergeMode.IsMultiValue()=%v",
			spec.CanonicalKey, spec.MultiValue, spec.MergeMode.IsMultiValue())
	}
	if spec.AllowList && !spec.StrictInOpenSSHConfig {
		t.Errorf("%s: AllowList=true must imply StrictInOpenSSHConfig=true", spec.CanonicalKey)
	}

	assertSpecTier4Policy(t, spec)
	assertSpecStrictConfig(t, spec)
	assertSpecMuxPolicy(t, spec)
	assertSpecMergeAndSyntax(t, spec)
}

func assertSpecTier4Policy(t *testing.T, spec OptionSpec) {
	t.Helper()

	var want OptionTier4Policy
	switch spec.CanonicalKey {
	case OptionStrictHostKeyChecking, OptionUserKnownHostsFile, OptionGlobalKnownHostsFile, OptionVerifyHostKeyDNS:
		want = OptionTier4Deny
	case OptionHashKnownHosts:
		want = OptionTier4OneWayYes
	default:
		want = OptionTier4Inherit
	}
	if spec.Tier4Policy != want {
		t.Errorf("%s: Tier4Policy = %d, want %d", spec.CanonicalKey, spec.Tier4Policy, want)
	}
}

func assertSpecStrictConfig(t *testing.T, spec OptionSpec) {
	t.Helper()

	wantStrict := spec.CanonicalKey == OptionControlMaster ||
		spec.CanonicalKey == OptionControlPersist ||
		spec.AllowList
	if spec.StrictInOpenSSHConfig != wantStrict {
		t.Errorf("%s: StrictInOpenSSHConfig = %v, want %v", spec.CanonicalKey, spec.StrictInOpenSSHConfig, wantStrict)
	}
}

func assertSpecMuxPolicy(t *testing.T, spec OptionSpec) {
	t.Helper()

	want := expectedMuxPolicyForSpec(spec)
	if spec.MuxPolicy != want {
		t.Errorf("%s: MuxPolicy = %d, want %d", spec.CanonicalKey, spec.MuxPolicy, want)
	}
}

func expectedMuxPolicyForSpec(spec OptionSpec) OptionMuxPolicy {
	switch spec.CanonicalKey {
	case OptionControlMaster, OptionControlPath, OptionControlPersist, OptionClearAllForwardings, OptionIdentityFile:
		return OptionMuxAuthoritative
	case OptionProxyCommand:
		return OptionMuxAllowNoneOnly
	case OptionGatewayPorts, OptionStreamLocalBindUnlink, OptionStreamLocalBindMask:
		return OptionMuxAllow
	}
	switch spec.Class {
	case OptionClassTransport, OptionClassTrust, OptionClassAuth:
		return OptionMuxAllow
	default:
		return OptionMuxReject
	}
}

func assertSpecMergeAndSyntax(t *testing.T, spec OptionSpec) {
	t.Helper()

	var wantMerge OptionMergeMode
	switch spec.CanonicalKey {
	case OptionLocalForward, OptionRemoteForward, OptionDynamicForward:
		wantMerge = OptionMergeAppendDedup
	case OptionIdentityFile, OptionCertificateFile:
		wantMerge = OptionMergeNoneTerminated
	case OptionSendEnv:
		wantMerge = OptionMergeOrderedEnv
	case OptionSetEnv:
		wantMerge = OptionMergeSingleDirectiveOrderedEnv
	default:
		wantMerge = OptionMergeFirstWins
	}
	if spec.MergeMode != wantMerge {
		t.Errorf("%s: MergeMode = %d, want %d", spec.CanonicalKey, spec.MergeMode, wantMerge)
	}

	var wantSyntax OptionConfigSyntax
	switch spec.CanonicalKey {
	case OptionCanonicalDomains, OptionCanonicalizePermittedCNAMEs, OptionUserKnownHostsFile, OptionGlobalKnownHostsFile:
		wantSyntax = OptionSyntaxMultiTokenList
	case OptionSendEnv, OptionSetEnv, OptionLocalForward, OptionRemoteForward, OptionDynamicForward:
		wantSyntax = OptionSyntaxRawTokenList
	case OptionProxyCommand, OptionLocalCommand, OptionRemoteCommand:
		wantSyntax = OptionSyntaxWholeLineCommand
	default:
		wantSyntax = OptionSyntaxStrictScalar
	}
	if spec.ConfigSyntax != wantSyntax {
		t.Errorf("%s: ConfigSyntax = %d, want %d", spec.CanonicalKey, spec.ConfigSyntax, wantSyntax)
	}
}

func assertLookupDirectiveSyntaxCompleteness(t *testing.T, specs []OptionSpec) {
	t.Helper()

	for _, spec := range specs {
		tokens := append([]string{spec.CanonicalKey, spec.OpenSSHName, "  " + strings.ToUpper(spec.OpenSSHName) + " "}, spec.Aliases...)
		for _, tok := range tokens {
			got, ok := LookupDirectiveSyntax(tok)
			if !ok || got != spec.ConfigSyntax {
				t.Errorf("LookupDirectiveSyntax(%q) = (%d, %v), want (%d, true)", tok, got, ok, spec.ConfigSyntax)
			}
		}
	}

	targetCases := []struct {
		key  string
		want OptionConfigSyntax
	}{
		{"port", OptionSyntaxStrictScalar},
		{"Port", OptionSyntaxStrictScalar},
		{"USER", OptionSyntaxStrictScalar},
		{"HostName", OptionSyntaxStrictScalar},
		{"  hostname  ", OptionSyntaxStrictScalar},
		{"ProxyJump", OptionSyntaxMultiTokenList},
		{"proxyjump", OptionSyntaxMultiTokenList},
		{"proxy_jump", OptionSyntaxMultiTokenList},
	}
	for _, tc := range targetCases {
		got, ok := LookupDirectiveSyntax(tc.key)
		if !ok || got != tc.want {
			t.Errorf("LookupDirectiveSyntax(%q) = (%d, %v), want (%d, true)", tc.key, got, ok, tc.want)
		}
	}

	for _, bad := range []string{"", "   ", "Host", "Match", "Include", "NoSuchDirective"} {
		if got, ok := LookupDirectiveSyntax(bad); ok || got != OptionSyntaxUnset {
			t.Errorf("LookupDirectiveSyntax(%q) = (%d, %v), want (OptionSyntaxUnset, false)", bad, got, ok)
		}
	}
}

func assertAllRegisteredOptionsRoundTrip(t *testing.T, specs []OptionSpec, samples map[string]string) {
	t.Helper()

	for _, spec := range specs {
		sample := samples[spec.CanonicalKey]
		cliInput := []string{spec.OpenSSHName + "=" + sample}
		parsed, err := ParseCLIOptions(cliInput)
		if err != nil {
			t.Fatalf("%s: ParseCLIOptions(%q) failed: %v", spec.CanonicalKey, cliInput[0], err)
		}
		merged, err := MergeEffectiveOptions(parsed)
		if err != nil {
			t.Fatalf("%s: MergeEffectiveOptions failed: %v", spec.CanonicalKey, err)
		}
		projected := ProjectCLIOptions(merged)
		if len(projected) != 1 {
			t.Fatalf("%s: ProjectCLIOptions = %v, want 1 entry", spec.CanonicalKey, projected)
		}
		reparsedLayer, err := ParseCLIOptions(projected)
		if err != nil {
			t.Fatalf("%s: re-ParseCLIOptions(%v) failed: %v", spec.CanonicalKey, projected, err)
		}
		reparsed, err := MergeEffectiveOptions(reparsedLayer)
		if err != nil {
			t.Fatalf("%s: re-MergeEffectiveOptions failed: %v", spec.CanonicalKey, err)
		}
		reprojected := ProjectCLIOptions(reparsed)
		if !slices.Equal(reprojected, projected) {
			t.Errorf("%s: round-trip not idempotent: first=%v second=%v", spec.CanonicalKey, projected, reprojected)
		}
	}

	// Also verify active ControlMaster + ControlPersist + ControlPath combination.
	muxParsed, err := ParseCLIOptions([]string{
		"ControlMaster=auto",
		"ControlPath=~/.ssh/cm-%C",
		"ControlPersist=10m",
	})
	if err != nil {
		t.Fatalf("ParseCLIOptions active mux: %v", err)
	}
	muxMerged, err := MergeEffectiveOptions(muxParsed)
	if err != nil {
		t.Fatalf("MergeEffectiveOptions active mux: %v", err)
	}
	muxProj := ProjectCLIOptions(muxMerged)
	wantMuxProj := []string{
		"ControlMaster=auto",
		"ControlPath=~/.ssh/cm-%C",
		"ControlPersist=10m",
	}
	if !slices.Equal(muxProj, wantMuxProj) {
		t.Fatalf("ProjectCLIOptions active mux = %v, want %v", muxProj, wantMuxProj)
	}
}

func TestP2_SplitOptionKeyValue(t *testing.T) {
	t.Parallel()

	valid := []struct {
		in      string
		wantKey string
		wantVal string
	}{
		{"LocalForward=8080:127.0.0.1:80", "LocalForward", "8080:127.0.0.1:80"},
		{"LocalForward 8080 127.0.0.1:80", "LocalForward", "8080 127.0.0.1:80"},
		{"LocalForward\t8080 127.0.0.1:80", "LocalForward", "8080 127.0.0.1:80"},
		{"LocalForward = 8080:127.0.0.1:80", "LocalForward", "8080:127.0.0.1:80"},
		{"Tunnel ethernet", "Tunnel", "ethernet"},
		{"Tunnel=ethernet", "Tunnel", "ethernet"},
		{"Tunnel = ethernet", "Tunnel", "ethernet"},
		{"Tunnel = ", "Tunnel", ""},
		{"ControlPath=", "ControlPath", ""},
		{"EscapeChar==", "EscapeChar", "="},
		{"RemoteCommand==foo bar", "RemoteCommand", "=foo bar"},
		{"SetEnv=FOO=bar BAZ=qux", "SetEnv", "FOO=bar BAZ=qux"},
		{"SetEnv = FOO=bar", "SetEnv", "FOO=bar"},
		{"", "", ""},
		{"   \t  ", "", ""},
	}
	for _, tc := range valid {
		k, v, err := SplitOptionKeyValue(tc.in)
		if err != nil {
			t.Errorf("SplitOptionKeyValue(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if k != tc.wantKey || v != tc.wantVal {
			t.Errorf("SplitOptionKeyValue(%q) = (%q, %q), want (%q, %q)", tc.in, k, v, tc.wantKey, tc.wantVal)
		}
	}

	for _, bad := range []string{"ControlMaster", "NoEquals", "=Value", "= Value", "=", " = "} {
		k, v, err := SplitOptionKeyValue(bad)
		if err == nil {
			t.Errorf("SplitOptionKeyValue(%q) expected error, got (%q, %q)", bad, k, v)
			continue
		}
		if !errors.Is(err, ErrSSHOptionsValidation) {
			t.Errorf("SplitOptionKeyValue(%q) error %v does not wrap ErrSSHOptionsValidation", bad, err)
		}
		if !strings.Contains(err.Error(), "invalid -o option format") {
			t.Errorf("SplitOptionKeyValue(%q) error %q missing 'invalid -o option format'", bad, err.Error())
		}
	}
}

func TestP2_ParseCLIOptions_MergeModesAndValidation(t *testing.T) {
	t.Parallel()

	t.Run("rejects_unknown_target_only_and_empty_values", func(t *testing.T) {
		badInputs := [][]string{
			{"UnknownOption=yes"},
			{"Port=2222"},
			{"User=alice"},
			{"HostName=10.0.0.1"},
			{"ProxyJump=bastion"},
			{"proxy_jump=bastion"},
			{"ControlPath="},
			{"Tunnel = "},
			{"ControlMaster"},
			{"SendEnv=LANG\nLC_ALL"},
			{"SetEnv=A=1\nB=2"},
			{"IdentityFile=/tmp/a\n/tmp/b"},
		}
		for _, in := range badInputs {
			got, err := ParseCLIOptions(in)
			if err == nil {
				t.Errorf("ParseCLIOptions(%v) expected error, got %+v", in, got)
				continue
			}
			if !errors.Is(err, ErrSSHOptionsValidation) {
				t.Errorf("ParseCLIOptions(%v) error %v does not wrap ErrSSHOptionsValidation", in, err)
			}
		}
	})

	t.Run("validates_shadowed_first_wins_and_setenv_directives", func(t *testing.T) {
		if _, err := ParseCLIOptions([]string{"ConnectTimeout=10", "ConnectTimeout=notaduration"}); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Fatalf("expected shadowed invalid FirstWins option to fail, got %v", err)
		}
		if _, err := ParseCLIOptions([]string{"SetEnv=FOO=1", "SetEnv=INVALID_NO_EQUALS"}); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Fatalf("expected shadowed invalid SetEnv option to fail, got %v", err)
		}
	})

	t.Run("first_wins_across_aliases_and_single_directive_setenv", func(t *testing.T) {
		parsed, err := ParseCLIOptions([]string{
			"",
			"   ",
			"KbdInteractiveAuthentication=yes",
			"ChallengeResponseAuthentication=no",
			"SetEnv=A=first B=first",
			"SetEnv=A=second C=second",
			"SendEnv=LANG",
			"SendEnv=-LC_ALL",
			"SendEnv=LANG",
			"LocalForward=8080:127.0.0.1:80",
			"LocalForward 8080 127.0.0.1:80",
			"LocalForward=9090 127.0.0.1:90",
		})
		if err != nil {
			t.Fatalf("ParseCLIOptions: %v", err)
		}
		if v, ok := parsed.KbdInteractiveAuthentication(); !ok || !v {
			t.Fatalf("KbdInteractiveAuthentication = (%v, %v), want (true, true)", v, ok)
		}
		if got := parsed.SetEnvDirectives(); !slices.Equal(got, []string{"A=first B=first"}) {
			t.Fatalf("SetEnvDirectives = %v, want [A=first B=first]", got)
		}
		if got := parsed.SendEnvPatterns(); !slices.Equal(got, []string{"LANG", "LANG"}) {
			t.Fatalf("SendEnvPatterns = %v, want [LANG LANG]", got)
		}
		if got := parsed.GetAll(OptionSendEnv); !slices.Equal(got, []string{"-LC_ALL", "LANG", "LANG"}) {
			t.Fatalf("GetAll(OptionSendEnv) = %v, want [-LC_ALL LANG LANG]", got)
		}
		if got := parsed.LocalForwards(); !slices.Equal(got, []string{"8080 127.0.0.1:80", "9090 127.0.0.1:90"}) {
			t.Fatalf("LocalForwards = %v", got)
		}
	})

	t.Run("identity_file_none_preserved_in_layer_and_truncated_on_merge", func(t *testing.T) {
		tier1, err := ParseCLIOptions([]string{
			"IdentityFile=/tmp/cli_key",
			"IdentityFile=none",
			"IdentityFile=/tmp/ignored_cli",
		})
		if err != nil {
			t.Fatalf("ParseCLIOptions tier1: %v", err)
		}
		if got := tier1.IdentityFiles(); !slices.Equal(got, []string{"/tmp/cli_key", "none"}) {
			t.Fatalf("unmerged tier1.IdentityFiles() = %v, want [/tmp/cli_key none]", got)
		}
		tier2, err := ParseCLIOptions([]string{"IdentityFile=/tmp/node_key"})
		if err != nil {
			t.Fatalf("ParseCLIOptions tier2: %v", err)
		}
		merged, err := MergeEffectiveOptions(tier1, tier2)
		if err != nil {
			t.Fatalf("MergeEffectiveOptions: %v", err)
		}
		if got := merged.IdentityFiles(); !slices.Equal(got, []string{"/tmp/cli_key"}) {
			t.Fatalf("merged.IdentityFiles() = %v, want [/tmp/cli_key]", got)
		}
	})
}

func TestP2_MergeEffectiveOptions_CrossFieldAndBackcompat(t *testing.T) {
	t.Parallel()

	if eff, err := MergeEffectiveOptions(nil, &Options{}); err != nil || eff != nil {
		t.Fatalf("MergeEffectiveOptions(empty) = (%+v, %v), want (nil, nil)", eff, err)
	}

	activeNoPath := MustOptions(OptionControlMaster, "yes")
	if eff, err := MergeEffectiveOptions(activeNoPath); !errors.Is(err, ErrSSHOptionsValidation) || eff != nil {
		t.Fatalf("MergeEffectiveOptions(ControlMaster=yes without path) = (%+v, %v), want (nil, ErrSSHOptionsValidation)", eff, err)
	}
	// EffectiveOptions itself must remain unchanged for callers that strip classes before validating.
	if eff, err := EffectiveOptions(activeNoPath); err != nil || eff == nil || eff.ControlMaster() != ControlMasterYes {
		t.Fatalf("EffectiveOptions backward compatibility broken: (%+v, %v)", eff, err)
	}

	persistNoMaster := MustOptions(OptionControlMaster, "no", OptionControlPath, "~/.ssh/cm-%C", OptionControlPersist, "10m")
	if eff, err := MergeEffectiveOptions(persistNoMaster); !errors.Is(err, ErrSSHOptionsValidation) || eff != nil {
		t.Fatalf("MergeEffectiveOptions(ControlPersist with Master=no) = (%+v, %v), want error", eff, err)
	}

	// ControlPath=none in higher layer disables lower-layer ControlMaster + ControlPersist.
	tier1 := MustOptions(OptionControlPath, "none")
	tier2 := MustOptions(OptionControlMaster, "auto", OptionControlPath, "~/.ssh/cm-%C", OptionControlPersist, "10m")
	disabled, err := MergeEffectiveOptions(tier1, tier2)
	if err != nil {
		t.Fatalf("MergeEffectiveOptions(ControlPath=none override): %v", err)
	}
	if disabled.ControlPath() != "none" || disabled.ControlMaster() != ControlMasterNo || disabled.ControlPersist() != "" {
		t.Fatalf("unexpected finalized disabled mux: %+v", disabled.Map())
	}
}

func TestP2_ProjectCLIOptions_SetEnvLosslessAndDeterministic(t *testing.T) {
	t.Parallel()

	if got := ProjectCLIOptions(nil); got != nil {
		t.Fatalf("ProjectCLIOptions(nil) = %v, want nil", got)
	}

	// Tier 2 (lower) defines B, A, GITHUB_TOKEN, EMPTY, SPECIAL.
	// Tier 1 (higher) overrides A (preserving A's position after B), overrides SPECIAL with quotes/backslash/tab, and adds C.
	tier2, err := ParseCLIOptions([]string{
		`SetEnv=B=node A=node_first A=node_dup GITHUB_TOKEN=secret_tok EMPTY= SPECIAL="a\b"`,
		`SendEnv=LANG LC_*`,
	})
	if err != nil {
		t.Fatalf("ParseCLIOptions tier2: %v", err)
	}
	tier1, err := ParseCLIOptions([]string{
		`SetEnv=A="cli \"val\" \\ end" SPECIAL="x	y\\" C=added`,
		`SendEnv=-LC_ALL`,
	})
	if err != nil {
		t.Fatalf("ParseCLIOptions tier1: %v", err)
	}

	merged, err := MergeEffectiveOptions(tier1, tier2)
	if err != nil {
		t.Fatalf("MergeEffectiveOptions: %v", err)
	}

	projected := ProjectCLIOptions(merged)
	wantProjected := []string{
		`SendEnv=-LC_ALL`,
		`SendEnv=LANG`,
		`SendEnv=LC_*`,
		`SetEnv="B=node" "A=cli \"val\" \\ end" "GITHUB_TOKEN=secret_tok" "EMPTY=" "SPECIAL=x	y\\" "C=added"`,
	}
	if !slices.Equal(projected, wantProjected) {
		t.Fatalf("ProjectCLIOptions =\n  %q\nwant:\n  %q", projected, wantProjected)
	}

	reparsedLayer, err := ParseCLIOptions(projected)
	if err != nil {
		t.Fatalf("re-ParseCLIOptions: %v", err)
	}
	reparsed, err := MergeEffectiveOptions(reparsedLayer)
	if err != nil {
		t.Fatalf("re-MergeEffectiveOptions: %v", err)
	}
	if got := ProjectCLIOptions(reparsed); !slices.Equal(got, projected) {
		t.Fatalf("second ProjectCLIOptions = %q, want %q", got, projected)
	}

	sampleEnv := func() []string {
		return []string{
			"LANG=en_US.UTF-8",
			"LC_CTYPE=UTF-8",
			"LC_ALL=C",
			"GITHUB_TOKEN=host_secret",
			"XOPS_SECRET=nope",
		}
	}
	wantEnv, err := ResolveSessionEnv(merged, sampleEnv)
	if err != nil {
		t.Fatalf("ResolveSessionEnv(merged): %v", err)
	}
	gotEnv, err := ResolveSessionEnv(reparsed, sampleEnv)
	if err != nil {
		t.Fatalf("ResolveSessionEnv(reparsed): %v", err)
	}
	if !slices.Equal(gotEnv, wantEnv) {
		t.Fatalf("ResolveSessionEnv mismatch:\n  got:  %+v\n  want: %+v", gotEnv, wantEnv)
	}
	for _, ev := range gotEnv {
		if ev.Name == "GITHUB_TOKEN" || ev.Name == "XOPS_SECRET" {
			t.Fatalf("denied env var %q leaked into ResolveSessionEnv", ev.Name)
		}
	}
}

func FuzzOptionLayersMergeProjectRoundTrip(f *testing.F) {
	// Seed corpus covering all merge modes, cross-layer precedence, quoting, and mutations.
	f.Add([]byte{1, 0, 1, 2, 3, 4, 5})
	f.Add([]byte{2, 10, 11, 12, 13, 14, 15, 16, 17, 18})
	f.Add([]byte{3, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30})
	f.Add([]byte{4, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42})
	f.Add([]byte{3, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54})
	f.Add([]byte{2, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71})
	f.Add([]byte{4, 0, 4, 9, 14, 19, 24, 29, 34, 39, 44, 49, 54, 59, 64, 69})

	sampleEnv := func() []string {
		return []string{
			"LANG=en_US.UTF-8",
			"LC_CTYPE=en_US.UTF-8",
			"LC_ALL=C",
			"APP_ENV=prod",
			"FOO=from_host",
			"BAR=from_host",
			"GITHUB_TOKEN=denied_host",
			"LD_PRELOAD=/tmp/bad.so",
			"XOPS_TEST=denied",
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		rawLayers := buildFuzzOptionLayers(data)
		parsedLayers := make([]*Options, 0, len(rawLayers))
		for _, layerStrs := range rawLayers {
			layerOpts, err := ParseCLIOptions(layerStrs)
			if err != nil {
				if !errors.Is(err, ErrSSHOptionsValidation) {
					t.Fatalf("ParseCLIOptions(%q) error %v does not wrap ErrSSHOptionsValidation", layerStrs, err)
				}
				return
			}
			parsedLayers = append(parsedLayers, layerOpts)
		}

		merged, err := MergeEffectiveOptions(parsedLayers...)
		if err != nil {
			if !errors.Is(err, ErrSSHOptionsValidation) {
				t.Fatalf("MergeEffectiveOptions error %v does not wrap ErrSSHOptionsValidation", err)
			}
			if merged != nil {
				t.Fatalf("MergeEffectiveOptions returned non-nil Options alongside error %v", err)
			}
			return
		}

		projected := ProjectCLIOptions(merged)
		reparsedLayer, err := ParseCLIOptions(projected)
		if err != nil {
			t.Fatalf("re-ParseCLIOptions(%q) failed: %v", projected, err)
		}
		reparsed, err := MergeEffectiveOptions(reparsedLayer)
		if err != nil {
			t.Fatalf("re-MergeEffectiveOptions(%q) failed: %v", projected, err)
		}

		reprojected := ProjectCLIOptions(reparsed)
		if !slices.Equal(reprojected, projected) {
			t.Fatalf("ProjectCLIOptions not idempotent:\n  first:  %q\n  second: %q", projected, reprojected)
		}

		assertFuzzSemanticEquivalence(t, merged, reparsed, sampleEnv)
	})
}

var fuzzOptionDirectivePool = []string{
	// Mux combinations (valid, disabled, and cross-field stress)
	"ControlMaster=auto",
	"ControlMaster=yes",
	"ControlMaster=no",
	"ControlMaster ask",
	"ControlPath=~/.ssh/cm-%C",
	"ControlPath=/tmp/sock-%r@%h:%p",
	"ControlPath=none",
	"ControlPath = NONE",
	"ControlPersist=10m",
	"ControlPersist=yes",
	"ControlPersist=no",
	"ControlPersist=false",
	// Transport & Trust scalars
	"AddressFamily=inet",
	"AddressFamily=inet6",
	"AddressFamily=any",
	"ConnectTimeout=15s",
	"ConnectTimeout=0",
	"ConnectTimeout=none",
	"ServerAliveInterval=30",
	"ServerAliveCountMax=5",
	"TCPKeepAlive=yes",
	"TCPKeepAlive=no",
	"StrictHostKeyChecking=accept-new",
	"StrictHostKeyChecking=yes",
	"StrictHostKeyChecking=off",
	"UserKnownHostsFile=~/.ssh/known_hosts /dev/null",
	"UserKnownHostsFile=none",
	"GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts",
	"GlobalKnownHostsFile=none",
	"HashKnownHosts=yes",
	"HashKnownHosts=no",
	"VerifyHostKeyDNS=ask",
	"CanonicalizeHostname=yes",
	"CanonicalDomains=dev.example.com corp.example.com",
	"CanonicalDomains=none",
	"CanonicalizeMaxDots=2",
	"CanonicalizeFallbackLocal=no",
	"CanonicalizePermittedCNAMEs=*.a.example.com:*.b.example.com",
	// Auth & Identity/Certificate NoneTerminated
	"IdentityFile=~/.ssh/id_ed25519",
	"IdentityFile=~/.ssh/id_%h",
	"IdentityFile=none",
	"IdentityFile = NONE",
	"CertificateFile=~/.ssh/id_ed25519-cert.pub",
	"CertificateFile=${CERT_DIR}/cert.pub",
	"CertificateFile=none",
	"IdentityAgent=SSH_AUTH_SOCK",
	"IdentityAgent=none",
	"PubkeyAuthentication=yes",
	"PasswordAuthentication=no",
	"KbdInteractiveAuthentication=yes",
	"ChallengeResponseAuthentication=no",
	"IdentitiesOnly=yes",
	"PreferredAuthentications=publickey,password",
	"BatchMode=yes",
	// Algorithm AllowLists
	"HostKeyAlgorithms=ssh-ed25519",
	"Ciphers=aes256-gcm@openssh.com",
	"MACs=hmac-sha2-256-etm@openssh.com",
	"KexAlgorithms=curve25519-sha256",
	// Forward scalars & AppendDedup multi-value
	"ExitOnForwardFailure=yes",
	"ClearAllForwardings=yes",
	"ForwardAgent=yes",
	"ForwardAgent=SSH_AUTH_SOCK",
	"GatewayPorts=clientspecified",
	"StreamLocalBindUnlink=yes",
	"StreamLocalBindMask=0117",
	"Tunnel=ethernet",
	"TunnelDevice=0:1",
	"LocalForward=8080:127.0.0.1:80",
	"LocalForward 8080 127.0.0.1:80",
	"LocalForward=*:8443 [::1]:443",
	`LocalForward="/tmp/my sock.s" /tmp/dest.s`,
	"RemoteForward=9090 127.0.0.1:90",
	"RemoteForward=1080",
	"RemoteForward=*:1081",
	"DynamicForward=127.0.0.1:1080",
	`DynamicForward="/tmp/dyn \"sock\" \\.s"`,
	// Session scalars & OrderedEnv / SingleDirectiveOrderedEnv
	"ForkAfterAuthentication=no",
	"StdinNull=yes",
	"SessionType=none",
	"RequestTTY=force",
	"SendEnv=LANG",
	"SendEnv=LC_* APP_*",
	"SendEnv=-LC_ALL",
	"SendEnv=-FOO",
	"SendEnv=FOO",
	`SetEnv=FOO=one BAR="two words"`,
	`SetEnv=BAR="override \"q\" \\" BAZ=three FOO=later`,
	`SetEnv=GITHUB_TOKEN=keep_syntactic EMPTY= TAB="a	b"`,
	`SetEnv=FOO=dup1 FOO=dup2 XOPS_KEY=denied`,
	"RemoteCommand=tmux attach || echo =ok",
	"RemoteCommand=none",
	"EscapeChar=~",
	"EscapeChar==",
	"EscapeChar=^?",
	"EscapeChar=none",
	// LocalExec
	"ProxyCommand=nc %h %p",
	"ProxyCommand=none",
	"LocalCommand=echo hi %h",
	"PermitLocalCommand=yes",
}

func buildFuzzOptionLayers(data []byte) [][]string {
	numLayers := int(data[0]%4) + 1
	layers := make([][]string, numLayers)
	pos := 1
	for layerIdx := 0; layerIdx < numLayers && pos < len(data); layerIdx++ {
		count := int(data[pos]%8) + 1
		pos++
		for j := 0; j < count && pos < len(data); j++ {
			b := data[pos]
			pos++
			switch {
			case b < 220:
				dir := fuzzOptionDirectivePool[int(b)%len(fuzzOptionDirectivePool)]
				layers[layerIdx] = append(layers[layerIdx], dir)
			case b < 245 && pos+1 < len(data):
				// Dynamic SetEnv value derived from fuzz bytes to stress quoting/escaping.
				varName := "V" + strconv.Itoa(int(data[pos]%6))
				pos++
				rawLen := int(data[pos]%12) + 1
				pos++
				end := min(pos+rawLen, len(data))
				val := sanitizeFuzzEnvValue(data[pos:end])
				pos = end
				layers[layerIdx] = append(layers[layerIdx], "SetEnv="+formatQuotedEnvToken(varName+"="+val))
			default:
				// Deliberate invalid/mutated directives to exercise error paths.
				badPool := []string{
					"Port=22",
					"Unknown=1",
					"ControlMaster=bogus",
					"SetEnv=NOEQUALS",
					"SendEnv=BAD=NAME",
					"ControlPath=",
					"NoDelimiter",
				}
				layers[layerIdx] = append(layers[layerIdx], badPool[int(b)%len(badPool)])
			}
		}
	}
	return layers
}

func sanitizeFuzzEnvValue(raw []byte) string {
	var sb strings.Builder
	for _, ch := range raw {
		if ch == '\t' || (ch >= 0x20 && ch <= 0x7e) {
			sb.WriteByte(ch)
		}
	}
	return sb.String()
}

func assertFuzzSemanticEquivalence(t *testing.T, merged, reparsed *Options, sampleEnv func() []string) {
	t.Helper()

	mergedMap := merged.Map()
	reparsedMap := reparsed.Map()
	for k, mv := range mergedMap {
		if k == OptionSetEnv {
			if _, ok := reparsedMap[OptionSetEnv]; !ok {
				t.Fatalf("reparsed missing %q present in merged", OptionSetEnv)
			}
			continue
		}
		if rv, ok := reparsedMap[k]; !ok || rv != mv {
			t.Fatalf("Map()[%q] mismatch: reparsed=%q (ok=%v), merged=%q", k, rv, ok, mv)
		}
	}
	for k := range reparsedMap {
		if _, ok := mergedMap[k]; !ok {
			t.Fatalf("reparsed has unexpected key %q not in merged", k)
		}
	}

	if !slices.Equal(reparsed.IdentityFiles(), merged.IdentityFiles()) {
		t.Fatalf("IdentityFiles mismatch: reparsed=%v merged=%v", reparsed.IdentityFiles(), merged.IdentityFiles())
	}
	if !slices.Equal(reparsed.CertificateFiles(), merged.CertificateFiles()) {
		t.Fatalf("CertificateFiles mismatch: reparsed=%v merged=%v", reparsed.CertificateFiles(), merged.CertificateFiles())
	}
	if !slices.Equal(reparsed.LocalForwards(), merged.LocalForwards()) {
		t.Fatalf("LocalForwards mismatch: reparsed=%v merged=%v", reparsed.LocalForwards(), merged.LocalForwards())
	}
	if !slices.Equal(reparsed.RemoteForwards(), merged.RemoteForwards()) {
		t.Fatalf("RemoteForwards mismatch: reparsed=%v merged=%v", reparsed.RemoteForwards(), merged.RemoteForwards())
	}
	if !slices.Equal(reparsed.DynamicForwards(), merged.DynamicForwards()) {
		t.Fatalf("DynamicForwards mismatch: reparsed=%v merged=%v", reparsed.DynamicForwards(), merged.DynamicForwards())
	}

	wantEnv, wantErr := ResolveSessionEnv(merged, sampleEnv)
	gotEnv, gotErr := ResolveSessionEnv(reparsed, sampleEnv)
	if (wantErr != nil) != (gotErr != nil) {
		t.Fatalf("ResolveSessionEnv error mismatch: reparsed=%v merged=%v", gotErr, wantErr)
	}
	if !slices.Equal(gotEnv, wantEnv) {
		t.Fatalf("ResolveSessionEnv mismatch:\n  reparsed: %+v\n  merged:   %+v", gotEnv, wantEnv)
	}
}
