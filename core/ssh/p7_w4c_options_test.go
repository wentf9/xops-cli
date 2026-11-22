package ssh

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	cryptoSSH "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func TestP7W4c_D2_ParseProxyJumpNoneNoneAndRejections(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"none", "NONE", "none,none", " NONE , none ", "none,NONE,none"} {
		ps, err := ParseProxyJump(raw)
		if err != nil {
			t.Errorf("ParseProxyJump(%q) unexpected error: %v", raw, err)
			continue
		}
		if !ps.Equal(DisabledProxyJumpSetting()) {
			t.Errorf("ParseProxyJump(%q) = %q, want DisabledProxyJumpSetting", raw, ps)
		}
		for _, src := range []OptionSource{OptionSourceCLI, OptionSourceOpenSSHConfig} {
			parsed, pErr := ParseOption("ProxyJump", raw, src)
			if pErr != nil {
				t.Errorf("ParseOption(ProxyJump, %q, %d) unexpected error: %v", raw, src, pErr)
				continue
			}
			if !parsed.ProxySetting.Equal(DisabledProxyJumpSetting()) || parsed.Normalized != "none" {
				t.Errorf("ParseOption(ProxyJump, %q, %d) = (%q, %q), want DisabledProxyJumpSetting/\"none\"",
					raw, src, parsed.ProxySetting, parsed.Normalized)
			}
		}
	}

	for _, bad := range []string{"", "   ", ",", " , ", "a,,b", "a,", ",b", "none,", ",none", "a,none", "none,a", "bastion\x00", "bastion\n"} {
		if ps, err := ParseProxyJump(bad); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Errorf("ParseProxyJump(%q) = (%q, %v), want ErrSSHOptionsValidation", bad, ps, err)
		}
		for _, src := range []OptionSource{OptionSourceCLI, OptionSourceOpenSSHConfig} {
			if parsed, err := ParseOption("ProxyJump", bad, src); !errors.Is(err, ErrSSHOptionsValidation) {
				t.Errorf("ParseOption(ProxyJump, %q, %d) = (%+v, %v), want ErrSSHOptionsValidation", bad, src, parsed, err)
			}
		}
	}
}

func TestP7W4c_D3_UnmarshalYAMLJSONRoutesThroughParseOptionAndSyncsValues(t *testing.T) {
	t.Parallel()

	ciphers := cryptoSSH.SupportedAlgorithms().Ciphers
	macs := cryptoSSH.SupportedAlgorithms().MACs
	kex := cryptoSSH.SupportedAlgorithms().KeyExchanges
	hostKeys := cryptoSSH.SupportedAlgorithms().HostKeys
	if len(ciphers) < 2 || len(macs) < 2 || len(kex) < 1 || len(hostKeys) < 1 {
		t.Fatal("unexpected empty Go SSH default algorithms")
	}

	dupCiphers := ciphers[0] + "," + ciphers[1] + "," + ciphers[0]
	wantCiphers := ciphers[0] + "," + ciphers[1]
	dupMACs := "+" + macs[0] + "," + macs[0]
	wantMACs := "+" + macs[0]
	dupKex := "^" + kex[0] + "," + kex[0]
	wantKex := "^" + kex[0]
	dupHostKeys := hostKeys[0] + "," + hostKeys[0]
	wantHostKeys := hostKeys[0]

	yamlDoc := "Ciphers: " + dupCiphers + "\n" +
		"macs: " + dupMACs + "\n" +
		"KexAlgorithms: " + dupKex + "\n" +
		"host_key_algorithms:\n  - " + hostKeys[0] + "\n  - " + hostKeys[0] + "\n" +
		"ProxyCommand: \"  none  \"\n" +
		"IdentityFile:\n  - /tmp/k1\n  - /tmp/k1\n"

	var yamlOpts Options
	if err := yaml.Unmarshal([]byte(yamlDoc), &yamlOpts); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}

	jsonDoc := `{"Ciphers":"` + dupCiphers + `","macs":"` + dupMACs + `","KexAlgorithms":"` + dupKex + `","host_key_algorithms":["` + hostKeys[0] + `","` + hostKeys[0] + `"],"ProxyCommand":"  none  ","IdentityFile":["/tmp/k1","/tmp/k1"]}`
	var jsonOpts Options
	if err := json.Unmarshal([]byte(jsonDoc), &jsonOpts); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	var setRawOpts Options
	setRawOpts.setRaw(OptionCiphers, dupCiphers)
	setRawOpts.setRaw(OptionMACs, dupMACs)
	setRawOpts.setRaw(OptionKexAlgorithms, dupKex)
	setRawOpts.setRaw(OptionHostKeyAlgorithms, dupHostKeys)
	setRawOpts.setRaw(OptionProxyCommand, "  none  ")
	setRawOpts.setRaw(OptionIdentityFile, "/tmp/k1\n/tmp/k1")

	setOpts := MustOptions(
		OptionCiphers, dupCiphers,
		OptionMACs, dupMACs,
		OptionKexAlgorithms, dupKex,
		OptionHostKeyAlgorithms, dupHostKeys,
		OptionProxyCommand, "  none  ",
		OptionIdentityFile, "/tmp/k1\n/tmp/k1",
	)

	wantVals := map[string]string{
		OptionCiphers:           wantCiphers,
		OptionMACs:              wantMACs,
		OptionKexAlgorithms:     wantKex,
		OptionHostKeyAlgorithms: wantHostKeys,
		OptionProxyCommand:      "none",
		OptionIdentityFile:      "/tmp/k1",
	}

	variants := []struct {
		name string
		opts *Options
	}{
		{"YAML", &yamlOpts},
		{"JSON", &jsonOpts},
		{"setRaw", &setRawOpts},
		{"Set", setOpts},
	}

	refDigest := DigestClientConfig(NewClientConfig(ClientConfig{
		NodeID:  "n1",
		Address: "10.0.0.1",
		Port:    22,
		User:    "ops",
		Options: setOpts,
	}), ZeroHopDigest)

	for _, v := range variants {
		assertP7W4cD3VariantParity(t, v.name, v.opts, wantVals, refDigest)
	}

	assertP7W4cD3RejectsInvalidYAMLAndJSON(t)
}

func assertP7W4cD3VariantParity(t *testing.T, name string, opts *Options, wantVals map[string]string, refDigest HopDigest) {
	t.Helper()
	for k, want := range wantVals {
		if got := opts.Get(k); got != want {
			t.Errorf("%s: Get(%q) = %q, want %q", name, k, got, want)
		}
		switch k {
		case OptionCiphers, OptionMACs, OptionKexAlgorithms, OptionHostKeyAlgorithms:
			pol, ok := opts.AlgoPolicy(k)
			if !ok || pol.String() != want {
				t.Errorf("%s: AlgoPolicy(%q) = (%q, %v), want (%q, true)", name, k, pol.String(), ok, want)
			}
		}
	}
	merged := MergeOptions(opts)
	if !opts.Equal(merged) {
		t.Errorf("%s: Equal(MergeOptions(opt)) = false (raw=%v merged=%v)", name, opts.Map(), merged.Map())
	}
	gotDigest := DigestClientConfig(NewClientConfig(ClientConfig{
		NodeID:  "n1",
		Address: "10.0.0.1",
		Port:    22,
		User:    "ops",
		Options: opts,
	}), ZeroHopDigest)
	mergedDigest := DigestClientConfig(NewClientConfig(ClientConfig{
		NodeID:  "n1",
		Address: "10.0.0.1",
		Port:    22,
		User:    "ops",
		Options: merged,
	}), ZeroHopDigest)
	if !gotDigest.Equal(refDigest) || !mergedDigest.Equal(refDigest) {
		t.Errorf("%s: HopDigest mismatch: got=%s merged=%s ref=%s", name, gotDigest, mergedDigest, refDigest)
	}
}

func assertP7W4cD3RejectsInvalidYAMLAndJSON(t *testing.T) {
	t.Helper()
	badYAML := []string{
		"ciphers: \"-\"\n",
		"ciphers: \"+\"\n",
		"kex_algorithms: \"^\"\n",
		"control_master: \"\"\n",
		"control_master: \"yes\\n\"\n",
		"proxy_command: \"\"\n",
	}
	for _, doc := range badYAML {
		var o Options
		if err := yaml.Unmarshal([]byte(doc), &o); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Errorf("yaml.Unmarshal(%q) err = %v, want ErrSSHOptionsValidation", doc, err)
		}
	}
	badJSON := []string{
		`{"ciphers":"-"}`,
		`{"ciphers":"+"}`,
		`{"kex_algorithms":"^"}`,
		`{"control_master":""}`,
		`{"control_master":"yes\n"}`,
		`{"proxy_command":""}`,
	}
	for _, doc := range badJSON {
		var o Options
		if err := json.Unmarshal([]byte(doc), &o); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Errorf("json.Unmarshal(%q) err = %v, want ErrSSHOptionsValidation", doc, err)
		}
	}
}

func TestP7W4c_D6_DefaultAlgoPolicyMonoidAndMultiLayerShadowing(t *testing.T) {
	t.Parallel()

	defaults := cryptoSSH.SupportedAlgorithms().MACs
	if len(defaults) < 2 {
		t.Fatalf("expected >= 2 default MACs, got %v", defaults)
	}

	assertP7W4cD6ParseOptionDefaultPolicy(t, defaults)

	defPol, err := DefaultAlgoPolicy(OptionMACs)
	if err != nil {
		t.Fatalf("DefaultAlgoPolicy(MACs): %v", err)
	}
	repPol, err := ParseAlgoPolicy(OptionMACs, defaults[0])
	if err != nil {
		t.Fatal(err)
	}
	appPol, err := ParseAlgoPolicy(OptionMACs, "+"+defaults[1])
	if err != nil {
		t.Fatal(err)
	}
	assertP7W4cD6MonoidLaws(t, []AlgoPolicy{UnsetAlgoPolicy(), defPol, repPol, appPol})
	assertP7W4cD6MultiLayerOptionsShadowing(t, defPol, defaults)
}

func assertP7W4cD6ParseOptionDefaultPolicy(t *testing.T, defaults []string) {
	t.Helper()
	for _, raw := range []string{"+umac-64@openssh.com", "^umac-64@openssh.com"} {
		parsed, err := ParseOption(OptionMACs, raw, OptionSourceOpenSSHConfig)
		if err != nil {
			t.Fatalf("ParseOption(MACs, %q, OpenSSHConfig): %v", raw, err)
		}
		if !parsed.IsNoOp || parsed.AlgoPolicy.IsUnset() || !parsed.AlgoPolicy.IsDefault() || parsed.AlgoPolicy.Op() != AlgoOpDefault {
			t.Fatalf("ParseOption(MACs, %q) = %+v, want IsNoOp=true AlgoOpDefault", raw, parsed)
		}
		if got, err := parsed.AlgoPolicy.Resolve(defaults); err != nil || !slices.Equal(got, defaults) {
			t.Fatalf("DefaultAlgoPolicy.Resolve = (%v, %v), want %v", got, err, defaults)
		}
	}
}

func assertP7W4cD6MonoidLaws(t *testing.T, universe []AlgoPolicy) {
	t.Helper()
	for _, a := range universe {
		if !MergeAlgoPolicy(UnsetAlgoPolicy(), a).Equal(a) || !MergeAlgoPolicy(a, UnsetAlgoPolicy()).Equal(a) {
			t.Errorf("identity law failed for %+v", a)
		}
		for _, b := range universe {
			if !a.IsUnset() && !MergeAlgoPolicy(a, b).Equal(a) {
				t.Errorf("first-wins absorption failed for %+v over %+v", a, b)
			}
			for _, c := range universe {
				left := MergeAlgoPolicy(MergeAlgoPolicy(a, b), c)
				right := MergeAlgoPolicy(a, MergeAlgoPolicy(b, c))
				if !left.Equal(right) {
					t.Errorf("associativity failed for (%+v, %+v, %+v)", a, b, c)
				}
			}
		}
	}
}

func assertP7W4cD6MultiLayerOptionsShadowing(t *testing.T, defPol AlgoPolicy, defaults []string) {
	t.Helper()
	layer1 := &Options{}
	layer1.SetAlgoPolicy(defPol)
	layer2 := MustOptions(OptionMACs, defaults[0])
	layer0 := MustOptions(OptionMACs, defaults[1])

	if layer1.IsEmpty() {
		t.Fatal("layer1 with DefaultAlgoPolicy must not report IsEmpty()")
	}
	if !layer1.IsZero() {
		t.Fatal("layer1 with only DefaultAlgoPolicy must remain IsZero() for YAML omitempty")
	}

	shadowed := MergeOptions(layer1, layer2)
	if shadowed == nil || shadowed.MACs() != "" {
		t.Fatalf("MergeOptions(DefaultAlgoPolicy, Replace) MACs = %q, want empty (defaults)", shadowed.MACs())
	}
	if gotPol, ok := shadowed.AlgoPolicy(OptionMACs); !ok || !gotPol.Equal(defPol) {
		t.Fatalf("shadowed AlgoPolicy(MACs) = (%+v, %v), want DefaultAlgoPolicy", gotPol, ok)
	}
	leftAssoc := MergeOptions(MergeOptions(layer1, &Options{}), layer2)
	rightAssoc := MergeOptions(layer1, MergeOptions(&Options{}, layer2))
	if !leftAssoc.Equal(rightAssoc) || leftAssoc.MACs() != "" {
		t.Fatalf("DefaultAlgoPolicy MergeOptions associativity broken: left=%+v right=%+v", leftAssoc, rightAssoc)
	}

	overridden := MergeOptions(layer0, layer1, layer2)
	if overridden == nil || overridden.MACs() != defaults[1] {
		t.Fatalf("MergeOptions(CLI, Default, Lower) MACs = %q, want %q", overridden.MACs(), defaults[1])
	}

	filtered := layer1.FilterByClasses(OptionClassTransport)
	if filtered == nil {
		t.Fatal("FilterByClasses(OptionClassTransport) dropped DefaultAlgoPolicy")
	}
	if gotPol, ok := filtered.AlgoPolicy(OptionMACs); !ok || !gotPol.Equal(defPol) {
		t.Fatalf("filtered AlgoPolicy(MACs) = (%+v, %v), want DefaultAlgoPolicy", gotPol, ok)
	}
}
