package ssh

import (
	"errors"
	"slices"
	"testing"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestAlgoPolicy_StrictParsingAndCapabilities(t *testing.T) {
	t.Parallel()

	// Reject bare modifiers, empty tokens, invalid syntax, and unsupported tokens.
	badCases := []struct {
		key string
		raw string
	}{
		{OptionCiphers, ""},
		{OptionCiphers, "   "},
		{OptionCiphers, "-"},
		{OptionCiphers, "+"},
		{OptionCiphers, "^"},
		{OptionCiphers, "-   "},
		{OptionCiphers, "+  "},
		{OptionCiphers, "^ "},
		{OptionCiphers, ","},
		{OptionCiphers, "aes256-gcm@openssh.com,"},
		{OptionCiphers, ",aes256-gcm@openssh.com"},
		{OptionCiphers, "aes256-gcm@openssh.com,,chacha20-poly1305@openssh.com"},
		{OptionCiphers, "+,aes256-gcm@openssh.com"},
		{OptionCiphers, "++aes256-gcm@openssh.com"},
		{OptionCiphers, "+-aes256-gcm@openssh.com"},
		{OptionCiphers, "aes256-gcm@openssh.com\n"},
		{OptionCiphers, "aes256-gcm@openssh.com\x00"},
		{OptionCiphers, "not-a-supported-cipher"},
		{OptionCiphers, "+not-a-supported-cipher"},
		{OptionCiphers, "^not-a-supported-cipher"},
		{OptionMACs, "-bad!mac"},
		{OptionMACs, "-bad mac"},
		{OptionKexAlgorithms, "^"},
		{OptionHostKeyAlgorithms, "+invalid$algo"},
		// Non-algorithm OptionSpecs must be rejected.
		{OptionPreferredAuthentications, "publickey"},
		{OptionAddressFamily, "inet"},
		{"UnknownOption", "aes256-gcm@openssh.com"},
	}

	for _, tc := range badCases {
		p, err := ParseAlgoPolicy(tc.key, tc.raw)
		if err == nil || !errors.Is(err, ErrSSHOptionsValidation) || !p.IsUnset() {
			t.Errorf("ParseAlgoPolicy(%q, %q) = (%+v, %v), want Unset + ErrSSHOptionsValidation", tc.key, tc.raw, p, err)
		}
	}

	// Single capability source check: every SupportedTokens entry of every algorithm
	// OptionSpec must parse across Replace, Append, Prepend, and Remove.
	for _, key := range []string{OptionCiphers, OptionMACs, OptionKexAlgorithms, OptionHostKeyAlgorithms} {
		spec, ok := LookupOptionSpec(key)
		if !ok || spec.SupportedTokens == nil {
			t.Fatalf("missing algorithm OptionSpec %q", key)
		}
		supported := spec.SupportedTokens()
		if len(supported) == 0 {
			t.Fatalf("%s SupportedTokens is empty", key)
		}
		tok := supported[0]
		for _, tc := range []struct {
			raw    string
			wantOp AlgoOp
		}{
			{tok, AlgoOpReplace},
			{"+" + tok, AlgoOpAppend},
			{"-" + tok, AlgoOpRemove},
			{"^" + tok, AlgoOpPrepend},
		} {
			p, err := ParseAlgoPolicy(spec.OpenSSHName, tc.raw)
			if err != nil {
				t.Fatalf("ParseAlgoPolicy(%q, %q): %v", spec.OpenSSHName, tc.raw, err)
			}
			if p.OptionKey() != key || p.Op() != tc.wantOp || !slices.Equal(p.Tokens(), []string{tok}) || p.String() != tc.raw {
				t.Fatalf("unexpected AlgoPolicy for (%q, %q): key=%q op=%v tokens=%v str=%q",
					key, tc.raw, p.OptionKey(), p.Op(), p.Tokens(), p.String())
			}
		}
	}

	// Removal of a syntactically valid legacy/unsupported algorithm is permitted.
	rem, err := ParseAlgoPolicy(OptionCiphers, "-blowfish-cbc,arcfour")
	if err != nil || rem.Op() != AlgoOpRemove || !slices.Equal(rem.Tokens(), []string{"blowfish-cbc", "arcfour"}) {
		t.Fatalf("ParseAlgoPolicy(-legacy) = (%+v, %v)", rem, err)
	}
}

func TestAlgoPolicy_ResolveAndEmptyError(t *testing.T) {
	t.Parallel()

	defaults := cryptoSSH.SupportedAlgorithms().Ciphers
	if len(defaults) < 2 {
		t.Fatalf("expected >= 2 default ciphers, got %v", defaults)
	}
	c0, c1 := defaults[0], defaults[1]

	// Unset clones defaults, errors on empty defaults.
	unset := UnsetAlgoPolicy()
	if got, err := unset.Resolve(defaults); err != nil || !slices.Equal(got, defaults) {
		t.Fatalf("Unset.Resolve(defaults) = (%v, %v)", got, err)
	}
	if _, err := unset.Resolve(nil); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("Unset.Resolve(nil) err = %v, want ErrSSHOptionsValidation", err)
	}

	// Replace
	rep, err := ParseAlgoPolicy(OptionCiphers, c1+","+c0+","+c1)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rep.Resolve(defaults); err != nil || !slices.Equal(got, []string{c1, c0}) {
		t.Fatalf("Replace.Resolve = (%v, %v), want [%s %s]", got, err, c1, c0)
	}

	// Append
	insecure := cryptoSSH.InsecureAlgorithms().Ciphers
	if len(insecure) > 0 {
		app, err := ParseAlgoPolicy(OptionCiphers, "+"+insecure[0])
		if err != nil {
			t.Fatal(err)
		}
		got, err := app.Resolve([]string{c0})
		if err != nil || !slices.Equal(got, []string{c0, insecure[0]}) {
			t.Fatalf("Append.Resolve = (%v, %v)", got, err)
		}
	}

	// Prepend
	prep, err := ParseAlgoPolicy(OptionCiphers, "^"+c1)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := prep.Resolve([]string{c0, c1}); err != nil || !slices.Equal(got, []string{c1, c0}) {
		t.Fatalf("Prepend.Resolve = (%v, %v), want [%s %s]", got, err, c1, c0)
	}

	// Remove partial vs remove all (empty result -> error)
	rem, err := ParseAlgoPolicy(OptionCiphers, "-"+c0)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rem.Resolve([]string{c0, c1}); err != nil || !slices.Equal(got, []string{c1}) {
		t.Fatalf("Remove partial = (%v, %v), want [%s]", got, err, c1)
	}
	if _, err := rem.Resolve([]string{c0}); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("Remove all err = %v, want ErrSSHOptionsValidation", err)
	}
}

func TestAlgoPolicy_MonoidLaws(t *testing.T) {
	t.Parallel()

	defaults := cryptoSSH.SupportedAlgorithms().Ciphers
	p1, err := ParseAlgoPolicy(OptionCiphers, defaults[0])
	if err != nil {
		t.Fatal(err)
	}
	p2, err := ParseAlgoPolicy(OptionCiphers, "+"+defaults[1])
	if err != nil {
		t.Fatal(err)
	}
	p3, err := ParseAlgoPolicy(OptionCiphers, "-"+defaults[0])
	if err != nil {
		t.Fatal(err)
	}

	universe := []AlgoPolicy{UnsetAlgoPolicy(), p1, p2, p3}
	for _, x := range universe {
		if !MergeAlgoPolicy(UnsetAlgoPolicy(), x).Equal(x) || !MergeAlgoPolicy(x, UnsetAlgoPolicy()).Equal(x) {
			t.Errorf("identity law failed for %q", x)
		}
	}
	for _, a := range universe {
		for _, b := range universe {
			if !a.IsUnset() && !MergeAlgoPolicy(a, b).Equal(a) {
				t.Errorf("first-wins absorption failed for %q over %q", a, b)
			}
			for _, c := range universe {
				left := MergeAlgoPolicy(MergeAlgoPolicy(a, b), c)
				right := MergeAlgoPolicy(a, MergeAlgoPolicy(b, c))
				if !left.Equal(right) || !MergeAlgoPolicies(a, b, c).Equal(left) {
					t.Errorf("associativity failed for (%q, %q, %q)", a, b, c)
				}
			}
		}
	}
}

func FuzzAlgoPolicyRoundTrip(f *testing.F) {
	ciphers := cryptoSSH.SupportedAlgorithms().Ciphers
	macs := cryptoSSH.SupportedAlgorithms().MACs
	kex := cryptoSSH.SupportedAlgorithms().KeyExchanges
	hk := cryptoSSH.SupportedAlgorithms().HostKeys

	seeds := []struct {
		keyIdx uint8
		raw    string
	}{
		{0, ciphers[0]},
		{0, "+" + ciphers[0]},
		{0, "-" + ciphers[0]},
		{0, "^" + ciphers[0]},
		{0, "-"},
		{0, "+"},
		{0, "^"},
		{1, macs[0]},
		{1, "-bad!mac"},
		{2, kex[0]},
		{3, hk[0]},
	}
	for _, s := range seeds {
		f.Add(s.keyIdx, s.raw)
	}

	keys := []string{OptionCiphers, OptionMACs, OptionKexAlgorithms, OptionHostKeyAlgorithms}
	f.Fuzz(func(t *testing.T, keyIdx uint8, raw string) {
		key := keys[int(keyIdx)%len(keys)]
		p, err := ParseAlgoPolicy(key, raw)
		if err != nil {
			if !p.IsUnset() {
				t.Fatalf("ParseAlgoPolicy(%q, %q) returned error %v with non-unset policy %+v", key, raw, err, p)
			}
			return
		}
		wire := p.String()
		reparsed, err := ParseAlgoPolicy(p.OptionKey(), wire)
		if err != nil {
			t.Fatalf("re-parse of (%q, %q) from %q failed: %v", p.OptionKey(), wire, raw, err)
		}
		if !p.Equal(reparsed) || reparsed.String() != wire {
			t.Fatalf("round-trip mismatch: first=%q second=%q", wire, reparsed.String())
		}
	})
}
