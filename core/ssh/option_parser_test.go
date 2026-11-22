package ssh

import (
	"errors"
	"slices"
	"testing"
)

func TestParseOption_ControlAndAlgoValidationAllSources(t *testing.T) {
	t.Parallel()

	t.Run("ControlMaster_rejects_empty_and_control_chars_all_sources", func(t *testing.T) {
		t.Parallel()
		for _, src := range []OptionSource{OptionSourceCLI, OptionSourceOpenSSHConfig, OptionSourceYAML, OptionSourceJSON} {
			for _, bad := range []string{"", "   ", "yes\n", "\nyes", "auto\r", "yes\x00"} {
				if _, err := ParseOption("ControlMaster", bad, src); !errors.Is(err, ErrSSHOptionsValidation) {
					t.Errorf("ParseOption(ControlMaster, %q, %d) = %v, want ErrSSHOptionsValidation", bad, src, err)
				}
			}
		}
	})

	t.Run("AlgoPolicy_rejects_bare_modifiers_and_invalid_tokens_all_sources", func(t *testing.T) {
		t.Parallel()
		badCases := []struct {
			key string
			raw string
		}{
			{"Ciphers", "-"},
			{"Ciphers", "+"},
			{"Ciphers", "^"},
			{"KexAlgorithms", "^"},
			{"MACs", "-bad!mac"},
			{"HostKeyAlgorithms", "ssh-ed25519,,rsa-sha2-512"},
			{"Ciphers", "aes256-gcm@openssh.com\n"},
		}
		for _, src := range []OptionSource{OptionSourceCLI, OptionSourceOpenSSHConfig, OptionSourceYAML, OptionSourceJSON} {
			for _, tc := range badCases {
				if _, err := ParseOption(tc.key, tc.raw, src); !errors.Is(err, ErrSSHOptionsValidation) {
					t.Errorf("ParseOption(%q, %q, %d) = %v, want ErrSSHOptionsValidation", tc.key, tc.raw, src, err)
				}
			}
		}
	})
}

func TestParseOption_OpenSSHAlgoFiltering(t *testing.T) {
	t.Parallel()

	got, err := ParseOption("KexAlgorithms", "sntrup761x25519-sha512@openssh.com,curve25519-sha256", OptionSourceOpenSSHConfig)
	if err != nil {
		t.Fatalf("ParseOption mixed KexAlgorithms: %v", err)
	}
	if got.IsNoOp || got.Normalized != "curve25519-sha256" || got.AlgoPolicy.String() != "curve25519-sha256" {
		t.Fatalf("got = %+v, want curve25519-sha256", got)
	}

	noop, err := ParseOption("KexAlgorithms", "+sntrup761x25519-sha512@openssh.com", OptionSourceOpenSSHConfig)
	if err != nil {
		t.Fatalf("ParseOption unsupported +Kex: %v", err)
	}
	if !noop.IsNoOp || noop.AlgoPolicy.IsUnset() || !noop.AlgoPolicy.IsDefault() || noop.AlgoPolicy.OptionKey() != OptionKexAlgorithms {
		t.Fatalf("expected IsNoOp=true DefaultAlgoPolicy(kex_algorithms), got %+v", noop)
	}

	if _, err := ParseOption("Ciphers", "unsupported-cipher@example.com", OptionSourceOpenSSHConfig); err == nil {
		t.Fatal("expected replace list with zero supported ciphers to fail")
	}

	// CLI source remains strict even on mixed OpenSSH-only tokens.
	if _, err := ParseOption("KexAlgorithms", "sntrup761x25519-sha512@openssh.com,curve25519-sha256", OptionSourceCLI); err == nil {
		t.Fatal("expected CLI source to reject unsupported KexAlgorithms token")
	}
}

func TestParseOption_TargetOptions(t *testing.T) {
	t.Parallel()

	portOpt, err := ParseOption("Port", "2222", OptionSourceCLI)
	if err != nil || !portOpt.IsTargetOption || portOpt.Port != 2222 {
		t.Fatalf("ParseOption(Port, 2222) = (%+v, %v)", portOpt, err)
	}
	if _, err := ParseOption("Port", "0", OptionSourceCLI); err == nil {
		t.Fatal("expected Port=0 to fail")
	}
	pjNone, err := ParseOption("ProxyJump", "none", OptionSourceCLI)
	if err != nil || !pjNone.IsTargetOption || !pjNone.ProxySetting.IsJumpDisabledOnly() {
		t.Fatalf("ParseOption(ProxyJump, none) = (%+v, %v)", pjNone, err)
	}
	pcNone, err := ParseOption("ProxyCommand", "none", OptionSourceCLI)
	if err != nil || pcNone.IsTargetOption || !pcNone.ProxySetting.IsDisabled() || pcNone.ProxySetting.IsJumpDisabledOnly() {
		t.Fatalf("ParseOption(ProxyCommand, none) = (%+v, %v)", pcNone, err)
	}
}

func TestMergeOptions_AlgebraicLaws(t *testing.T) {
	t.Parallel()

	samples := []*Options{
		nil,
		{},
		MustOptions(OptionIdentityFile, "/tmp/k1", OptionCiphers, "aes256-gcm@openssh.com", OptionSendEnv, "FOO_1 FOO_2"),
		MustOptions(OptionIdentityFile, "none", OptionCertificateFile, "none", OptionSendEnv, "-FOO_*"),
		MustOptions(OptionIdentityFile, "/tmp/k2", OptionCertificateFile, "/tmp/c2.pub", OptionSendEnv, "FOO_3 BAR"),
		MustOptions(OptionProxyCommand, "none", OptionControlPath, "/tmp/cm-%C"),
		MustOptions(OptionProxyCommand, "nc %h %p", OptionCiphers, "chacha20-poly1305@openssh.com"),
	}

	// Identity element: nil and empty Options act as left and right identities.
	for _, a := range samples {
		if got := MergeOptions(nil, a); !got.Equal(a) {
			t.Fatalf("left identity failed for %v: got %v", a, got)
		}
		if got := MergeOptions(a, nil); !got.Equal(a) {
			t.Fatalf("right identity failed for %v: got %v", a, got)
		}
	}

	// Associativity across all triples: ((a ⊕ b) ⊕ c) == (a ⊕ (b ⊕ c)) == (a ⊕ b ⊕ c).
	for i, a := range samples {
		for j, b := range samples {
			for k, c := range samples {
				left := MergeOptions(MergeOptions(a, b), c)
				right := MergeOptions(a, MergeOptions(b, c))
				flat := MergeOptions(a, b, c)
				if !left.Equal(right) || !left.Equal(flat) {
					t.Fatalf("associativity violated for (%d,%d,%d):\n  left:  %v\n  right: %v\n  flat:  %v",
						i, j, k, left.Map(), right.Map(), flat.Map())
				}
				if !slices.Equal(left.IdentityFiles(), right.IdentityFiles()) ||
					!slices.Equal(left.SendEnvPatterns(), right.SendEnvPatterns()) {
					t.Fatalf("projected accessors diverged for (%d,%d,%d)", i, j, k)
				}
			}
		}
	}
}
