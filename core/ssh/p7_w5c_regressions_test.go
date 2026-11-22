package ssh

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestP7W5c_ValidateIPv6ZoneAndEndpointRejection(t *testing.T) {
	t.Parallel()

	for _, okZone := range []string{"", "eth0", "en0", "fe80_1", "12", "Ethernet-0"} {
		if err := ValidateIPv6Zone(okZone); err != nil {
			t.Errorf("ValidateIPv6Zone(%q) unexpected error: %v", okZone, err)
		}
	}

	badZones := []string{
		"[",
		"]",
		"eth[0]",
		"eth:0",
		"eth%0",
		"eth/0",
		`eth\0`,
		"eth@0",
		"eth,0",
		"eth 0",
		"eth\t0",
		"eth\n0",
		"eth\x00",
		"eth\u2028",
		"eth\u2029",
	}
	for _, z := range badZones {
		if err := ValidateIPv6Zone(z); !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("ValidateIPv6Zone(%q) = %v, want ErrInvalidEndpoint", z, err)
		}
		addr := netip.MustParseAddr("fe80::1").WithZone(z)
		if _, err := NewAddrEndpoint(addr, 22); !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("NewAddrEndpoint(fe80::1%%%q) = %v, want ErrInvalidEndpoint", z, err)
		}
	}

	badEndpoints := []string{
		"[::%[]",
		"[::%]]",
		"[::%@]",
		"[::%,]",
		"[::%:]",
		"[::%/]",
		`[::%\]`,
		"[::%%]",
		"::%[",
		"fe80::1%eth@0",
		"fe80::1%eth,0",
		"fe80::1%eth:0",
		"[fe80::1%eth@0]:22",
		"[fe80::1%eth,0]:22",
	}
	for _, raw := range badEndpoints {
		if ep, err := ParseEndpoint(raw); !errors.Is(err, ErrInvalidEndpoint) || ep.IsValid() {
			t.Errorf("ParseEndpoint(%q) = (%+v, %v), want invalid + ErrInvalidEndpoint", raw, ep, err)
		}
		if ep, err := NewEndpoint(raw, 22); !errors.Is(err, ErrInvalidEndpoint) || ep.IsValid() {
			t.Errorf("NewEndpoint(%q, 22) = (%+v, %v), want invalid + ErrInvalidEndpoint", raw, ep, err)
		}
	}
}

func TestP7W5c_ParseProxyJumpAndIsDisabledProxyJumpSingleAuthority(t *testing.T) {
	t.Parallel()

	for _, disabled := range []string{"none", "NONE", "none,none", " NONE , none ", "none,NONE,none"} {
		if !IsDisabledProxyJump(disabled) {
			t.Errorf("IsDisabledProxyJump(%q) = false, want true", disabled)
		}
		ps, err := ParseProxyJump(disabled)
		if err != nil || !ps.Equal(DisabledProxyJumpSetting()) {
			t.Errorf("ParseProxyJump(%q) = (%q, %v), want DisabledProxyJumpSetting", disabled, ps, err)
		}
	}

	for _, bad := range []string{"", "   ", ",", " , ", "none,", ",none", "bastion,", ",bastion", "a,,b", "a,none", "none,a", "bastion\n", "bastion\x00"} {
		if IsDisabledProxyJump(bad) {
			t.Errorf("IsDisabledProxyJump(%q) = true, want false", bad)
		}
		if ps, err := ParseProxyJump(bad); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Errorf("ParseProxyJump(%q) = (%q, %v), want ErrSSHOptionsValidation", bad, ps, err)
		}
	}

	ps, err := ParseProxyJump("bastion1, user@bastion2:2222")
	if err != nil || ps.Kind() != ProxyJump || IsDisabledProxyJump("bastion1, user@bastion2:2222") {
		t.Fatalf("ParseProxyJump active failed: ps=%q err=%v", ps, err)
	}
}

func TestP7W5c_D5M1_AlgoOpDefaultHopDigestAndDropDefaultAlgoPolicies(t *testing.T) {
	t.Parallel()

	if err := ValidateDigestTags(reflect.TypeFor[Options]()); err != nil {
		t.Fatalf("ValidateDigestTags(Options): %v", err)
	}

	defMACs, err := DefaultAlgoPolicy(OptionMACs)
	if err != nil {
		t.Fatalf("DefaultAlgoPolicy(MACs): %v", err)
	}
	defCiphers, err := DefaultAlgoPolicy(OptionCiphers)
	if err != nil {
		t.Fatalf("DefaultAlgoPolicy(Ciphers): %v", err)
	}

	digestFor := func(opts *Options) HopDigest {
		return DigestClientConfig(NewClientConfig(ClientConfig{
			NodeID:  "n1",
			Address: "10.0.0.1",
			Port:    22,
			User:    "ops",
			Options: opts,
		}), ZeroHopDigest)
	}

	emptyDigest := digestFor(&Options{})
	nilDigest := digestFor(nil)
	if !emptyDigest.Equal(nilDigest) {
		t.Fatal("nil and empty Options must share HopDigest")
	}

	optsDefMAC := &Options{}
	optsDefMAC.SetAlgoPolicy(defMACs)
	optsDefCipher := &Options{}
	optsDefCipher.SetAlgoPolicy(defCiphers)

	dDefMAC := digestFor(optsDefMAC)
	dDefCipher := digestFor(optsDefCipher)
	if dDefMAC.Equal(emptyDigest) {
		t.Fatal("Options with AlgoOpDefault(MACs) must NOT share HopDigest with empty Options")
	}
	if dDefMAC.Equal(dDefCipher) {
		t.Fatal("Options with AlgoOpDefault(MACs) must NOT share HopDigest with AlgoOpDefault(Ciphers)")
	}
	if !dDefMAC.Equal(digestFor(optsDefMAC.Clone())) {
		t.Fatal("Clone must preserve HopDigest for AlgoOpDefault")
	}

	withTimeout := MustOptions(OptionConnectTimeout, "15")
	withTimeoutAndDefMAC := withTimeout.Clone()
	withTimeoutAndDefMAC.SetAlgoPolicy(defMACs)
	if digestFor(withTimeout).Equal(digestFor(withTimeoutAndDefMAC)) {
		t.Fatal("Options differing in AlgoOpDefault alongside other values must produce distinct HopDigests")
	}

	// DropDefaultAlgoPolicies strips AlgoOpDefault while keeping non-default policies and scalar values.
	supportedCiphers := cryptoSSH.SupportedAlgorithms().Ciphers
	if len(supportedCiphers) == 0 {
		t.Fatal("expected non-empty supported ciphers")
	}
	mixed := MustOptions(OptionConnectTimeout, "15", OptionCiphers, supportedCiphers[0])
	mixed.SetAlgoPolicy(defMACs)
	mixed.DropDefaultAlgoPolicies()
	if _, ok := mixed.AlgoPolicy(OptionMACs); ok {
		t.Fatal("DropDefaultAlgoPolicies did not strip AlgoOpDefault(MACs)")
	}
	if pol, ok := mixed.AlgoPolicy(OptionCiphers); !ok || pol.Op() != AlgoOpReplace {
		t.Fatalf("DropDefaultAlgoPolicies stripped non-default cipher policy: (%+v, %v)", pol, ok)
	}
	if mixed.Get(OptionConnectTimeout) != "15" {
		t.Fatalf("DropDefaultAlgoPolicies altered ConnectTimeout: %q", mixed.Get(OptionConnectTimeout))
	}

	optsDefMAC.DropDefaultAlgoPolicies()
	if !optsDefMAC.IsEmpty() || !optsDefMAC.IsZero() {
		t.Fatalf("DropDefaultAlgoPolicies on default-only Options must leave IsEmpty=true IsZero=true, got empty=%v zero=%v",
			optsDefMAC.IsEmpty(), optsDefMAC.IsZero())
	}
	if !digestFor(optsDefMAC).Equal(emptyDigest) {
		t.Fatal("after DropDefaultAlgoPolicies, default-only Options must match empty HopDigest")
	}
}

func TestP7W5c_C5L1_StripClassesResetsImplicitTier4(t *testing.T) {
	t.Parallel()

	opts := MustOptions(OptionControlMaster, "auto", OptionControlPath, "/tmp/cm-%C", OptionConnectTimeout, "10")
	opts.ImplicitTier4 = true

	// Stripping a non-mux class preserves ImplicitTier4.
	nonMux := opts.Clone()
	nonMux.StripClasses(OptionClassTransport)
	if !nonMux.ImplicitTier4 {
		t.Fatal("StripClasses(OptionClassTransport) unexpectedly cleared ImplicitTier4")
	}

	// Stripping OptionClassMux clears ImplicitTier4 and matches HopDigest of non-ImplicitTier4 Options.
	opts.StripClasses(OptionClassMux)
	if opts.ImplicitTier4 {
		t.Fatal("StripClasses(OptionClassMux) did not reset ImplicitTier4 to false")
	}
	if opts.ControlMaster() != "" || opts.ControlPath() != "" || opts.Get(OptionConnectTimeout) != "10" {
		t.Fatalf("unexpected remaining options after StripClasses(OptionClassMux): %v", opts.Map())
	}
	expected := MustOptions(OptionConnectTimeout, "10")
	dGot := DigestClientConfig(NewClientConfig(ClientConfig{NodeID: "n1", Address: "10.0.0.1", Port: 22, Options: opts}), ZeroHopDigest)
	dWant := DigestClientConfig(NewClientConfig(ClientConfig{NodeID: "n1", Address: "10.0.0.1", Port: 22, Options: expected}), ZeroHopDigest)
	if !dGot.Equal(dWant) {
		t.Fatalf("HopDigest mismatch after StripClasses(OptionClassMux): got=%s want=%s", dGot, dWant)
	}

	// Even an otherwise-empty Options with ImplicitTier4=true resets it when stripping OptionClassMux.
	emptyImplicit := &Options{ImplicitTier4: true}
	emptyImplicit.StripClasses(OptionClassMux)
	if emptyImplicit.ImplicitTier4 {
		t.Fatal("StripClasses(OptionClassMux) did not reset ImplicitTier4 on empty Options")
	}

	// FilterByClasses without OptionClassMux must not leak ImplicitTier4=true.
	withMux := MustOptions(OptionControlMaster, "auto", OptionConnectTimeout, "10")
	withMux.ImplicitTier4 = true
	if transportOnly := withMux.FilterByClasses(OptionClassTransport); transportOnly == nil || transportOnly.ImplicitTier4 {
		t.Fatalf("FilterByClasses(OptionClassTransport) leaked ImplicitTier4: %+v", transportOnly)
	}
	if muxOnly := withMux.FilterByClasses(OptionClassMux); muxOnly == nil || !muxOnly.ImplicitTier4 {
		t.Fatalf("FilterByClasses(OptionClassMux) did not preserve ImplicitTier4: %+v", muxOnly)
	}
}

func TestP7W5c_D5L2_KnownHostsDevNullParity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		goos string
		path string
		want bool
	}{
		{"linux", "/dev/null", true},
		{"linux", "  /dev/null  ", true},
		{"linux", "/dev//null", true},
		{"darwin", "/dev/null", true},
		{"linux", "/DEV/NULL", false},
		{"linux", "NUL", false},
		{"linux", `\\.\NUL`, false},
		{"windows", "/dev/null", true},
		{"windows", "/dev//null", true},
		{"windows", "/DEV/NULL", true},
		{"windows", `\dev\null`, true},
		{"windows", `\DEV\NULL`, true},
		{"windows", "NUL", true},
		{"windows", "nul", true},
		{"windows", "Nul", true},
		{"windows", `\\.\NUL`, true},
		{"windows", `\\.\nul`, true},
		{"windows", `//./NUL`, true},
		{"windows", `//./nul`, true},
		{"windows", `C:\Users\alice\NUL`, false},
		{"windows", "NUL.txt", false},
		{"windows", "/dev/zero", false},
		{"linux", "/dev/zero", false},
		{"linux", "", false},
		{"windows", "", false},
	}

	for _, tc := range cases {
		if got := isKnownHostsDevNullForOS(tc.goos, tc.path); got != tc.want {
			t.Errorf("isKnownHostsDevNullForOS(%q, %q) = %v, want %v", tc.goos, tc.path, got, tc.want)
		}
	}

	if !isKnownHostsDevNull("/dev/null") {
		t.Fatal("isKnownHostsDevNull(/dev/null) = false, want true")
	}
	db := newKnownHostsDB()
	if err := db.parseFileStrict("/dev/null"); err != nil {
		t.Fatalf("parseFileStrict(/dev/null) unexpected error: %v", err)
	}
}

func TestP7W5c_D5L3_ResolveLocalExecOriginalHostCaseInsensitiveOpenSSHPrefix(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		nodeID string
		want   string
	}{
		{"openssh:web", "web"},
		{"OPENSSH:web", "web"},
		{"OpenSSH:alice@web:2222", "web"},
		{"oPeNsSh:[2001:db8::1]:22", "2001:db8::1"},
		{"OPENSSH:[fe80::1%eth0]", "fe80::1%eth0"},
	} {
		got, err := resolveLocalExecOriginalHost("", tc.nodeID, "", "")
		if err != nil {
			t.Errorf("resolveLocalExecOriginalHost(%q) unexpected error: %v", tc.nodeID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveLocalExecOriginalHost(%q) = %q, want %q", tc.nodeID, got, tc.want)
		}
	}

	for _, bad := range []string{"openssh:", "OPENSSH:", "OpenSSH:"} {
		if got, err := resolveLocalExecOriginalHost("", bad, "", ""); !errors.Is(err, ErrUnsafeExecToken) {
			t.Errorf("resolveLocalExecOriginalHost(%q) = (%q, %v), want ErrUnsafeExecToken", bad, got, err)
		}
	}
}
