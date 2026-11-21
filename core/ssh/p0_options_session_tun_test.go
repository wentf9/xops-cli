package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// TestP0_ControlValidationAndProjectionParity verifies that Validate,
// ValidateEffective, and ValidatedControlConfig agree on cross-field control
// invariants (including ControlMaster=no/unset with enabled ControlPersist),
// while ControlConfig() remains lenient and ControlPath=none normalization is preserved.
func TestP0_ControlValidationAndProjectionParity(t *testing.T) {
	t.Parallel()
	t.Run("master_no_or_false_with_enabled_persist_rejected_everywhere", testP0ControlMasterNoWithEnabledPersist)
	t.Run("unset_master_with_enabled_persist_rejected_effectively", testP0ControlUnsetMasterWithEnabledPersist)
	t.Run("cross_layer_master_no_over_lower_persist_rejected", testP0ControlCrossLayerMasterNoOverPersist)
	t.Run("master_no_with_persist_no_allowed", testP0ControlMasterNoWithPersistNo)
	t.Run("control_path_none_cross_layer_finalizes_cleanly", testP0ControlPathNoneFinalizesCleanly)
}

func testP0ControlMasterNoWithEnabledPersist(t *testing.T) {
	for _, master := range []ControlMasterMode{ControlMasterNo, ControlMasterMode("false")} {
		for _, persist := range []string{"10m", "yes", "true", "0", "30s"} {
			opts := OptionsFromControl(&ControlConfig{
				Master:  master,
				Path:    "/tmp/cm-%C",
				Persist: persist,
			})
			if err := opts.Validate(); !errors.Is(err, ErrSSHOptionsValidation) {
				t.Errorf("Validate(master=%q, persist=%q) = %v, want ErrSSHOptionsValidation", master, persist, err)
			}
			if err := opts.ValidateEffective(); !errors.Is(err, ErrSSHOptionsValidation) {
				t.Errorf("ValidateEffective(master=%q, persist=%q) = %v, want ErrSSHOptionsValidation", master, persist, err)
			}
			if ctrl, err := opts.ValidatedControlConfig(); err == nil {
				t.Errorf("ValidatedControlConfig(master=%q, persist=%q) = %+v, want error", master, persist, ctrl)
			}
			if ctrl := opts.ControlConfig(); ctrl == nil {
				t.Errorf("ControlConfig(master=%q, persist=%q) = nil, want lenient projection", master, persist)
			}
		}
	}
}

func testP0ControlUnsetMasterWithEnabledPersist(t *testing.T) {
	opts := OptionsFromControl(&ControlConfig{
		Path:    "/tmp/cm-%C",
		Persist: "10m",
	})
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate(partial Path+Persist) unexpected error: %v", err)
	}
	if err := opts.ValidateEffective(); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("ValidateEffective(unset Master + Persist=10m) = %v, want ErrSSHOptionsValidation", err)
	}
	if ctrl, err := opts.ValidatedControlConfig(); err == nil {
		t.Fatalf("ValidatedControlConfig(unset Master + Persist=10m) = %+v, want error", ctrl)
	}
	ctrl := opts.ControlConfig()
	if ctrl == nil || ctrl.Master != "" || ctrl.Path != "/tmp/cm-%C" || ctrl.Persist != "10m" {
		t.Fatalf("ControlConfig(partial Path+Persist) = %+v, want unset Master", ctrl)
	}
}

func testP0ControlCrossLayerMasterNoOverPersist(t *testing.T) {
	tier1 := MustOptions(OptionControlMaster, "no")
	tier2 := MustOptions(
		OptionControlMaster, "auto",
		OptionControlPath, "/tmp/cm-%C",
		OptionControlPersist, "10m",
	)
	eff, err := EffectiveOptions(tier1, tier2)
	if err != nil {
		t.Fatalf("EffectiveOptions failed: %v", err)
	}
	if err := eff.ValidateEffective(); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("ValidateEffective(cross-layer Master=no + Persist=10m) = %v, want ErrSSHOptionsValidation", err)
	}
	if ctrl, err := eff.ValidatedControlConfig(); err == nil {
		t.Fatalf("ValidatedControlConfig(cross-layer Master=no + Persist=10m) = %+v, want error", ctrl)
	}
}

func testP0ControlMasterNoWithPersistNo(t *testing.T) {
	for _, persist := range []string{"no", "false"} {
		opts := OptionsFromControl(&ControlConfig{
			Master:  ControlMasterNo,
			Path:    "/tmp/cm-%C",
			Persist: persist,
		})
		if err := opts.ValidateEffective(); err != nil {
			t.Fatalf("ValidateEffective(master=no, persist=%q) failed: %v", persist, err)
		}
		ctrl, err := opts.ValidatedControlConfig()
		if err != nil || ctrl == nil || ctrl.Master != ControlMasterNo || ctrl.Persist != persist {
			t.Fatalf("ValidatedControlConfig(master=no, persist=%q) = (%+v, %v)", persist, ctrl, err)
		}
	}
}

func testP0ControlPathNoneFinalizesCleanly(t *testing.T) {
	eff, err := EffectiveOptions(
		MustOptions(OptionControlPath, "none"),
		MustOptions(OptionControlMaster, "auto", OptionControlPath, "/tmp/cm-%C", OptionControlPersist, "10m"),
	)
	if err != nil {
		t.Fatalf("EffectiveOptions failed: %v", err)
	}
	if err := eff.ValidateEffective(); err != nil {
		t.Fatalf("ValidateEffective(finalized none) failed: %v", err)
	}
	ctrl, err := eff.ValidatedControlConfig()
	if err != nil || ctrl == nil || ctrl.Master != ControlMasterNo || ctrl.Path != "none" || ctrl.Persist != "" {
		t.Fatalf("ValidatedControlConfig(finalized none) = (%+v, %v)", ctrl, err)
	}
}

// TestP0_FilterSupportedListValue_PreferredAuthFailClosed verifies that
// PreferredAuthentications containing only recognized unimplemented OpenSSH
// methods (gssapi-with-mic, hostbased) is retained so auth.go fails closed,
// while mixed lists still filter to implemented methods and garbage yields "".
func TestP0_FilterSupportedListValue_PreferredAuthFailClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw             string
		wantFiltered    string
		wantFailClosed  bool
		wantOrderLabels []string
	}{
		{"gssapi-with-mic", "gssapi-with-mic", true, nil},
		{"hostbased", "hostbased", true, nil},
		{"GSSAPI-WITH-MIC, HostBased, gssapi-with-mic", "gssapi-with-mic,hostbased", true, nil},
		{"gssapi-with-mic,unknown-auth", "gssapi-with-mic", true, nil},
		{"gssapi-with-mic,publickey,password", "publickey,password", false, []string{"pk", "pw"}},
		{"hostbased,keyboard-interactive", "keyboard-interactive", false, []string{"kb"}},
		{"unknown-only,bogus", "", false, nil},
	}

	for _, tc := range cases {
		got := FilterSupportedListValue(OptionPreferredAuthentications, tc.raw)
		if got != tc.wantFiltered {
			t.Errorf("FilterSupportedListValue(PreferredAuthentications, %q) = %q, want %q", tc.raw, got, tc.wantFiltered)
			continue
		}
		if tc.wantFiltered == "" {
			continue
		}
		opts, err := NewOptions(OptionPreferredAuthentications, got)
		if err != nil {
			t.Fatalf("NewOptions(PreferredAuthentications=%q) failed: %v", got, err)
		}
		pkAllowed, pwAllowed, kbAllowed, _, preferred := resolveAutoAuthPolicy(opts)
		ordered := orderAutoAuthCandidates(
			preferred,
			[]autoAuthCandidate{{label: "pk"}},
			[]autoAuthCandidate{{label: "pw"}},
			[]autoAuthCandidate{{label: "kb"}},
		)
		if tc.wantFailClosed {
			if pkAllowed || pwAllowed || kbAllowed || len(ordered) != 0 {
				t.Errorf("raw=%q: expected fail-closed auth policy, got pk=%v pw=%v kb=%v ordered=%+v",
					tc.raw, pkAllowed, pwAllowed, kbAllowed, ordered)
			}
			continue
		}
		var labels []string
		for _, c := range ordered {
			labels = append(labels, c.label)
		}
		if !slices.Equal(labels, tc.wantOrderLabels) {
			t.Errorf("raw=%q: ordered labels = %v, want %v", tc.raw, labels, tc.wantOrderLabels)
		}
	}
}

// TestP0_MergeOptionLayers_IdentityAndCertificateNoneTruncation verifies that
// IdentityFile=none and CertificateFile=none truncate subsequent entries and
// all lower-priority layers while preserving preceding concrete entries.
func TestP0_MergeOptionLayers_IdentityAndCertificateNoneTruncation(t *testing.T) {
	t.Parallel()

	t.Run("identity_file_none_first_ignores_lower_layers", func(t *testing.T) {
		merged := MergeOptionLayers(
			MustOptions(OptionIdentityFile, "none"),
			MustOptions(OptionIdentityFile, "~/.ssh/node_key"),
			MustOptions(OptionIdentityFile, "~/.ssh/global_key"),
		)
		if got := merged.IdentityFiles(); !slices.Equal(got, []string{"none"}) {
			t.Fatalf("IdentityFiles() = %v, want [none]", got)
		}
		keys, hasExplicit := collectExplicitKeyCandidates(nil, "", merged, Environment{}, TargetContext{Host: "h"}, nil, nil)
		if !hasExplicit || len(keys) != 0 {
			t.Fatalf("collectExplicitKeyCandidates = (%v, %v), want ([], true)", keys, hasExplicit)
		}
	})

	t.Run("identity_file_concrete_before_none_keeps_concrete_and_truncates_lower", func(t *testing.T) {
		merged := MergeOptionLayers(
			MustOptions(OptionIdentityFile, "/tmp/cli_key"),
			MustOptions(OptionIdentityFile, "NONE"),
			MustOptions(OptionIdentityFile, "/tmp/global_key"),
		)
		if got := merged.IdentityFiles(); !slices.Equal(got, []string{"/tmp/cli_key"}) {
			t.Fatalf("IdentityFiles() = %v, want [/tmp/cli_key]", got)
		}
	})

	t.Run("identity_file_intra_layer_truncation", func(t *testing.T) {
		layerConcreteFirst := &Options{}
		_ = layerConcreteFirst.Append(OptionIdentityFile, "/tmp/k1")
		_ = layerConcreteFirst.Append(OptionIdentityFile, "none")
		_ = layerConcreteFirst.Append(OptionIdentityFile, "/tmp/k2")
		lower := MustOptions(OptionIdentityFile, "/tmp/k3")

		if got := MergeOptionLayers(layerConcreteFirst, lower).IdentityFiles(); !slices.Equal(got, []string{"/tmp/k1"}) {
			t.Fatalf("intra-layer concrete-then-none IdentityFiles() = %v, want [/tmp/k1]", got)
		}

		layerNoneFirst := &Options{}
		_ = layerNoneFirst.Append(OptionIdentityFile, "none")
		_ = layerNoneFirst.Append(OptionIdentityFile, "/tmp/k2")
		if got := MergeOptionLayers(layerNoneFirst, lower).IdentityFiles(); !slices.Equal(got, []string{"none"}) {
			t.Fatalf("intra-layer none-then-concrete IdentityFiles() = %v, want [none]", got)
		}
	})

	t.Run("certificate_file_none_truncation_independent_of_identity_file", func(t *testing.T) {
		merged := MergeOptionLayers(
			MustOptions(OptionCertificateFile, "none", OptionIdentityFile, "/tmp/k1"),
			MustOptions(OptionCertificateFile, "/tmp/c1-cert.pub", OptionIdentityFile, "/tmp/k2"),
			MustOptions(OptionCertificateFile, "/tmp/c2-cert.pub", OptionIdentityFile, "none"),
			MustOptions(OptionIdentityFile, "/tmp/k4"),
		)
		if got := merged.CertificateFiles(); !slices.Equal(got, []string{"none"}) {
			t.Fatalf("CertificateFiles() = %v, want [none]", got)
		}
		if got := merged.IdentityFiles(); !slices.Equal(got, []string{"/tmp/k1", "/tmp/k2"}) {
			t.Fatalf("IdentityFiles() = %v, want [/tmp/k1 /tmp/k2]", got)
		}
		certs, hasExplicit := collectExplicitUserCerts(merged, Environment{}, TargetContext{Host: "h"}, nil, nil)
		if !hasExplicit || len(certs) != 0 {
			t.Fatalf("collectExplicitUserCerts = (%v, %v), want ([], true)", certs, hasExplicit)
		}
	})

	t.Run("certificate_file_concrete_before_none_truncates_lower", func(t *testing.T) {
		merged := MergeOptionLayers(
			MustOptions(OptionCertificateFile, "/tmp/c1-cert.pub"),
			MustOptions(OptionCertificateFile, "none"),
			MustOptions(OptionCertificateFile, "/tmp/c2-cert.pub"),
		)
		if got := merged.CertificateFiles(); !slices.Equal(got, []string{"/tmp/c1-cert.pub"}) {
			t.Fatalf("CertificateFiles() = %v, want [/tmp/c1-cert.pub]", got)
		}
	})
}

func assertRawEndpointMethods(t *testing.T, ep ForwardEndpoint, wantRaw string) {
	t.Helper()
	if netw, addr := ep.LocalListenAddress(false); netw != "unix" || addr != wantRaw {
		t.Errorf("LocalListenAddress(false) = (%q, %q), want (unix, %q)", netw, addr, wantRaw)
	}
	if netw, addr := ep.LocalListenAddressWithNetwork(true, "tcp6"); netw != "unix" || addr != wantRaw {
		t.Errorf("LocalListenAddressWithNetwork = (%q, %q), want (unix, %q)", netw, addr, wantRaw)
	}
	if netw, addr := ep.RemoteListenAddress(); netw != "unix" || addr != wantRaw {
		t.Errorf("RemoteListenAddress = (%q, %q), want (unix, %q)", netw, addr, wantRaw)
	}
	if netw, addr := ep.RemoteListenAddressForMode(GatewayPortsYes, "tcp4"); netw != "unix" || addr != wantRaw {
		t.Errorf("RemoteListenAddressForMode = (%q, %q), want (unix, %q)", netw, addr, wantRaw)
	}
	if netw, addr := ep.ConnectAddress(); netw != "unix" || addr != wantRaw {
		t.Errorf("ConnectAddress = (%q, %q), want (unix, %q)", netw, addr, wantRaw)
	}
	if netw, addr := ep.ConnectAddressWithNetwork("tcp6"); netw != "unix" || addr != wantRaw {
		t.Errorf("ConnectAddressWithNetwork = (%q, %q), want (unix, %q)", netw, addr, wantRaw)
	}
	if h, p := ep.MuxListenEndpoint(); h != wantRaw || p != MUX_SPECIAL_PORT_UNIX {
		t.Errorf("MuxListenEndpoint = (%q, %d), want (%q, %d)", h, p, wantRaw, MUX_SPECIAL_PORT_UNIX)
	}
	if h, p := ep.MuxConnectEndpoint(); h != wantRaw || p != MUX_SPECIAL_PORT_UNIX {
		t.Errorf("MuxConnectEndpoint = (%q, %d), want (%q, %d)", h, p, wantRaw, MUX_SPECIAL_PORT_UNIX)
	}
}

// TestP0_ForwardEndpoint_StreamLocalQuotingRoundTrip_AndStdioValidation tests
// lossless quoting/escaping of StreamLocal paths with spaces, quotes, and
// backslashes across all forward parsers and Options serialization, plus
// ParseStdioForward wildcard rejection and upfront control-char validation.
func TestP0_ForwardEndpoint_StreamLocalQuotingRoundTrip_AndStdioValidation(t *testing.T) {
	t.Parallel()
	t.Run("curated_streamlocal_paths_roundtrip", testP0StreamLocalCuratedPathsRoundTrip)
	t.Run("property_roundtrip_random_streamlocal_paths", testP0StreamLocalPropertyRoundTrip)
	t.Run("stdio_forward_and_unwrap_reject_wildcards", testP0StdioForwardRejectsWildcards)
	t.Run("forward_parsers_reject_control_chars_upfront", testP0ForwardParsersRejectControlChars)
}

func assertForwardSpecRoundTrip(t *testing.T, wantSpec ForwardSpec) {
	t.Helper()
	wire := wantSpec.String()
	gotSpec, err := ParseForwardSpec(wire)
	if err != nil {
		t.Fatalf("ParseForwardSpec(%q) failed: %v", wire, err)
	}
	if gotSpec != wantSpec {
		t.Fatalf("ParseForwardSpec round-trip mismatch for wire %q:\ngot:  %+v\nwant: %+v", wire, gotSpec, wantSpec)
	}
	opts := &Options{}
	if err := opts.Append(OptionLocalForward, wire); err != nil {
		t.Fatalf("Options.Append(LocalForward, %q) failed: %v", wire, err)
	}
	stored := opts.LocalForwards()
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored LocalForward, got %v", stored)
	}
	reparsed, err := ParseForwardSpec(stored[0])
	if err != nil || reparsed != wantSpec {
		t.Fatalf("Options stored LocalForward %q re-parse = (%+v, %v), want %+v", stored[0], reparsed, err, wantSpec)
	}
}

func testP0StreamLocalCuratedPathsRoundTrip(t *testing.T) {
	paths := []string{
		"/tmp/my dir/app.sock",
		"/tmp/two  spaces/app.sock",
		`C:\Program Files\xops\agent.sock`,
		`\\server\share\agent.sock`,
		`\\server\my share\agent.sock`,
		`/tmp/dir with "double quotes"/a.sock`,
		`/tmp/dir with 'single quotes'/a.sock`,
		`/tmp/mix "dq" and 'sq' and \slash\/a.sock`,
		`/tmp/double\\backslash/a.sock`,
		`/tmp/trailing-backslash\`,
		" /tmp/leading-space.sock",
		"/tmp/trailing-space.sock ",
		"/tmp/unicode\u00a0space/a.sock",
		`C:\temp\a.sock`,
	}

	for _, p := range paths {
		ep := ForwardEndpoint{SocketPath: p}
		assertRawEndpointMethods(t, ep, p)

		dynParsed, err := ParseDynamicForwardEndpoint(ep.String())
		if err != nil || dynParsed != ep {
			t.Fatalf("DynamicForward round-trip for %q (wire=%q) = (%+v, %v), want %+v", p, ep.String(), dynParsed, err, ep)
		}

		for _, wantSpec := range []ForwardSpec{
			{Bind: ep, Dest: ForwardEndpoint{Host: "127.0.0.1", Port: 8080, HasHost: true}, BindAddr: p, DestAddr: "127.0.0.1:8080"},
			{Bind: ForwardEndpoint{Port: 8080}, Dest: ep, BindAddr: "127.0.0.1:8080", DestAddr: p},
			{Bind: ep, Dest: ForwardEndpoint{SocketPath: "/tmp/other dir/dest.sock"}, BindAddr: p, DestAddr: "/tmp/other dir/dest.sock"},
			{Bind: ForwardEndpoint{SocketPath: `C:\temp\a.sock`}, Dest: ep, BindAddr: `C:\temp\a.sock`, DestAddr: p},
		} {
			assertForwardSpecRoundTrip(t, wantSpec)
		}

		wantRem := ForwardSpec{Bind: ep, IsDynamic: true, BindAddr: p}
		gotRem, err := ParseRemoteForwardSpec(wantRem.String())
		if err != nil || gotRem != wantRem {
			t.Fatalf("ParseRemoteForwardSpec round-trip for %q = (%+v, %v), want %+v", p, gotRem, err, wantRem)
		}
	}
}

func testP0StreamLocalPropertyRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261121, 42))
	alphabet := []byte{'a', 'b', '0', '/', '\\', ' ', '"', '\'', '-', '_', '.'}
	for i := range 200 {
		var sb strings.Builder
		if i%3 == 0 {
			sb.WriteString(`C:\`)
		} else {
			sb.WriteString("/tmp/")
		}
		n := 1 + rng.IntN(24)
		for range n {
			sb.WriteByte(alphabet[rng.IntN(len(alphabet))])
		}
		p := sb.String()
		bindEp := ForwardEndpoint{SocketPath: p}
		destEp := ForwardEndpoint{SocketPath: "/var/run/" + p}
		spec := ForwardSpec{Bind: bindEp, Dest: destEp, BindAddr: p, DestAddr: "/var/run/" + p}
		got, err := ParseForwardSpec(spec.String())
		if err != nil || got != spec {
			t.Fatalf("iter %d: ParseForwardSpec(%q) for path %q = (%+v, %v), want %+v", i, spec.String(), p, got, err, spec)
		}
		gotDyn, err := ParseDynamicForwardEndpoint(bindEp.String())
		if err != nil || gotDyn != bindEp {
			t.Fatalf("iter %d: ParseDynamicForwardEndpoint(%q) = (%+v, %v), want %+v", i, bindEp.String(), gotDyn, err, bindEp)
		}
	}
}

func testP0StdioForwardRejectsWildcards(t *testing.T) {
	for _, bad := range []string{"[*]:22", "*:22", ":22", "[]:22", "\r127.0.0.1:22", "127.0.0.1:22\n"} {
		if host, port, err := ParseStdioForward(bad); err == nil {
			t.Errorf("ParseStdioForward(%q) = (%q, %d, nil), want error", bad, host, port)
		}
	}
	for _, badHost := range []string{"[*]", "*", ""} {
		if got, err := unwrapForwardHost(badHost, false); err == nil {
			t.Errorf("unwrapForwardHost(%q, false) = (%q, nil), want error", badHost, got)
		}
	}
	if got, err := unwrapForwardHost("[*]", true); err != nil || got != "" {
		t.Errorf("unwrapForwardHost([*], true) = (%q, %v), want (\"\", nil)", got, err)
	}
}

func testP0ForwardParsersRejectControlChars(t *testing.T) {
	if spec, err := ParseForwardSpec("8080\t127.0.0.1:80"); err != nil || spec.Bind.Port != 8080 || spec.Dest.Port != 80 {
		t.Fatalf("ParseForwardSpec(tab-separated) = (%+v, %v), want success", spec, err)
	}
	for _, ctrl := range []string{"\r", "\n", "\x00", "\x1b", "\u0085", "\u2028", "\u2029"} {
		for _, sample := range []string{ctrl + "8080 127.0.0.1:80", "8080 127.0.0.1:80" + ctrl} {
			if _, err := ParseForwardSpec(sample); err == nil {
				t.Errorf("ParseForwardSpec accepted control sample %q", sample)
			}
		}
		for _, sample := range []string{ctrl + "1080", "1080" + ctrl} {
			if _, err := ParseRemoteForwardSpec(sample); err == nil {
				t.Errorf("ParseRemoteForwardSpec accepted control sample %q", sample)
			}
			if _, err := ParseDynamicForwardEndpoint(sample); err == nil {
				t.Errorf("ParseDynamicForwardEndpoint accepted control sample %q", sample)
			}
		}
	}
}

// TestP0_SendEnv_NegativePatternDoesNotPruneBroaderWildcard verifies that a
// narrower negative wildcard pattern (e.g. -LC_?) does not falsely delete an
// earlier broader positive wildcard pattern (e.g. LC_*).
func TestP0_SendEnv_NegativePatternDoesNotPruneBroaderWildcard(t *testing.T) {
	t.Parallel()

	t.Run("lc_star_then_minus_lc_qmark", func(t *testing.T) {
		opts := &Options{}
		if err := opts.Append(OptionSendEnv, "LC_*"); err != nil {
			t.Fatalf("Append(LC_*): %v", err)
		}
		if err := opts.Append(OptionSendEnv, "-LC_?"); err != nil {
			t.Fatalf("Append(-LC_?): %v", err)
		}
		got, err := ResolveSessionEnv(opts, func() []string {
			return []string{
				"LC_ALL=C.UTF-8",
				"LC_CTYPE=en_US.UTF-8",
				"LC_X=should_be_excluded",
				"LC_1=should_also_be_excluded",
				"OTHER=ignored",
			}
		})
		if err != nil {
			t.Fatalf("ResolveSessionEnv: %v", err)
		}
		want := []EnvVar{
			{Name: "LC_ALL", Value: "C.UTF-8"},
			{Name: "LC_CTYPE", Value: "en_US.UTF-8"},
		}
		if !slices.Equal(got, want) {
			t.Fatalf("ResolveSessionEnv = %+v, want %+v", got, want)
		}
	})

	t.Run("multi_tier_merge_and_re_enable", func(t *testing.T) {
		merged, err := EffectiveOptions(
			MustOptions(OptionSendEnv, "LC_X"),
			MustOptions(OptionSendEnv, "-LC_?"),
			MustOptions(OptionSendEnv, "LC_*"),
		)
		if err != nil {
			t.Fatalf("EffectiveOptions: %v", err)
		}
		got, err := ResolveSessionEnv(merged, func() []string {
			return []string{"LC_ALL=C", "LC_X=kept", "LC_Y=dropped"}
		})
		if err != nil {
			t.Fatalf("ResolveSessionEnv: %v", err)
		}
		want := []EnvVar{
			{Name: "LC_ALL", Value: "C"},
			{Name: "LC_X", Value: "kept"},
		}
		if !slices.Equal(got, want) {
			t.Fatalf("ResolveSessionEnv = %+v, want %+v", got, want)
		}
	})

	t.Run("exact_negative_pattern_removes_positive", func(t *testing.T) {
		opts := &Options{}
		_ = opts.Append(OptionSendEnv, "LC_*")
		_ = opts.Append(OptionSendEnv, "-LC_*")
		got, err := ResolveSessionEnv(opts, func() []string { return []string{"LC_ALL=C", "LC_X=1"} })
		if err != nil {
			t.Fatalf("ResolveSessionEnv: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected empty resolved env after LC_* then -LC_*, got %+v", got)
		}
	})
}

// TestP0_EscapeFilter_ConcurrentOutputSynchronization_AndDoubledSpecialEscape
// verifies under -race that escape filter local output shares outputMu with
// startSessionOutput, and that doubled escape characters pass through literally
// even when EscapeChar is '.', '#', '?', or '^Z'.
func TestP0_EscapeFilter_ConcurrentOutputSynchronization_AndDoubledSpecialEscape(t *testing.T) {
	t.Parallel()
	t.Run("race_free_concurrent_session_output_and_escape_local_out", testP0EscapeConcurrentOutputSync)
	t.Run("localOut_falls_back_to_synchronized_stdout_when_stderr_nil", testP0EscapeStdoutFallbackSync)
	t.Run("doubled_special_escape_chars_pass_through_literally", testP0EscapeDoubledSpecialChars)
	t.Run("suspend_callback_blocks_until_resume_before_continuing_input", testP0EscapeSuspendBlocksUntilResume)
}

func testP0EscapeConcurrentOutputSync(t *testing.T) {
	var sharedOut bytes.Buffer // intentionally unsynchronized; must be protected by outputMu
	outR, outW := io.Pipe()
	errR, errW := io.Pipe()
	output := startSessionOutput(outR, errR, &sharedOut, &sharedOut)

	client := &Client{connCfg: ConnectionConfig{Address: "race-host.internal"}}
	var remoteIn bytes.Buffer
	var disconnected atomic.Bool
	wrapped, filter := client.wrapTerminalEscapeInput(
		&remoteIn,
		output.localOut(),
		'~',
		true,
		func() { disconnected.Store(true) },
		func() error { return errors.New("test suspend denied") },
	)
	if filter == nil {
		t.Fatal("expected non-nil escapeFilterWriter")
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		defer func() { _ = outW.Close() }()
		for i := range 100 {
			_, _ = fmt.Fprintf(outW, "stdout-chunk-%d\r\n", i)
		}
	})
	wg.Go(func() {
		defer func() { _ = errW.Close() }()
		for i := range 100 {
			_, _ = fmt.Fprintf(errW, "stderr-chunk-%d\r\n", i)
		}
	})
	wg.Go(func() {
		for range 25 {
			_, _ = wrapped.Write([]byte("~?"))
			_, _ = wrapped.Write([]byte("~#"))
			_, _ = wrapped.Write([]byte{'~', 0x1a})
		}
		_, _ = wrapped.Write([]byte("~."))
	})

	wg.Wait()
	if err := output.wait(); err != nil {
		t.Fatalf("output.wait() failed: %v", err)
	}
	if !disconnected.Load() || !filter.Disconnected() {
		t.Fatal("expected ~. to trigger disconnect")
	}
	got := sharedOut.String()
	for _, want := range []string{
		"Supported escape sequences",
		"The following connections are open",
		"[suspend failed: test suspend denied]",
		"Connection to race-host.internal closed.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing expected escape message %q in output", want)
		}
	}
}

func testP0EscapeStdoutFallbackSync(t *testing.T) {
	var sharedOut bytes.Buffer
	outR, outW := io.Pipe()
	output := startSessionOutput(outR, nil, &sharedOut, nil)

	client := &Client{connCfg: ConnectionConfig{Address: "stdout-only.internal"}}
	var remoteIn bytes.Buffer
	wrapped, _ := client.wrapTerminalEscapeInput(&remoteIn, output.localOut(), '~', true, nil, nil)

	var wg sync.WaitGroup
	wg.Go(func() {
		defer func() { _ = outW.Close() }()
		for range 50 {
			_, _ = io.WriteString(outW, "remote-data\n")
		}
	})
	wg.Go(func() {
		for range 20 {
			_, _ = wrapped.Write([]byte("~?"))
		}
	})
	wg.Wait()
	if err := output.wait(); err != nil {
		t.Fatalf("output.wait() failed: %v", err)
	}
	if !strings.Contains(sharedOut.String(), "Supported escape sequences") {
		t.Fatalf("expected ~? help written to synchronized stdout fallback, got %q", sharedOut.String())
	}
}

func testP0EscapeDoubledSpecialChars(t *testing.T) {
	for _, tc := range []struct {
		name       string
		escapeByte byte
	}{
		{"dot", '.'},
		{"hash", '#'},
		{"question", '?'},
		{"ctrl_z", 0x1a},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var remoteIn, localOut bytes.Buffer
			disconnected := false
			suspended := false
			w := newEscapeFilterWriter(&remoteIn, escapeFilterConfig{
				escapeByte:   tc.escapeByte,
				host:         "special.example",
				localOut:     &localOut,
				onDisconnect: func() { disconnected = true },
				onSuspend: func() error {
					suspended = true
					return nil
				},
			})

			if _, err := w.Write([]byte{tc.escapeByte, tc.escapeByte, '\n'}); err != nil {
				t.Fatalf("Write doubled escape failed: %v", err)
			}
			if disconnected || suspended || localOut.Len() != 0 {
				t.Fatalf("doubled escape %q triggered action: disconnected=%v suspended=%v localOut=%q",
					tc.escapeByte, disconnected, suspended, localOut.String())
			}
			if !bytes.Equal(remoteIn.Bytes(), []byte{tc.escapeByte, '\n'}) {
				t.Fatalf("remoteIn = %x, want %x", remoteIn.Bytes(), []byte{tc.escapeByte, '\n'})
			}
			if tc.escapeByte != '?' {
				if _, err := w.Write([]byte{tc.escapeByte, '?'}); err != nil {
					t.Fatalf("Write escape+? failed: %v", err)
				}
				if !strings.Contains(localOut.String(), "Supported escape sequences") {
					t.Fatalf("expected escape+? help, got %q", localOut.String())
				}
			}
		})
	}
}

func testP0EscapeSuspendBlocksUntilResume(t *testing.T) {
	var remoteIn, localOut bytes.Buffer
	enteredSuspend := make(chan struct{})
	releaseSuspend := make(chan struct{})
	w := newEscapeFilterWriter(&remoteIn, escapeFilterConfig{
		escapeByte: '~',
		host:       "suspend.example",
		localOut:   &localOut,
		onSuspend: func() error {
			close(enteredSuspend)
			<-releaseSuspend
			return nil
		},
	})

	writeDone := make(chan error, 1)
	go func() {
		_, err := w.Write([]byte{'~', 0x1a, 'a', 'f', 't', 'e', 'r'})
		writeDone <- err
	}()

	select {
	case <-enteredSuspend:
	case <-time.After(2 * time.Second):
		t.Fatal("onSuspend was not called")
	}
	select {
	case err := <-writeDone:
		t.Fatalf("Write returned before suspend resumed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseSuspend)
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("Write after resume failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not finish after suspend resumed")
	}
	if remoteIn.String() != "after" {
		t.Fatalf("remoteIn = %q, want %q", remoteIn.String(), "after")
	}
}

type countingFrameReader struct {
	frame []byte
	reads atomic.Int32
}

func (r *countingFrameReader) Read(p []byte) (int, error) {
	if r.reads.Add(1) > 10 {
		return 0, io.EOF
	}
	return copy(p, r.frame), nil
}

type writeErrTunnelDevice struct {
	name     string
	writeErr error
}

func (d *writeErrTunnelDevice) Name() string                      { return d.name }
func (d *writeErrTunnelDevice) Mode() TunnelMode                  { return TunnelModePointToPoint }
func (d *writeErrTunnelDevice) ReadPacket([]byte) ([]byte, error) { return nil, os.ErrClosed }
func (d *writeErrTunnelDevice) WritePacket([]byte) error          { return d.writeErr }
func (d *writeErrTunnelDevice) Close() error                      { return nil }

// TestP0_TunnelForward_ClosedDeviceStopsRxPumpImmediately verifies that
// pumpPointToPointToDevice exits cleanly and immediately when dev.WritePacket
// reports a closed device or canceled context, and checks Darwin utun invariants.
func TestP0_TunnelForward_ClosedDeviceStopsRxPumpImmediately(t *testing.T) {
	t.Run("rx_pump_exits_without_re_reading_on_closed_device", testP0TunnelRxPumpClosedDevice)
	t.Run("full_tunnel_forward_exits_cleanly_when_local_device_closes", testP0TunnelFullForwardLocalClose)
	t.Run("darwin_utun_structural_invariants", testP0DarwinUtunStructuralInvariants)
}

func testP0TunnelRxPumpClosedDevice(t *testing.T) {
	pkt := makeTestIPv4Packet([]byte("closed-dev"))
	wire := append([]byte{0x00, 0x00, 0x00, 0x02}, pkt...)

	for _, tc := range []struct {
		name     string
		writeErr error
		canceled bool
	}{
		{"os_ErrClosed", os.ErrClosed, false},
		{"net_ErrClosed", net.ErrClosed, false},
		{"canceled_ctx", errors.New("broken pipe"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if tc.canceled {
				cancel()
			} else {
				defer cancel()
			}
			reader := &countingFrameReader{frame: wire}
			dev := &writeErrTunnelDevice{name: "tun0", writeErr: tc.writeErr}
			if err := pumpPointToPointToDevice(ctx, reader, dev, nil); err != nil {
				t.Fatalf("pumpPointToPointToDevice() = %v, want nil", err)
			}
			if gotReads := reader.reads.Load(); gotReads != 1 {
				t.Fatalf("ch.Read called %d times, want 1 (must not loop after closed device)", gotReads)
			}
		})
	}
}

func testP0TunnelFullForwardLocalClose(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	channelReady := make(chan struct{})
	stopServer := make(chan struct{})

	_, client, opener, teardown := startMockOpenSSHTunnelServer(t, func(newChan cryptoSSH.NewChannel) {
		if newChan.ChannelType() != "tun@openssh.com" {
			_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unexpected")
			return
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go cryptoSSH.DiscardRequests(reqs)
		close(channelReady)
		defer func() { _ = ch.Close() }()
		pkt := makeTestIPv4Packet([]byte("stream-after-close"))
		wire := append([]byte{0x00, 0x00, 0x00, 0x02}, pkt...)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopServer:
				return
			case <-ticker.C:
				if _, err := ch.Write(wire); err != nil {
					return
				}
			}
		}
	})
	defer teardown()
	defer close(stopServer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fwd, err := client.TunnelDeviceForward(ctx, TunnelModePointToPoint, TunnelDeviceSpec{LocalUnit: 0, RemoteUnit: 0})
	if err != nil {
		t.Fatalf("TunnelDeviceForward failed: %v", err)
	}
	select {
	case <-channelReady:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel channel not ready")
	}

	if err := opener.lastDev.Close(); err != nil {
		t.Fatalf("close fake device: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- fwd.Wait() }()
	select {
	case waitErr := <-done:
		if waitErr != nil {
			t.Fatalf("fwd.Wait() after local device close = %v, want nil", waitErr)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("TunnelDeviceForward hung after local device closed")
	}
}

func structHasField(file *ast.File, structName, fieldName string) bool {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != structName {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, field := range st.Fields.List {
				for _, name := range field.Names {
					if name.Name == fieldName {
						return true
					}
				}
			}
		}
	}
	return false
}

func inspectDarwinReadPacketBody(body *ast.BlockStmt) (sawPollNval, sawEOF, sawZeroCheck bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := node.X.(*ast.Ident); ok {
				sawPollNval = sawPollNval || (pkg.Name == "unix" && node.Sel.Name == "POLLNVAL")
				sawEOF = sawEOF || (pkg.Name == "io" && node.Sel.Name == "EOF")
			}
		case *ast.BinaryExpr:
			if isIdentEqZero(node, "n") {
				sawZeroCheck = true
			}
		}
		return true
	})
	return sawPollNval, sawEOF, sawZeroCheck
}

func isIdentEqZero(bin *ast.BinaryExpr, identName string) bool {
	if bin.Op != token.EQL {
		return false
	}
	id, idOK := bin.X.(*ast.Ident)
	lit, litOK := bin.Y.(*ast.BasicLit)
	return idOK && litOK && id.Name == identName && lit.Value == "0"
}

func testP0DarwinUtunStructuralInvariants(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "tun_device_darwin.go", nil, 0)
	if err != nil {
		t.Fatalf("parse tun_device_darwin.go failed: %v", err)
	}
	if !structHasField(file, "darwinTunnelDevice", "readBuf") {
		t.Fatal("darwinTunnelDevice must maintain a reusable readBuf field")
	}
	var readFn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "ReadPacket" {
			readFn = fn
			break
		}
	}
	if readFn == nil || readFn.Body == nil {
		t.Fatal("missing ReadPacket in tun_device_darwin.go")
	}
	sawPollNval, sawEOF, sawZeroCheck := inspectDarwinReadPacketBody(readFn.Body)
	if !sawPollNval {
		t.Error("darwinTunnelDevice.ReadPacket must handle unix.POLLNVAL")
	}
	if !sawZeroCheck || !sawEOF {
		t.Errorf("darwinTunnelDevice.ReadPacket must handle n == 0 by returning io.EOF (zeroCheck=%v eof=%v)", sawZeroCheck, sawEOF)
	}
}
