package ssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControlPath_StandardTokens(t *testing.T) {
	env := Environment{
		HomeDir:   "/home/wuyue",
		LocalUser: "wuyue",
		LocalHost: "desktop.internal.net",
		LocalUID:  "1000",
	}
	target := TargetContext{
		Host:         "web.corp.internal",
		Port:         2222,
		User:         "deploy",
		OriginalHost: "web.corp.internal",
	}

	pattern := "~/.ssh/mux-%u@%h:%p-%r-%n-%L-%i-%%"
	expanded, err := ExpandControlPath(pattern, env, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := filepath.Join("/home/wuyue", ".ssh/mux-wuyue@web.corp.internal:2222-deploy-web.corp.internal-desktop-1000-%")
	if expanded != expected {
		t.Fatalf("expected %q, got %q", expected, expanded)
	}
}

func TestControlPath_ConnectionHash_OpenSSHExact(t *testing.T) {
	// Probe matching: LocalHost: "cachyos-x8664", Host: "example.com", Port: 2222, User: "user", JumpHost: ""
	hash := ComputeConnectionHash("cachyos-x8664", "example.com", "2222", "user", "")
	expected := "0b0117f298c0491db0094f1e54b915bc9cd61bea"
	if hash != expected {
		t.Fatalf("expected hash %q, got %q", expected, hash)
	}

	env := Environment{
		LocalHost: "cachyos-x8664",
	}
	target := TargetContext{
		Host: "example.com",
		Port: 2222,
		User: "user",
	}
	expanded, err := ExpandControlPath("/tmp/ssh-%C.sock", env, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedPath := "/tmp/ssh-0b0117f298c0491db0094f1e54b915bc9cd61bea.sock"
	if expanded != expectedPath {
		t.Fatalf("expected %q, got %q", expectedPath, expanded)
	}
}

func TestControlPath_ConnectionHash_WithProxyJump(t *testing.T) {
	hash := ComputeConnectionHash("cachyos-x8664", "example.com", "2222", "user", "jumphost")
	expected := "0cc142fc042f7e309a8b5a01cc61af09717fb809"
	if hash != expected {
		t.Fatalf("expected hash %q, got %q", expected, hash)
	}
}

func TestControlPath_TildeExpansion(t *testing.T) {
	env := Environment{HomeDir: "/home/testuser"}
	target := TargetContext{Host: "host.local", User: "root"}

	// 1. ~/sock
	res, err := ExpandControlPath("~/sock", env, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expected := filepath.Join("/home/testuser", "sock"); res != expected {
		t.Fatalf("expected %q, got %q", expected, res)
	}

	// 2. ~
	res, err = ExpandControlPath("~", env, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != "/home/testuser" {
		t.Fatalf("expected /home/testuser, got %q", res)
	}

	// 3. /tmp/~not-home/sock
	res, err = ExpandControlPath("/tmp/~not-home/sock", env, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != "/tmp/~not-home/sock" {
		t.Fatalf("expected unchanged, got %q", res)
	}
}

func TestControlPath_EnvVarExpansion(t *testing.T) {
	env := Environment{
		LookupEnv: func(key string) (string, bool) {
			if key == "XDG_RUNTIME_DIR" {
				return "/run/user/1000", true
			}
			if key == "RUN_ID" {
				return "xyz123", true
			}
			return "", false
		},
	}
	target := TargetContext{Host: "host"}

	res, err := ExpandControlPath("${XDG_RUNTIME_DIR}/ssh-${RUN_ID}/sock", env, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != "/run/user/1000/ssh-xyz123/sock" {
		t.Fatalf("unexpected expansion: %q", res)
	}
}

func TestControlPath_MissingEnvVar_Error(t *testing.T) {
	env := Environment{
		LookupEnv: func(key string) (string, bool) {
			return "", false
		},
	}
	target := TargetContext{Host: "host"}

	_, err := ExpandControlPath("/tmp/${UNSET_VAR_XYZ}/sock", env, target)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "env var ${UNSET_VAR_XYZ} has no value") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestControlPath_UnknownToken_Error(t *testing.T) {
	env := Environment{}
	target := TargetContext{Host: "host"}

	_, err := ExpandControlPath("/tmp/cm-%z", env, target)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown ControlPath token %z") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestControlPath_TrailingPercent_Error(t *testing.T) {
	env := Environment{}
	target := TargetContext{Host: "host"}

	_, err := ExpandControlPath("/tmp/cm-%", env, target)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "trailing '%' in ControlPath") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestControlPath_DefaultPortAndHost(t *testing.T) {
	env := Environment{}
	target := TargetContext{Host: "server.com"}

	res, err := ExpandControlPath("/tmp/cm-%n:%p", env, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != "/tmp/cm-server.com:22" {
		t.Fatalf("expected /tmp/cm-server.com:22, got %q", res)
	}
}

func TestValidateControlPath_Limits(t *testing.T) {
	maxLen := MaxControlPathLength()

	shortPath := strings.Repeat("a", maxLen-1)
	if err := ValidateControlPath(shortPath); err != nil {
		t.Fatalf("expected valid for len %d, got: %v", len(shortPath), err)
	}

	exactPath := strings.Repeat("a", maxLen)
	if err := ValidateControlPath(exactPath); err == nil {
		t.Fatalf("expected error for len %d, got nil", len(exactPath))
	}

	overPath := strings.Repeat("a", maxLen+10)
	if err := ValidateControlPath(overPath); err == nil {
		t.Fatalf("expected error for len %d, got nil", len(overPath))
	}

	if err := ValidateControlPath(""); err == nil {
		t.Fatal("expected error for empty path")
	}
	if err := ValidateControlPath("none"); err != nil {
		t.Fatalf("expected nil for none, got %v", err)
	}
}

func TestParseControlPersist_Booleans(t *testing.T) {
	tests := []struct {
		input      string
		enabled    bool
		indefinite bool
		timeout    time.Duration
	}{
		{"", false, false, 0},
		{"no", false, false, 0},
		{"false", false, false, 0},
		{"yes", true, true, 0},
		{"true", true, true, 0},
		{"0", true, true, 0},
	}
	for _, tc := range tests {
		en, ind, dur, err := ParseControlPersist(tc.input)
		if err != nil {
			t.Fatalf("input %q: unexpected error: %v", tc.input, err)
		}
		if en != tc.enabled || ind != tc.indefinite || dur != tc.timeout {
			t.Fatalf("input %q: got en=%v ind=%v dur=%v, expected en=%v ind=%v dur=%v",
				tc.input, en, ind, dur, tc.enabled, tc.indefinite, tc.timeout)
		}
	}
}

func TestParseControlPersist_Durations(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"600", 600 * time.Second},
		{"10m", 10 * time.Minute},
		{"1h30m", 90 * time.Minute},
		{"1d", 24 * time.Hour},
		{"1w", 7 * 24 * time.Hour},
		{"10s", 10 * time.Second},
	}
	for _, tc := range tests {
		en, ind, dur, err := ParseControlPersist(tc.input)
		if err != nil {
			t.Fatalf("input %q: unexpected error: %v", tc.input, err)
		}
		if !en || ind || dur != tc.expected {
			t.Fatalf("input %q: got en=%v ind=%v dur=%v, expected en=true ind=false dur=%v",
				tc.input, en, ind, dur, tc.expected)
		}
	}
}

func TestParseControlPersist_Invalid(t *testing.T) {
	invalids := []string{"-5", "invalid", "10x", "0m", "m", "10000000000", "18446744074", "99999999999w", "1h10000000000s"}
	for _, inv := range invalids {
		_, _, _, err := ParseControlPersist(inv)
		if err == nil {
			t.Fatalf("input %q: expected error, got nil", inv)
		}
	}
}

func TestParseControlMasterMode(t *testing.T) {
	tests := []struct {
		input    string
		expected ControlMasterMode
	}{
		{"no", ControlMasterNo},
		{"false", ControlMasterNo},
		{"", ControlMasterNo},
		{"yes", ControlMasterYes},
		{"true", ControlMasterYes},
		{"ask", ControlMasterAsk},
		{"auto", ControlMasterAuto},
		{"autoask", ControlMasterAutoAsk},
	}
	for _, tc := range tests {
		m, err := ParseControlMasterMode(tc.input)
		if err != nil {
			t.Fatalf("input %q: unexpected error: %v", tc.input, err)
		}
		if m != tc.expected {
			t.Fatalf("input %q: expected %v, got %v", tc.input, tc.expected, m)
		}
	}

	if _, err := ParseControlMasterMode("invalid"); err == nil {
		t.Fatal("expected error for invalid mode, got nil")
	}
}

func TestControlConfig_CloneAndEqual(t *testing.T) {
	var nilCtrl *ControlConfig
	if nilCtrl.Clone() != nil {
		t.Fatal("expected nil clone for nil ControlConfig")
	}
	if !nilCtrl.Equal(nil) {
		t.Fatal("expected nil ControlConfig equal nil")
	}

	orig := &ControlConfig{
		Master:  ControlMasterAuto,
		Path:    "~/.ssh/cm-%r@%h:%p",
		Persist: "10m",
	}

	if orig.Equal(nil) || nilCtrl.Equal(orig) {
		t.Fatal("non-nil ControlConfig should not equal nil")
	}

	cloned := orig.Clone()
	if !orig.Equal(cloned) {
		t.Fatal("cloned ControlConfig should equal original")
	}

	// Mutate clone to ensure deep copy
	cloned.Master = ControlMasterYes
	if orig.Equal(cloned) {
		t.Fatal("modifying cloned Master should break equality")
	}
	cloned.Master = orig.Master

	cloned.Path = "/tmp/sock"
	if orig.Equal(cloned) {
		t.Fatal("modifying cloned Path should break equality")
	}
	cloned.Path = orig.Path

	cloned.Persist = "20m"
	if orig.Equal(cloned) {
		t.Fatal("modifying cloned Persist should break equality")
	}
}

func mustResolveControlForTest(t *testing.T, layers ...*Options) *ControlConfig {
	t.Helper()
	eff, err := EffectiveOptions(layers...)
	if err != nil {
		t.Fatalf("EffectiveOptions failed: %v", err)
	}
	res, err := eff.ValidatedControlConfig()
	if err != nil {
		t.Fatalf("ValidatedControlConfig failed: %v", err)
	}
	return res
}

func TestControlConfig_EffectiveOptionsValidatedControlConfig(t *testing.T) {
	parentCfg := &ControlConfig{Master: ControlMasterAuto, Path: "~/.ssh/cm-%h", Persist: "5m"}
	parent := OptionsFromControl(parentCfg)

	t.Run("nil_and_single_layer", func(t *testing.T) {
		if res := mustResolveControlForTest(t, nil, nil); res != nil {
			t.Fatalf("expected nil, got %+v", res)
		}
		childCfg := &ControlConfig{Master: ControlMasterYes, Path: "/tmp/sock"}
		if res := mustResolveControlForTest(t, OptionsFromControl(childCfg), nil); !res.Equal(childCfg) {
			t.Fatalf("expected child control config, got %+v", res)
		}
		if res := mustResolveControlForTest(t, nil, parent); !res.Equal(parentCfg) {
			t.Fatalf("expected parent control config, got %+v", res)
		}
	})

	t.Run("partial_and_multi_tier_override", func(t *testing.T) {
		res := mustResolveControlForTest(t, OptionsFromControl(&ControlConfig{Master: ControlMasterAsk}), parent)
		expected := &ControlConfig{Master: ControlMasterAsk, Path: "~/.ssh/cm-%h", Persist: "5m"}
		if !res.Equal(expected) {
			t.Fatalf("expected %+v, got %+v", expected, res)
		}

		// Multi-tier hierarchy (CLI > Node > Global > OpenSSH).
		t4 := OptionsFromControl(&ControlConfig{Master: ControlMasterAuto, Path: "~/.ssh/cm-%r@%h:%p", Persist: "10m"})
		t3 := OptionsFromControl(&ControlConfig{Persist: "15m"})
		t2 := OptionsFromControl(&ControlConfig{Path: "/tmp/node-%h.sock"})
		t1 := OptionsFromControl(&ControlConfig{Master: ControlMasterYes})
		res = mustResolveControlForTest(t, t1, t2, t3, t4)
		want4Tier := &ControlConfig{Master: ControlMasterYes, Path: "/tmp/node-%h.sock", Persist: "15m"}
		if !res.Equal(want4Tier) {
			t.Fatalf("expected %+v, got %+v", want4Tier, res)
		}
	})

	t.Run("disable_with_none_and_re_enable_override", func(t *testing.T) {
		expectedDisabled := &ControlConfig{Master: ControlMasterNo, Path: "none", Persist: ""}
		for _, disableChild := range []*ControlConfig{
			{Path: "none"},
			{Path: "NONE"},
			{Path: "none", Persist: "10m"},
		} {
			res := mustResolveControlForTest(t, OptionsFromControl(disableChild), parent)
			if !res.Equal(expectedDisabled) || res.IsEnabled() {
				t.Fatalf("expected disabled control config for %+v, got %+v", disableChild, res)
			}
		}

		// Inherited ControlPath="none" with higher-tier Master/Persist still normalizes to disabled.
		res := mustResolveControlForTest(
			t,
			OptionsFromControl(&ControlConfig{Master: ControlMasterYes, Persist: "10m"}),
			OptionsFromControl(&ControlConfig{Path: "NONE"}),
		)
		if !res.Equal(expectedDisabled) || res.IsEnabled() {
			t.Fatalf("expected inherited Path=NONE to disable multiplexing, got %+v", res)
		}

		// Higher-tier concrete Path overrides middle-tier Path="none" while preserving lower-tier Master/Persist.
		res = mustResolveControlForTest(
			t,
			OptionsFromControl(&ControlConfig{Path: "/tmp/override.sock"}),
			OptionsFromControl(&ControlConfig{Path: "none"}),
			parent,
		)
		wantOverride := &ControlConfig{Master: ControlMasterAuto, Path: "/tmp/override.sock", Persist: "5m"}
		if !res.Equal(wantOverride) {
			t.Fatalf("expected %+v, got %+v", wantOverride, res)
		}
	})

	t.Run("persist_no_without_control_path_allowed", func(t *testing.T) {
		for _, noPersist := range []string{"no", "false"} {
			res := mustResolveControlForTest(t, OptionsFromControl(&ControlConfig{Persist: noPersist}))
			if res == nil || res.Master != ControlMasterNo || res.Persist != noPersist || res.IsEnabled() {
				t.Fatalf("unexpected ControlConfig for Persist=%s: %+v", noPersist, res)
			}
		}
	})
}

func TestMultiplexDisableGuard_CaseInsensitiveAndEnvExpandedNone(t *testing.T) {
	// Case-insensitive "NONE" / " none " must never be treated as enabled (M1).
	for _, rawPath := range []string{"none", "NONE", " None "} {
		target := TargetContext{
			Host:    "example.com",
			Port:    22,
			User:    "ops",
			Control: &ControlConfig{Master: ControlMasterAuto, Path: rawPath},
		}
		if isMultiplexControlEnabled(target) {
			t.Fatalf("isMultiplexControlEnabled(%q) = true, want false", rawPath)
		}
	}

	// Env-expanded ControlPath resolving to "none"/"NONE" must not bind ./none in CWD (M1).
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()

	for _, envVal := range []string{"none", "NONE"} {
		conn := NewConnector(nil, WithEnvironment(Environment{
			LookupEnv: func(key string) (string, bool) {
				if key == "XOPS_CTRL_PATH" {
					return envVal, true
				}
				return "", false
			},
		}))
		planNode := connectionPlanNode{
			name: "web",
			cfg: &ClientConfig{
				Address: "example.com",
				Port:    22,
				User:    "ops",
			},
			control: &ControlConfig{
				Master: ControlMasterYes,
				Path:   "${XOPS_CTRL_PATH}",
			},
		}
		if cli, tryErr := conn.tryConnectMultiplex(t.Context(), planNode); cli != nil || tryErr != nil {
			t.Fatalf("tryConnectMultiplex(env=%q) = (%v, %v), want (nil, nil)", envVal, cli, tryErr)
		}
		conn.maybeStartMasterListener(planNode, "", nil, nil)
		if _, statErr := os.Lstat(filepath.Join(tmpDir, envVal)); !os.IsNotExist(statErr) {
			t.Fatalf("expected no ./%s socket created in CWD, stat err = %v", envVal, statErr)
		}
	}

	// Defense in depth: NewMuxServer rejects "none" / "NONE" directly.
	if _, err := NewMuxServer(MuxServerOptions{ControlPath: "NONE"}); err == nil {
		t.Fatal("NewMuxServer(ControlPath=NONE) succeeded, want error")
	}
}

func TestTargetContext_CanonicalTargetIdentityAndMatching(t *testing.T) {
	t1 := TargetContext{
		Host: "Web.Corp.Internal",
		Port: 2222,
		User: "deploy",
	}
	id1 := t1.CanonicalTargetIdentity()
	if id1 != "host=web.corp.internal;port=2222;user=deploy;jump=" {
		t.Fatalf("unexpected canonical identity: %q", id1)
	}
	if got := FormatTargetIdentity(id1); got != "deploy@web.corp.internal:2222" {
		t.Fatalf("unexpected formatted identity: %q", got)
	}

	// Same host (case-insensitive), port, and user matches
	same := TargetContext{Host: "web.corp.internal", Port: 2222, User: "deploy"}
	if !same.MatchesMasterTarget(id1) {
		t.Fatal("expected same target to match master identity")
	}

	// Different host must not match
	diffHost := TargetContext{Host: "db.corp.internal", Port: 2222, User: "deploy"}
	if diffHost.MatchesMasterTarget(id1) {
		t.Fatal("expected different host to fail target match")
	}

	// Different port must not match
	diffPort := TargetContext{Host: "web.corp.internal", Port: 22, User: "deploy"}
	if diffPort.MatchesMasterTarget(id1) {
		t.Fatal("expected different port to fail target match")
	}

	// Different user must not match
	diffUser := TargetContext{Host: "web.corp.internal", Port: 2222, User: "root"}
	if diffUser.MatchesMasterTarget(id1) {
		t.Fatal("expected different user to fail target match")
	}

	// Different jump host must not match
	withJump := TargetContext{Host: "web.corp.internal", Port: 2222, User: "deploy", JumpHost: "bastion"}
	if withJump.MatchesMasterTarget(id1) {
		t.Fatal("expected different jump host to fail target match")
	}
}

func TestExpandControlPath_AndConnectorTargetContext_EmptyUserFallsBackToLocalUser(t *testing.T) {
	env := Environment{
		HomeDir:   "/home/localdev",
		LocalHost: "workstation.local",
		LocalUser: "localdev",
		LocalUID:  "1000",
	}

	emptyUserTarget := TargetContext{
		Host: "10.0.0.10",
		Port: 22,
		User: "",
	}
	explicitUserTarget := TargetContext{
		Host: "10.0.0.10",
		Port: 22,
		User: "localdev",
	}

	gotEmpty, err := ExpandControlPath("~/.ssh/cm-%r-%C", env, emptyUserTarget)
	if err != nil {
		t.Fatalf("ExpandControlPath(emptyUser) failed: %v", err)
	}
	gotExplicit, err := ExpandControlPath("~/.ssh/cm-%r-%C", env, explicitUserTarget)
	if err != nil {
		t.Fatalf("ExpandControlPath(explicitUser) failed: %v", err)
	}
	if gotEmpty != gotExplicit {
		t.Fatalf("expected empty TargetContext.User to fall back to env.LocalUser: got %q vs %q", gotEmpty, gotExplicit)
	}

	conn := NewConnector(nil, WithEnvironment(env))
	targetCtx := conn.buildTargetContext(connectionPlanNode{
		name: "adhoc-node",
		cfg: &ClientConfig{
			Address: "10.0.0.10",
			Port:    0,
			User:    "",
		},
	})
	if targetCtx.User != "localdev" || targetCtx.Port != 22 {
		t.Fatalf("expected buildTargetContext to populate User='localdev' and Port=22, got %+v", targetCtx)
	}
}

func TestParseOpenSSHDuration_RejectsSignedLeadingPlus(t *testing.T) {
	if got, err := parseOpenSSHDuration("10"); err != nil || got != 10*time.Second {
		t.Fatalf("parseOpenSSHDuration(\"10\") = (%v, %v), want (10s, nil)", got, err)
	}
	for _, raw := range []string{"+10", "-10", "+10s", "-10s", "+"} {
		if _, err := parseOpenSSHDuration(raw); err == nil {
			t.Fatalf("parseOpenSSHDuration(%q) succeeded, want error", raw)
		}
	}
}
