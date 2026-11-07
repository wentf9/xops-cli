package ssh

import (
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
	invalids := []string{"-5", "invalid", "10x", "0m", "m"}
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

func TestControlConfig_ResolveControl(t *testing.T) {
	// 1. Both nil
	res, err := ResolveControl(nil, nil)
	if err != nil || res != nil {
		t.Fatalf("expected nil, nil; got %v, %v", res, err)
	}

	// 2. Child only
	child := &ControlConfig{Master: ControlMasterYes, Path: "/tmp/sock"}
	res, err = ResolveControl(child, nil)
	if err != nil || !res.Equal(child) {
		t.Fatalf("expected child clone, got %v, %v", res, err)
	}

	// 3. Parent only
	parent := &ControlConfig{Master: ControlMasterAuto, Path: "~/.ssh/cm-%h", Persist: "5m"}
	res, err = ResolveControl(nil, parent)
	if err != nil || !res.Equal(parent) {
		t.Fatalf("expected parent clone, got %v, %v", res, err)
	}

	// 4. Child overrides parent partially (field-by-field)
	child = &ControlConfig{Master: ControlMasterAsk}
	res, err = ResolveControl(child, parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := &ControlConfig{Master: ControlMasterAsk, Path: "~/.ssh/cm-%h", Persist: "5m"}
	if !res.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, res)
	}

	// 5. Child overrides all (with valid path)
	child = &ControlConfig{Master: ControlMasterAsk, Path: "/tmp/custom.sock", Persist: "10m"}
	res, err = ResolveControl(child, parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Equal(child) {
		t.Fatalf("expected %v, got %v", child, res)
	}

	// 6. Child disables multiplexing with Path="none" (overrides active parent)
	child = &ControlConfig{Path: "none"}
	res, err = ResolveControl(child, parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedDisabled := &ControlConfig{Master: ControlMasterNo, Path: "none", Persist: ""}
	if !res.Equal(expectedDisabled) {
		t.Fatalf("expected %v, got %v", expectedDisabled, res)
	}
	if res.IsEnabled() {
		t.Fatal("expected IsEnabled() to be false when Path is none")
	}

	// 7. Child sets Path="none" with nil parent
	res, err = ResolveControl(&ControlConfig{Path: "none"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Equal(expectedDisabled) {
		t.Fatalf("expected %v, got %v", expectedDisabled, res)
	}
	if res.IsEnabled() {
		t.Fatal("expected IsEnabled() to be false when Path is none")
	}

	// 8. Child sets Path="none" with explicit child Persist (Persist must still be cleared)
	child = &ControlConfig{Path: "none", Persist: "10m"}
	res, err = ResolveControl(child, parent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Equal(expectedDisabled) {
		t.Fatalf("expected %v, got %v", expectedDisabled, res)
	}
}

func TestControlConfig_EffectiveControl(t *testing.T) {
	// Tier 4: OpenSSH
	t4 := &ControlConfig{Master: ControlMasterAuto, Path: "~/.ssh/cm-%r@%h:%p", Persist: "10m"}
	// Tier 3: Global
	t3 := &ControlConfig{Persist: "15m"}
	// Tier 2: Node
	t2 := &ControlConfig{Path: "/tmp/node-%h.sock"}
	// Tier 1: CLI
	t1 := &ControlConfig{Master: ControlMasterYes}

	// Layers ordered highest to lowest priority: t1, t2, t3, t4
	eff, err := EffectiveControl(t1, t2, t3, t4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := &ControlConfig{
		Master:  ControlMasterYes,
		Path:    "/tmp/node-%h.sock",
		Persist: "15m",
	}
	if !eff.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, eff)
	}

	// Test with nil layers
	eff2, err := EffectiveControl(nil, t2, nil, t4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected2 := &ControlConfig{
		Master:  ControlMasterAuto,
		Path:    "/tmp/node-%h.sock",
		Persist: "10m",
	}
	if !eff2.Equal(expected2) {
		t.Fatalf("expected %v, got %v", expected2, eff2)
	}

	// All nil
	eff3, err := EffectiveControl(nil, nil)
	if err != nil || eff3 != nil {
		t.Fatalf("expected nil, nil; got %v, %v", eff3, err)
	}

	// Test EffectiveControl where a higher-priority layer disables multiplexing via Path="none"
	effDisabled, err := EffectiveControl(
		nil,                          // Tier 1: CLI (nil)
		&ControlConfig{Path: "none"}, // Tier 2: Node opts out
		&ControlConfig{Master: ControlMasterAuto, Path: "~/.ssh/cm-%r@%h:%p", Persist: "10m"}, // Tier 3: Global
		&ControlConfig{Master: ControlMasterYes, Path: "~/.ssh/mux.sock", Persist: "1h"},      // Tier 4: OpenSSH
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedEffDisabled := &ControlConfig{
		Master:  ControlMasterNo,
		Path:    "none",
		Persist: "",
	}
	if !effDisabled.Equal(expectedEffDisabled) {
		t.Fatalf("expected %v, got %v", expectedEffDisabled, effDisabled)
	}
	if effDisabled.IsEnabled() {
		t.Fatal("expected effective control to be disabled")
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
