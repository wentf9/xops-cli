package ssh

import (
	"errors"
	"testing"
	"time"
)

func TestControlSetting_ValidAndCrossFieldInvariants(t *testing.T) {
	t.Parallel()

	unset := UnsetControlSetting()
	if !unset.IsUnset() || unset.IsDisabled() || unset.IsEnabled() || unset.EffectiveMaster() != ControlMasterNo || unset.String() != "" || unset.ToControlConfig() != nil {
		t.Fatalf("unexpected unset ControlSetting: %+v", unset)
	}

	// Valid combinations.
	validCases := []struct {
		name    string
		master  string
		path    string
		literal bool
		persist string
	}{
		{"all_empty", "", "", false, ""},
		{"master_no_only", "no", "", false, ""},
		{"disabled_path_only", "", "none", false, ""},
		{"disabled_path_with_no", "no", "NONE", false, "no"},
		{"reuse_template_path", "", "~/.ssh/cm-%C", false, ""},
		{"reuse_literal_path_with_spaces", "no", " /tmp/cm %z literal ", true, "false"},
		{"active_auto_with_duration", "auto", "~/.ssh/cm-%r@%h:%p", false, "10m"},
		{"active_yes_indefinite", "yes", "/tmp/mux.sock", true, "yes"},
		{"active_ask_persist_no", "ask", "~/.ssh/cm-%C", false, "no"},
		{"active_autoask_no_persist", "autoask", "~/.ssh/cm-%C", false, ""},
	}
	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := ParseControlSetting(tc.master, tc.path, tc.literal, tc.persist)
			if err != nil {
				t.Fatalf("ParseControlSetting(%q, %q, %v, %q): %v", tc.master, tc.path, tc.literal, tc.persist, err)
			}
			reparsed, err := ParseControlSettingString(cs.String())
			if err != nil || !cs.Equal(reparsed) {
				t.Fatalf("round-trip failed: wire=%q reparsed=(%+v, %v) orig=%+v", cs.String(), reparsed, err, cs)
			}
		})
	}

	// Cross-field and intra-field invariant rejections (must match validateControlLayerInvariants + ValidateEffective).
	invalidCases := []struct {
		name    string
		master  string
		path    string
		literal bool
		persist string
	}{
		{"active_master_without_path", "yes", "", false, ""},
		{"auto_master_without_path", "auto", "", false, ""},
		{"ask_master_without_path", "ask", "", false, ""},
		{"autoask_master_without_path", "autoask", "", false, ""},
		{"active_master_with_none_path", "auto", "none", false, ""},
		{"persist_enabled_without_path", "yes", "", false, "10m"},
		{"persist_enabled_with_none_path", "yes", "none", false, "10m"},
		{"persist_enabled_with_master_no", "no", "~/.ssh/cm-%C", false, "10m"},
		{"persist_indefinite_with_master_unset", "", "~/.ssh/cm-%C", false, "yes"},
		{"persist_duration_with_master_unset", "", "~/.ssh/cm-%C", false, "5m"},
		{"invalid_master", "maybe", "~/.ssh/cm-%C", false, ""},
		{"master_whitespace", "   ", "~/.ssh/cm-%C", false, ""},
		{"master_newline", "yes\n", "~/.ssh/cm-%C", false, ""},
		{"invalid_template_token", "auto", "~/.ssh/cm-%z", false, ""},
		{"path_control_char", "auto", "/tmp/cm\x00", true, ""},
		{"persist_invalid_duration", "auto", "~/.ssh/cm-%C", false, "notaduration"},
		{"persist_control_char", "auto", "~/.ssh/cm-%C", false, "10m\n"},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if cs, err := ParseControlSetting(tc.master, tc.path, tc.literal, tc.persist); err == nil || !errors.Is(err, ErrSSHOptionsValidation) {
				t.Errorf("ParseControlSetting(%q, %q, %v, %q) = (%+v, %v), want ErrSSHOptionsValidation",
					tc.master, tc.path, tc.literal, tc.persist, cs, err)
			}
		})
	}
}

func TestControlSetting_TypedConstructorAndConversions(t *testing.T) {
	t.Parallel()

	// Construct using typed PersistSetting with Duration only (no Raw).
	pathSetting, err := ParseControlPathSetting("~/.ssh/cm-%C", false)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := NewControlSetting(ControlMasterAuto, pathSetting, PersistSetting{Kind: PersistDuration, Duration: 5 * time.Minute})
	if err != nil {
		t.Fatalf("NewControlSetting duration-only: %v", err)
	}
	if cs.Persist().Duration != 5*time.Minute || cs.Persist().Raw != "300s" || !cs.IsEnabled() {
		t.Fatalf("unexpected ControlSetting: %+v", cs)
	}

	// Sub-second duration rejected.
	if _, err := NewControlSetting(ControlMasterAuto, pathSetting, PersistSetting{Kind: PersistDuration, Duration: 500 * time.Millisecond}); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("sub-second duration err = %v, want ErrSSHOptionsValidation", err)
	}

	// Mismatched Duration vs Raw rejected.
	if _, err := NewControlSetting(ControlMasterAuto, pathSetting, PersistSetting{Kind: PersistDuration, Raw: "10m", Duration: 5 * time.Minute}); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("mismatched duration err = %v, want ErrSSHOptionsValidation", err)
	}

	// Conversion round-trips with ControlConfig and Options.
	cfg := cs.ToControlConfig()
	fromCfg, err := ControlSettingFromConfig(cfg)
	if err != nil || !fromCfg.Equal(cs) {
		t.Fatalf("ControlSettingFromConfig = (%+v, %v), want %+v", fromCfg, err, cs)
	}
	opts := OptionsFromControl(cfg)
	fromOpts, err := ControlSettingFromOptions(opts)
	if err != nil || !fromOpts.Equal(cs) {
		t.Fatalf("ControlSettingFromOptions = (%+v, %v), want %+v", fromOpts, err, cs)
	}
	if empty, err := ControlSettingFromConfig(nil); err != nil || !empty.IsUnset() {
		t.Fatalf("ControlSettingFromConfig(nil) = (%+v, %v)", empty, err)
	}
	if empty, err := ControlSettingFromOptions(nil); err != nil || !empty.IsUnset() {
		t.Fatalf("ControlSettingFromOptions(nil) = (%+v, %v)", empty, err)
	}
}

func FuzzControlSettingRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"",
		"ControlMaster=no",
		"ControlPath=none",
		"ControlPath=~/.ssh/cm-%C",
		"ControlMaster=auto\nControlPath=~/.ssh/cm-%r@%h:%p\nControlPersist=10m",
		"ControlMaster=yes\nControlPathLiteral=/tmp/sock %z\nControlPersist=yes",
		"ControlMaster=yes",
		"ControlMaster=no\nControlPath=~/.ssh/cm-%C\nControlPersist=10m",
		"ControlPathLiteral=none",
		"UnknownKey=foo",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		cs, err := ParseControlSettingString(raw)
		if err != nil {
			return
		}
		wire := cs.String()
		reparsed, err := ParseControlSettingString(wire)
		if err != nil {
			t.Fatalf("re-parse of %q (from %q) failed: %v", wire, raw, err)
		}
		if !cs.Equal(reparsed) || reparsed.String() != wire {
			t.Fatalf("round-trip mismatch: first=%q second=%q", wire, reparsed.String())
		}
	})
}
