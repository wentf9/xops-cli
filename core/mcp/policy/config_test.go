package policy

import (
	"bytes"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigUnmarshalYAML_FailClosedDisabledDefault(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantDisabled bool
		wantThresh   string
	}{
		{
			name:         "omitted disabled defaults to false (guardrail ON)",
			input:        "approval_threshold: moderate\nno_elicit_fallback: deny\n",
			wantDisabled: false,
			wantThresh:   "moderate",
		},
		{
			name:         "empty mapping defaults to false (guardrail ON)",
			input:        "{}\n",
			wantDisabled: false,
		},
		{
			name:         "null disabled defaults to false (guardrail ON)",
			input:        "disabled: null\napproval_threshold: dangerous\n",
			wantDisabled: false,
			wantThresh:   "dangerous",
		},
		{
			name:         "empty scalar disabled defaults to false (guardrail ON)",
			input:        "disabled:\napproval_threshold: safe\n",
			wantDisabled: false,
			wantThresh:   "safe",
		},
		{
			name:         "explicit disabled true disables guardrail",
			input:        "disabled: true\napproval_threshold: dangerous\n",
			wantDisabled: true,
			wantThresh:   "dangerous",
		},
		{
			name:         "explicit disabled false keeps guardrail active",
			input:        "disabled: false\napproval_threshold: moderate\n",
			wantDisabled: false,
			wantThresh:   "moderate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Pre-populate Disabled=true to prove UnmarshalYAML resets to zero-value active state.
			cfg := Config{Disabled: true}
			if err := yaml.Unmarshal([]byte(tc.input), &cfg); err != nil {
				t.Fatalf("yaml.Unmarshal failed: %v", err)
			}
			if cfg.Disabled != tc.wantDisabled {
				t.Fatalf("cfg.Disabled = %t, want %t", cfg.Disabled, tc.wantDisabled)
			}
			if cfg.ApprovalThreshold != tc.wantThresh {
				t.Fatalf("cfg.ApprovalThreshold = %q, want %q", cfg.ApprovalThreshold, tc.wantThresh)
			}
		})
	}
}

func TestConfigUnmarshalYAML_NestedBlockAndNull(t *testing.T) {
	type wrapperPtr struct {
		Guardrail *Config `yaml:"guardrail,omitempty"`
	}
	type wrapperVal struct {
		Guardrail Config `yaml:"guardrail"`
	}

	var p wrapperPtr
	if err := yaml.Unmarshal([]byte("guardrail:\n  approval_threshold: moderate\n"), &p); err != nil {
		t.Fatalf("unmarshal ptr wrapper: %v", err)
	}
	if p.Guardrail == nil || p.Guardrail.Disabled || p.Guardrail.ApprovalThreshold != "moderate" {
		t.Fatalf("unexpected ptr guardrail: %+v", p.Guardrail)
	}

	var pDisabled wrapperPtr
	if err := yaml.Unmarshal([]byte("guardrail:\n  disabled: true\n"), &pDisabled); err != nil {
		t.Fatalf("unmarshal ptr wrapper disabled: %v", err)
	}
	if pDisabled.Guardrail == nil || !pDisabled.Guardrail.Disabled {
		t.Fatalf("expected explicit disabled: true, got %+v", pDisabled.Guardrail)
	}

	var pNull wrapperPtr
	if err := yaml.Unmarshal([]byte("guardrail: null\n"), &pNull); err != nil {
		t.Fatalf("unmarshal ptr wrapper null: %v", err)
	}
	if pNull.Guardrail != nil {
		t.Fatalf("expected nil *Config for guardrail: null (caller falls back to active defaults), got %+v", pNull.Guardrail)
	}

	var vEmpty wrapperVal
	if err := yaml.Unmarshal([]byte("guardrail: {}\n"), &vEmpty); err != nil {
		t.Fatalf("unmarshal empty value wrapper: %v", err)
	}
	if vEmpty.Guardrail.Disabled {
		t.Fatalf("empty guardrail mapping must fail closed with Disabled=false, got %+v", vEmpty.Guardrail)
	}

	var directNull Config
	directNull.Disabled = true
	if err := directNull.UnmarshalYAML(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"}); err != nil {
		t.Fatalf("direct null UnmarshalYAML failed: %v", err)
	}
	if directNull.Disabled {
		t.Fatalf("direct null UnmarshalYAML must fail closed with Disabled=false, got %+v", directNull)
	}
}

func TestConfigZeroValueIsActive(t *testing.T) {
	var zero Config
	if zero.Disabled {
		t.Fatal("zero-value Config must have Disabled == false (guardrail ON)")
	}
	explicit := &Config{Disabled: true}
	if !explicit.Disabled {
		t.Fatal("&Config{Disabled: true} must remain true")
	}
}

func TestConfigUnmarshalYAML_FullRoundTripAndMerge(t *testing.T) {
	const source = "audit_log: /var/lib/xops/audit.jsonl\napproval_threshold: dangerous\nblocked_patterns:\n    - '*forbidden*'\nprotected_paths:\n    - /etc\nnodes:\n    production:\n        approval_threshold: safe\nno_elicit_fallback: deny\n"

	var cfg Config
	if err := yaml.Unmarshal([]byte(source), &cfg); err != nil {
		t.Fatalf("unmarshal full config: %v", err)
	}
	want := Config{
		Disabled:          false,
		AuditLog:          "/var/lib/xops/audit.jsonl",
		ApprovalThreshold: "dangerous",
		BlockedPatterns:   []string{"*forbidden*"},
		ProtectedPaths:    []string{"/etc"},
		NodeOverrides: map[string]NodeConfig{
			"production": {ApprovalThreshold: "safe"},
		},
		NoElicitFallback: "deny",
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("decoded config = %#v, want %#v", cfg, want)
	}

	encoded, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if !bytes.Equal(encoded, []byte(source)) {
		t.Fatalf("marshaled YAML changed:\ngot:\n%s\nwant:\n%s", encoded, source)
	}

	// YAML anchor + merge key must keep fail-closed active default when disabled is omitted.
	mergeYAML := `
defaults: &base
  approval_threshold: moderate
  no_elicit_fallback: deny
guardrail:
  <<: *base
  protected_paths:
    - /etc
`
	var merged struct {
		Defaults  map[string]any `yaml:"defaults"`
		Guardrail *Config        `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal([]byte(mergeYAML), &merged); err != nil {
		t.Fatalf("unmarshal merged guardrail: %v", err)
	}
	if merged.Guardrail == nil || merged.Guardrail.Disabled || merged.Guardrail.ApprovalThreshold != "moderate" || merged.Guardrail.NoElicitFallback != "deny" {
		t.Fatalf("unexpected merged guardrail: %+v", merged.Guardrail)
	}
}

func TestConfigUnmarshalYAML_RejectsUnknownFieldsAndLegacyEnabledKey(t *testing.T) {
	badInputs := []struct {
		name  string
		input string
	}{
		{name: "removed legacy enabled true", input: "enabled: true\n"},
		{name: "removed legacy enabled false", input: "enabled: false\n"},
		{name: "unknown top-level field", input: "unknown_flag: false\n"},
		{name: "unknown node override field", input: "nodes:\n  prod:\n    unknown_threshold: safe\n"},
		{name: "non-bool disabled", input: "disabled: notabool\n"},
		{name: "scalar guardrail", input: "\"disabled\"\n"},
		{name: "sequence guardrail", input: "- item\n"},
		{name: "scalar node override", input: "nodes:\n  prod: safe\n"},
	}

	for _, tc := range badInputs {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			if err := yaml.Unmarshal([]byte(tc.input), &cfg); err == nil {
				t.Fatalf("yaml.Unmarshal(%q) succeeded (%+v), want error", tc.input, cfg)
			}
		})
	}
}
