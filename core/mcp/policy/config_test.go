package policy

import (
	"bytes"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigUnmarshalYAML_FailClosedEnabledDefault(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantEnabled bool
		wantThresh  string
	}{
		{
			name:        "omitted enabled defaults to true",
			input:       "approval_threshold: moderate\nno_elicit_fallback: deny\n",
			wantEnabled: true,
			wantThresh:  "moderate",
		},
		{
			name:        "empty mapping defaults to true",
			input:       "{}\n",
			wantEnabled: true,
		},
		{
			name:        "null enabled defaults to true",
			input:       "enabled: null\napproval_threshold: dangerous\n",
			wantEnabled: true,
			wantThresh:  "dangerous",
		},
		{
			name:        "empty scalar enabled defaults to true",
			input:       "enabled:\napproval_threshold: safe\n",
			wantEnabled: true,
			wantThresh:  "safe",
		},
		{
			name:        "explicit enabled false disables guardrail",
			input:       "enabled: false\napproval_threshold: dangerous\n",
			wantEnabled: false,
			wantThresh:  "dangerous",
		},
		{
			name:        "explicit enabled true enables guardrail",
			input:       "enabled: true\napproval_threshold: moderate\n",
			wantEnabled: true,
			wantThresh:  "moderate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Pre-populate Enabled=false to prove UnmarshalYAML does not preserve stale false values.
			cfg := Config{Enabled: false}
			if err := yaml.Unmarshal([]byte(tc.input), &cfg); err != nil {
				t.Fatalf("yaml.Unmarshal failed: %v", err)
			}
			if cfg.Enabled != tc.wantEnabled {
				t.Fatalf("cfg.Enabled = %t, want %t", cfg.Enabled, tc.wantEnabled)
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
	if p.Guardrail == nil || !p.Guardrail.Enabled || p.Guardrail.ApprovalThreshold != "moderate" {
		t.Fatalf("unexpected ptr guardrail: %+v", p.Guardrail)
	}

	var pFalse wrapperPtr
	if err := yaml.Unmarshal([]byte("guardrail:\n  enabled: false\n"), &pFalse); err != nil {
		t.Fatalf("unmarshal ptr wrapper disabled: %v", err)
	}
	if pFalse.Guardrail == nil || pFalse.Guardrail.Enabled {
		t.Fatalf("expected explicit enabled: false, got %+v", pFalse.Guardrail)
	}

	var pNull wrapperPtr
	if err := yaml.Unmarshal([]byte("guardrail: null\n"), &pNull); err != nil {
		t.Fatalf("unmarshal ptr wrapper null: %v", err)
	}
	if pNull.Guardrail != nil {
		t.Fatalf("expected nil *Config for guardrail: null (caller falls back to enabled defaults), got %+v", pNull.Guardrail)
	}

	var vEmpty wrapperVal
	if err := yaml.Unmarshal([]byte("guardrail: {}\n"), &vEmpty); err != nil {
		t.Fatalf("unmarshal empty value wrapper: %v", err)
	}
	if !vEmpty.Guardrail.Enabled {
		t.Fatalf("empty guardrail mapping should fail closed with Enabled=true, got %+v", vEmpty.Guardrail)
	}

	var directNull Config
	if err := directNull.UnmarshalYAML(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"}); err != nil {
		t.Fatalf("direct null UnmarshalYAML failed: %v", err)
	}
	if !directNull.Enabled {
		t.Fatalf("direct null UnmarshalYAML should fail closed with Enabled=true, got %+v", directNull)
	}
}

func TestConfigStructLiteralCompatibility(t *testing.T) {
	disabled := &Config{Enabled: false}
	if disabled.Enabled {
		t.Fatal("&Config{Enabled: false} must remain false")
	}
	enabled := &Config{Enabled: true}
	if !enabled.Enabled {
		t.Fatal("&Config{Enabled: true} must remain true")
	}
}

func TestConfigUnmarshalYAML_FullRoundTripAndMerge(t *testing.T) {
	const source = "enabled: true\naudit_log: /var/lib/xops/audit.jsonl\napproval_threshold: dangerous\nblocked_patterns:\n    - '*forbidden*'\nprotected_paths:\n    - /etc\nnodes:\n    production:\n        approval_threshold: safe\nno_elicit_fallback: deny\n"

	var cfg Config
	if err := yaml.Unmarshal([]byte(source), &cfg); err != nil {
		t.Fatalf("unmarshal full config: %v", err)
	}
	want := Config{
		Enabled:           true,
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

	// YAML anchor + merge key must keep fail-closed enabled default when omitted.
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
	if merged.Guardrail == nil || !merged.Guardrail.Enabled || merged.Guardrail.ApprovalThreshold != "moderate" || merged.Guardrail.NoElicitFallback != "deny" {
		t.Fatalf("unexpected merged guardrail: %+v", merged.Guardrail)
	}
}

func TestConfigUnmarshalYAML_RejectsUnknownFieldsAndInvalidTypes(t *testing.T) {
	badInputs := []struct {
		name  string
		input string
	}{
		{name: "unknown top-level field", input: "unknown_flag: false\n"},
		{name: "unknown node override field", input: "nodes:\n  prod:\n    unknown_threshold: safe\n"},
		{name: "non-bool enabled", input: "enabled: notabool\n"},
		{name: "scalar guardrail", input: "\"enabled\"\n"},
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
