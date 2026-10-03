// Package clicontract verifies the CLI configuration and MCP wire contracts.
package clicontract

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/pkg/config"
	"gopkg.in/yaml.v3"
)

func TestPolicyConfigurationRoundTrip(t *testing.T) {
	const source = "enabled: true\naudit_log: /var/lib/xops/audit.jsonl\napproval_threshold: dangerous\nblocked_patterns:\n    - '*forbidden*'\nprotected_paths:\n    - /etc\nnodes:\n    production:\n        approval_threshold: safe\nno_elicit_fallback: deny\n"
	var configuration config.Configuration
	input := "guardrail:\n  " + strings.ReplaceAll(strings.TrimSuffix(source, "\n"), "\n", "\n  ") + "\n"
	if err := yaml.Unmarshal([]byte(input), &configuration); err != nil {
		t.Fatal(err)
	}
	shared := configuration.Guardrail
	encoded, err := yaml.Marshal(shared)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, []byte(source)) {
		t.Fatalf("policy serialization changed:\n%s", encoded)
	}
	if got := guardrail.NewPolicy(shared).Evaluate(guardrail.Safe, guardrail.RiskInput{
		ToolName: "xops_ssh_run", NodeID: "production", Command: "echo ok",
	}); got != guardrail.NeedApproval {
		t.Fatalf("per-node policy = %v, want approval", got)
	}
}
