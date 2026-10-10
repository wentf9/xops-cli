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

const roundTripSource = `schema_version: 2
credential:
    stores: {}
identities:
    deploy:
        user: app
        auth_type: key
hosts:
    srv1:
        address: 10.0.0.1
        port: 22
nodes:
    node1:
        host_ref: srv1
        identity_ref: deploy
        sudo_mode: none
        execution:
            interpreter: server
    node2:
        host_ref: srv1
        identity_ref: deploy
        sudo_mode: none
        execution:
            login: true
execution:
    interpreter: bash
    launch_dialect: posix
    login: false
`

func parseRoundTripV2(t *testing.T) *config.ConfigurationV2 {
	t.Helper()
	v2, err := config.UnmarshalV2([]byte(roundTripSource))
	if err != nil {
		t.Fatalf("UnmarshalV2 failed: %v", err)
	}
	return v2
}

func TestExecutionConfigurationRoundTrip_Parsed(t *testing.T) {
	v2 := parseRoundTripV2(t)
	if v2.Execution == nil || v2.Execution.Interpreter != "bash" || v2.Execution.LaunchDialect != "posix" || v2.Execution.Login == nil || *v2.Execution.Login != false {
		t.Fatalf("unexpected parsed global execution: %+v", v2.Execution)
	}
	n1Exec := v2.Nodes["node1"].Execution
	if n1Exec == nil || n1Exec.Interpreter != "server" || n1Exec.Login != nil {
		t.Fatalf("unexpected node1 execution: %+v", n1Exec)
	}
	n2Exec := v2.Nodes["node2"].Execution
	if n2Exec == nil || n2Exec.Login == nil || *n2Exec.Login != true {
		t.Fatalf("unexpected node2 execution: %+v", n2Exec)
	}
}

func TestExecutionConfigurationRoundTrip_ModelConversion(t *testing.T) {
	v2 := parseRoundTripV2(t)
	modelCfg, err := config.FromV2(v2)
	if err != nil {
		t.Fatalf("FromV2 failed: %v", err)
	}
	if modelCfg.Execution == nil || modelCfg.Execution.Interpreter != "bash" || *modelCfg.Execution.Login != false {
		t.Fatalf("FromV2 lost global execution: %+v", modelCfg.Execution)
	}

	clonedModel := modelCfg.Snapshot()
	if clonedModel.Execution == nil || *clonedModel.Execution.Login != false {
		t.Fatalf("Snapshot lost global execution: %+v", clonedModel.Execution)
	}
	f := true
	clonedModel.Execution.Login = &f
	if *modelCfg.Execution.Login != false {
		t.Fatal("mutating clonedModel affected original modelCfg")
	}

	v2RoundTrip, err := modelCfg.ToV2()
	if err != nil {
		t.Fatalf("ToV2 failed: %v", err)
	}
	encoded, err := yaml.Marshal(v2RoundTrip)
	if err != nil {
		t.Fatalf("yaml.Marshal failed: %v", err)
	}

	var reparsed config.ConfigurationV2
	if err := yaml.Unmarshal(encoded, &reparsed); err != nil {
		t.Fatalf("re-Unmarshal failed: %v", err)
	}
	if reparsed.Execution == nil || *reparsed.Execution.Login != false || reparsed.Execution.Interpreter != "bash" {
		t.Fatalf("roundtripped execution mismatch: %+v", reparsed.Execution)
	}
	if reparsed.Nodes["node1"].Execution == nil || reparsed.Nodes["node1"].Execution.Interpreter != "server" {
		t.Fatalf("roundtripped node1 execution mismatch: %+v", reparsed.Nodes["node1"].Execution)
	}
	if reparsed.Nodes["node2"].Execution == nil || reparsed.Nodes["node2"].Execution.Login == nil || *reparsed.Nodes["node2"].Execution.Login != true {
		t.Fatalf("roundtripped node2 execution mismatch: %+v", reparsed.Nodes["node2"].Execution)
	}
}

func TestExecutionConfigurationPresence(t *testing.T) {
	// 验证缺省 login 与显式 login: false 的精确序列化区别
	yamlExplicitFalse := `interpreter: bash
launch_dialect: posix
login: false
`
	sourceFalse := "schema_version: 2\ncredential: {stores: {}}\nidentities: {}\nhosts: {}\nnodes: {}\nexecution:\n  " +
		strings.ReplaceAll(strings.TrimSuffix(yamlExplicitFalse, "\n"), "\n", "\n  ") + "\n"
	parsedFalse, err := config.UnmarshalV2([]byte(sourceFalse))
	if err != nil {
		t.Fatalf("UnmarshalV2 explicit false failed: %v", err)
	}
	if parsedFalse.Execution.Login == nil || *parsedFalse.Execution.Login != false {
		t.Fatalf("expected login == false, got %v", parsedFalse.Execution.Login)
	}

	// 序列化后必须包含 "login: false"
	marshaledFalse, err := yaml.Marshal(parsedFalse.Execution)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !strings.Contains(string(marshaledFalse), "login: false") {
		t.Fatalf("marshaled output does not contain 'login: false': %s", marshaledFalse)
	}

	// 缺省 login
	yamlOmittedLogin := `interpreter: bash
launch_dialect: posix
`
	sourceOmitted := "schema_version: 2\ncredential: {stores: {}}\nidentities: {}\nhosts: {}\nnodes: {}\nexecution:\n  " +
		strings.ReplaceAll(strings.TrimSuffix(yamlOmittedLogin, "\n"), "\n", "\n  ") + "\n"
	parsedOmitted, err := config.UnmarshalV2([]byte(sourceOmitted))
	if err != nil {
		t.Fatalf("UnmarshalV2 omitted login failed: %v", err)
	}
	if parsedOmitted.Execution.Login != nil {
		t.Fatalf("expected login == nil, got %v", parsedOmitted.Execution.Login)
	}

	// 序列化后不得包含 "login:"
	marshaledOmitted, err := yaml.Marshal(parsedOmitted.Execution)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if strings.Contains(string(marshaledOmitted), "login:") {
		t.Fatalf("marshaled output unexpectedly contains 'login:': %s", marshaledOmitted)
	}
}
