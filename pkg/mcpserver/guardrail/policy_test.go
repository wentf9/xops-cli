package guardrail

import (
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
)

func defaultTestConfig() *config.GuardrailConfig {
	return &config.GuardrailConfig{
		Enabled:           true,
		ApprovalThreshold: "dangerous",
		ProtectedPaths:    []string{"/etc", "/boot"},
	}
}

func TestPolicyEvaluate_Disabled(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Enabled = false
	p := NewPolicy(cfg)

	got := p.Evaluate(Dangerous, RiskInput{ToolName: "xops_fs_rm", Paths: []string{"/"}})
	if got != Allow {
		t.Errorf("disabled policy should Allow everything, got %v", got)
	}
}

func TestPolicyEvaluate_BlockedCommand(t *testing.T) {
	p := NewPolicy(defaultTestConfig())

	got := p.Evaluate(Dangerous, RiskInput{
		ToolName: "xops_ssh_run",
		Command:  "rm -rf /",
		NodeID:   "test-node",
	})
	if got != Deny {
		t.Errorf("blocked command should be Deny, got %v", got)
	}
}

func TestPolicyEvaluate_SafeOperation(t *testing.T) {
	p := NewPolicy(defaultTestConfig())

	got := p.Evaluate(Safe, RiskInput{
		ToolName: "xops_list_nodes",
	})
	if got != Allow {
		t.Errorf("safe operation should Allow, got %v", got)
	}
}

func TestPolicyEvaluate_DangerousNeedsApproval(t *testing.T) {
	p := NewPolicy(defaultTestConfig())

	got := p.Evaluate(Dangerous, RiskInput{
		ToolName: "xops_fs_rm",
		NodeID:   "prod-web-1",
		Paths:    []string{"/var/log/app"},
	})
	if got != NeedApproval {
		t.Errorf("dangerous op should NeedApproval, got %v", got)
	}
}

func TestPolicyEvaluate_ModerateWithThreshold(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.ApprovalThreshold = "moderate"
	p := NewPolicy(cfg)

	got := p.Evaluate(Moderate, RiskInput{
		ToolName: "xops_write_file",
		NodeID:   "test-node",
		Paths:    []string{"/tmp/test.txt"},
	})
	if got != NeedApproval {
		t.Errorf("moderate op with moderate threshold should NeedApproval, got %v", got)
	}
}

func TestPolicyEvaluate_NodeOverride(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.NodeOverrides = map[string]config.NodeGuardrailCfg{
		"prod-*": {ApprovalThreshold: "moderate"},
	}
	p := NewPolicy(cfg)

	got := p.Evaluate(Moderate, RiskInput{
		ToolName: "xops_write_file",
		NodeID:   "prod-web-1",
		Paths:    []string{"/tmp/test.txt"},
	})
	if got != NeedApproval {
		t.Errorf("prod node with moderate threshold should NeedApproval, got %v", got)
	}

	got = p.Evaluate(Moderate, RiskInput{
		ToolName: "xops_write_file",
		NodeID:   "dev-api-1",
		Paths:    []string{"/tmp/test.txt"},
	})
	if got != Allow {
		t.Errorf("dev node with dangerous threshold should Allow moderate, got %v", got)
	}
}

func TestPolicyEvaluate_ProtectedPath(t *testing.T) {
	p := NewPolicy(defaultTestConfig())

	got := p.Evaluate(Safe, RiskInput{
		ToolName: "xops_read_file",
		NodeID:   "test-node",
		Paths:    []string{"/etc/passwd"},
	})
	// read_file is Safe, but /etc is protected -> elevated to Moderate,
	// threshold is dangerous -> still Allow
	if got != Allow {
		t.Errorf("safe read on protected path with dangerous threshold should Allow, got %v", got)
	}

	cfg := defaultTestConfig()
	cfg.ApprovalThreshold = "moderate"
	p2 := NewPolicy(cfg)

	got = p2.Evaluate(Safe, RiskInput{
		ToolName: "xops_read_file",
		NodeID:   "test-node",
		Paths:    []string{"/etc/passwd"},
	})
	if got != NeedApproval {
		t.Errorf("safe read on protected path with moderate threshold should NeedApproval, got %v", got)
	}
}

func TestPolicyEvaluate_CustomBlockedPattern(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.BlockedPatterns = []string{"*dangerous*"}
	p := NewPolicy(cfg)

	got := p.Evaluate(Moderate, RiskInput{
		ToolName: "xops_ssh_run",
		Command:  "run_dangerous_script.sh",
		NodeID:   "test",
	})
	if got != Deny {
		t.Errorf("custom blocked pattern should Deny, got %v", got)
	}
}

func TestValidateConfig(t *testing.T) {
	validCfg := defaultTestConfig()
	validCfg.BlockedPatterns = []string{"*.sh", "rm *"}
	validCfg.NodeOverrides = map[string]config.NodeGuardrailCfg{
		"prod-*": {ApprovalThreshold: "dangerous"},
	}
	if err := ValidateConfig(validCfg); err != nil {
		t.Errorf("expected valid config to pass, got: %v", err)
	}

	invalidPatternCfg := defaultTestConfig()
	invalidPatternCfg.BlockedPatterns = []string{"["}
	if err := ValidateConfig(invalidPatternCfg); err == nil {
		t.Error("expected error for invalid glob '[', got nil")
	}

	invalidNodeCfg := defaultTestConfig()
	invalidNodeCfg.NodeOverrides = map[string]config.NodeGuardrailCfg{
		"[": {ApprovalThreshold: "dangerous"},
	}
	if err := ValidateConfig(invalidNodeCfg); err == nil {
		t.Error("expected error for invalid node override glob '[', got nil")
	}
}

func TestPolicyEvaluate_MalformedPattern_FailClosed(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.BlockedPatterns = []string{"["}
	p := NewPolicy(cfg)

	got := p.Evaluate(Safe, RiskInput{
		ToolName: "xops_ssh_run",
		Command:  "echo safe",
		NodeID:   "test",
	})
	if got != Deny {
		t.Errorf("malformed glob pattern in blocked list should fail-closed to Deny, got %v", got)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name  string
		input RiskInput
		want  RiskLevel
	}{
		{
			"safe tool",
			RiskInput{ToolName: "xops_list_nodes"},
			Safe,
		},
		{
			"moderate tool",
			RiskInput{ToolName: "xops_write_file", Paths: []string{"/tmp/file"}},
			Moderate,
		},
		{
			"dangerous tool",
			RiskInput{ToolName: "xops_fs_rm", Paths: []string{"/tmp/file"}},
			Dangerous,
		},
		{
			"ssh_run safe command",
			RiskInput{ToolName: "xops_ssh_run", Command: "ls -la"},
			Safe,
		},
		{
			"ssh_run dangerous command",
			RiskInput{ToolName: "xops_ssh_run", Command: "rm -rf /var/log"},
			Dangerous,
		},
		{
			"ssh_run with sudo",
			RiskInput{ToolName: "xops_ssh_run", Command: "ls -la", Sudo: true},
			Moderate,
		},
		{
			"moderate tool on root path",
			RiskInput{ToolName: "xops_fs_cp", Paths: []string{"/"}},
			Dangerous,
		},
		{
			"unknown tool",
			RiskInput{ToolName: "xops_unknown"},
			Dangerous,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.input); got != tt.want {
				t.Errorf("Classify(%+v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
