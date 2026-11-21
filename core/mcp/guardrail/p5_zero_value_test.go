package guardrail

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"gopkg.in/yaml.v3"
)

func TestDecision_ZeroValueIsDeny(t *testing.T) {
	var d Decision
	if d != Deny {
		t.Fatalf("zero-value Decision = %v (%d), want Deny (%d)", d, d, Deny)
	}
	if d.String() != "deny" {
		t.Fatalf("zero-value Decision.String() = %q, want %q", d.String(), "deny")
	}
	if Deny == NeedApproval || Deny == Allow || NeedApproval == Allow {
		t.Fatalf("Decision constants must be distinct: Deny=%d NeedApproval=%d Allow=%d", Deny, NeedApproval, Allow)
	}
	if got := Decision(99).String(); got != "unknown" {
		t.Fatalf("Decision(99).String() = %q, want %q", got, "unknown")
	}

	var zeroPolicy Policy
	if got := zeroPolicy.Evaluate(Safe, RiskInput{ToolName: "nodes"}); got != Deny {
		t.Fatalf("zero-value Policy.Evaluate() = %v, want Deny", got)
	}
	var nilPolicy *Policy
	if got := nilPolicy.Evaluate(Safe, RiskInput{ToolName: "nodes"}); got != Deny {
		t.Fatalf("nil Policy.Evaluate() = %v, want Deny", got)
	}
	var nilGuardrail *Guardrail
	if got := nilGuardrail.Evaluate(RiskInput{ToolName: "nodes"}); got != Deny {
		t.Fatalf("nil Guardrail.Evaluate() = %v, want Deny", got)
	}
	var zeroGuardrail Guardrail
	if got := zeroGuardrail.Evaluate(RiskInput{ToolName: "nodes"}); got != Deny {
		t.Fatalf("zero-value Guardrail.Evaluate() = %v, want Deny", got)
	}
}

func TestAuthorize_UnknownDecisionAndNilGuardrailFailClosed(t *testing.T) {
	t.Run("nil_guardrail_denied", func(t *testing.T) {
		var nilGuardrail *Guardrail
		opID, pending, err := nilGuardrail.Authorize(context.Background(), &mcp.CallToolRequest{}, RiskInput{ToolName: "transfer", Action: "pull", Paths: []string{"/tmp/a"}}, nil)
		if err == nil {
			t.Fatal("expected error from nil Guardrail.Authorize, got nil")
		}
		if opID != "" || pending != nil {
			t.Fatalf("expected empty opID and nil pending, got opID=%q pending=%#v", opID, pending)
		}
	})

	for _, unknown := range []Decision{Decision(99), Decision(-1)} {
		t.Run("unknown_"+unknown.String(), func(t *testing.T) {
			g := New(defaultTestConfig())
			fakeAudit := &fakeAuditWriter{}
			g.SetAuditWriter(fakeAudit)
			g.evaluateOverride = func(context.Context, RiskInput) Decision {
				return unknown
			}

			opID, pending, err := g.Authorize(
				context.Background(),
				&mcp.CallToolRequest{},
				RiskInput{ToolName: "transfer", Action: "pull", NodeID: "node-1", Paths: []string{"/tmp/file.txt"}},
				dummyInput{Command: "pull"},
			)
			if err == nil {
				t.Fatalf("expected error from Authorize for unknown Decision(%d), got nil", unknown)
			}
			if !strings.Contains(err.Error(), "denied") || !strings.Contains(err.Error(), "unexpected policy decision") {
				t.Fatalf("unexpected Authorize error for unknown Decision(%d): %v", unknown, err)
			}
			if opID != "" || pending != nil {
				t.Fatalf("Authorize must not issue opID or pending result on unknown decision, got opID=%q pending=%#v", opID, pending)
			}
			if len(fakeAudit.entries) != 1 {
				t.Fatalf("expected 1 audit entry, got %d: %#v", len(fakeAudit.entries), fakeAudit.entries)
			}
			entry := fakeAudit.entries[0]
			if entry.Outcome != "denied" {
				t.Fatalf("audit Outcome = %q, want %q", entry.Outcome, "denied")
			}
			if entry.Decision != "deny" {
				t.Fatalf("audit Decision = %q, want %q", entry.Decision, "deny")
			}
			if !strings.Contains(entry.Error, "unexpected policy decision") {
				t.Fatalf("audit Error = %q, want unexpected policy decision detail", entry.Error)
			}
		})
	}

	t.Run("unknown_decision_audit_failure_still_denies", func(t *testing.T) {
		g := New(defaultTestConfig())
		g.SetAuditWriter(&fakeAuditWriter{failOn: 1})
		g.evaluateOverride = func(context.Context, RiskInput) Decision {
			return Decision(99)
		}

		opID, pending, err := g.Authorize(
			context.Background(),
			&mcp.CallToolRequest{},
			RiskInput{ToolName: "transfer", Action: "pull", Paths: []string{"/tmp/file.txt"}},
			dummyInput{Command: "pull"},
		)
		if err == nil {
			t.Fatal("expected joined deny + audit error from Authorize, got nil")
		}
		if !strings.Contains(err.Error(), "unexpected policy decision") || !strings.Contains(err.Error(), "audit log failed") {
			t.Fatalf("expected both deny and audit errors, got: %v", err)
		}
		if opID != "" || pending != nil {
			t.Fatalf("Authorize must not issue opID on unknown decision + audit error, got opID=%q pending=%#v", opID, pending)
		}
	})
}

func TestWithGuardrail_UnknownDecisionFailsClosedAndAudits(t *testing.T) {
	for _, unknown := range []Decision{Decision(99), Decision(-1)} {
		t.Run(unknown.String(), func(t *testing.T) {
			g := New(defaultTestConfig())
			fakeAudit := &fakeAuditWriter{}
			g.SetAuditWriter(fakeAudit)
			g.evaluateOverride = func(context.Context, RiskInput) Decision {
				return unknown
			}

			handlerCalled := false
			handler := func(context.Context, *mcp.CallToolRequest, dummyInput) (*mcp.CallToolResult, dummyOutput, error) {
				handlerCalled = true
				return nil, dummyOutput{Response: "must-not-run"}, nil
			}

			wrapped := WithGuardrail(g, "terminal", func(in dummyInput) RiskInput {
				return RiskInput{ToolName: "terminal", Command: in.Command, NodeID: "node-1"}
			}, handler)

			res, out, err := wrapped(context.Background(), &mcp.CallToolRequest{}, dummyInput{Command: "echo hi"})
			if err == nil {
				t.Fatalf("expected error for unknown Decision(%d), got nil", unknown)
			}
			if !strings.Contains(err.Error(), "denied") || !strings.Contains(err.Error(), "unexpected policy decision") {
				t.Fatalf("unexpected error text for unknown Decision(%d): %v", unknown, err)
			}
			if handlerCalled {
				t.Fatalf("handler must NOT be called for unknown Decision(%d)", unknown)
			}
			if res != nil || out != (dummyOutput{}) {
				t.Fatalf("expected nil result and zero output on deny, got res=%#v out=%#v", res, out)
			}
			if len(fakeAudit.entries) != 1 {
				t.Fatalf("expected 1 audit entry, got %d: %#v", len(fakeAudit.entries), fakeAudit.entries)
			}
			entry := fakeAudit.entries[0]
			if entry.Outcome != "denied" {
				t.Fatalf("audit Outcome = %q, want %q", entry.Outcome, "denied")
			}
			if entry.Decision != "deny" {
				t.Fatalf("audit Decision = %q, want %q", entry.Decision, "deny")
			}
			if !strings.Contains(entry.Error, "unexpected policy decision") {
				t.Fatalf("audit Error = %q, want unexpected policy decision detail", entry.Error)
			}
		})
	}

	t.Run("unknown_decision_audit_failure_still_blocks_handler", func(t *testing.T) {
		g := New(defaultTestConfig())
		g.SetAuditWriter(&fakeAuditWriter{failOn: 1})
		g.evaluateOverride = func(context.Context, RiskInput) Decision {
			return Decision(99)
		}

		handlerCalled := false
		handler := func(context.Context, *mcp.CallToolRequest, dummyInput) (*mcp.CallToolResult, dummyOutput, error) {
			handlerCalled = true
			return nil, dummyOutput{Response: "must-not-run"}, nil
		}

		wrapped := WithGuardrail(g, "terminal", func(in dummyInput) RiskInput {
			return RiskInput{ToolName: "terminal", Command: in.Command}
		}, handler)

		_, _, err := wrapped(context.Background(), &mcp.CallToolRequest{}, dummyInput{Command: "echo hi"})
		if err == nil {
			t.Fatal("expected joined deny + audit error, got nil")
		}
		if !strings.Contains(err.Error(), "unexpected policy decision") || !strings.Contains(err.Error(), "audit log failed") {
			t.Fatalf("expected both deny and audit errors, got: %v", err)
		}
		if handlerCalled {
			t.Fatal("handler must NOT execute on unknown decision even when audit fails")
		}
	})
}

func TestGuardrail_ZeroValueAndYAMLDisabledDefaultBlocksDangerous(t *testing.T) {
	// 0. Go zero-value policy.Config{} is active (Disabled == false) and blocks dangerous commands.
	if got := NewPolicy(&policy.Config{}).Evaluate(Dangerous, RiskInput{ToolName: "terminal", Command: "rm -rf /"}); got != Deny {
		t.Fatalf("NewPolicy(&policy.Config{}).Evaluate(rm -rf /) = %v, want Deny", got)
	}

	type rootConfig struct {
		Guardrail *policy.Config `yaml:"guardrail,omitempty"`
	}

	const yamlOmittedDisabled = `
guardrail:
  approval_threshold: dangerous
  no_elicit_fallback: deny
  protected_paths:
    - /etc
`
	var parsed rootConfig
	if err := yaml.Unmarshal([]byte(yamlOmittedDisabled), &parsed); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}
	if parsed.Guardrail == nil {
		t.Fatal("expected parsed guardrail config, got nil")
	}
	if parsed.Guardrail.Disabled {
		t.Fatal("YAML guardrail block omitting disabled must default to Disabled=false")
	}

	g := New(parsed.Guardrail)
	fakeAudit := &fakeAuditWriter{}
	g.SetAuditWriter(fakeAudit)

	var calledCommands []string
	handler := func(_ context.Context, _ *mcp.CallToolRequest, in dummyInput) (*mcp.CallToolResult, dummyOutput, error) {
		calledCommands = append(calledCommands, in.Command)
		return nil, dummyOutput{Response: "ok"}, nil
	}
	wrapped := WithGuardrail(g, "terminal", func(in dummyInput) RiskInput {
		return RiskInput{ToolName: "terminal", Action: "once", Command: in.Command, NodeID: "prod-1"}
	}, handler)

	// 1. Hard-blocked dangerous command must be denied.
	if _, _, err := wrapped(context.Background(), &mcp.CallToolRequest{}, dummyInput{Command: "rm -rf /"}); err == nil {
		t.Fatal("expected rm -rf / to be denied when YAML omits disabled")
	}
	if len(calledCommands) != 0 {
		t.Fatalf("blocked command must not execute handler, called: %v", calledCommands)
	}

	// 2. Dangerous command requiring approval with no_elicit_fallback: deny must be denied.
	if _, _, err := wrapped(context.Background(), &mcp.CallToolRequest{}, dummyInput{Command: "rm -rf /var/log/app"}); err == nil {
		t.Fatal("expected dangerous command to be denied when no elicitation is available")
	}
	if len(calledCommands) != 0 {
		t.Fatalf("unapproved dangerous command must not execute handler, called: %v", calledCommands)
	}

	// 3. Safe command must still be allowed.
	if _, out, err := wrapped(context.Background(), &mcp.CallToolRequest{}, dummyInput{Command: "ls -la"}); err != nil {
		t.Fatalf("expected safe command to succeed, got: %v", err)
	} else if out.Response != "ok" {
		t.Fatalf("unexpected response %q", out.Response)
	}
	if len(calledCommands) != 1 || calledCommands[0] != "ls -la" {
		t.Fatalf("expected only safe command to execute, got %v", calledCommands)
	}

	// 4. Explicit disabled: true disables guardrail policy; legacy enabled: key is rejected.
	var parsedDisabled rootConfig
	if err := yaml.Unmarshal([]byte("guardrail:\n  disabled: true\n"), &parsedDisabled); err != nil {
		t.Fatalf("yaml.Unmarshal explicit disabled: true failed: %v", err)
	}
	if parsedDisabled.Guardrail == nil || !parsedDisabled.Guardrail.Disabled {
		t.Fatalf("expected explicit disabled: true, got %+v", parsedDisabled.Guardrail)
	}
	if got := NewPolicy(parsedDisabled.Guardrail).Evaluate(Dangerous, RiskInput{ToolName: "terminal", Command: "rm -rf /"}); got != Allow {
		t.Fatalf("explicitly disabled guardrail policy returned %v, want Allow", got)
	}
	var legacy rootConfig
	if err := yaml.Unmarshal([]byte("guardrail:\n  enabled: false\n"), &legacy); err == nil {
		t.Fatalf("expected legacy enabled: key to fail with unknown field error, got %+v", legacy.Guardrail)
	}
}
