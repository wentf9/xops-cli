package runtime

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestExecutionRiskUsesTrustedDialectAndLegacyDefaults(t *testing.T) {
	for _, test := range []struct {
		name            string
		request, target *ssh.ExecutionConfig
		want            guardrail.RiskLevel
		dialect         string
	}{
		{"unconfigured request", nil, nil, guardrail.Moderate, "unknown"},
		{"unspecified server dialect", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, nil, guardrail.Moderate, "unknown"},
		{"node server unspecified dialect", nil, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, guardrail.Moderate, "unknown"},
		{"untrusted POSIX assertion", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX}, nil, guardrail.Moderate, "unknown"},
		{"trusted POSIX server", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}, guardrail.Safe, "posix"},
		{"fish through POSIX stays conservative", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchPOSIX}, &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}, guardrail.Moderate, "fish"},
		{"configured fish", nil, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish}, guardrail.Moderate, "fish"},
		{"configured zsh", nil, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchPOSIX}, guardrail.Safe, "posix"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ri, err := resolveExecutionRisk(guardrail.RiskInput{ToolName: "terminal", Command: "ls", Execution: test.request}, ports.Target{Execution: test.target})
			if err != nil {
				t.Fatal(err)
			}
			if ri.Dialect != test.dialect || guardrail.Classify(ri) != test.want || ri.PlanDigest == "" {
				t.Fatalf("incorrect effective risk: %+v", ri)
			}
		})
	}
}

type executionRiskSource struct {
	ports.StateSource
	execution *ssh.ExecutionConfig
}

func (s executionRiskSource) Resolve(ctx context.Context, request ports.ResolveRequest) (ports.OperationSnapshot, error) {
	view, err := s.StateSource.Resolve(ctx, request)
	if err != nil {
		return view, err
	}
	view = view.Clone()
	view.Policy = policy.Config{Enabled: true, ApprovalThreshold: "moderate", NoElicitFallback: guardrail.FallbackDeny}
	for id, target := range view.Targets {
		target.Execution = s.execution.Clone()
		target.ExecutionVersion = ports.ExecutionVersion(target.Execution)
		view.Targets[id] = target
	}
	return view, nil
}

type executionRiskGate struct{ domain string }

func (g executionRiskGate) DomainID() string { return g.domain }
func (g executionRiskGate) Enter(ctx context.Context, a ports.Admission) (ports.Permit, error) {
	return ports.NewPermit(ctx, a, nil)
}

type executionRiskBackend struct {
	ports.Backend
	calls atomic.Int32
}

func (b *executionRiskBackend) Run(context.Context, ports.Permit, string, ports.Command) (ports.CommandResult, error) {
	b.calls.Add(1)
	return ports.CommandResult{Output: "executed", Connected: true, Outcome: ssh.ExecutionCompleted}, nil
}
func (b *executionRiskBackend) Shutdown(context.Context) error { return nil }

func TestUnknownServerRequiresApprovalBeforeBackend(t *testing.T) {
	for _, test := range []struct {
		name            string
		request, target *ssh.ExecutionConfig
		denied          bool
	}{
		{"unconfigured request", nil, nil, true},
		{"request server unknown", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, nil, true},
		{"node server unknown", nil, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, true},
		{"request cannot assert safety", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX}, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := runtimeTestProvider("node")
			source := executionRiskSource{provider, test.target}
			backend := &executionRiskBackend{}
			dependencies := ports.Dependencies{State: source, Gate: executionRiskGate{source.DomainID()}, Audit: ports.NoopAudit{}, NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil }}
			r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)
			result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "terminal", Arguments: TerminalInput{NodeID: "node", Command: "ls", Execution: test.request}})
			if err != nil {
				t.Fatal(err)
			}
			wantCalls := int32(1)
			if test.denied {
				wantCalls = 0
			}
			if result.IsError != test.denied || backend.calls.Load() != wantCalls {
				t.Fatalf("unknown server bypassed approval: result=%+v calls=%d", result, backend.calls.Load())
			}
		})
	}
}

func TestMCPToolExecutionNullLoginHandling(t *testing.T) {
	provider := runtimeTestProvider("node")
	target := &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}
	source := executionRiskSource{provider, target}
	backend := &executionRiskBackend{}
	dependencies := ports.Dependencies{
		State:      source,
		Gate:       executionRiskGate{source.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)

	// Call tool with server interpreter and explicit null login
	argsServerNullLogin := map[string]any{
		"nodeID": "node",
		"cmd":    "ls",
		"execution": map[string]any{
			"interpreter": "server",
			"login":       nil,
		},
	}
	result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "terminal", Arguments: argsServerNullLogin})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("expected server with null login to succeed, got error: %+v", result)
	}

	// Call tool with null login alone
	argsNullLogin := map[string]any{
		"nodeID": "node",
		"cmd":    "ls",
		"execution": map[string]any{
			"login": nil,
		},
	}
	result, err = client.CallTool(t.Context(), &mcp.CallToolParams{Name: "terminal", Arguments: argsNullLogin})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("expected null login to succeed, got error: %+v", result)
	}
}

func TestMCPToolExecutionSupportedJSONForms(t *testing.T) {
	provider := runtimeTestProvider("node")
	target := &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}
	source := executionRiskSource{provider, target}
	backend := &executionRiskBackend{}
	dependencies := ports.Dependencies{
		State:      source,
		Gate:       executionRiskGate{source.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)

	validForms := []struct {
		name      string
		execution map[string]any
	}{
		{
			name: "launch_dialect alias",
			execution: map[string]any{
				"launch_dialect": "posix",
			},
		},
		{
			name: "launchDialect camelCase",
			execution: map[string]any{
				"launchDialect": "posix",
			},
		},
		{
			name: "login enabled string",
			execution: map[string]any{
				"interpreter": "bash",
				"login":       "enabled",
			},
		},
		{
			name: "login disabled string",
			execution: map[string]any{
				"interpreter": "bash",
				"login":       "disabled",
			},
		},
		{
			name: "login inherit string",
			execution: map[string]any{
				"login": "inherit",
			},
		},
		{
			name: "login boolean true",
			execution: map[string]any{
				"interpreter": "bash",
				"login":       true,
			},
		},
		{
			name: "login boolean false",
			execution: map[string]any{
				"interpreter": "bash",
				"login":       false,
			},
		},
		{
			name: "login null",
			execution: map[string]any{
				"login": nil,
			},
		},
		{
			name: "combined server with launch_dialect and login inherit",
			execution: map[string]any{
				"interpreter":    "server",
				"launch_dialect": "posix",
				"login":          "inherit",
			},
		},
		{
			name: "combined server with launchDialect and login null",
			execution: map[string]any{
				"interpreter":   "server",
				"launchDialect": "posix",
				"login":         nil,
			},
		},
	}

	for _, tc := range validForms {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{
				"nodeID":    "node",
				"cmd":       "uptime",
				"execution": tc.execution,
			}
			result, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "terminal",
				Arguments: args,
			})
			if err != nil {
				t.Fatalf("call tool error: %v", err)
			}
			if result.IsError {
				t.Fatalf("expected valid execution form %v to succeed, got error: %+v", tc.execution, result)
			}
		})
	}

	// Verify schema rejects unknown properties in execution
	t.Run("rejects unknown field in execution", func(t *testing.T) {
		args := map[string]any{
			"nodeID": "node",
			"cmd":    "uptime",
			"execution": map[string]any{
				"unknown_property": "bad",
			},
		}
		result, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "terminal",
			Arguments: args,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatal("expected schema validation error for unknown_property, but call succeeded")
		}
	})

	// Verify schema rejects invalid login type (e.g. integer)
	t.Run("rejects numeric login", func(t *testing.T) {
		args := map[string]any{
			"nodeID": "node",
			"cmd":    "uptime",
			"execution": map[string]any{
				"login": 12345,
			},
		}
		result, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "terminal",
			Arguments: args,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatal("expected schema validation error for numeric login, but call succeeded")
		}
	})
}
