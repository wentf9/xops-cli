package runtime

import (
	"context"
	"strings"
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
		{"csh through POSIX stays conservative", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterCsh, LaunchDialect: ssh.LaunchPOSIX}, &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}, guardrail.Moderate, "csh"},
		{"tcsh through POSIX stays conservative", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterTcsh, LaunchDialect: ssh.LaunchPOSIX}, &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}, guardrail.Moderate, "csh"},
		{"configured csh", nil, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterCsh, LaunchDialect: ssh.LaunchCsh}, guardrail.Moderate, "csh"},
		{"configured tcsh", nil, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterTcsh, LaunchDialect: ssh.LaunchCsh}, guardrail.Moderate, "csh"},
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

func TestResolveExecutionRisk_PersistentSessionPreservesOuterDialect(t *testing.T) {
	for _, tc := range []struct {
		name          string
		targetDialect ssh.LaunchDialect
		interpreter   ssh.Interpreter
		expectedShell string
		expectedOnce  string
	}{
		{"csh on posix", ssh.LaunchPOSIX, ssh.InterpreterCsh, "posix", "csh"},
		{"tcsh on posix", ssh.LaunchPOSIX, ssh.InterpreterTcsh, "posix", "csh"},
		{"fish on posix", ssh.LaunchPOSIX, ssh.InterpreterFish, "posix", "fish"},
		{"csh on csh", ssh.LaunchCsh, ssh.InterpreterCsh, "csh", "csh"},
		{"tcsh on csh", ssh.LaunchCsh, ssh.InterpreterTcsh, "csh", "csh"},
		{"fish on fish", ssh.LaunchFish, ssh.InterpreterFish, "fish", "fish"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := ports.Target{
				Execution: &ssh.ExecutionConfig{
					LaunchDialect: tc.targetDialect,
				},
			}
			reqExecution := &ssh.ExecutionConfig{
				Interpreter:   tc.interpreter,
				LaunchDialect: tc.targetDialect,
			}

			// In persistent session (riskActionShell), outer PTY launch dialect must be preserved.
			riShell, err := resolveExecutionRisk(guardrail.RiskInput{
				ToolName:  "terminal",
				Action:    riskActionShell,
				Command:   "ls",
				Execution: reqExecution,
			}, target)
			if err != nil {
				t.Fatalf("resolveExecutionRisk(riskActionShell) failed: %v", err)
			}
			if riShell.Dialect != tc.expectedShell {
				t.Fatalf("expected persistent session dialect %q, got %q", tc.expectedShell, riShell.Dialect)
			}

			// In once session (riskActionOnce), single-command plan interpreter should set dialect.
			riOnce, err := resolveExecutionRisk(guardrail.RiskInput{
				ToolName:  "terminal",
				Action:    riskActionOnce,
				Command:   "ls",
				Execution: reqExecution,
			}, target)
			if err != nil {
				t.Fatalf("resolveExecutionRisk(riskActionOnce) failed: %v", err)
			}
			if riOnce.Dialect != tc.expectedOnce {
				t.Fatalf("expected once session dialect %q, got %q", tc.expectedOnce, riOnce.Dialect)
			}
		})
	}
}

func TestTerminalPersistentSessionSignalSkipsProbeAndPlan(t *testing.T) {
	signals := []string{"SIGINT", "EOF", "SIGTERM", "SIGKILL", "sigint", " eof "}
	for _, sig := range signals {
		t.Run("signal_"+sig, func(t *testing.T) {
			backend := &probeRuntimeBackend{
				executed: make(chan *ssh.ExecutionConfig, 1),
				result: &ssh.ProbeResult{
					DetectedDialect: ssh.LaunchPOSIX,
					SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX},
				},
			}
			provider := runtimeTestProvider("node")
			gate := &probeRuntimeGate{domain: provider.DomainID()}
			r, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{
				State:      provider,
				Gate:       gate,
				Audit:      ports.NoopAudit{},
				NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
			}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = r.Close()
			})
			client := connectRuntimeTestClient(t, r)

			// Signal on persistent session must skip prepareExecution (0 probes).
			_, _ = client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "terminal",
				Arguments: TerminalInput{
					NodeID:  "node",
					Session: "dev",
					Command: sig,
				},
			})
			if backend.probes.Load() != 0 {
				t.Fatalf("expected 0 probes for signal %q on persistent session, got %d", sig, backend.probes.Load())
			}
		})
	}

	// Normal command on persistent session without static execution config MUST trigger probe.
	t.Run("normal_command_triggers_probe", func(t *testing.T) {
		login := false
		backend := &probeRuntimeBackend{
			executed: make(chan *ssh.ExecutionConfig, 1),
			result: &ssh.ProbeResult{
				DetectedDialect: ssh.LaunchPOSIX,
				SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &login},
			},
		}
		provider := runtimeTestProvider("node")
		gate := &probeRuntimeGate{domain: provider.DomainID()}
		r, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{
			State:      provider,
			Gate:       gate,
			Audit:      ports.NoopAudit{},
			NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
		}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = r.Close()
		})
		client := connectRuntimeTestClient(t, r)
		_, _ = client.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "terminal",
			Arguments: TerminalInput{
				NodeID:  "node",
				Session: "dev",
				Command: "uptime",
			},
		})
		if backend.probes.Load() != 1 {
			t.Fatalf("expected 1 probe for normal command on persistent session, got %d", backend.probes.Load())
		}
	})
}

func assertEarlyRejected(t *testing.T, client *mcp.ClientSession, in TerminalInput, wantErr string) {
	t.Helper()
	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "terminal",
		Arguments: in,
	})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatal("expected error, got success")
	}
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	} else if res != nil && len(res.Content) > 0 {
		if text, ok := res.Content[0].(*mcp.TextContent); ok {
			errMsg = text.Text
		}
	}
	if !strings.Contains(errMsg, wantErr) {
		t.Fatalf("unexpected error message: %q, want it to contain %q", errMsg, wantErr)
	}
}

func TestPersistentSessionRejectsSudoAndExecutionEarly(t *testing.T) {
	login := false
	backend := &probeRuntimeBackend{
		executed: make(chan *ssh.ExecutionConfig, 1),
		result: &ssh.ProbeResult{
			DetectedDialect: ssh.LaunchPOSIX,
			SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &login},
		},
	}
	provider := runtimeTestProvider("node")
	gate := &probeRuntimeGate{domain: provider.DomainID()}
	r, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{
		State:      provider,
		Gate:       gate,
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
	})
	client := connectRuntimeTestClient(t, r)

	wantErr := "sudo and execution are supported only with session='once'; run sudo inside the persistent shell instead"

	t.Run("rejects_sudo", func(t *testing.T) {
		assertEarlyRejected(t, client, TerminalInput{
			NodeID:  "node",
			Session: "dev",
			Command: "whoami",
			Sudo:    true,
		}, wantErr)
		if backend.probes.Load() != 0 {
			t.Fatalf("expected 0 probes when sudo on persistent session is rejected early, got %d", backend.probes.Load())
		}
	})

	t.Run("rejects_execution", func(t *testing.T) {
		assertEarlyRejected(t, client, TerminalInput{
			NodeID:    "node",
			Session:   "dev",
			Command:   "uptime",
			Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash},
		}, wantErr)
		if backend.probes.Load() != 0 {
			t.Fatalf("expected 0 probes when execution on persistent session is rejected early, got %d", backend.probes.Load())
		}
	})

	t.Run("rejects_before_guardrail_approval", func(t *testing.T) {
		providerWithPolicy := runtimeTestProvider("node")
		state := executionRiskSource{
			StateSource: providerWithPolicy,
			execution:   &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX},
		}
		gateStrict := &probeRuntimeGate{domain: providerWithPolicy.DomainID()}
		rStrict, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{
			State:      state,
			Gate:       gateStrict,
			Audit:      ports.NoopAudit{},
			NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
		}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = rStrict.Close()
		})
		clientStrict := connectRuntimeTestClient(t, rStrict)
		assertEarlyRejected(t, clientStrict, TerminalInput{
			NodeID:  "node",
			Session: "dev",
			Command: "whoami",
			Sudo:    true,
		}, wantErr)
	})

	t.Run("passive_poll_skips_probe", func(t *testing.T) {
		for _, cmd := range []string{"", "   "} {
			backendProbeCount := backend.probes.Load()
			_, _ = client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "terminal",
				Arguments: TerminalInput{
					NodeID:  "node",
					Session: "dev",
					Command: cmd,
					Cwd:     "",
				},
			})
			if backend.probes.Load() != backendProbeCount {
				t.Fatalf("expected 0 probes when command %q and cwd are empty on persistent session, got delta %d", cmd, backend.probes.Load()-backendProbeCount)
			}
		}
	})

	t.Run("empty_cmd_with_cwd_performs_probe", func(t *testing.T) {
		for _, cmd := range []string{"", "   "} {
			backendProbeCount := backend.probes.Load()
			_, _ = client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "terminal",
				Arguments: TerminalInput{
					NodeID:  "node",
					Session: "dev",
					Command: cmd,
					Cwd:     "/var/tmp",
				},
			})
			if backend.probes.Load() != backendProbeCount+1 {
				t.Fatalf("expected 1 probe when command %q has persistent cwd on unconfigured session, got delta %d", cmd, backend.probes.Load()-backendProbeCount)
			}
		}
	})
}

func TestPersistentSessionWindowsRejection(t *testing.T) {
	winBackend := &probeRuntimeBackend{
		executed: make(chan *ssh.ExecutionConfig, 1),
		result: &ssh.ProbeResult{
			DetectedDialect: ssh.LaunchPowerShell,
			SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterPowerShell, LaunchDialect: ssh.LaunchPowerShell},
		},
	}
	winProvider := runtimeTestProvider("node-win")
	winGate := &probeRuntimeGate{domain: winProvider.DomainID()}
	rWin, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{
		State:      winProvider,
		Gate:       winGate,
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return winBackend, nil },
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = rWin.Close()
	})
	clientWin := connectRuntimeTestClient(t, rWin)
	res, err := clientWin.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "terminal",
		Arguments: TerminalInput{
			NodeID:  "node-win",
			Session: "dev",
			Command: "",
			Cwd:     "C:\\temp",
		},
	})
	wantErr := "persistent sessions require a Unix login shell"
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	} else if res != nil && len(res.Content) > 0 {
		if text, ok := res.Content[0].(*mcp.TextContent); ok {
			errMsg = text.Text
		}
	}
	if !strings.Contains(errMsg, wantErr) {
		t.Fatalf("expected persistent session Unix login shell error, got err=%v errMsg=%q res=%+v", err, errMsg, res)
	}
	if winBackend.probes.Load() != 1 {
		t.Fatalf("expected 1 probe for unconfigured Windows node with persistent cwd switch, got %d", winBackend.probes.Load())
	}
}

func TestOnceSessionCmdValidationEarly(t *testing.T) {
	login := false
	backend := &probeRuntimeBackend{
		executed: make(chan *ssh.ExecutionConfig, 1),
		result: &ssh.ProbeResult{
			DetectedDialect: ssh.LaunchPOSIX,
			SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &login},
		},
	}
	provider := runtimeTestProvider("node")
	gate := &probeRuntimeGate{domain: provider.DomainID()}
	r, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{
		State:      provider,
		Gate:       gate,
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
	})
	client := connectRuntimeTestClient(t, r)

	t.Run("once_session_allows_sudo_and_execution", func(t *testing.T) {
		for _, in := range []TerminalInput{
			{NodeID: "node", Session: "once", Command: "whoami", Sudo: true},
			{NodeID: "node", Session: "once", Command: "uptime", Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash}},
			{NodeID: "node", Session: "", Command: "whoami", Sudo: true},
			{NodeID: "node", Session: "", Command: "uptime", Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash}},
		} {
			if err := in.Validate(); err != nil {
				t.Fatalf("expected Validate() nil for once session with sudo/execution, got: %v", err)
			}
		}
	})

	t.Run("once_session_rejects_empty_and_whitespace_cmd_early", func(t *testing.T) {
		backendProbeCount := backend.probes.Load()
		wantErr := "cmd is required for once session mode"
		for _, cmd := range []string{"", "   ", "\t\n"} {
			for _, sess := range []string{"", "once"} {
				in := TerminalInput{NodeID: "node", Session: sess, Command: cmd}
				if err := in.Validate(); err == nil || !strings.Contains(err.Error(), wantErr) {
					t.Fatalf("expected Validate() error containing %q for sess=%q cmd=%q, got: %v", wantErr, sess, cmd, err)
				}
				assertEarlyRejected(t, client, in, wantErr)
			}
		}
		if backend.probes.Load() != backendProbeCount {
			t.Fatalf("expected 0 probes when once session cmd is rejected early, got delta %d", backend.probes.Load()-backendProbeCount)
		}
	})
}
