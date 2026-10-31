package runtime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

type probeRuntimeSource struct {
	ports.StateSource
	execution *ssh.ExecutionConfig
	policy    policy.Config
}

func (s probeRuntimeSource) Resolve(ctx context.Context, req ports.ResolveRequest) (ports.OperationSnapshot, error) {
	view, err := s.StateSource.Resolve(ctx, req)
	view = view.Clone()
	view.Policy = s.policy
	for id, target := range view.Targets {
		target.Execution = s.execution.Clone()
		target.ExecutionVersion = ports.ExecutionVersion(target.Execution)
		view.Targets[id] = target
	}
	return view, err
}

type probeRuntimeBackend struct {
	executionRiskBackend
	probes   atomic.Int32
	result   *ssh.ProbeResult
	err      error
	executed chan *ssh.ExecutionConfig
}

func (b *probeRuntimeBackend) ProbeExecution(ctx context.Context, p ports.Permit, _ string) (*ssh.ProbeResult, error) {
	if _, cancel, err := ports.WorkContext(ctx, p, ports.Inspect); err != nil {
		return nil, err
	} else {
		defer cancel()
	}
	b.probes.Add(1)
	return b.result, b.err
}

func (b *probeRuntimeBackend) Run(ctx context.Context, p ports.Permit, _ string, command ports.Command) (ports.CommandResult, error) {
	work, cancel, err := ports.WorkContext(ctx, p, ports.Execute)
	if err != nil {
		return ports.CommandResult{}, err
	}
	defer cancel()
	b.calls.Add(1)
	b.executed <- command.Execution.Clone()
	return ports.CommandResult{Connected: true, Outcome: ssh.ExecutionCompleted}, work.Err()
}

func (b *probeRuntimeBackend) OpenPTY(ctx context.Context, p ports.Permit, _ string) (ports.PTYSession, error) {
	return nil, errors.New("pty not implemented in stub")
}

type probeRuntimeGate struct {
	domain    string
	stale     bool
	closed    atomic.Int32
	onExecute func()
}

func (g *probeRuntimeGate) DomainID() string { return g.domain }
func (g *probeRuntimeGate) Enter(ctx context.Context, a ports.Admission) (ports.Permit, error) {
	if a.Phase == ports.Execute {
		if g.stale {
			return nil, ports.ErrStaleBinding
		}
		if g.onExecute != nil {
			g.onExecute()
		}
	}
	return ports.NewPermit(ctx, a, func() error { g.closed.Add(1); return nil })
}

func TestMCPExecutionProbeFreezesDefaultShellBeforeDispatch(t *testing.T) {
	for _, interpreter := range []ssh.Interpreter{ssh.InterpreterFish, ssh.InterpreterZsh} {
		for _, sudo := range []bool{false, true} {
			t.Run(string(interpreter)+map[bool]string{false: "/command", true: "/sudo"}[sudo], func(t *testing.T) {
				dialect := ssh.LaunchPOSIX
				if interpreter == ssh.InterpreterFish {
					dialect = ssh.LaunchFish
				}
				login := false
				backend := &probeRuntimeBackend{executed: make(chan *ssh.ExecutionConfig, 1), result: &ssh.ProbeResult{DetectedDialect: dialect, SuggestedConfig: ssh.ExecutionConfig{Interpreter: interpreter, LaunchDialect: dialect, Login: &login}}}
				provider := runtimeTestProvider("node")
				gate := &probeRuntimeGate{domain: provider.DomainID(), onExecute: func() { backend.result.SuggestedConfig.Interpreter = ssh.InterpreterBash }}
				r, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{State: provider, Gate: gate, Audit: ports.NoopAudit{}, NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil }}))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := r.Close(); err != nil {
						t.Error(err)
					}
				})
				client := connectRuntimeTestClient(t, r)
				result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "terminal", Arguments: TerminalInput{NodeID: "node", Command: "ls", Sudo: sudo}})
				if err != nil || result.IsError || backend.probes.Load() != 1 || backend.calls.Load() != 1 || gate.closed.Load() != 2 {
					t.Fatalf("probe/execute lifecycle: result=%+v error=%v probes=%d calls=%d closed=%d", result, err, backend.probes.Load(), backend.calls.Load(), gate.closed.Load())
				}
				executed := <-backend.executed
				if executed.Interpreter != interpreter || executed.LaunchDialect != dialect || executed.Login == nil || *executed.Login {
					t.Fatalf("execution changed after preparation: %+v", executed)
				}
				view, err := provider.Resolve(t.Context(), ports.ResolveRequest{Selectors: []string{"node"}})
				if err != nil || view.Targets["node"].Execution != nil {
					t.Fatalf("probe mutated source: %+v %v", view, err)
				}
			})
		}
	}
}

func TestMCPExecutionProbeRespectsOverridesAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		command                  string
		target, request          *ssh.ExecutionConfig
		policy                   policy.Config
		probeErr                 error
		incomplete, stale, empty bool
		probes, calls            int32
		denied                   bool
	}{
		{name: "explicit server", request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, calls: 1},
		{name: "configured fish", target: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish}, calls: 1},
		{name: "request zsh overrides fish", target: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish}, request: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchPOSIX}, calls: 1},
		{name: "probe failure", probeErr: errors.New("transport failed"), probes: 1, denied: true},
		{name: "canceled probe", probeErr: context.Canceled, probes: 1, denied: true},
		{name: "incomplete probe", incomplete: true, probes: 1, denied: true},
		{name: "empty probe", empty: true, probes: 1, denied: true},
		{name: "stale execution admission", stale: true, probes: 1, denied: true},
		{name: "fish still needs approval", policy: policy.Config{Enabled: true, ApprovalThreshold: "moderate", NoElicitFallback: "deny"}, probes: 1, denied: true},
		{name: "hard deny does not probe", policy: policy.Config{Enabled: true, BlockedPatterns: []string{"*"}}, denied: true},
		{name: "built-in block does not probe", command: "rm -rf /", policy: policy.Config{Enabled: true}, denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := runtimeTestProvider("node")
			source := probeRuntimeSource{StateSource: provider, execution: tc.target, policy: tc.policy}
			backend := &probeRuntimeBackend{executed: make(chan *ssh.ExecutionConfig, 1), err: tc.probeErr, result: &ssh.ProbeResult{DetectedDialect: ssh.LaunchFish, SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish}}}
			if tc.incomplete {
				backend.result = nil
			}
			if tc.empty {
				backend.result = &ssh.ProbeResult{}
			}
			gate := &probeRuntimeGate{domain: source.DomainID(), stale: tc.stale}
			r, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{State: source, Gate: gate, Audit: ports.NoopAudit{}, NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil }}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)
			command := tc.command
			if command == "" {
				command = "ls"
			}
			result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "terminal", Arguments: TerminalInput{NodeID: "node", Command: command, Execution: tc.request}})
			if err != nil || result.IsError != tc.denied || backend.probes.Load() != tc.probes || backend.calls.Load() != tc.calls {
				t.Fatalf("result=%+v error=%v probes=%d calls=%d", result, err, backend.probes.Load(), backend.calls.Load())
			}
		})
	}
}

func TestMCPProbedPOSIXCommandsStillRequireApproval(t *testing.T) {
	for _, tc := range []struct {
		command string
		denied  bool
	}{
		{`echo =(touch "$XOPS_REVIEW_MARKER")`, true},
		{`echo $(touch /tmp/marker)`, true},
		{"echo `touch /tmp/marker`", true},
		{"echo hello\ntouch /tmp/marker", true},
		{"find /tmp/marker -delete", true},
		{"find /tmp/marker -exec touch /tmp/owned +", true},
		{"find /tmp/marker -fprint /tmp/output", true},
		{"sed -i s/old/new/ /tmp/marker", true},
		{"awk -f /tmp/program /tmp/marker", true},
		{"hostname changed-host", true},
		{"date -s 2030-01-01", true},
		{"ip route flush table main", true},
		{"ss -K dst 192.0.2.1", true},
		{"file -C", true},
		{"journalctl --rotate", true},
		{"systemctl status-invalid nginx", true},
		{"systemctl status nginx --unknown", true},
		{"LD_PRELOAD=/tmp/code.so ls", true},
		{"find /tmp/marker -print", true},
		{"hostname -f", false},
		{"date +%F", false},
		{"ip route show", false},
		{"systemctl status nginx --no-pager", false},
		{"ls -la /tmp", false},
		{"echo hello", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			provider := runtimeTestProvider("node")
			source := probeRuntimeSource{StateSource: provider, policy: policy.Config{Enabled: true, ApprovalThreshold: "moderate", NoElicitFallback: "deny"}}
			backend := &probeRuntimeBackend{executed: make(chan *ssh.ExecutionConfig, 1), result: &ssh.ProbeResult{DetectedDialect: ssh.LaunchPOSIX, SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterZsh, LaunchDialect: ssh.LaunchPOSIX}}}
			r, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{State: source, Gate: &probeRuntimeGate{domain: source.DomainID()}, Audit: ports.NoopAudit{}, NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil }}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)
			result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "terminal", Arguments: TerminalInput{NodeID: "node", Command: tc.command}})
			wantCalls := int32(1)
			if tc.denied {
				wantCalls = 0
			}
			if err != nil || result.IsError != tc.denied || backend.calls.Load() != wantCalls || backend.probes.Load() != 1 {
				t.Fatalf("approval after discovery: result=%+v error=%v calls=%d probes=%d", result, err, backend.calls.Load(), backend.probes.Load())
			}
		})
	}
}
