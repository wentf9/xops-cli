package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/sshexec"
	"github.com/wentf9/xops-cli/core/mcp/state"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type publicationSecrets struct{}

func (publicationSecrets) ResolveSecret(ctx context.Context, _ ssh.SecretRequest) ([]byte, error) {
	return []byte(sshfixture.Password), ctx.Err()
}

type publicationTrust map[string]cryptoSSH.PublicKey

func (keys publicationTrust) Verify(ctx context.Context, request ssh.HostKeyRequest, key cryptoSSH.PublicKey) error {
	expected := keys[net.JoinHostPort(request.Host, strconv.Itoa(request.Port))]
	if expected == nil || !bytes.Equal(expected.Marshal(), key.Marshal()) {
		return ssh.ErrHostKeyMismatch
	}
	return ctx.Err()
}

type publicationFixture struct {
	ctx           context.Context
	coordinator   *state.Coordinator
	backend       *sshexec.Backend
	runtime       *Runtime
	client        *mcp.ClientSession
	first, second *sshfixture.Server
}

func setupPublication(t *testing.T, options *mcp.ClientOptions, enabled bool, httpMode ...bool) *publicationFixture {
	t.Helper()
	return setupPublicationWithAdmission(t, options, enabled, state.Options{}, httpMode...)
}

func setupPublicationWithAdmission(t *testing.T, options *mcp.ClientOptions, enabled bool, admissionOptions state.Options, httpMode ...bool) *publicationFixture {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	f := &publicationFixture{ctx: ctx}
	var err error
	f.first, err = sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(command string, ch cryptoSSH.Channel) { replyPublicationCommand(t, command, ch) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.first.Close(); err != nil {
			t.Error(err)
		}
	})
	f.second, err = sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: func(command string, ch cryptoSSH.Channel) { replyPublicationCommand(t, command, ch) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.second.Close(); err != nil {
			t.Error(err)
		}
	})
	view := ports.OperationSnapshot{DomainID: "publication-test", Revision: "1", PolicyRevision: "policy-1", Policy: policy.Config{Enabled: enabled, ApprovalThreshold: "safe", NoElicitFallback: "deny"}, Targets: map[string]ports.Target{"node": publicationTarget(t, f.first.Address)}}
	f.coordinator, err = state.New(view, admissionOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.coordinator.Close(); err != nil {
			t.Error(err)
		}
	})
	f.backend, err = sshexec.New(ctx, sshexec.Options{SSH: []ssh.Option{ssh.WithSecretResolver(publicationSecrets{}), ssh.WithHostKeyVerifier(publicationTrust{f.first.Address: f.first.HostKey, f.second.Address: f.second.HostKey})}})
	if err != nil {
		t.Fatal(err)
	}
	runtimeOptions := []Option{WithDependencies(ports.Dependencies{State: f.coordinator, Gate: f.coordinator, NewBackend: func(context.Context) (ports.Backend, error) { return f.backend, nil }, Audit: ports.NoopAudit{}})}
	if len(httpMode) > 0 && httpMode[0] {
		configuration := DefaultHTTPOptions()
		configuration.Token = httpTestToken
		configuration.StateDir = filepath.Join(t.TempDir(), "transfers")
		runtimeOptions = append(runtimeOptions, WithHTTP(configuration))
	}
	f.runtime, err = NewRuntime(ctx, runtimeOptions...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.runtime.Close(); err != nil {
			t.Error(err)
		}
	})
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	if _, err := f.runtime.server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "publication-test", Version: "1"}, options)
	f.client, err = client.Connect(ctx, clientTransport, &mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.client.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func TestTransferApprovalCannotIssueTaskForEditedTarget(t *testing.T) {
	prompted, approve := make(chan struct{}), make(chan struct{})
	f := setupPublication(t, &mcp.ClientOptions{ElicitationHandler: func(ctx context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		close(prompted)
		select {
		case <-approve:
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}, true, true)
	sum := sha256.Sum256([]byte("x"))
	input := PrepareUploadInput{Action: "prepare_push", RequestID: "prepare-race", NodeID: "node", RemotePath: "/prepared", Size: 1, SHA256: hex.EncodeToString(sum[:])}
	finished := make(chan error, 1)
	go func() {
		result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "transfer", Arguments: input})
		if err == nil && !result.IsError {
			err = errors.New("stale approval issued a transfer task")
		}
		finished <- err
	}()
	select {
	case <-prompted:
	case <-f.ctx.Done():
		t.Fatal("transfer approval did not start")
	}
	publishTarget(t, f, f.second.Address)
	close(approve)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	digest, err := transferRequestDigest(transfer.Upload, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.runtime.transfers.Retry(f.runtime.http.scope, input.RequestID, digest); err != nil || found {
		t.Fatalf("stale preparation left a reusable task: found=%v error=%v", found, err)
	}
}

func publicationTarget(t *testing.T, address string) ports.Target {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	// Publication-only command cases request explicit passthrough.
	return ports.Target{ExecutionVersion: ports.ExecutionVersion(nil), Info: ports.NodeInfo{ID: "node", Address: address, User: "fixture", AuthType: "password"}, Version: "1", Plan: ssh.ConnectionPlan{Scope: "publication-test", Hops: []ssh.ConnectionConfig{{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", AuthUpdateToken: "auth-1", TrustVersion: "trust-1"}}}}
}

func replyPublicationCommand(t *testing.T, command string, ch cryptoSSH.Channel) {
	t.Helper()
	output, status := "fixture-output", uint32(0)
	switch {
	case strings.Contains(command, "__XOPS_INTERP_END__"):
		output = "__XOPS_INTERP__:bash\n__XOPS_INTERP__:sh\n__XOPS_INTERP__:fish\n__XOPS_INTERP_END__\n"
	case strings.Contains(command, "__XOPS_DIALECT_FISH__"):
		output = "__XOPS_DIALECT_FISH__:3.7.0\n__XOPS_FISH_OS__:Linux\n__XOPS_FISH_SHELL__:/bin/fish\n"
	case strings.Contains(command, "__XOPS_DIALECT_"):
		output, status = "syntax error\n", 1
	}
	if _, err := io.WriteString(ch, output); err != nil {
		t.Error(err)
	}
	if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{status})); err != nil {
		t.Error(err)
	}
}

func TestMCPDefaultFishProbeSDKRoundTripAndCache(t *testing.T) {
	f := setupPublication(t, nil, false)
	login := false
	plan, err := ssh.PlanCommand("hostname", ssh.CommandOptions{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish, Login: ssh.LoginDisabled})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "terminal", Arguments: TerminalInput{NodeID: "node", Command: "hostname"}})
		if err != nil || result.IsError {
			t.Fatalf("MCP roundtrip: %+v %v", result, err)
		}
		data, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		var output TerminalOutput
		if err := json.Unmarshal(data, &output); err != nil {
			t.Fatal(err)
		}
		if output.PlanDigest != plan.Digest() || output.Output != "fixture-output" {
			t.Fatalf("wrong executed plan: %+v", output)
		}
	}
	if f.first.Executed.Load() != 7 {
		t.Fatalf("expected five probes and two user commands: %d", f.first.Executed.Load())
	}
	if f.coordinator.Snapshot().Targets["node"].Execution != nil {
		t.Fatal("probe persisted configuration")
	}
	// Exercise the wire schema's snake_case alias and explicit login value.
	result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "terminal", Arguments: map[string]any{"nodeID": "node", "cmd": "hostname", "execution": map[string]any{"interpreter": "fish", "launch_dialect": "fish", "login": login}}})
	if err != nil || result.IsError || f.first.Executed.Load() != 8 {
		t.Fatalf("explicit fish wire configuration: %+v %v", result, err)
	}
}

func publishTarget(t *testing.T, f *publicationFixture, address string) {
	t.Helper()
	next := f.coordinator.Snapshot()
	previous := next.Revision
	next.Revision = "next-" + previous
	next.Targets["node"] = publicationTarget(t, address)
	update, err := f.coordinator.BeginUpdate(f.ctx, previous, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := update.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := update.Publish(f.ctx, f.backend.RetirePlans); err != nil {
		t.Fatal(err)
	}
}

func TestApprovedCommandCannotSwitchTargetBeforeAdmission(t *testing.T) {
	prompted, approve := make(chan struct{}), make(chan struct{})
	f := setupPublication(t, &mcp.ClientOptions{ElicitationHandler: func(ctx context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		close(prompted)
		select {
		case <-approve:
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}, true)
	finished := make(chan error, 1)
	// Both client cancellation and the released approval terminate this call.
	go func() {
		result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "terminal", Arguments: TerminalInput{NodeID: "node", Command: "hostname", Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}}})
		if err == nil && !result.IsError {
			err = errors.New("stale approval executed")
		}
		finished <- err
	}()
	select {
	case <-prompted:
	case <-f.ctx.Done():
		t.Fatal("approval did not start")
	}
	publishTarget(t, f, f.second.Address)
	close(approve)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if f.first.Executed.Load() != 0 || f.second.Executed.Load() != 0 {
		t.Fatal("approval was applied to an edited target")
	}
}

func TestRuntimeUsesNewTargetOnlyForNewInvocations(t *testing.T) {
	f := setupPublication(t, nil, false)
	call := func() {
		t.Helper()
		result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "terminal", Arguments: TerminalInput{NodeID: "node", Command: "hostname", Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}}})
		if err != nil || result.IsError {
			t.Fatalf("command: %+v %v", result, err)
		}
	}
	call()
	publishTarget(t, f, f.second.Address)
	call()
	if f.first.Executed.Load() != 1 || f.second.Executed.Load() != 1 {
		t.Fatalf("wrong execution targets: first=%d second=%d", f.first.Executed.Load(), f.second.Executed.Load())
	}
}

type delayedPublicationBackend struct {
	ports.Backend
	started, release chan struct{}
}

func (b *delayedPublicationBackend) Run(ctx context.Context, permission ports.Permit, nodeID string, command ports.Command) (ports.CommandResult, error) {
	close(b.started)
	select {
	case <-b.release:
	case <-ctx.Done():
		return ports.CommandResult{}, ctx.Err()
	}
	return b.Backend.Run(ctx, permission, nodeID, command)
}

func TestAdmittedCommandKeepsItsTargetAcrossPublication(t *testing.T) {
	f := setupPublication(t, nil, false)
	backend := &delayedPublicationBackend{Backend: f.backend, started: make(chan struct{}), release: make(chan struct{})}
	f.runtime.backend = backend
	finished := make(chan error, 1)
	// The barrier separates gate admission from connection acquisition.
	go func() {
		result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "terminal", Arguments: TerminalInput{NodeID: "node", Command: "hostname", Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}}})
		if err == nil && result.IsError {
			err = errors.New("admitted command failed")
		}
		finished <- err
	}()
	select {
	case <-backend.started:
	case <-f.ctx.Done():
		t.Fatal("command never reached the admitted backend")
	}
	publishTarget(t, f, f.second.Address)
	close(backend.release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if f.first.Executed.Load() != 1 || f.second.Executed.Load() != 0 {
		t.Fatal("in-flight command was retargeted by publication")
	}
}

func TestTunnelApprovalCannotStartOnEditedTarget(t *testing.T) {
	prompted, approve := make(chan struct{}), make(chan struct{})
	f := setupPublication(t, &mcp.ClientOptions{ElicitationHandler: func(ctx context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		close(prompted)
		select {
		case <-approve:
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}, true)
	finished := make(chan *mcp.CallToolResult, 1)
	failures := make(chan error, 1)
	input := CreateTunnelInput{Action: "create", RequestID: "approval-race", NodeID: "node", Mode: "local", ListenHost: "127.0.0.1", TargetHost: "127.0.0.1", TargetPort: 80, TTLSeconds: 60}
	go func() {
		result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "tunnel", Arguments: input})
		if err != nil {
			failures <- err
		} else {
			finished <- result
		}
	}()
	select {
	case <-prompted:
	case <-f.ctx.Done():
		t.Fatal("tunnel approval did not start")
	}
	publishTarget(t, f, f.second.Address)
	close(approve)
	select {
	case err := <-failures:
		t.Fatal(err)
	case <-finished:
		for _, task := range f.runtime.tunnels.List("", "") {
			if task.State == "running" {
				t.Fatal("stale tunnel approval opened a listener")
			}
		}
	case <-f.ctx.Done():
		t.Fatal("tunnel request did not finish")
	}
}

func TestTunnelCreationUsesPublishedPolicy(t *testing.T) {
	f := setupPublication(t, nil, false)
	next := f.coordinator.Snapshot()
	next.Revision = "2"
	next.PolicyRevision = "policy-2"
	next.Policy.Enabled = true
	update, err := f.coordinator.BeginUpdate(f.ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if err := update.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := update.Publish(f.ctx, f.backend.RetirePlans); err != nil {
		t.Fatal(err)
	}
	result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "tunnel", Arguments: CreateTunnelInput{Action: "create", RequestID: "policy", NodeID: "node", Mode: "local", ListenHost: "127.0.0.1", TargetHost: "127.0.0.1", TargetPort: 80, TTLSeconds: 60}})
	if err != nil || !result.IsError {
		t.Fatalf("new policy was ignored: %+v %v", result, err)
	}
	if len(f.runtime.tunnels.List("", "")) != 0 {
		t.Fatal("denied policy created a task")
	}
}
