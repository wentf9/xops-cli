package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
	"github.com/wentf9/xops-cli/core/testutil/mcphost/models"
)

type w17aFailAuditSink struct {
	mu           sync.Mutex
	failOutcomes map[string]error
	entries      []guardrail.AuditEntry
}

func (s *w17aFailAuditSink) Log(entry guardrail.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	if err, ok := s.failOutcomes[entry.Outcome]; ok {
		return err
	}
	return nil
}

func (s *w17aFailAuditSink) snapshot() []guardrail.AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.entries)
}

func (s *w17aFailAuditSink) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = nil
}

func seedW17aTransfer(t *testing.T, r *Runtime, scope, reqID, nodeID, remotePath string) transfer.Prepared {
	t.Helper()
	sum := sha256.Sum256(nil)
	prepared, err := r.transfers.Prepare(transfer.Spec{
		Scope:         scope,
		RequestID:     reqID,
		RequestDigest: strings.Repeat("a", 64),
		NodeID:        nodeID,
		TargetID:      "target-" + nodeID,
		RemotePath:    remotePath,
		RequestedPath: remotePath,
		Direction:     transfer.Upload,
		Size:          0,
		SHA256:        hex.EncodeToString(sum[:]),
	}, "seed-op-"+reqID)
	if err != nil {
		t.Fatalf("seed transfer %s: %v", reqID, err)
	}
	return prepared
}

func connectW17aInMemorySession(t *testing.T, r *Runtime, protocol string, opts *mcp.ClientOptions) (*mcp.ServerSession, *mcp.ClientSession) {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := r.server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := ss.Close(); err != nil {
			t.Error(err)
		}
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "w17a-client", Version: "1"}, opts)
	cs, err := client.Connect(t.Context(), ct, &mcp.ClientSessionOptions{ProtocolVersion: protocol})
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := cs.Close(); err != nil {
			t.Error(err)
		}
	})
	return ss, cs
}

func startW17aHTTPTransferRuntime(t *testing.T, guardCfg *policy.Config, extraNodes ...string) (*Runtime, *w17aFailAuditSink) {
	t.Helper()
	cfg := runtimeTestProvider("files").Snapshot()
	for _, id := range extraNodes {
		cfg.Nodes.Set(id, models.Node{HostRef: "host", IdentityRef: "identity"})
	}
	cfg.Guardrail = guardCfg
	opts := DefaultHTTPOptions()
	opts.Token = httpTestToken
	opts.PublicURL = "http://127.0.0.1:19876"
	opts.StateDir = filepath.Join(t.TempDir(), "transfers")
	r, err := NewRuntime(t.Context(), WithConfigProvider(config.NewProviderWithoutOpenSSH(cfg)), WithHTTP(opts))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	audit := &w17aFailAuditSink{}
	r.guardrail.SetAuditWriter(audit)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r, audit
}

func TestP7W17a_AB17M1_HTTPTransferStatusAndCancelGuardrailAndAudit(t *testing.T) {
	t.Run("blocked_patterns_deny_status_and_cancel_without_leaking_or_cancelling", testP7W17aAB17M1BlockedPatterns)
	t.Run("approval_threshold_safe_and_node_overrides_gate_status_and_cancel", testP7W17aAB17M1ThresholdsAndOverrides)
	t.Run("roundtrip_request_state_decline_and_forged_rejected_under_allow", testP7W17aAB17M1RoundTripUnderAllow)
	t.Run("pre_execution_audit_failure_fails_closed_before_status_and_cancel", testP7W17aAB17M1PreExecutionAudit)
}

func testP7W17aAB17M1BlockedPatterns(t *testing.T) {
	r, audit := startW17aHTTPTransferRuntime(t, &policy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDeny,
		BlockedPatterns:   []string{"*"},
	})
	task := seedW17aTransfer(t, r, r.http.scope, "blocked-task", "files", "/secret/payload.bin")
	_, client := connectW17aInMemorySession(t, r, "2025-11-25", nil)

	for _, action := range []string{"status", "cancel"} {
		audit.reset()
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "transfer",
			Arguments: TransferTaskInput{Action: action, TransferID: task.Status.ID},
		})
		if err != nil {
			t.Fatalf("%s transport error: %v", action, err)
		}
		if !res.IsError {
			t.Fatalf("%s bypassed BlockedPatterns=[\"*\"], got %+v", action, res)
		}
		raw, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "/secret/payload.bin") {
			t.Fatalf("%s leaked task metadata on deny: %s", action, raw)
		}
		entries := audit.snapshot()
		if len(entries) != 1 || entries[0].Tool != "transfer" || entries[0].NodeID != "files" || entries[0].Outcome != "denied" {
			t.Fatalf("%s audit = %+v, want single denied entry for files", action, entries)
		}
	}

	// Task must still be Ready (never cancelled by denied cancel call).
	st, err := r.transfers.Lookup(r.http.scope, task.Status.ID)
	if err != nil || st.State != transfer.Ready || st.CancelRequested {
		t.Fatalf("denied cancel mutated task state: %+v err=%v", st, err)
	}

	// Nonexistent transferID must still be denied by BlockedPatterns (not return ErrNotFound).
	audit.reset()
	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "transfer",
		Arguments: TransferTaskInput{Action: "status", TransferID: "00000000000000000000000000000000"},
	})
	if err != nil || !res.IsError {
		t.Fatalf("unknown status under BlockedPatterns: res=%+v err=%v", res, err)
	}
	entries := audit.snapshot()
	if len(entries) != 1 || entries[0].Outcome != "denied" {
		t.Fatalf("unknown status audit under BlockedPatterns = %+v, want denied", entries)
	}
}

func testP7W17aAB17M1ThresholdsAndOverrides(t *testing.T) {
	t.Run("2025-11-25_inline_elicitation", testP7W17aAB17M1InlineElicitation)
	t.Run("2026-07-28_two_step_pending_and_accept", testP7W17aAB17M1TwoStepElicitation)
	t.Run("global_approval_threshold_safe", testP7W17aAB17M1GlobalSafeThreshold)
}

func testP7W17aAB17M1InlineElicitation(t *testing.T) {
	r, audit := startW17aHTTPTransferRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc"},
		NodeOverrides: map[string]policy.NodeConfig{
			"restricted-*": {ApprovalThreshold: "safe"},
		},
	}, "restricted-a")
	normalTask := seedW17aTransfer(t, r, r.http.scope, "normal-etc", "files", "/etc/secret.conf")
	restrictedTask := seedW17aTransfer(t, r, r.http.scope, "restricted-1", "restricted-a", "/tmp/data.bin")

	// Client without elicitation: normal node status & cancel succeed; restricted node denied.
	_, noElicit := connectW17aInMemorySession(t, r, "2025-11-25", nil)
	assertW17aTransferActionsSucceed(t, noElicit, normalTask.Status.ID)
	assertW17aTransferActionsDenied(t, noElicit, restrictedTask.Status.ID, "/tmp/data.bin")
	assertW17aTransferState(t, r, restrictedTask.Status.ID, transfer.Ready)

	// Client with decline elicitation: denied without mutating task.
	var declineCalls atomic.Int32
	_, declineClient := connectW17aInMemorySession(t, r, "2025-11-25", &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			declineCalls.Add(1)
			return &mcp.ElicitResult{Action: "decline"}, nil
		},
	})
	assertW17aTransferActionsDenied(t, declineClient, restrictedTask.Status.ID, "/tmp/data.bin")
	if declineCalls.Load() != 2 {
		t.Fatalf("decline elicitation calls = %d, want 2", declineCalls.Load())
	}
	assertW17aTransferState(t, r, restrictedTask.Status.ID, transfer.Ready)

	// Client with accept elicitation: both status and cancel succeed.
	var acceptCalls atomic.Int32
	audit.reset()
	_, acceptClient := connectW17aInMemorySession(t, r, "2025-11-25", &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			acceptCalls.Add(1)
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
		},
	})
	assertW17aTransferActionsSucceed(t, acceptClient, restrictedTask.Status.ID)
	if acceptCalls.Load() != 2 {
		t.Fatalf("accept elicitation calls = %d, want 2", acceptCalls.Load())
	}
	assertW17aTransferState(t, r, restrictedTask.Status.ID, transfer.Cancelled)
}

func assertW17aTransferActionsSucceed(t *testing.T, client *mcp.ClientSession, transferID string) {
	t.Helper()
	for _, action := range []string{"status", "cancel"} {
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "transfer",
			Arguments: TransferTaskInput{Action: action, TransferID: transferID},
		})
		if err != nil || res.IsError {
			t.Fatalf("%s unexpectedly failed: res=%+v err=%v", action, res, err)
		}
	}
}

func assertW17aTransferActionsDenied(t *testing.T, client *mcp.ClientSession, transferID, secretPath string) {
	t.Helper()
	for _, action := range []string{"status", "cancel"} {
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "transfer",
			Arguments: TransferTaskInput{Action: action, TransferID: transferID},
		})
		if err != nil || !res.IsError {
			t.Fatalf("%s unexpectedly succeeded: res=%+v err=%v", action, res, err)
		}
		if secretPath != "" {
			raw, _ := json.Marshal(res)
			if strings.Contains(string(raw), secretPath) {
				t.Fatalf("%s leaked task path %q on denial: %s", action, secretPath, raw)
			}
		}
	}
}

func assertW17aTransferState(t *testing.T, r *Runtime, transferID string, want transfer.State) {
	t.Helper()
	st, err := r.transfers.Lookup(r.http.scope, transferID)
	if err != nil || st.State != want {
		t.Fatalf("transfer %s state = %+v (err=%v), want %s", transferID, st, err, want)
	}
}

func testP7W17aAB17M1TwoStepElicitation(t *testing.T) {
	r, _ := startW17aHTTPTransferRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		NodeOverrides: map[string]policy.NodeConfig{
			"restricted-*": {ApprovalThreshold: "safe"},
		},
	}, "restricted-a")
	restrictedTask := seedW17aTransfer(t, r, r.http.scope, "restricted-2step", "restricted-a", "/tmp/two-step.bin")
	ss := connectW17aModernServerSession(t)

	for _, action := range []string{"status", "cancel"} {
		pending, out1, err := r.httpTransferHandler(t.Context(), &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, HTTPTransferInput{Action: action, TransferID: restrictedTask.Status.ID})
		if err != nil || pending == nil || pending.RequestState == "" || out1.Task.ID != "" {
			t.Fatalf("two-step %s round 1: pending=%+v out=%+v err=%v", action, pending, out1, err)
		}
		res2, out2, err := r.httpTransferHandler(t.Context(), &mcp.CallToolRequest{
			Session: ss,
			Params: &mcp.CallToolParamsRaw{
				RequestState:   pending.RequestState,
				InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}},
			},
		}, HTTPTransferInput{Action: action, TransferID: restrictedTask.Status.ID})
		if err != nil || res2 != nil || out2.Task.ID != restrictedTask.Status.ID {
			t.Fatalf("two-step %s round 2 accept failed: res=%+v out=%+v err=%v", action, res2, out2, err)
		}
	}
	assertW17aTransferState(t, r, restrictedTask.Status.ID, transfer.Cancelled)
}

func testP7W17aAB17M1GlobalSafeThreshold(t *testing.T) {
	r, _ := startW17aHTTPTransferRuntime(t, &policy.Config{
		ApprovalThreshold: "safe",
		NoElicitFallback:  guardrail.FallbackDeny,
	})
	task := seedW17aTransfer(t, r, r.http.scope, "global-safe", "files", "/tmp/global.bin")
	_, client := connectW17aInMemorySession(t, r, "2025-11-25", nil)
	assertW17aTransferActionsDenied(t, client, task.Status.ID, "/tmp/global.bin")
	assertW17aTransferState(t, r, task.Status.ID, transfer.Ready)
}

func connectW17aModernServerSession(t *testing.T) *mcp.ServerSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	srv := mcp.NewServer(&mcp.Implementation{Name: "w17a-modern-server", Version: "1"}, nil)
	ss, err := srv.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatalf("modern server.Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := ss.Close(); err != nil {
			t.Error(err)
		}
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "w17a-modern-client", Version: "1"}, &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "decline"}, nil
		},
	})
	cs, err := client.Connect(t.Context(), ct, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatalf("modern client.Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := cs.Close(); err != nil {
			t.Error(err)
		}
	})
	return ss
}

func testP7W17aAB17M1RoundTripUnderAllow(t *testing.T) {
	// Start with strict ApprovalThreshold: "safe" via publicationFixture so we can
	// relax policy to "dangerous" (Allow) between Round 1 and Round 2, testing AB16-M2
	// on transfer status and cancel.
	f := setupPublication(t, nil, false, true)
	audit := &w17aFailAuditSink{}
	f.runtime.guardrail.SetAuditWriter(audit)
	changeTransferState(t, f, func(view *ports.OperationSnapshot) {
		view.Policy = policy.Config{
			ApprovalThreshold: "safe",
			NoElicitFallback:  guardrail.FallbackDeny,
		}
	})
	task := seedW17aTransfer(t, f.runtime, f.runtime.http.scope, "roundtrip-task", "node", "/tmp/rt.bin")
	ss := connectW17aModernServerSession(t)

	for _, action := range []string{"status", "cancel"} {
		// Round 1 under strict policy: must return pending challenge, no task returned/cancelled.
		changeTransferState(t, f, func(view *ports.OperationSnapshot) {
			view.Policy = policy.Config{ApprovalThreshold: "safe", NoElicitFallback: guardrail.FallbackDeny}
		})
		req1 := &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}
		pending, out1, err := f.runtime.httpTransferHandler(t.Context(), req1, HTTPTransferInput{Action: action, TransferID: task.Status.ID})
		if err != nil || pending == nil || pending.RequestState == "" || out1.Task.ID != "" {
			t.Fatalf("%s round 1: pending=%+v out=%+v err=%v", action, pending, out1, err)
		}

		// Relax policy to Allow before Round 2.
		changeTransferState(t, f, func(view *ports.OperationSnapshot) {
			view.Policy = policy.Config{ApprovalThreshold: "dangerous", NoElicitFallback: guardrail.FallbackDeny}
		})

		// Round 2 with decline response MUST be rejected under Allow.
		audit.reset()
		reqDecline := &mcp.CallToolRequest{
			Session: ss,
			Params: &mcp.CallToolParamsRaw{
				RequestState:   pending.RequestState,
				InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "decline"}},
			},
		}
		if res, out, err := f.runtime.httpTransferHandler(t.Context(), reqDecline, HTTPTransferInput{Action: action, TransferID: task.Status.ID}); err == nil || res != nil || out.Task.ID != "" {
			t.Fatalf("%s decline under Allow succeeded: res=%+v out=%+v err=%v", action, res, out, err)
		}
		if entries := audit.snapshot(); len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
			t.Fatalf("%s decline audit = %+v, want denied", action, entries)
		}

		// Forged RequestState and unsolicited InputResponses MUST be rejected under Allow.
		for _, forged := range []*mcp.CallToolRequest{
			{Session: ss, Params: &mcp.CallToolParamsRaw{RequestState: "forged-state"}},
			{Session: ss, Params: &mcp.CallToolParamsRaw{InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}}}},
		} {
			if _, out, err := f.runtime.httpTransferHandler(t.Context(), forged, HTTPTransferInput{Action: action, TransferID: task.Status.ID}); err == nil || out.Task.ID != "" {
				t.Fatalf("%s forged params %+v succeeded under Allow: out=%+v", action, forged.Params, out)
			}
		}
	}

	if st, err := f.runtime.transfers.Lookup(f.runtime.http.scope, task.Status.ID); err != nil || st.State != transfer.Ready {
		t.Fatalf("task was cancelled despite rejected round-trip params: %+v err=%v", st, err)
	}
}

func testP7W17aAB17M1PreExecutionAudit(t *testing.T) {
	r, audit := startW17aHTTPTransferRuntime(t, &policy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDeny,
	})
	task := seedW17aTransfer(t, r, r.http.scope, "audit-task", "files", "/tmp/audited.bin")
	_, client := connectW17aInMemorySession(t, r, "2025-11-25", nil)

	// Fail pre-execution "authorized" audit: BOTH status and cancel MUST fail closed
	// without returning metadata or cancelling the task.
	audit.failOutcomes = map[string]error{"authorized": errors.New("audit disk full")}
	for _, action := range []string{"status", "cancel"} {
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "transfer",
			Arguments: TransferTaskInput{Action: action, TransferID: task.Status.ID},
		})
		if err != nil || !res.IsError {
			t.Fatalf("%s succeeded despite pre-execution audit failure: res=%+v err=%v", action, res, err)
		}
		raw, _ := json.Marshal(res)
		if strings.Contains(string(raw), "/tmp/audited.bin") {
			t.Fatalf("%s leaked metadata despite audit failure: %s", action, raw)
		}
	}
	if st, err := r.transfers.Lookup(r.http.scope, task.Status.ID); err != nil || st.State != transfer.Ready || st.CancelRequested {
		t.Fatalf("cancel mutated task despite pre-execution audit failure: %+v err=%v", st, err)
	}

	// Restore working audit: status records "authorized"; cancel records both "authorized" and "cancel_requested".
	audit.failOutcomes = nil
	audit.reset()
	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "transfer",
		Arguments: TransferTaskInput{Action: "status", TransferID: task.Status.ID},
	})
	if err != nil || res.IsError {
		t.Fatalf("status with healthy audit failed: res=%+v err=%v", res, err)
	}
	statusEntries := audit.snapshot()
	if len(statusEntries) != 1 || statusEntries[0].Tool != "transfer" || statusEntries[0].NodeID != "files" || statusEntries[0].Outcome != "authorized" || statusEntries[0].RiskLevel != "safe" {
		t.Fatalf("status audit entries = %+v, want single safe authorized entry", statusEntries)
	}

	audit.reset()
	res, err = client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "transfer",
		Arguments: TransferTaskInput{Action: "cancel", TransferID: task.Status.ID},
	})
	if err != nil || res.IsError {
		t.Fatalf("cancel with healthy audit failed: res=%+v err=%v", res, err)
	}
	cancelEntries := audit.snapshot()
	if len(cancelEntries) != 2 || cancelEntries[0].Outcome != "authorized" || cancelEntries[1].Outcome != "cancel_requested" {
		t.Fatalf("cancel audit entries = %+v, want [authorized, cancel_requested]", cancelEntries)
	}
}

func TestP7W17a_AB17L1_IdempotencyFastPathRejectsRoundTripApprovalParams(t *testing.T) {
	t.Run("tunnel_create_idempotency_does_not_bypass_roundtrip_params", testP7W17aAB17L1TunnelIdempotency)
	t.Run("transfer_prepare_idempotency_does_not_bypass_roundtrip_params", testP7W17aAB17L1TransferIdempotency)
}

func testP7W17aAB17L1TunnelIdempotency(t *testing.T) {
	f := startTunnelSSHFixture(t, 0)
	target := startTunnelEcho(t)
	r := newTunnelRuntime(t, f)
	audit := &w17aFailAuditSink{}
	r.guardrail.SetAuditWriter(audit)

	ss, client := connectW17aInMemorySession(t, r, "2026-07-28", &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "decline"}, nil
		},
	})
	input := tunnelTestInput(t, target, "local", "idem-tunnel-1")
	created := callTunnelTool(t, client, "xops_tunnel_create", input)
	if created.State != "running" {
		t.Fatalf("initial tunnel create: %+v", created)
	}

	// Retry with forged RequestState or unsolicited InputResponses MUST NOT take
	// the idempotency fast-path and MUST fail closed with a denied audit entry.
	for _, forged := range []*mcp.CallToolRequest{
		{Session: ss, Params: &mcp.CallToolParamsRaw{RequestState: "forged-tunnel-state"}},
		{Session: ss, Params: &mcp.CallToolParamsRaw{InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "decline"}}}},
		{Session: ss, Params: &mcp.CallToolParamsRaw{RequestState: "forged-tunnel-state", InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}}}},
	} {
		audit.reset()
		_, out, err := r.createTunnel(t.Context(), forged, input)
		if err == nil || out.Tunnel.TunnelID != "" {
			t.Fatalf("tunnel idempotency bypassed round-trip params %+v: out=%+v err=%v", forged.Params, out, err)
		}
		if entries := audit.snapshot(); len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
			t.Fatalf("tunnel forged retry audit = %+v, want denied", entries)
		}
	}

	// Normal idempotent retry without round-trip params still returns the existing tunnel.
	_, out, err := r.createTunnel(t.Context(), &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, input)
	if err != nil || out.Tunnel.TunnelID != created.TunnelID {
		t.Fatalf("normal idempotent tunnel retry failed: out=%+v err=%v", out, err)
	}
}

func testP7W17aAB17L1TransferIdempotency(t *testing.T) {
	r, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler())
	audit := &w17aFailAuditSink{}
	r.guardrail.SetAuditWriter(audit)
	ss := connectW17aModernServerSession(t)

	payload := []byte("idempotent-body")
	input := uploadBoundaryInput("idem-transfer-1", "/idem-file", payload)
	prepared := prepareTransferTest(t, client, "xops_prepare_upload", input)
	originalAuth := prepared.Headers["Authorization"]

	// 1. Ready state: retry carrying forged RequestState / InputResponses MUST fail closed
	// and MUST NOT return cached transfer or rotate its credential!
	for _, forged := range []*mcp.CallToolRequest{
		{Session: ss, Params: &mcp.CallToolParamsRaw{RequestState: "forged-transfer-state"}},
		{Session: ss, Params: &mcp.CallToolParamsRaw{InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "decline"}}}},
		{Session: ss, Params: &mcp.CallToolParamsRaw{RequestState: "forged-transfer-state", InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}}}},
	} {
		audit.reset()
		_, out, err := r.prepareUpload(t.Context(), forged, input)
		if err == nil || out.Task.ID != "" || len(out.Headers) != 0 {
			t.Fatalf("ready transfer idempotency bypassed round-trip params %+v: out=%+v err=%v", forged.Params, out, err)
		}
		if entries := audit.snapshot(); len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
			t.Fatalf("ready transfer forged retry audit = %+v, want denied", entries)
		}
	}

	// Verify the original token was NOT rotated by the rejected calls: PUT with originalAuth succeeds.
	resp, body := transferTestRequest(t, server, prepared.Method, prepared.URL, map[string]string{
		"Authorization": originalAuth,
		"Content-Type":  "application/octet-stream",
	}, bytes.NewReader(payload))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("original token was invalidated by rejected forged retries: HTTP %d %s", resp.StatusCode, body)
	}

	// 2. Completed (terminal) state: retry carrying forged RequestState / InputResponses
	// MUST ALSO fail closed with denied audit (not return cached Completed status)!
	audit.reset()
	forged := &mcp.CallToolRequest{
		Session: ss,
		Params: &mcp.CallToolParamsRaw{
			RequestState:   "forged-terminal-state",
			InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "decline"}},
		},
	}
	if _, out, err := r.prepareUpload(t.Context(), forged, input); err == nil || out.Task.ID != "" {
		t.Fatalf("completed transfer idempotency bypassed round-trip params: out=%+v err=%v", out, err)
	}
	if entries := audit.snapshot(); len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
		t.Fatalf("completed transfer forged retry audit = %+v, want denied", entries)
	}

	// Normal idempotent retry without round-trip params still returns Completed status.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, out, err := r.prepareUpload(ctx, &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, input)
	if err != nil || out.Task.ID != prepared.Task.ID || out.Task.State != transfer.Completed {
		t.Fatalf("normal completed transfer idempotency failed: out=%+v err=%v", out, err)
	}
}
