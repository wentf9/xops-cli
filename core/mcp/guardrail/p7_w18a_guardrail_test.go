package guardrail

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/policy"
)

func TestP7W18a_AB18M1_RecursiveProtectedPathsDescendantMatching(t *testing.T) {
	p := NewPolicy(&policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  FallbackDeny,
		ProtectedPaths: []string{
			"/opt/app/secrets",
			"/home/user/.ssh",
			`C:\ProgramData\ssh`,
		},
	})

	protectedDirs := []string{
		"/opt/app",
		"/opt",
		"/home/user",
		"/var", // contains sensitivePaths entry /var/lib
		`C:\ProgramData`,
		"/C:/ProgramData",
		`C:\Windows`, // contains sensitiveWindowsPaths /windows/system32/config
		"/C:/Windows",
		"/opt/app/secrets/sub", // child of protected path
	}
	for _, dir := range protectedDirs {
		in := RiskInput{
			ToolName:       "transfer",
			Action:         "pull",
			NodeID:         "node-1",
			Paths:          []string{"/tmp/out", dir},
			RecursivePaths: []string{dir},
		}
		if got := p.Evaluate(Classify(in), in); got != NeedApproval {
			t.Errorf("RecursivePaths=[%q]: Evaluate = %s, want NeedApproval", dir, got)
		}
	}

	safeDirs := []string{
		"/opt/app2",
		"/home/user2",
		"/tmp/public",
		`C:\Users\public`,
		"/D:/ProgramData",
	}
	for _, dir := range safeDirs {
		in := RiskInput{
			ToolName:       "transfer",
			Action:         "pull",
			NodeID:         "node-1",
			Paths:          []string{"/tmp/out", dir},
			RecursivePaths: []string{dir},
		}
		if got := p.Evaluate(Classify(in), in); got != Allow {
			t.Errorf("RecursivePaths=[%q]: Evaluate = %s, want Allow", dir, got)
		}
	}

	// Verify Classify itself elevates recursive /var and C:\Windows via built-in sensitive paths.
	for _, dir := range []string{"/var", `C:\Windows`, "/C:/Windows"} {
		in := RiskInput{
			ToolName:       "transfer",
			Action:         "pull",
			NodeID:         "node-1",
			Paths:          []string{dir},
			RecursivePaths: []string{dir},
		}
		if got := Classify(in); got != Moderate {
			t.Errorf("Classify(RecursivePaths=[%q]) = %s, want Moderate", dir, got)
		}
	}
}

func connectW18aApprovalServerSession(t *testing.T, protocol string, opts *mcp.ClientOptions) *mcp.ServerSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	srv := mcp.NewServer(&mcp.Implementation{Name: "w18a-l1-srv", Version: "1"}, nil)
	ss, err := srv.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := ss.Close(); err != nil {
			t.Error(err)
		}
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "w18a-l1-cli", Version: "1"}, opts)
	cs, err := client.Connect(t.Context(), ct, &mcp.ClientSessionOptions{ProtocolVersion: protocol})
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := cs.Close(); err != nil {
			t.Error(err)
		}
	})
	return ss
}

func TestP7W18a_AB18L1_RequestToolApprovalRejectsRoundTripBeforeFallback(t *testing.T) {
	sessions := []struct {
		name string
		ss   *mcp.ServerSession
	}{
		{
			name: "legacy_2025_no_elicitation",
			ss:   connectW18aApprovalServerSession(t, "2025-11-25", nil),
		},
		{
			name: "legacy_2025_with_elicitation_accept",
			ss: connectW18aApprovalServerSession(t, "2025-11-25", &mcp.ClientOptions{
				ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
					return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
				},
			}),
		},
		{
			name: "modern_2026_no_elicitation",
			ss:   connectW18aApprovalServerSession(t, "2026-07-28", nil),
		},
	}

	fallbacks := []string{FallbackAllow, FallbackDowngrade}

	for _, sess := range sessions {
		for _, fallback := range fallbacks {
			t.Run(sess.name+"/"+fallback, func(t *testing.T) {
				cfg := &policy.Config{
					ApprovalThreshold: "moderate",
					NoElicitFallback:  fallback,
				}
				g := New(cfg)
				audit := &fakeAuditWriter{}
				g.SetAuditWriter(audit)
				ctx := WithPolicy(t.Context(), *cfg, "w18a-l1-binding")
				ri := RiskInput{ToolName: "file", Action: "write", NodeID: "node-1", Paths: []string{"/tmp/x"}}
				input := dummyInput{Command: "write"}

				var executed atomic.Int32
				wrapped := WithGuardrail(g, "file", func(dummyInput) RiskInput { return ri },
					func(context.Context, *mcp.CallToolRequest, dummyInput) (*mcp.CallToolResult, dummyOutput, error) {
						executed.Add(1)
						return nil, dummyOutput{Response: "ok"}, nil
					})

				roundTripReqs := []*mcp.CallToolRequest{
					{
						Session: sess.ss,
						Params:  &mcp.CallToolParamsRaw{RequestState: "forged-state"},
					},
					{
						Session: sess.ss,
						Params: &mcp.CallToolParamsRaw{
							InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "decline"}},
						},
					},
					{
						Session: sess.ss,
						Params: &mcp.CallToolParamsRaw{
							RequestState:   "forged-state",
							InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}},
						},
					},
				}

				for _, req := range roundTripReqs {
					// WithGuardrail (NeedApproval) MUST reject.
					if _, _, err := wrapped(ctx, req, input); err == nil {
						t.Fatalf("WithGuardrail allowed round-trip params %+v under NeedApproval", req.Params)
					}
					// Authorize (NeedApproval) MUST reject.
					if opID, pending, err := g.Authorize(ctx, req, ri, input); err == nil || opID != "" || pending != nil {
						t.Fatalf("Authorize allowed round-trip params %+v under NeedApproval: op=%q pending=%+v", req.Params, opID, pending)
					}
				}
				if executed.Load() != 0 {
					t.Fatalf("handler executed %d times despite forged/declined round-trip params", executed.Load())
				}

				// Sanity check: ordinary request WITHOUT round-trip params still obeys fallback on non-eliciting client.
				plainReq := &mcp.CallToolRequest{Session: sess.ss, Params: &mcp.CallToolParamsRaw{}}
				if _, _, err := wrapped(ctx, plainReq, input); err != nil {
					t.Fatalf("plain request without round-trip params failed unexpectedly: %v", err)
				}
				if executed.Load() != 1 {
					t.Fatalf("plain request executed %d times, want 1", executed.Load())
				}
			})
		}
	}
}

func TestP7W18a_AB18M1_HasActivePendingApproval(t *testing.T) {
	acceptOpts := &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
		},
	}
	ss1 := connectW18aApprovalServerSession(t, "2026-07-28", acceptOpts)
	ss2 := connectW18aApprovalServerSession(t, "2026-07-28", acceptOpts)
	cfg := &policy.Config{ApprovalThreshold: "moderate", NoElicitFallback: FallbackDeny}
	g := New(cfg)
	ctx := WithPolicy(t.Context(), *cfg, "w18a-active-pending")
	ri := RiskInput{ToolName: "file", Action: "write", NodeID: "node-1", Paths: []string{"/tmp/x"}}
	_, pending, err := g.Authorize(ctx, &mcp.CallToolRequest{Session: ss1, Params: &mcp.CallToolParamsRaw{}}, ri, dummyInput{Command: "write"})
	if err != nil || pending == nil || pending.RequestState == "" {
		t.Fatalf("mint pending challenge: pending=%+v err=%v", pending, err)
	}
	if !g.HasActivePendingApproval(&mcp.CallToolRequest{Session: ss1, Params: &mcp.CallToolParamsRaw{RequestState: pending.RequestState}}) {
		t.Fatal("HasActivePendingApproval(live own session) = false, want true")
	}
	if g.HasActivePendingApproval(&mcp.CallToolRequest{Session: ss2, Params: &mcp.CallToolParamsRaw{RequestState: pending.RequestState}}) {
		t.Fatal("HasActivePendingApproval(cross session) = true, want false")
	}
	if g.HasActivePendingApproval(&mcp.CallToolRequest{Session: ss1, Params: &mcp.CallToolParamsRaw{RequestState: "forged"}}) {
		t.Fatal("HasActivePendingApproval(forged) = true, want false")
	}
	if g.HasActivePendingApproval(&mcp.CallToolRequest{Session: ss1, Params: &mcp.CallToolParamsRaw{}}) {
		t.Fatal("HasActivePendingApproval(empty) = true, want false")
	}

	g.approvalMu.Lock()
	entry := g.pendingApprovals[pending.RequestState]
	entry.expires = time.Now().Add(-time.Second)
	g.pendingApprovals[pending.RequestState] = entry
	g.approvalMu.Unlock()
	if g.HasActivePendingApproval(&mcp.CallToolRequest{Session: ss1, Params: &mcp.CallToolParamsRaw{RequestState: pending.RequestState}}) {
		t.Fatal("HasActivePendingApproval(expired) = true, want false")
	}
}
