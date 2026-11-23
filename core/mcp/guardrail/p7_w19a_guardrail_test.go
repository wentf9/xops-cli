package guardrail

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/policy"
)

type w19aEnvelopeFixture struct {
	g      *Guardrail
	audit  *fakeAuditWriter
	cfg    *policy.Config
	ss1    *mcp.ServerSession
	ss2    *mcp.ServerSession
	envA   w19aTestEnvelope
	lexCtx context.Context
	effCtx context.Context
	lexRI  RiskInput
	effRI  RiskInput
}

type w19aTestEnvelope struct {
	Scope string
	Snap  string
	Path  string
}

func newW19aEnvelopeFixture(t *testing.T) *w19aEnvelopeFixture {
	t.Helper()
	acceptOpts := &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
		},
	}
	cfg := &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  FallbackDeny,
		ProtectedPaths:    []string{"/etc"},
	}
	g := New(cfg)
	audit := &fakeAuditWriter{}
	g.SetAuditWriter(audit)
	envA := w19aTestEnvelope{Scope: "s1", Snap: "snap-1", Path: "/tmp/a.txt"}
	return &w19aEnvelopeFixture{
		g:      g,
		audit:  audit,
		cfg:    cfg,
		ss1:    connectW18aApprovalServerSession(t, "2026-07-28", acceptOpts),
		ss2:    connectW18aApprovalServerSession(t, "2026-07-28", acceptOpts),
		envA:   envA,
		lexCtx: WithRequestEnvelope(WithPolicy(t.Context(), *cfg, "bind-lex-a"), envA),
		effCtx: WithRequestEnvelope(WithPolicy(t.Context(), *cfg, "bind-eff-a"), envA),
		lexRI:  RiskInput{ToolName: "file", Action: "write", NodeID: "node-a", Paths: []string{"/tmp/a.txt"}},
		effRI:  RiskInput{ToolName: "file", Action: "write", NodeID: "node-a", Paths: []string{"/tmp/a.txt", "/private/tmp/a.txt"}},
	}
}

func TestP7W19a_AB19M1_RequestEnvelopeBindingAndLifecycle(t *testing.T) {
	t.Run("envelope_matching_and_mismatches", testP7W19aEnvelopeMatchingAndMismatches)
	t.Run("invalidation_and_decline_consumption", testP7W19aInvalidationAndDecline)
	t.Run("retire_and_consume_for_scope", testP7W19aRetireAndConsumeForScope)
}

func testP7W19aEnvelopeMatchingAndMismatches(t *testing.T) {
	f := newW19aEnvelopeFixture(t)
	_, pending, err := f.g.Authorize(f.effCtx, &mcp.CallToolRequest{Session: f.ss1, Params: &mcp.CallToolParamsRaw{}}, f.effRI, "bound-eff")
	if err != nil || pending == nil || pending.RequestState == "" {
		t.Fatalf("mint canonical challenge: pending=%+v err=%v", pending, err)
	}
	tokenReq := &mcp.CallToolRequest{
		Session: f.ss1,
		Params:  &mcp.CallToolParamsRaw{RequestState: pending.RequestState},
	}

	if ok, err := f.g.HasActivePendingApprovalForEnvelope(f.lexCtx, tokenReq, f.lexRI, "bound-lex"); err != nil || !ok {
		t.Fatalf("HasActivePendingApprovalForEnvelope(matching envelope) = (%v, %v), want (true, nil)", ok, err)
	}

	mismatches := []struct {
		name string
		ctx  context.Context
		ri   RiskInput
		in   any
	}{
		{"cross_tool", f.lexCtx, RiskInput{ToolName: "transfer", Action: "write", NodeID: "node-a", Paths: []string{"/tmp/a.txt"}}, "bound-lex"},
		{"cross_action", f.lexCtx, RiskInput{ToolName: "file", Action: "read", NodeID: "node-a", Paths: []string{"/tmp/a.txt"}}, "bound-lex"},
		{"cross_node", f.lexCtx, RiskInput{ToolName: "file", Action: "write", NodeID: "restricted-b", Paths: []string{"/tmp/a.txt"}}, "bound-lex"},
		{"cross_path_envelope", WithRequestEnvelope(WithPolicy(t.Context(), *f.cfg, "bind-lex-b"), w19aTestEnvelope{Scope: "s1", Snap: "snap-1", Path: "/etc/shadow"}), f.lexRI, "bound-lex"},
		{"cross_policy", WithRequestEnvelope(WithPolicy(t.Context(), policy.Config{ApprovalThreshold: "dangerous", NoElicitFallback: FallbackDeny}, "bind-lex-a"), f.envA), f.lexRI, "bound-lex"},
		{"no_envelope_context", WithPolicy(t.Context(), *f.cfg, "bind-lex-a"), f.lexRI, "bound-lex"},
	}
	for _, tc := range mismatches {
		ok, err := f.g.HasActivePendingApprovalForEnvelope(tc.ctx, tokenReq, tc.ri, tc.in)
		if err != nil || ok {
			t.Errorf("%s: HasActivePendingApprovalForEnvelope = (%v, %v), want (false, nil)", tc.name, ok, err)
		}
	}
}

func testP7W19aInvalidationAndDecline(t *testing.T) {
	f := newW19aEnvelopeFixture(t)
	_, pending, err := f.g.Authorize(f.effCtx, &mcp.CallToolRequest{Session: f.ss1, Params: &mcp.CallToolParamsRaw{}}, f.effRI, "bound-eff")
	if err != nil || pending == nil || pending.RequestState == "" {
		t.Fatalf("mint canonical challenge: pending=%+v err=%v", pending, err)
	}
	tokenReq := &mcp.CallToolRequest{Session: f.ss1, Params: &mcp.CallToolParamsRaw{RequestState: pending.RequestState}}

	// InvalidatePendingApproval from ss2 does NOT delete ss1's token.
	otherReq := &mcp.CallToolRequest{Session: f.ss2, Params: &mcp.CallToolParamsRaw{RequestState: pending.RequestState}}
	_ = f.g.InvalidatePendingApproval(f.lexCtx, otherReq, f.lexRI, "error", errors.New("other session error"))
	if ok, err := f.g.HasActivePendingApprovalForEnvelope(f.lexCtx, tokenReq, f.lexRI, "bound-lex"); err != nil || !ok {
		t.Fatalf("InvalidatePendingApproval from ss2 deleted ss1 token: ok=%v err=%v", ok, err)
	}

	// InvalidatePendingApproval from owning session deletes token and audits "error" with canonical paths.
	f.audit.entries = nil
	cause := errors.New("sftp inspection failed")
	if err := f.g.InvalidatePendingApproval(f.lexCtx, tokenReq, f.lexRI, "error", cause); !errors.Is(err, cause) {
		t.Fatalf("InvalidatePendingApproval err = %v, want %v", err, cause)
	}
	if ok, err := f.g.HasActivePendingApprovalForEnvelope(f.lexCtx, tokenReq, f.lexRI, "bound-lex"); err != nil || ok {
		t.Fatalf("token remained active after InvalidatePendingApproval: ok=%v err=%v", ok, err)
	}
	if len(f.audit.entries) != 1 || f.audit.entries[0].Outcome != "error" || !slices.Contains(f.audit.entries[0].Paths, "/private/tmp/a.txt") {
		t.Fatalf("invalidation audit = %+v, want error entry with /private/tmp/a.txt", f.audit.entries)
	}

	// ConsumeDeclinedPendingApproval consumes token and audits "denied" with canonical paths.
	_, pendingDecline, err := f.g.Authorize(f.effCtx, &mcp.CallToolRequest{Session: f.ss1, Params: &mcp.CallToolParamsRaw{}}, f.effRI, "bound-eff")
	if err != nil || pendingDecline == nil {
		t.Fatalf("mint decline challenge: %v", err)
	}
	f.audit.entries = nil
	declineReq := &mcp.CallToolRequest{
		Session: f.ss1,
		Params: &mcp.CallToolParamsRaw{
			RequestState:   pendingDecline.RequestState,
			InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "decline"}},
		},
	}
	if f.g.IsApprovedRoundTripResponse(declineReq) {
		t.Fatal("IsApprovedRoundTripResponse(decline) = true, want false")
	}
	if err := f.g.ConsumeDeclinedPendingApproval(f.lexCtx, declineReq, f.lexRI, "bound-lex"); err == nil {
		t.Fatal("ConsumeDeclinedPendingApproval returned nil error")
	}
	if ok, _ := f.g.HasActivePendingApprovalForEnvelope(f.lexCtx, declineReq, f.lexRI, "bound-lex"); ok {
		t.Fatal("declined token was not consumed")
	}
	if len(f.audit.entries) != 1 || f.audit.entries[0].Outcome != "denied" || !slices.Contains(f.audit.entries[0].Paths, "/private/tmp/a.txt") {
		t.Fatalf("decline audit = %+v, want denied with /private/tmp/a.txt", f.audit.entries)
	}
}

func testP7W19aRetireAndConsumeForScope(t *testing.T) {
	f := newW19aEnvelopeFixture(t)
	_, pendingLex, err := f.g.Authorize(f.lexCtx, &mcp.CallToolRequest{Session: f.ss1, Params: &mcp.CallToolParamsRaw{}}, f.lexRI, "bound-lex")
	if err != nil || pendingLex == nil {
		t.Fatalf("mint lexical challenge: %v", err)
	}
	f.audit.entries = nil
	lexAcceptReq := &mcp.CallToolRequest{
		Session: f.ss1,
		Params: &mcp.CallToolParamsRaw{
			RequestState:   pendingLex.RequestState,
			InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}},
		},
	}
	if !f.g.IsApprovedRoundTripResponse(lexAcceptReq) {
		t.Fatal("IsApprovedRoundTripResponse(accept) = false, want true")
	}
	if err := f.g.RetirePendingApproval(f.lexCtx, lexAcceptReq, f.lexRI, "bound-lex"); err != nil {
		t.Fatalf("first RetirePendingApproval failed: %v", err)
	}
	if len(f.audit.entries) != 0 {
		t.Fatalf("RetirePendingApproval wrote unexpected audit entries: %+v", f.audit.entries)
	}
	if err := f.g.RetirePendingApproval(f.lexCtx, lexAcceptReq, f.lexRI, "bound-lex"); err == nil {
		t.Fatal("second RetirePendingApproval succeeded on already-retired token")
	}

	_, pendingScope, err := f.g.Authorize(f.lexCtx, &mcp.CallToolRequest{Session: f.ss1, Params: &mcp.CallToolParamsRaw{}}, f.lexRI, "bound-lex")
	if err != nil || pendingScope == nil {
		t.Fatalf("mint scope challenge: %v", err)
	}
	f.audit.entries = nil
	scopeAcceptReq := &mcp.CallToolRequest{
		Session: f.ss1,
		Params: &mcp.CallToolParamsRaw{
			RequestState:   pendingScope.RequestState,
			InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}},
		},
	}
	opID, err := f.g.ConsumePendingApprovalForScope(f.lexCtx, scopeAcceptReq, f.lexRI, "bound-lex", f.effCtx, f.effRI)
	if err != nil || opID == "" {
		t.Fatalf("ConsumePendingApprovalForScope = (%q, %v), want valid opID", opID, err)
	}
	if len(f.audit.entries) != 1 || f.audit.entries[0].OperationID != opID || f.audit.entries[0].Outcome != "authorized" || f.audit.entries[0].Binding != "bind-eff-a" || !slices.Contains(f.audit.entries[0].Paths, "/private/tmp/a.txt") {
		t.Fatalf("ConsumePendingApprovalForScope audit = %+v", f.audit.entries)
	}
}

func TestP7W19a_AB19L1_HasProtectedPath(t *testing.T) {
	cfg := &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  FallbackDeny,
		ProtectedPaths:    []string{"/opt/secrets"},
	}
	g := New(cfg)
	ctx := WithPolicy(t.Context(), *cfg, "bind")

	var nilG *Guardrail
	if !nilG.HasProtectedPath(ctx, RiskInput{Paths: []string{"/tmp/a.txt"}}) {
		t.Fatal("nil Guardrail.HasProtectedPath should fail closed (true)")
	}
	disabledCtx := WithPolicy(t.Context(), policy.Config{Disabled: true}, "bind")
	if g.HasProtectedPath(disabledCtx, RiskInput{Paths: []string{"/etc/shadow"}}) {
		t.Fatal("disabled policy should report HasProtectedPath = false")
	}

	protectedCases := []RiskInput{
		{Paths: []string{"/etc/shadow"}},
		{Paths: []string{"/opt/secrets/token"}},
		{Paths: []string{"/C:/Windows/System32/config/SAM"}},
		{Paths: []string{"/opt"}, RecursivePaths: []string{"/opt"}},
	}
	for _, ri := range protectedCases {
		if !g.HasProtectedPath(ctx, ri) {
			t.Errorf("HasProtectedPath(%+v) = false, want true", ri)
		}
	}

	benignCases := []RiskInput{
		{Paths: []string{"/tmp/a.txt"}},
		{Paths: []string{"/tmp/a.txt", "/private/tmp/a.txt"}},
		{Paths: []string{"/home/user/doc.txt", "/tmp/doc.txt"}},
	}
	for _, ri := range benignCases {
		if g.HasProtectedPath(ctx, ri) {
			t.Errorf("HasProtectedPath(%+v) = true, want false", ri)
		}
	}
}
