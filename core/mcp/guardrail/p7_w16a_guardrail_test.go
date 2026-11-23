package guardrail

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestP7W16a_AB16H1_OSIndependentGlobBlockedPatterns(t *testing.T) {
	t.Run("wildcard_lockdown_blocks_separators_and_preflight_probe", assertAB16H1WildcardLockdown)
	t.Run("common_blocked_patterns_match_across_separators", assertAB16H1CommonBlockedPatterns)
	t.Run("literal_backslash_matches_identically_on_all_oses", assertAB16H1LiteralBackslash)
	t.Run("gui_text_with_separators_blocked", assertAB16H1GUITextBlocked)
	t.Run("glob_syntax_edge_cases_and_linear_backtracking", assertAB16H1GlobSyntaxAndBacktracking)
}

func assertAB16H1WildcardLockdown(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.BlockedPatterns = []string{"*"}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig([\"*\"]): %v", err)
	}
	p := NewPolicy(cfg)
	g := New(cfg)
	ctx := WithPolicy(t.Context(), *cfg, "binding-lockdown")

	for _, cmd := range []string{
		"ls /tmp",
		`type C:\secret.txt`,
		"echo hello\nls /var/log",
		"cat /etc/中文/file.txt",
	} {
		in := RiskInput{
			ToolName: "terminal",
			Action:   "once",
			NodeID:   "node-1",
			Command:  cmd,
			Dialect:  string(ssh.LaunchUnknown),
		}
		if got := p.Evaluate(Safe, in); got != Deny {
			t.Errorf("Evaluate(command=%q) = %s, want Deny", cmd, got)
		}
		// Pre-flight ProbeExecution gate in runtime/invocation.go checks
		// g.EvaluateContext(work, preflight) == Deny before invoking ProbeExecution.
		if got := g.EvaluateContext(ctx, in); got != Deny {
			t.Errorf("EvaluateContext preflight(command=%q) = %s, want Deny", cmd, got)
		}
	}
}

func assertAB16H1CommonBlockedPatterns(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.BlockedPatterns = []string{"*dangerous*", "*.sh", "rm *"}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	p := NewPolicy(cfg)

	for _, tc := range []struct {
		cmd  string
		want Decision
	}{
		{"./run_dangerous_script.sh", Deny},
		{"/opt/bin/run_dangerous_tool --now", Deny},
		{`C:\scripts\run_dangerous.bat`, Deny},
		{"./deploy.sh", Deny},
		{"/usr/local/bin/deploy.sh", Deny},
		{"rm /tmp/foo", Deny},
		{`rm C:\temp\foo`, Deny},
		{"ls /tmp/foo", Allow},
	} {
		got := p.Evaluate(Safe, RiskInput{
			ToolName: "terminal",
			Action:   "once",
			NodeID:   "node-1",
			Command:  tc.cmd,
		})
		if got != tc.want {
			t.Errorf("Evaluate(%q) = %s, want %s", tc.cmd, got, tc.want)
		}
	}
}

func assertAB16H1LiteralBackslash(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.BlockedPatterns = []string{`C:\Windows\*`, `foo\`}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig with literal backslash: %v", err)
	}
	p := NewPolicy(cfg)

	for _, tc := range []struct {
		cmd  string
		want Decision
	}{
		{`C:\Windows\System32`, Deny},
		{`C:\Windows\System32\cmd.exe`, Deny},
		{`foo\`, Deny},
		{`C:\Users\alice`, Allow},
	} {
		if got := p.Evaluate(Safe, RiskInput{ToolName: "terminal", Command: tc.cmd}); got != tc.want {
			t.Fatalf("Evaluate(%q) = %s, want %s", tc.cmd, got, tc.want)
		}
	}
}

func assertAB16H1GUITextBlocked(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.BlockedPatterns = []string{"*.sh", "*secret*"}
	p := NewPolicy(cfg)

	for _, text := range []string{"./deploy.sh", "cat /etc/secret/key", `type C:\secret\token`} {
		got := p.Evaluate(Safe, RiskInput{
			ToolName: "gui",
			Action:   "type",
			NodeID:   "desktop-1",
			Text:     text,
		})
		if got != Deny {
			t.Errorf("gui text %q = %s, want Deny", text, got)
		}
	}
}

func assertAB16H1GlobSyntaxAndBacktracking(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		input   string
		want    bool
	}{
		{"?", "/", true},
		{"?", `\`, true},
		{"?", "中", true},
		{"?", "", false},
		{"a?c", "a/c", true},
		{"a?c", `a\c`, true},
		{"[a-z]*", "hello/world", true},
		{"[^0-9]*", "/etc/passwd", true},
		{"[!0-9]*", `\Windows`, true},
		{"[!0-9]*", "5foo", false},
		{"[]a]", "]", true},
		{"[]a]", "a", true},
		{"[a-z0-9_-]*", "prod-db_01", true},
		{`[\]`, `\`, true},
		{"**a**b**", "xx/a\\yy/b\\zz", true},
	} {
		got, err := matchGuardrailGlob(tc.pattern, tc.input)
		if err != nil {
			t.Errorf("matchGuardrailGlob(%q, %q) unexpected err: %v", tc.pattern, tc.input, err)
		}
		if got != tc.want {
			t.Errorf("matchGuardrailGlob(%q, %q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
		}
	}

	for _, bad := range []string{"[", "[]", "[^]", "[!]", "[a-", "[z-a]", "\xff*", "[\xff]"} {
		if err := validateGuardrailGlob(bad); err == nil {
			t.Errorf("validateGuardrailGlob(%q) = nil, want error", bad)
		}
		if matched, err := matchGuardrailGlob(bad, "anything"); err == nil || matched {
			t.Errorf("matchGuardrailGlob(%q, _) = (%v, %v), want (false, err)", bad, matched, err)
		}
	}

	start := time.Now()
	matched, err := matchGuardrailGlob("*a*a*a*a*a*a*a*a*b", strings.Repeat("a", 5000))
	if err != nil || matched {
		t.Fatalf("pathological match = (%v, %v), want (false, nil)", matched, err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("glob matching took %v (possible backtracking blowup)", elapsed)
	}
}

func TestP7W16a_AB16M1_DeterministicStrictestNodeOverrides(t *testing.T) {
	t.Run("overlapping_overrides_strictest_wins_200_iterations", assertAB16M1OverlappingOverrides)
	t.Run("malformed_override_always_fail_closed_regardless_of_map_order", assertAB16M1MalformedOverrideFailClosed)
	t.Run("separator_in_node_id_matches_glob", assertAB16M1SeparatorNodeID)
}

func assertAB16M1OverlappingOverrides(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.ApprovalThreshold = "dangerous"
	cfg.NodeOverrides = map[string]policy.NodeConfig{
		"*":        {ApprovalThreshold: "dangerous"},
		"prod-*":   {ApprovalThreshold: "moderate"},
		"prod-db":  {ApprovalThreshold: "safe"},
		"prod-db*": {ApprovalThreshold: "dangerous"},
	}
	p := NewPolicy(cfg)

	for i := range 200 {
		if got := p.Evaluate(Safe, RiskInput{ToolName: "nodes", NodeID: "prod-db"}); got != NeedApproval {
			t.Fatalf("iter %d: prod-db Safe = %s, want NeedApproval (strictest=safe)", i, got)
		}
		if got := p.Evaluate(Safe, RiskInput{ToolName: "nodes", NodeID: "prod-web-1"}); got != Allow {
			t.Fatalf("iter %d: prod-web-1 Safe = %s, want Allow (strictest=moderate)", i, got)
		}
		if got := p.Evaluate(Moderate, RiskInput{ToolName: "file", Action: "write", NodeID: "prod-web-1"}); got != NeedApproval {
			t.Fatalf("iter %d: prod-web-1 Moderate = %s, want NeedApproval (strictest=moderate)", i, got)
		}
		if got := p.Evaluate(Moderate, RiskInput{ToolName: "file", Action: "write", NodeID: "dev-web-1"}); got != Allow {
			t.Fatalf("iter %d: dev-web-1 Moderate = %s, want Allow (only *=dangerous matches)", i, got)
		}
		if got := p.Evaluate(Dangerous, RiskInput{ToolName: "terminal", NodeID: "dev-web-1"}); got != NeedApproval {
			t.Fatalf("iter %d: dev-web-1 Dangerous = %s, want NeedApproval", i, got)
		}
	}
}

func assertAB16M1MalformedOverrideFailClosed(t *testing.T) {
	for _, badPattern := range []string{"[", "[z-a]", "\xff"} {
		cfg := defaultTestConfig()
		cfg.ApprovalThreshold = "dangerous"
		cfg.NodeOverrides = map[string]policy.NodeConfig{
			"*":        {ApprovalThreshold: "dangerous"},
			"prod-db":  {ApprovalThreshold: "dangerous"},
			badPattern: {ApprovalThreshold: "dangerous"},
		}
		p := NewPolicy(cfg)
		for i := range 200 {
			if got := p.Evaluate(Safe, RiskInput{ToolName: "nodes", NodeID: "prod-db"}); got != NeedApproval {
				t.Fatalf("badPattern=%q iter=%d: got %s, want NeedApproval (fail-closed Safe)", badPattern, i, got)
			}
		}
	}
}

func assertAB16M1SeparatorNodeID(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.ApprovalThreshold = "dangerous"
	cfg.NodeOverrides = map[string]policy.NodeConfig{
		"prod/*": {ApprovalThreshold: "safe"},
	}
	p := NewPolicy(cfg)
	if got := p.Evaluate(Safe, RiskInput{ToolName: "nodes", NodeID: "prod/eu/db-1"}); got != NeedApproval {
		t.Fatalf("prod/eu/db-1 = %s, want NeedApproval", got)
	}
}

func startModernApprovalServerSession(t *testing.T) *mcp.ServerSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	server := mcp.NewServer(&mcp.Implementation{Name: "w16a-server", Version: "1"}, nil)
	ss, err := server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := ss.Close(); err != nil {
			t.Error(err)
		}
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "w16a-client", Version: "1"}, &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "decline"}, nil
		},
	})
	cs, err := client.Connect(t.Context(), ct, nil)
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

func TestP7W16a_AB16M2_ApprovalRoundTripValidatedUnderAllow(t *testing.T) {
	t.Run("with_guardrail_direct_decline_cancel_and_forged_rejected", assertAB16M2WithGuardrailDirectDeclineAndForged)
	t.Run("with_guardrail_direct_accept_and_replay_rejected", assertAB16M2WithGuardrailDirectAcceptAndReplay)
	t.Run("with_guardrail_mcp_wire_roundtrip_relaxed_to_allow_decline", assertAB16M2WithGuardrailWireDecline)
	t.Run("authorize_roundtrip_relaxed_to_allow_decline", assertAB16M2AuthorizeDecline)
	t.Run("authorize_roundtrip_relaxed_to_allow_accept_replay_and_forged", assertAB16M2AuthorizeAcceptReplayAndForged)
}

func newW16aGuardedFileHandler(g *Guardrail, executed *atomic.Int32) mcp.ToolHandlerFor[dummyInput, dummyOutput] {
	return WithGuardrail(g, "file", func(in dummyInput) RiskInput {
		return RiskInput{ToolName: "file", Action: "write", NodeID: "node-1", Command: in.Command, Paths: []string{"/tmp/x"}}
	}, func(context.Context, *mcp.CallToolRequest, dummyInput) (*mcp.CallToolResult, dummyOutput, error) {
		executed.Add(1)
		return nil, dummyOutput{Response: "ok"}, nil
	})
}

func assertAB16M2WithGuardrailDirectDeclineAndForged(t *testing.T) {
	ss := startModernApprovalServerSession(t)
	strictCfg := &policy.Config{ApprovalThreshold: "moderate", NoElicitFallback: FallbackDeny}
	relaxedCfg := &policy.Config{ApprovalThreshold: "dangerous", NoElicitFallback: FallbackDeny}

	g := New(strictCfg)
	audit := &fakeAuditWriter{}
	g.SetAuditWriter(audit)

	var executed atomic.Int32
	wrapped := newW16aGuardedFileHandler(g, &executed)

	in := dummyInput{Command: "write-file"}
	strictCtx := WithPolicy(t.Context(), *strictCfg, "binding-v1")
	relaxedSameBinding := WithPolicy(t.Context(), *relaxedCfg, "binding-v1")
	relaxedNewBinding := WithPolicy(t.Context(), *relaxedCfg, "binding-v2")

	for _, tc := range []struct {
		name      string
		round2Ctx context.Context
		resp      *mcp.ElicitResult
	}{
		{"decline_same_binding", relaxedSameBinding, &mcp.ElicitResult{Action: "decline"}},
		{"decline_changed_binding", relaxedNewBinding, &mcp.ElicitResult{Action: "decline"}},
		{"cancel_same_binding", relaxedSameBinding, &mcp.ElicitResult{Action: "cancel"}},
		{"accept_false_same_binding", relaxedSameBinding, &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": false}}},
	} {
		pending, _, err := wrapped(strictCtx, &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, in)
		if err != nil || pending == nil || pending.RequestState == "" {
			t.Fatalf("%s round 1: pending=%+v err=%v", tc.name, pending, err)
		}
		req2 := &mcp.CallToolRequest{
			Session: ss,
			Params: &mcp.CallToolParamsRaw{
				RequestState:   pending.RequestState,
				InputResponses: mcp.InputResponseMap{"approval": tc.resp},
			},
		}
		if _, _, err := wrapped(tc.round2Ctx, req2, in); err == nil {
			t.Fatalf("%s: expected error under Allow, got nil", tc.name)
		}
		lastAudit := audit.entries[len(audit.entries)-1]
		if lastAudit.Outcome != "denied" || lastAudit.Error == "" {
			t.Fatalf("%s: audit=%+v, want denied with error", tc.name, lastAudit)
		}
	}

	for _, forged := range []*mcp.CallToolRequest{
		{Session: ss, Params: &mcp.CallToolParamsRaw{RequestState: "forged-token"}},
		{Session: ss, Params: &mcp.CallToolParamsRaw{InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}}}},
		{Session: nil, Params: &mcp.CallToolParamsRaw{RequestState: "forged-nil-session"}},
	} {
		if _, _, err := wrapped(relaxedSameBinding, forged, in); err == nil {
			t.Fatalf("forged round-trip params %+v succeeded under Allow", forged.Params)
		}
	}
	if executed.Load() != 0 {
		t.Fatalf("handler executed %d times despite rejected/forged approvals, want 0", executed.Load())
	}
}

func assertAB16M2WithGuardrailDirectAcceptAndReplay(t *testing.T) {
	ss := startModernApprovalServerSession(t)
	strictCfg := &policy.Config{ApprovalThreshold: "moderate", NoElicitFallback: FallbackDeny}
	relaxedCfg := &policy.Config{ApprovalThreshold: "dangerous", NoElicitFallback: FallbackDeny}

	g := New(strictCfg)
	audit := &fakeAuditWriter{}
	g.SetAuditWriter(audit)

	var executed atomic.Int32
	wrapped := newW16aGuardedFileHandler(g, &executed)

	in := dummyInput{Command: "write-file"}
	strictCtx := WithPolicy(t.Context(), *strictCfg, "binding-v1")
	relaxedSameBinding := WithPolicy(t.Context(), *relaxedCfg, "binding-v1")

	pending, _, err := wrapped(strictCtx, &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, in)
	if err != nil || pending == nil || pending.RequestState == "" {
		t.Fatalf("round 1: pending=%+v err=%v", pending, err)
	}
	reqAccept := &mcp.CallToolRequest{
		Session: ss,
		Params: &mcp.CallToolParamsRaw{
			RequestState:   pending.RequestState,
			InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}},
		},
	}
	if _, out, err := wrapped(relaxedSameBinding, reqAccept, in); err != nil || out.Response != "ok" {
		t.Fatalf("valid accept under Allow failed: out=%+v err=%v", out, err)
	}
	if executed.Load() != 1 {
		t.Fatalf("handler executed %d times, want 1", executed.Load())
	}
	if got := audit.entries[len(audit.entries)-1].Decision; got != "approved" {
		t.Fatalf("approved round-trip audit decision = %q, want approved", got)
	}
	if _, _, err := wrapped(relaxedSameBinding, reqAccept, in); err == nil {
		t.Fatal("replayed RequestState succeeded under Allow")
	}
	if executed.Load() != 1 {
		t.Fatalf("handler executed %d times after replay, want 1", executed.Load())
	}
}

func assertAB16M2WithGuardrailWireDecline(t *testing.T) {
	ct, st := mcp.NewInMemoryTransports()
	g := New(&policy.Config{ApprovalThreshold: "moderate", NoElicitFallback: FallbackDeny})
	audit := &fakeAuditWriter{}
	g.SetAuditWriter(audit)

	var calls, executed atomic.Int32
	g.evaluateOverride = func(context.Context, RiskInput) Decision {
		if calls.Add(1) == 1 {
			return NeedApproval
		}
		// Simulate policy relaxing to Allow between Round 1 and Round 2.
		return Allow
	}

	wrapped := newW16aGuardedFileHandler(g, &executed)
	server := mcp.NewServer(&mcp.Implementation{Name: "w16a-wire", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "file"}, wrapped)
	ss, err := server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ss.Close(); err != nil {
			t.Error(err)
		}
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "w16a-wire-client", Version: "1"}, &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "decline"}, nil
		},
	})
	cs, err := client.Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cs.Close(); err != nil {
			t.Error(err)
		}
	})

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "file", Arguments: dummyInput{Command: "write"}})
	if err != nil {
		t.Fatalf("CallTool transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected tool error on user decline after policy relaxed to Allow, got %+v", res)
	}
	if executed.Load() != 0 {
		t.Fatalf("handler executed %d times despite decline, want 0", executed.Load())
	}
	if len(audit.entries) == 0 || audit.entries[len(audit.entries)-1].Outcome != "denied" {
		t.Fatalf("expected final audit outcome denied, got %+v", audit.entries)
	}
}

func assertAB16M2AuthorizeDecline(t *testing.T) {
	ss := startModernApprovalServerSession(t)
	strictCfg := &policy.Config{ApprovalThreshold: "moderate", NoElicitFallback: FallbackDeny}
	relaxedCfg := &policy.Config{ApprovalThreshold: "dangerous", NoElicitFallback: FallbackDeny}

	g := New(strictCfg)
	audit := &fakeAuditWriter{}
	g.SetAuditWriter(audit)

	ri := RiskInput{ToolName: "transfer", Action: "prepare_push", NodeID: "node-1", Paths: []string{"/tmp/upload.bin"}}
	completeIn := struct{ Size int }{Size: 42}
	strictCtx := WithPolicy(t.Context(), *strictCfg, "transfer-bind-1")
	relaxedCtx := WithPolicy(t.Context(), *relaxedCfg, "transfer-bind-1")

	opID, pending, err := g.Authorize(strictCtx, &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, ri, completeIn)
	if err != nil || opID != "" || pending == nil || pending.RequestState == "" {
		t.Fatalf("Authorize round 1 = (op=%q, pending=%+v, err=%v), want pending", opID, pending, err)
	}
	declineReq := &mcp.CallToolRequest{
		Session: ss,
		Params: &mcp.CallToolParamsRaw{
			RequestState:   pending.RequestState,
			InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "decline"}},
		},
	}
	if opID, pending, err = g.Authorize(relaxedCtx, declineReq, ri, completeIn); err == nil || opID != "" || pending != nil {
		t.Fatalf("Authorize after decline under Allow = (op=%q, pending=%+v, err=%v), want error", opID, pending, err)
	}
	if last := audit.entries[len(audit.entries)-1]; last.Outcome != "denied" || last.Error == "" {
		t.Fatalf("Authorize decline audit = %+v, want outcome=denied with error", last)
	}
}

func assertAB16M2AuthorizeAcceptReplayAndForged(t *testing.T) {
	ss := startModernApprovalServerSession(t)
	strictCfg := &policy.Config{ApprovalThreshold: "moderate", NoElicitFallback: FallbackDeny}
	relaxedCfg := &policy.Config{ApprovalThreshold: "dangerous", NoElicitFallback: FallbackDeny}

	g := New(strictCfg)
	audit := &fakeAuditWriter{}
	g.SetAuditWriter(audit)

	ri := RiskInput{ToolName: "transfer", Action: "prepare_push", NodeID: "node-1", Paths: []string{"/tmp/upload.bin"}}
	completeIn := struct{ Size int }{Size: 42}
	strictCtx := WithPolicy(t.Context(), *strictCfg, "transfer-bind-1")
	relaxedCtx := WithPolicy(t.Context(), *relaxedCfg, "transfer-bind-1")

	_, pending, err := g.Authorize(strictCtx, &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, ri, completeIn)
	if err != nil || pending == nil {
		t.Fatalf("Authorize round 1 (accept): err=%v", err)
	}
	acceptReq := &mcp.CallToolRequest{
		Session: ss,
		Params: &mcp.CallToolParamsRaw{
			RequestState:   pending.RequestState,
			InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}},
		},
	}
	opID, pending, err := g.Authorize(relaxedCtx, acceptReq, ri, completeIn)
	if err != nil || opID == "" || pending != nil {
		t.Fatalf("Authorize after valid accept under Allow = (op=%q, pending=%+v, err=%v), want opID", opID, pending, err)
	}
	if last := audit.entries[len(audit.entries)-1]; last.Decision != "approved" || last.Outcome != "authorized" {
		t.Fatalf("Authorize accept audit = %+v, want decision=approved outcome=authorized", last)
	}
	if op2, _, err := g.Authorize(relaxedCtx, acceptReq, ri, completeIn); err == nil || op2 != "" {
		t.Fatalf("Authorize allowed replayed RequestState under Allow: op=%q err=%v", op2, err)
	}
	forgedReq := &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{RequestState: "forged-auth"}}
	if op3, _, err := g.Authorize(relaxedCtx, forgedReq, ri, completeIn); err == nil || op3 != "" {
		t.Fatalf("Authorize allowed forged RequestState under Allow: op=%q err=%v", op3, err)
	}
}
