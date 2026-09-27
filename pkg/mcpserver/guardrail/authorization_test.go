package guardrail

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"testing"
)

func TestDeferredAuthorizationDoesNotReportExecution(t *testing.T) {
	g := New(defaultTestConfig())
	audit := &fakeAuditWriter{}
	g.SetAuditWriter(audit)
	risk := RiskInput{ToolName: "xops_prepare_upload", NodeID: "fixture", Paths: []string{"/tmp/file"}, Details: "size=3; overwrite=false"}
	op, pending, err := g.Authorize(t.Context(), &mcp.CallToolRequest{}, risk, struct{ Size int }{3})
	if err != nil || pending != nil || op == "" {
		t.Fatalf("authorization: op=%q pending=%+v err=%v", op, pending, err)
	}
	if len(audit.entries) != 1 || audit.entries[0].Outcome != "authorized" {
		t.Fatalf("creation marked as execution: %+v", audit.entries)
	}
	if err := g.RecordAuthorized(op, risk, "started", nil); err != nil {
		t.Fatal(err)
	}
	if err := g.RecordAuthorized(op, risk, "completed", nil); err != nil {
		t.Fatal(err)
	}
	for _, entry := range audit.entries {
		if entry.OperationID != op || entry.Details != risk.Details {
			t.Fatalf("deferred audit lost identity/details: %+v", entry)
		}
	}
}

func TestDeferredAuthorizationAuditFailureIssuesNoGrant(t *testing.T) {
	g := New(defaultTestConfig())
	g.SetAuditWriter(&fakeAuditWriter{failOn: 1})
	op, pending, err := g.Authorize(t.Context(), nil, RiskInput{ToolName: "xops_prepare_download"}, struct{}{})
	if err == nil || op != "" || pending != nil {
		t.Fatalf("grant survived audit failure: %q %+v %v", op, pending, err)
	}
}
