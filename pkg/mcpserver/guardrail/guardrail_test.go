package guardrail

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type dummyInput struct {
	Command string `json:"command"`
}

type dummyOutput struct {
	Response string `json:"response"`
}

func TestWithGuardrail_TwoPhaseAudit(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	cfg := defaultTestConfig()
	cfg.AuditLog = auditFile
	cfg.ApprovalThreshold = "dangerous"
	g := New(cfg)

	handlerCalled := false
	handler := func(ctx context.Context, req *mcp.CallToolRequest, input dummyInput) (*mcp.CallToolResult, dummyOutput, error) {
		handlerCalled = true
		return nil, dummyOutput{Response: "success"}, nil
	}

	wrapped := WithGuardrail(g, "xops_list_nodes", func(in dummyInput) RiskInput {
		return RiskInput{ToolName: "xops_list_nodes", Command: in.Command}
	}, handler)

	_, out, err := wrapped(context.Background(), &mcp.CallToolRequest{}, dummyInput{Command: "ls"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !handlerCalled {
		t.Fatal("expected handler to be called")
	}
	if out.Response != "success" {
		t.Fatalf("expected response 'success', got %s", out.Response)
	}

	// 检查审计日志是否正确生成两阶段记录：intent 和 executed，且包含相同的 op_id
	entries := readAuditEntries(t, auditFile)

	if len(entries) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(entries))
	}
	if entries[0].OperationID == "" {
		t.Error("expected non-empty operation ID in first entry")
	}
	if entries[0].OperationID != entries[1].OperationID {
		t.Errorf("expected matching operation IDs, got %q and %q", entries[0].OperationID, entries[1].OperationID)
	}
	if entries[0].Outcome != "intent" {
		t.Errorf("expected first entry outcome 'intent', got %q", entries[0].Outcome)
	}
	if entries[1].Outcome != "executed" {
		t.Errorf("expected second entry outcome 'executed', got %q", entries[1].Outcome)
	}
}

type fakeAuditWriter struct {
	entries []AuditEntry
	failOn  int // 1-indexed call count to fail
	calls   int
}

func (f *fakeAuditWriter) Log(entry AuditEntry) error {
	f.calls++
	if f.failOn > 0 && f.calls == f.failOn {
		return errors.New("simulated audit disk full error")
	}
	f.entries = append(f.entries, entry)
	return nil
}

func TestWithGuardrail_FirstAuditFails_BlocksExecution(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.ApprovalThreshold = "dangerous"
	g := New(cfg)

	fake := &fakeAuditWriter{failOn: 1} // 第一次 (intent) 就失败
	g.SetAuditWriter(fake)

	handlerCalled := false
	handler := func(ctx context.Context, req *mcp.CallToolRequest, input dummyInput) (*mcp.CallToolResult, dummyOutput, error) {
		handlerCalled = true
		return nil, dummyOutput{Response: "success"}, nil
	}

	wrapped := WithGuardrail(g, "xops_list_nodes", func(in dummyInput) RiskInput {
		return RiskInput{ToolName: "xops_list_nodes", Command: in.Command}
	}, handler)

	_, _, err := wrapped(context.Background(), &mcp.CallToolRequest{}, dummyInput{Command: "ls"})
	if err == nil {
		t.Fatal("expected error when intent audit fails, got nil")
	}
	if handlerCalled {
		t.Fatal("handler must NOT be called when intent audit log fails")
	}
}

func TestWithGuardrail_SecondAuditFails_PreservesResultAndWarns(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.ApprovalThreshold = "dangerous"
	g := New(cfg)

	fake := &fakeAuditWriter{failOn: 2} // 第二次 (post-audit) 失败
	g.SetAuditWriter(fake)

	handlerCalled := false
	handler := func(ctx context.Context, req *mcp.CallToolRequest, input dummyInput) (*mcp.CallToolResult, dummyOutput, error) {
		handlerCalled = true
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "business output"},
			},
		}, dummyOutput{Response: "data created"}, nil
	}

	wrapped := WithGuardrail(g, "xops_list_nodes", func(in dummyInput) RiskInput {
		return RiskInput{ToolName: "xops_list_nodes", Command: in.Command}
	}, handler)

	res, out, err := wrapped(context.Background(), &mcp.CallToolRequest{}, dummyInput{Command: "ls"})
	if err != nil {
		t.Fatalf("expected nil error to prevent MCP SDK dropping result, got %v", err)
	}
	if !handlerCalled {
		t.Fatal("handler must have been executed")
	}
	if out.Response != "data created" {
		t.Fatalf("expected output preserved 'data created', got %s", out.Response)
	}
	if res == nil || len(res.Content) != 2 {
		t.Fatalf("expected 2 content elements (business + warning), got %#v", res)
	}

	warningFound := false
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			if strings.Contains(tc.Text, "AUDIT_FAILED") && strings.Contains(tc.Text, "DO NOT RETRY") {
				warningFound = true
				break
			}
		}
	}
	if !warningFound {
		t.Error("expected AUDIT_FAILED DO NOT RETRY warning in result content")
	}

	metadata, ok := res.Meta[auditMetadataKey].(map[string]any)
	if !ok {
		t.Fatalf("expected %q metadata, got %#v", auditMetadataKey, res.Meta)
	}
	if metadata["executed"] != true || metadata["audit_failed"] != true || metadata["retryable"] != false {
		t.Fatalf("unexpected audit metadata: %#v", metadata)
	}
	if metadata["operation_id"] == "" {
		t.Fatal("expected non-empty operation_id metadata")
	}
}

func TestWithGuardrail_SecondAuditFails_PreservesResultAcrossMCPTransport(t *testing.T) {
	g := New(defaultTestConfig())
	g.SetAuditWriter(&fakeAuditWriter{failOn: 2})

	handler := func(context.Context, *mcp.CallToolRequest, dummyInput) (*mcp.CallToolResult, dummyOutput, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "business output"}},
		}, dummyOutput{Response: "data created"}, nil
	}
	wrapped := WithGuardrail(g, "xops_list_nodes", func(in dummyInput) RiskInput {
		return RiskInput{ToolName: "xops_list_nodes", Command: in.Command}
	}, handler)

	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "v1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "xops_list_nodes"}, wrapped)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(t.Context(), serverTransport, nil)
	if err != nil {
		t.Fatalf("connect mcp server failed: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := serverSession.Close(); closeErr != nil {
			t.Errorf("close mcp server session failed: %v", closeErr)
		}
	})

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1"}, nil)
	clientSession, err := client.Connect(t.Context(), clientTransport, nil)
	if err != nil {
		t.Fatalf("connect mcp client failed: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := clientSession.Close(); closeErr != nil {
			t.Errorf("close mcp client session failed: %v", closeErr)
		}
	})

	result, err := clientSession.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "xops_list_nodes",
		Arguments: dummyInput{Command: "ls"},
	})
	if err != nil {
		t.Fatalf("call guarded tool across mcp transport failed: %v", err)
	}
	if result.IsError {
		t.Fatal("post-execution audit failure must not turn an executed operation into a tool error")
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured tool result failed: %v", err)
	}
	var output dummyOutput
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("decode structured tool result failed: %v", err)
	}
	if output.Response != "data created" {
		t.Fatalf("expected structured result to survive transport, got %#v", output)
	}
	metadata, ok := result.Meta[auditMetadataKey].(map[string]any)
	if !ok {
		t.Fatalf("expected audit metadata to survive transport, got %#v", result.Meta)
	}
	if metadata["executed"] != true || metadata["audit_failed"] != true || metadata["retryable"] != false {
		t.Fatalf("unexpected transported audit metadata: %#v", metadata)
	}
}

func readAuditEntries(t *testing.T, path string) []AuditEntry {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit file failed: %v", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close audit file failed: %v", closeErr)
		}
	}()

	var entries []AuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("unmarshal audit entry failed: %v", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit file failed: %v", err)
	}
	return entries
}
