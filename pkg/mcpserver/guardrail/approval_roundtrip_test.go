package guardrail

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestModernApprovalRoundTrip(t *testing.T) {
	for _, approve := range []bool{true, false} {
		t.Run(map[bool]string{true: "approve", false: "decline"}[approve], func(t *testing.T) {
			ct, st := mcp.NewInMemoryTransports()
			g := New(nil)
			server := mcp.NewServer(&mcp.Implementation{Name: "roundtrip", Version: "1"}, nil)
			var executed atomic.Int32
			mcp.AddTool(server, &mcp.Tool{Name: "test_approval"}, func(ctx context.Context, req *mcp.CallToolRequest, in struct{ Value string }) (*mcp.CallToolResult, any, error) {
				pending, err := g.requestToolApproval(ctx, req, Dangerous, RiskInput{ToolName: "test_approval"}, in)
				if err != nil || pending != nil {
					return pending, nil, err
				}
				executed.Add(1)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "executed"}}}, nil, nil
			})
			ss, err := server.Connect(t.Context(), st, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := ss.Close(); err != nil {
					t.Error(err)
				}
			})
			client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "1"}, &mcp.ClientOptions{ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				if req.Params.RequestedSchema == nil {
					t.Error("missing schema")
				}
				return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": approve}}, nil
			}})
			cs, err := client.Connect(t.Context(), ct, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := cs.Close(); err != nil {
					t.Error(err)
				}
			})
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "test_approval", Arguments: map[string]any{"Value": "one"}})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError == approve {
				t.Fatalf("approve=%v result=%+v", approve, res)
			}
			if got := executed.Load(); (got == 1) != approve {
				t.Fatalf("executed=%d approve=%v", got, approve)
			}
			// A challenge cannot authorize different input or a second execution.
			req := &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}
			ri := RiskInput{ToolName: "test_approval"}
			pending, err := g.requestToolApproval(t.Context(), req, Dangerous, ri, "original")
			if err != nil {
				t.Fatal(err)
			}
			req.Params.RequestState = pending.RequestState
			req.Params.InputResponses = mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}}
			if _, err := g.requestToolApproval(t.Context(), req, Dangerous, ri, "changed"); err == nil {
				t.Fatal("changed input approved")
			}
			if _, err := g.requestToolApproval(t.Context(), req, Dangerous, ri, "original"); err != nil {
				t.Fatal(err)
			}
			if _, err := g.requestToolApproval(t.Context(), req, Dangerous, ri, "original"); err == nil {
				t.Fatal("replayed approval")
			}
			req.Params = &mcp.CallToolParamsRaw{}
			pending, err = g.requestToolApproval(t.Context(), req, Dangerous, ri, "original")
			if err != nil {
				t.Fatal(err)
			}
			req.Params.RequestState = pending.RequestState
			req.Params.InputResponses = mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}}
			g.approvalMu.Lock()
			challenge := g.pendingApprovals[pending.RequestState]
			challenge.expires = time.Now().Add(-time.Second)
			g.pendingApprovals[pending.RequestState] = challenge
			g.approvalMu.Unlock()
			if _, err := g.requestToolApproval(t.Context(), req, Dangerous, ri, "original"); err == nil {
				t.Fatal("expired approval accepted")
			}
		})
	}
}
