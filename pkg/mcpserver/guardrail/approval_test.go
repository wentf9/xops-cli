package guardrail

import (
	"context"
	"fmt"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestApprovalProtocol(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		approved     any
		rpcCode      int64
		wantErr      bool
	}{
		{name: "approve", action: "accept", approved: true},
		{name: "unchecked", action: "accept", approved: false, wantErr: true},
		{name: "missing", action: "accept", wantErr: true},
		{name: "invalid", action: "accept", approved: "true", wantErr: true},
		{name: "decline", action: "decline", wantErr: true},
		{name: "cancel", action: "cancel", wantErr: true},
		{name: "protocol error", rpcCode: jsonrpc.CodeInvalidParams, wantErr: true},
		{name: "method unsupported", rpcCode: jsonrpc.CodeMethodNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct, st := mcp.NewInMemoryTransports()
			server := mcp.NewServer(&mcp.Implementation{Name: "approval-test", Version: "1"}, nil)
			ss, err := server.Connect(t.Context(), legacyApprovalTransport{st}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := ss.Close(); err != nil {
					t.Error(err)
				}
			})
			client := mcp.NewClient(&mcp.Implementation{Name: "approval-client", Version: "1"}, &mcp.ClientOptions{ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				if req.Params.Mode != "form" || req.Params.RequestedSchema == nil {
					return nil, fmt.Errorf("invalid approval request schema")
				}
				if tc.rpcCode != 0 {
					return nil, &jsonrpc.Error{Code: tc.rpcCode, Message: "test protocol error"}
				}
				content := map[string]any{}
				if tc.approved != nil {
					content["approved"] = tc.approved
				}
				return &mcp.ElicitResult{Action: tc.action, Content: content}, nil
			}})
			client.AddSendingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
				return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
					if method == "server/discover" {
						return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "legacy transport"}
					}
					if init, ok := req.(*mcp.InitializeRequest); ok {
						init.Params.ProtocolVersion = "2025-11-25"
					}
					return next(ctx, method, req)
				}
			})
			cs, err := client.Connect(t.Context(), legacyApprovalTransport{ct}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := cs.Close(); err != nil {
					t.Error(err)
				}
			})
			err = RequestApproval(t.Context(), ss, Dangerous, RiskInput{ToolName: "delete"}, FallbackAllow)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

type legacyApprovalTransport struct{ mcp.Transport }

func (legacyApprovalTransport) SupportsProtocolVersion(version string) bool {
	return version <= "2025-11-25"
}

func TestApprovalNilAndUnsupported(t *testing.T) {
	if err := interpretApproval(nil); err == nil {
		t.Fatal("nil approval accepted")
	}
	for _, fallback := range []string{FallbackAllow, FallbackDeny, FallbackDowngrade} {
		for _, risk := range []RiskLevel{Moderate, Dangerous} {
			err := applyFallback(fmt.Errorf("unsupported"), risk, fallback)
			wantAllowed := fallback == FallbackAllow || (fallback == FallbackDowngrade && risk < Dangerous)
			if (err == nil) != wantAllowed {
				t.Fatalf("fallback=%s risk=%v err=%v", fallback, risk, err)
			}
		}
	}
}
