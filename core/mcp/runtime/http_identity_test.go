package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
)

func TestHTTPClientIdentityAndTransferIsolation(t *testing.T) {
	r, server := startHTTPTestRuntime(t, func(o *HTTPOptions) {
		o.Token = ""
		o.TokenVerifier = func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
			if token != "client-a" && token != "client-b" {
				return nil, auth.ErrInvalidToken
			}
			return &auth.TokenInfo{UserID: token, Extra: map[string]any{"tokenID": token + "-credential"}}, nil
		}
	}, nil, func(r *Runtime) {
		mcp.AddTool(r.server, &mcp.Tool{Name: "test_identity", Description: "fixture"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ClientIdentity, error) {
			identity, ok := ClientIdentityFromContext(ctx)
			if !ok || r.scope(ctx) != identity.ClientID {
				return nil, ClientIdentity{}, errors.New("missing request identity")
			}
			return nil, identity, nil
		})
	})
	clients := map[string]*mcp.ClientSession{}
	for _, id := range []string{"client-a", "client-b"} {
		client := mcp.NewClient(&mcp.Implementation{Name: id, Version: "1"}, nil)
		session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{base: server.Client().Transport, token: id}}, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: httpProtocolVersion})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closeTransferTestResource(t, session) })
		clients[id] = session
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "test_identity", Arguments: map[string]any{}})
		if err != nil || result.IsError {
			t.Fatalf("identity tool: %v %+v", err, result)
		}
		data, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		var identity ClientIdentity
		if err := json.Unmarshal(data, &identity); err != nil {
			t.Fatal(err)
		}
		if identity.ClientID != id || identity.TokenID != id+"-credential" {
			t.Fatalf("detached request identity: %+v", identity)
		}
	}
	prepared, err := r.transfers.Prepare(transfer.Spec{Scope: "client-a", RequestID: "same-request", RequestDigest: strings.Repeat("a", 64), NodeID: "node", TargetID: "target", RemotePath: "/one", Direction: transfer.Upload, Size: 0, SHA256: strings.Repeat("0", 64)}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	for id, session := range clients {
		for _, tool := range []string{"xops_transfer_status", "xops_transfer_cancel"} {
			if id == "client-a" && tool == "xops_transfer_cancel" {
				continue
			}
			result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: map[string]any{"transferID": prepared.Status.ID}})
			if err != nil {
				t.Fatal(err)
			}
			if result.IsError != (id == "client-b") {
				t.Fatalf("%s accessed %s: %+v", id, tool, result)
			}
		}
	}
}

func TestHTTPVerifierFailsClosedAndRedactsErrors(t *testing.T) {
	_, server := startHTTPTestRuntime(t, func(o *HTTPOptions) {
		o.Token = ""
		o.TokenVerifier = func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
			switch token {
			case "empty":
				return &auth.TokenInfo{}, nil
			case "nil":
				return nil, nil
			case "expired":
				return &auth.TokenInfo{UserID: "client", Expiration: time.Now().Add(-time.Hour)}, nil
			default:
				return nil, errors.New("private-database-diagnostic")
			}
		}
	}, nil, nil)
	for token, want := range map[string]int{"empty": 401, "nil": 401, "expired": 401, "backend": 500} {
		req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/mcp", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		closeTransferTestResource(t, resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want || strings.Contains(string(data), "private-database") {
			t.Fatalf("unsafe verification response %d %s", resp.StatusCode, data)
		}
	}
	o := DefaultHTTPOptions()
	o.Token = httpTestToken
	o.TokenVerifier = func(context.Context, string, *http.Request) (*auth.TokenInfo, error) { return nil, nil }
	if err := o.validate(); err == nil {
		t.Fatal("ambiguous authentication configuration accepted")
	}
}
