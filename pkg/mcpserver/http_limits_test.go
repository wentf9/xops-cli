package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func rawMCPRequest(ctx context.Context, client *http.Client, endpoint, session string, payload any) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+httpTestToken)
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", httpProtocolVersion)
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	return client.Do(req)
}
func TestDisconnectedMCPToolRetainsExecutionCapacity(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var fastCalls atomic.Int32
	_, server := startHTTPTestRuntime(t, func(o *HTTPOptions) { o.MaxRequests = 1; o.ToolTimeout = 3 * time.Second }, nil, func(r *Runtime) {
		mcp.AddTool(r.server, &mcp.Tool{Name: "hold_capacity"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{}, error) {
			entered <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, struct{}{}, nil
		})
		mcp.AddTool(r.server, &mcp.Tool{Name: "fast_probe"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
			fastCalls.Add(1)
			return nil, struct{}{}, nil
		})
	})
	releaseTool := sync.OnceFunc(func() { close(release) })
	defer releaseTool()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	response, err := rawMCPRequest(ctx, server.Client(), server.URL+"/mcp", "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": httpProtocolVersion, "clientInfo": map[string]string{"name": "limit-test", "version": "1"}, "capabilities": map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	session := response.Header.Get("Mcp-Session-Id")
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	closeTransferTestResource(t, response.Body)
	if session == "" {
		t.Fatal("missing stateful session")
	}
	response, err = rawMCPRequest(ctx, server.Client(), server.URL+"/mcp", session, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if err != nil {
		t.Fatal(err)
	}
	closeTransferTestResource(t, response.Body)
	requestCtx, disconnect := context.WithCancel(ctx)
	defer disconnect()
	done := make(chan struct{})
	go func() {
		defer close(done)
		response, err := rawMCPRequest(requestCtx, server.Client(), server.URL+"/mcp", session, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "hold_capacity", "arguments": map[string]any{}}})
		if err == nil {
			closeTransferTestResource(t, response.Body)
		}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("tool did not start")
	}
	disconnect()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("POST did not disconnect")
	}
	for {
		response, err = rawMCPRequest(ctx, server.Client(), server.URL+"/mcp", session, map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "fast_probe", "arguments": map[string]any{}}})
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeTransferTestResource(t, response.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode == http.StatusTooManyRequests {
			select {
			case <-time.After(5 * time.Millisecond):
				continue
			case <-ctx.Done():
				t.Fatal("request slot did not release")
			}
		}
		if !bytes.Contains(body, []byte("tool_execution_limit")) || fastCalls.Load() != 0 {
			t.Fatalf("disconnect bypassed execution capacity: calls=%d body=%s", fastCalls.Load(), body)
		}
		break
	}
	releaseTool()
	assertExecutionSlotReusable(t, ctx, server.Client(), server.URL+"/mcp", session, &fastCalls)
}

func assertExecutionSlotReusable(t *testing.T, ctx context.Context, client *http.Client, endpoint, session string, calls *atomic.Int32) {
	t.Helper()
	for {
		response, err := rawMCPRequest(ctx, client, endpoint, session, map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{"name": "fast_probe", "arguments": map[string]any{}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		closeTransferTestResource(t, response.Body)
		if calls.Load() == 1 {
			return
		}
		select {
		case <-time.After(5 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("execution slot was not released after completion")
		}
	}
}

func TestHTTPDefaultPortOriginEquivalence(t *testing.T) {
	for _, tc := range []struct {
		public, canonical, host, origin string
		allowed                         bool
	}{
		{"http://mcp.test:80", "http://mcp.test", "mcp.test", "http://mcp.test", true},
		{"http://mcp.test", "http://mcp.test", "mcp.test:80", "http://mcp.test:80", true},
		{"https://mcp.test:443", "https://mcp.test", "mcp.test", "https://mcp.test", true},
		{"https://mcp.test", "https://mcp.test", "mcp.test:443", "https://mcp.test:443", true},
		{"https://[::1]:443", "https://[::1]", "[::1]", "https://[::1]:443", true},
		{"https://mcp.test:8443", "https://mcp.test:8443", "mcp.test:8443", "https://mcp.test:8443", true},
		{"https://mcp.test:443", "https://mcp.test", "mcp.test:80", "https://mcp.test", false},
		{"https://mcp.test:8443", "https://mcp.test:8443", "mcp.test", "https://mcp.test:8443", false},
		{"https://mcp.test", "https://mcp.test", "mcp.test", "http://mcp.test", false},
	} {
		t.Run(tc.public+"/"+tc.host+"/"+tc.origin, func(t *testing.T) {
			options := DefaultHTTPOptions()
			options.PublicURL = tc.public
			options.Token = httpTestToken
			options.StateDir = t.TempDir()
			if err := options.validate(); err != nil {
				t.Fatal(err)
			}
			if options.PublicURL != tc.canonical {
				t.Errorf("canonical origin = %s", options.PublicURL)
			}
			r := Runtime{http: &options}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://internal-proxy/mcp", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = tc.host
			req.Header.Set("Origin", tc.origin)
			if r.allowedHTTPRequest(req) != tc.allowed {
				t.Fatalf("incorrect Host/Origin equivalence")
			}
		})
	}
}
