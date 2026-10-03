package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
)

type observeSSETransport struct {
	http.RoundTripper
	ready chan struct{}
	once  sync.Once
}

func (t *observeSSETransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.RoundTripper.RoundTrip(req)
	if err == nil && req.Method == http.MethodGet && response.StatusCode == http.StatusOK {
		t.once.Do(func() { close(t.ready) })
	}
	return response, err
}

func observeHTTPInitialization(r *Runtime, finished chan<- struct{}) {
	next := r.httpHandler
	finish := sync.OnceFunc(func() { close(finished) })
	r.httpHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		next.ServeHTTP(w, req)
		if req.Method == http.MethodPost && req.Header.Get("Mcp-Session-Id") == "" {
			// Observe completion outside admission so its ordinary request slot
			// is released. Client Connect/SSE readiness can precede this point.
			finish()
		}
	})
}

func waitHTTPInitialization(t *testing.T, ctx context.Context, finished <-chan struct{}) {
	t.Helper()
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("initialize request did not release admission capacity")
	}
}

func TestApprovalReplyCompletesAtHTTPRequestLimit(t *testing.T) {
	var executed atomic.Int32
	initialized := make(chan struct{})
	policy := &config.GuardrailConfig{Enabled: true, ApprovalThreshold: "dangerous"}
	_, server := startHTTPTestRuntime(t, func(o *HTTPOptions) { o.MaxRequests = 2; o.ToolTimeout = 800 * time.Millisecond }, policy, func(r *Runtime) {
		observeHTTPInitialization(r, initialized)
		mcp.AddTool(r.server, &mcp.Tool{Name: "guarded_probe"}, guardrail.WithGuardrail(r.guardrail, "guarded_probe",
			func(struct{}) guardrail.RiskInput { return guardrail.RiskInput{} },
			func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, map[string]string, error) {
				executed.Add(1)
				return nil, map[string]string{"result": "executed"}, nil
			}))
	})
	transport := &observeSSETransport{RoundTripper: bearerTransport{base: server.Client().Transport, token: httpTestToken}, ready: make(chan struct{})}
	client := mcp.NewClient(&mcp.Implementation{Name: "approval-capacity-test", Version: "1"}, &mcp.ClientOptions{ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
	}})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: &http.Client{Transport: transport, Timeout: 3 * time.Second}, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: httpProtocolVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, session)
	waitHTTPInitialization(t, ctx, initialized)
	select {
	case <-transport.ready:
	case <-ctx.Done():
		t.Fatal("standalone SSE did not occupy a request slot")
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "guarded_probe", Arguments: map[string]any{}})
	if err != nil || result.IsError || executed.Load() != 1 {
		t.Fatalf("accepted approval could not complete at request limit: result=%+v error=%v executions=%d", result, err, executed.Load())
	}
}

func TestCancellationCompletesAtHTTPRequestLimit(t *testing.T) {
	for _, requestID := range []any{77, "long-running-request"} {
		t.Run(fmt.Sprint(requestID), func(t *testing.T) {
			entered := make(chan struct{})
			stopped := make(chan struct{})
			initialized := make(chan struct{})
			_, server := startHTTPTestRuntime(t, func(o *HTTPOptions) { o.MaxRequests = 2; o.ToolTimeout = 3 * time.Second }, nil, func(r *Runtime) {
				observeHTTPInitialization(r, initialized)
				mcp.AddTool(r.server, &mcp.Tool{Name: "cancel_probe"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{}, error) {
					close(entered)
					<-ctx.Done()
					close(stopped)
					return nil, struct{}{}, ctx.Err()
				})
			})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			transport := &observeSSETransport{RoundTripper: bearerTransport{base: server.Client().Transport, token: httpTestToken}, ready: make(chan struct{})}
			client := mcp.NewClient(&mcp.Implementation{Name: "cancel-capacity-test", Version: "1"}, nil)
			session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: httpProtocolVersion})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTransferTestResource(t, session)
			waitHTTPInitialization(t, ctx, initialized)
			select {
			case <-transport.ready:
			case <-ctx.Done():
				t.Fatal("SSE connection did not occupy capacity")
			}
			done := make(chan struct{})
			var requestErr error
			go func() {
				defer close(done)
				response, err := rawMCPRequest(ctx, server.Client(), server.URL+"/mcp", session.ID(), map[string]any{"jsonrpc": "2.0", "id": requestID, "method": "tools/call", "params": map[string]any{"name": "cancel_probe", "arguments": map[string]any{}}})
				if response != nil {
					if response.StatusCode != http.StatusOK {
						err = errors.Join(err, fmt.Errorf("tool request returned HTTP %d", response.StatusCode))
					}
					_, readErr := io.Copy(io.Discard, response.Body)
					err = errors.Join(err, readErr, response.Body.Close())
				}
				requestErr = err
			}()
			// Join the client request even if the cancellation notification is rejected.
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("tool HTTP request did not stop")
				}
			}()
			select {
			case <-entered:
			case <-done:
				t.Fatalf("tool request ended before execution: %v", requestErr)
			case <-ctx.Done():
				t.Fatal("tool did not start")
			}
			response, err := rawMCPRequest(ctx, server.Client(), server.URL+"/mcp", session.ID(), map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": requestID, "reason": "test cancellation at capacity"}})
			if err != nil {
				t.Fatal(err)
			}
			defer closeTransferTestResource(t, response.Body)
			if response.StatusCode != http.StatusAccepted {
				t.Fatalf("cancellation rejected at request limit: HTTP %d", response.StatusCode)
			}
			timer := time.NewTimer(700 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-stopped:
			case <-timer.C:
				t.Fatal("cancellation did not reach detached tool before its deadline")
			}
		})
	}
}
