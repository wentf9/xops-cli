package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestInitializationCompletesAtHTTPRequestLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	r := Runtime{http: &HTTPOptions{MaxRequests: 2}}
	server := mcp.NewServer(&mcp.Implementation{Name: "handshake-capacity-test", Version: "1"}, nil)
	protocol := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	requests := make(chan struct{}, r.http.MaxRequests)
	release := make(chan struct{})
	releaseInitialize := sync.OnceFunc(func() { close(release) })
	finished := make(chan struct{})
	isInitialize := func(req *http.Request) bool {
		return req.Method == http.MethodPost && req.Header.Get("Mcp-Session-Id") == ""
	}
	admitted := r.protocolAdmission(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		protocol.ServeHTTP(w, req)
		if !isInitialize(req) {
			return
		}
		// The client can read the initialize result and open its standalone SSE
		// stream before this POST releases its admission slot. Hold that overlap
		// until Connect has sent notifications/initialized, without timing sleeps.
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush initialize response: %v", err)
			return
		}
		select {
		case <-release:
		case <-ctx.Done():
		case <-req.Context().Done():
		}
	}), requests)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		admitted.ServeHTTP(w, req)
		if isInitialize(req) {
			close(finished)
		}
	}))
	defer func() {
		cancel()
		releaseInitialize()
		for session := range server.Sessions() {
			closeTransferTestResource(t, session)
		}
		httpServer.Close()
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "handshake-capacity-client", Version: "1"}, nil)
	httpClient := httpServer.Client()
	httpClient.Timeout = 5 * time.Second
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL + "/mcp", HTTPClient: httpClient, MaxRetries: -1,
	}, &mcp.ClientSessionOptions{ProtocolVersion: httpProtocolVersion})
	if session != nil {
		defer closeTransferTestResource(t, session)
	}
	if err == nil && len(requests) != cap(requests) {
		t.Errorf("handshake did not fill ordinary request capacity: %d/%d", len(requests), cap(requests))
	}
	if err != nil {
		t.Fatalf("handshake rejected while initialize response and SSE occupied capacity: %v", err)
	}
	// Connect and the SSE response can finish while initialize still owns the
	// other ordinary slot. A tool request must wait for that slot to be released.
	response, err := rawMCPRequest(ctx, httpClient, httpServer.URL+"/mcp", session.ID(), map[string]any{
		"jsonrpc": "2.0", "id": "held-initialize", "method": "tools/list",
	})
	if err != nil {
		t.Fatal(err)
	}
	closeTransferTestResource(t, response.Body)
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("ordinary request bypassed held initialization: HTTP %d", response.StatusCode)
	}
	releaseInitialize()
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("initialize request did not release its slot")
	}
	if _, err := session.ListTools(ctx, nil); err != nil {
		t.Fatalf("ordinary request failed after initialize released capacity: %v", err)
	}
}
