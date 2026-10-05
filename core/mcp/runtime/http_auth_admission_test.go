package runtime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

type authenticationAdmissionResponse struct {
	code int
	body string
	err  error
}

func requestInvalidAuthentication(ctx context.Context, client *http.Client, endpoint string) authenticationAdmissionResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return authenticationAdmissionResponse{err: err}
	}
	req.Header.Set("Authorization", "Bearer invalid-token")
	result, err := client.Do(req)
	if err != nil {
		return authenticationAdmissionResponse{err: err}
	}
	body, readErr := io.ReadAll(result.Body)
	return authenticationAdmissionResponse{code: result.StatusCode, body: string(body), err: errors.Join(readErr, result.Body.Close())}
}

func TestHTTPAuthenticationAdmissionBoundsBlockedVerifier(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	releaseAll := sync.OnceFunc(func() { close(release) })
	var calls atomic.Int32
	_, server := startHTTPTestRuntime(t, func(options *HTTPOptions) {
		options.Token = ""
		options.MaxRequests = 1
		options.TokenVerifier = func(ctx context.Context, _ string, _ *http.Request) (*auth.TokenInfo, error) {
			calls.Add(1)
			entered <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, auth.ErrInvalidToken
		}
	}, nil, nil)
	request := func() authenticationAdmissionResponse {
		return requestInvalidAuthentication(ctx, server.Client(), server.URL+"/mcp")
	}
	var workers sync.WaitGroup
	// Every worker has a bounded request context and is joined, including on
	// regression failure while the verifier is deliberately held at a barrier.
	defer func() { releaseAll(); cancel(); workers.Wait() }()
	first := make(chan authenticationAdmissionResponse, 1)
	workers.Go(func() { first <- request() })
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first verifier did not start")
	}
	results := make(chan authenticationAdmissionResponse, 7)
	for range 7 {
		workers.Go(func() { results <- request() })
	}
	for range 7 {
		select {
		case <-entered:
			t.Fatalf("external authentication exceeded MaxRequests=1: %d callbacks entered", calls.Load())
		case result := <-results:
			if result.err != nil || result.code != http.StatusTooManyRequests || strings.TrimSpace(result.body) != "authentication_limit" {
				t.Fatalf("saturated authentication did not reject promptly: %+v", result)
			}
		case <-ctx.Done():
			t.Fatal("saturated requests waited for the verifier")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("excess verifier calls: %d", calls.Load())
	}
	releaseAll()
	if result := <-first; result.err != nil || result.code != http.StatusUnauthorized {
		t.Fatalf("invalid token response: %+v", result)
	}
	if result := request(); result.err != nil || result.code != http.StatusUnauthorized {
		t.Fatalf("authentication slot leaked: %+v", result)
	}
	if calls.Load() != 2 {
		t.Fatal("request after rejection did not reach verifier")
	}
}

func TestHTTPAuthenticationAdmissionPreservesControlLane(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var verified atomic.Int32
	r := Runtime{http: &HTTPOptions{MaxRequests: 1, HeaderTimeout: time.Second, TokenVerifier: func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		verified.Add(1)
		return &auth.TokenInfo{UserID: "client"}, nil
	}}}
	const call = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`
	entered := make(chan struct{})
	release := make(chan struct{})
	releaseAll := sync.OnceFunc(func() { close(release) })
	done := make(chan struct{})
	handler := r.authenticateHTTP(r.protocolAdmission(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		defer closeTransferTestResource(t, req.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if string(body) == call {
			close(entered)
			select {
			case <-release:
			case <-req.Context().Done():
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}), make(chan struct{}, 1)))
	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer valid-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	defer func() { releaseAll(); cancel(); <-done }()
	// The ordinary protocol request owns its slot until explicitly released;
	// authentication must already be finished so controls can still authenticate.
	go func() {
		defer close(done)
		if response := request(call); response.Code != http.StatusAccepted {
			t.Errorf("ordinary call rejected: %d", response.Code)
		}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("ordinary call did not start")
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"approval","result":{"action":"accept"}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
	} {
		if response := request(body); response.Code != http.StatusAccepted {
			t.Fatalf("ordinary call blocked control authentication: %d %s", response.Code, response.Body.String())
		}
	}
	response := request(call)
	if response.Code != http.StatusTooManyRequests || strings.TrimSpace(response.Body.String()) != "request_limit" {
		t.Fatalf("ordinary request bypassed protocol limit: %d %s", response.Code, response.Body.String())
	}
	if verified.Load() != 5 {
		t.Fatal("authentication incorrectly shared the protocol request quota")
	}
}

func TestHTTPAuthenticationAdmissionReleasesOnTimeoutAndMalformedHeader(t *testing.T) {
	var calls atomic.Int32
	r := Runtime{http: &HTTPOptions{MaxRequests: 1, HeaderTimeout: 20 * time.Millisecond, TokenVerifier: func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		calls.Add(1)
		if token == "blocked" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &auth.TokenInfo{UserID: "client"}, nil
	}}}
	handler := r.authenticateHTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, test := range []struct {
		header string
		status int
	}{
		{"Bearer blocked", http.StatusInternalServerError},
		{"Bearer valid", http.StatusNoContent},
		{"Basic malformed", http.StatusUnauthorized},
		{"Bearer valid", http.StatusNoContent},
	} {
		if test.header != "Bearer blocked" {
			// Only the deliberately blocked request needs a short deadline.
			r.http.HeaderTimeout = time.Second
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", test.header)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != test.status {
			t.Fatalf("authentication quota leaked: %d want %d", response.Code, test.status)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("malformed header reached verifier: %d calls", calls.Load())
	}
}
