package runtime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
)

func TestHTTPRejectsUnauthorizedSlowBodyWithoutDraining(t *testing.T) {
	_, server := startHTTPTestRuntime(t, nil, nil, nil)
	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, conn)
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "POST /mcp HTTP/1.1\r\nHost: %s\r\nContent-Length: 100000\r\n\r\n", server.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("rejection waited for an untrusted body: %v", err)
	}
	defer closeTransferTestResource(t, response.Body)
	if response.StatusCode != http.StatusUnauthorized || !response.Close {
		t.Fatalf("unsafe rejection: status=%d close=%v", response.StatusCode, response.Close)
	}
}

func TestHTTPBodyDeadlineDoesNotExpireIdleSSE(t *testing.T) {
	_, server := startHTTPTestRuntime(t, func(options *HTTPOptions) { options.BodyTimeout = 30 * time.Millisecond }, nil, nil)
	client := connectHTTPTestClient(t, server, nil)
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	assertRuntimeNode(t, client, "http-node")
}

const httpTestToken = "xops-http-test-token-not-for-production-012345"

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copyReq := req.Clone(req.Context())
	copyReq.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(copyReq)
}

func startHTTPTestRuntime(t *testing.T, mutate func(*HTTPOptions), policy *config.GuardrailConfig, register func(*Runtime), runtimeOptions ...Option) (*Runtime, *httptest.Server) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	options := DefaultHTTPOptions()
	options.Token = httpTestToken
	options.PublicURL = "http://" + server.Listener.Addr().String()
	options.StateDir = filepath.Join(t.TempDir(), "transfers")
	if mutate != nil {
		mutate(&options)
	}
	provider := runtimeTestProvider("http-node")
	configuration := provider.Snapshot()
	if policy != nil {
		configuration.Guardrail = policy
	}
	opts := []Option{WithConfigProvider(config.NewProviderWithoutOpenSSH(configuration)), WithHTTP(options)}
	r, err := NewRuntime(t.Context(), append(opts, runtimeOptions...)...)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
		server.Close()
	})
	if register != nil {
		register(r)
	}
	server.Config.Handler, err = r.HTTPHandler()
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	return r, server
}

func connectHTTPTestClient(t *testing.T, server *httptest.Server, options *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "http-client", Version: "1"}, options)
	httpClient := &http.Client{Transport: bearerTransport{base: server.Client().Transport, token: httpTestToken}, Timeout: 30 * time.Second}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: server.URL + "/mcp", HTTPClient: httpClient, MaxRetries: -1,
	}, &mcp.ClientSessionOptions{ProtocolVersion: httpProtocolVersion})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Error(err)
		}
	})
	return session
}

func TestHTTPRuntimeProtocolAndLocalFileBoundary(t *testing.T) {
	r, server := startHTTPTestRuntime(t, nil, nil, nil)
	if r.http.Token != "" {
		t.Fatal("runtime retained plaintext service token")
	}
	client := connectHTTPTestClient(t, server, nil)
	assertRuntimeNode(t, client, "http-node")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tools, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if tool.Name == "xops_upload" || tool.Name == "xops_download" {
			t.Fatalf("HTTP exposed server-local file tool %q", tool.Name)
		}
		if strings.HasPrefix(tool.Name, "xops_tunnel_") {
			t.Fatalf("HTTP exposed stdio tunnel tool %q", tool.Name)
		}
	}
	if r.tunnels != nil {
		t.Fatal("HTTP initialized a tunnel manager")
	}
	for _, name := range []string{"xops_tunnel_create", "xops_tunnel_list", "xops_tunnel_status", "xops_tunnel_stop"} {
		result, callErr := client.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{}})
		if callErr == nil && !result.IsError {
			t.Fatalf("HTTP accepted unregistered tool %s", name)
		}
	}
}

func TestHTTPAuthenticationHostAndOrigin(t *testing.T) {
	_, server := startHTTPTestRuntime(t, nil, nil, nil)
	for _, tc := range []struct {
		name, host, origin, token, path string
		status                          int
	}{
		{name: "missing auth", path: "/mcp", status: http.StatusUnauthorized},
		{name: "bad auth", token: "wrong", path: "/mcp", status: http.StatusUnauthorized},
		{name: "bad host", host: "attacker.invalid", token: httpTestToken, path: "/mcp", status: http.StatusForbidden},
		{name: "bad origin", origin: "https://attacker.invalid", token: httpTestToken, path: "/mcp", status: http.StatusForbidden},
		{name: "null origin", origin: "null", token: httpTestToken, path: "/mcp", status: http.StatusForbidden},
		{name: "no legacy SSE", token: httpTestToken, path: "/sse", status: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.host != "" {
				req.Host = tc.host
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			client := server.Client()
			client.Timeout = 5 * time.Second
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := response.Body.Close(); err != nil {
					t.Error(err)
				}
			}()
			body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status {
				t.Errorf("status = %d, want %d, body=%s", response.StatusCode, tc.status, body)
			}
			if strings.Contains(string(body), httpTestToken) || response.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("secret reflected or broad CORS enabled")
			}
		})
	}
}

func TestHTTPGuardrailApprovalRoundTrip(t *testing.T) {
	for _, action := range []string{"accept", "decline", "cancel", "unsupported"} {
		t.Run(action, func(t *testing.T) {
			var executed atomic.Int32
			policy := &config.GuardrailConfig{Enabled: true, ApprovalThreshold: "dangerous"}
			_, server := startHTTPTestRuntime(t, nil, policy, func(r *Runtime) {
				mcp.AddTool(r.server, &mcp.Tool{Name: "guarded_probe"}, guardrail.WithGuardrail(r.guardrail, "guarded_probe",
					func(struct{}) guardrail.RiskInput { return guardrail.RiskInput{} },
					func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, map[string]string, error) {
						executed.Add(1)
						return nil, map[string]string{"result": "executed"}, nil
					}))
			})
			options := &mcp.ClientOptions{}
			if action != "unsupported" {
				options.ElicitationHandler = func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
					return &mcp.ElicitResult{Action: action, Content: map[string]any{"approved": action == "accept"}}, nil
				}
			}
			client := connectHTTPTestClient(t, server, options)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "guarded_probe", Arguments: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			approved := action == "accept"
			if result.IsError == approved || (executed.Load() == 1) != approved {
				t.Fatalf("action=%s result=%+v executed=%d", action, result, executed.Load())
			}
		})
	}
}

func TestHTTPToolTimeoutCancelsDetachedSDKCall(t *testing.T) {
	stopped := make(chan struct{})
	_, server := startHTTPTestRuntime(t, func(o *HTTPOptions) { o.ToolTimeout = 100 * time.Millisecond }, nil, func(r *Runtime) {
		mcp.AddTool(r.server, &mcp.Tool{Name: "wait_probe"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]string, error) {
			<-ctx.Done()
			close(stopped)
			return nil, nil, fmt.Errorf("probe stopped: %w", ctx.Err())
		})
	})
	client := connectHTTPTestClient(t, server, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "wait_probe", Arguments: map[string]any{}})
	if err == nil && !result.IsError {
		t.Fatal("timed out operation reported success")
	}
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("HTTP request ended but SDK tool execution was not cancelled")
	}
}

func TestHTTPOptionsRejectInvalidBoundaries(t *testing.T) {
	for name, mutate := range map[string]func(*HTTPOptions){
		"short token":     func(o *HTTPOptions) { o.Token = "short" },
		"no state":        func(o *HTTPOptions) { o.StateDir = "" },
		"zero timeout":    func(o *HTTPOptions) { o.BodyTimeout = 0 },
		"wildcard host":   func(o *HTTPOptions) { o.AllowedHosts = []string{"*"} },
		"public userinfo": func(o *HTTPOptions) { o.PublicURL = "https://secret@host" },
		"public query":    func(o *HTTPOptions) { o.PublicURL = "http://host?token=secret" },
		"LAN no URL":      func(o *HTTPOptions) { o.Listen, o.PublicURL = "0.0.0.0:8080", "" },
	} {
		t.Run(name, func(t *testing.T) {
			options := DefaultHTTPOptions()
			options.Token, options.StateDir = httpTestToken, t.TempDir()
			mutate(&options)
			_, err := NewRuntime(t.Context(), WithConfigProvider(runtimeTestProvider("node")), WithHTTP(options))
			if err == nil || errors.Is(err, context.Canceled) {
				t.Fatalf("invalid configuration not rejected: %v", err)
			}
			if strings.Contains(err.Error(), httpTestToken) {
				t.Fatal("configuration error exposed token")
			}
		})
	}
}
