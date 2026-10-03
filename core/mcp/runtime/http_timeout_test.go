package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHTTPToolDeadlinePreservesConfiguredLimit(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		httpTimeout, override time.Duration
		overrideFirst         bool
	}{
		{name: "default"},
		{name: "configured", httpTimeout: 20 * time.Minute},
		{name: "shorter override", httpTimeout: 20 * time.Minute, override: 2 * time.Minute},
		{name: "longer override", httpTimeout: 20 * time.Minute, override: 30 * time.Minute},
		{name: "override before HTTP", httpTimeout: 20 * time.Minute, override: 30 * time.Minute, overrideFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := DefaultHTTPOptions()
			options.Token = httpTestToken
			options.StateDir = filepath.Join(t.TempDir(), "transfers")
			if tc.httpTimeout != 0 {
				options.ToolTimeout = tc.httpTimeout
			}
			original := options
			configuration := []Option{WithConfigProvider(runtimeTestProvider("node")), WithHTTP(options)}
			want := options.ToolTimeout
			if tc.override != 0 {
				if tc.overrideFirst {
					configuration = append([]Option{WithToolTimeout(tc.override)}, configuration...)
				} else {
					configuration = append(configuration, WithToolTimeout(tc.override))
				}
				want = tc.override
			}
			r, err := NewRuntime(t.Context(), configuration...)
			if err != nil {
				t.Fatal(err)
			}
			defer closeTransferTestResource(t, r)
			if !reflect.DeepEqual(options, original) {
				t.Fatal("construction changed caller-owned HTTP options")
			}
			for _, layer := range []string{"request", "middleware", "tool", "session"} {
				t.Run(layer, func(t *testing.T) {
					for _, boundedParent := range []bool{false, true} {
						parent, cancel := context.WithCancel(t.Context())
						defer cancel()
						timeout := want
						if layer == "session" {
							timeout = options.SessionTimeout
						}
						var parentDeadline time.Time
						if boundedParent {
							parentDeadline = time.Now().Add(time.Minute)
							parent, cancel = context.WithDeadline(parent, parentDeadline)
							defer cancel()
						}
						start := time.Now()
						check := func(ctx context.Context) {
							t.Helper()
							deadline, ok := ctx.Deadline()
							if !ok {
								t.Fatal("operation has no deadline")
							}
							if boundedParent {
								if !deadline.Equal(parentDeadline) {
									t.Errorf("caller deadline = %v, got %v", parentDeadline, deadline)
								}
							} else if deadline.Before(start.Add(timeout)) || deadline.After(time.Now().Add(timeout)) {
								t.Errorf("deadline is %v from entry, want %v", deadline.Sub(start), timeout)
							}
						}
						checkHTTPTimeoutLayer(t, r, layer, parent, check)
					}
				})
			}
		})
	}
}

func checkHTTPTimeoutLayer(t *testing.T, r *Runtime, layer string, parent context.Context, check func(context.Context)) {
	t.Helper()
	switch layer {
	case "request", "session":
		method := http.MethodPost
		if layer == "session" {
			method = http.MethodGet
		}
		writer := &idleTestResponseWriter{httptest.NewRecorder()}
		request := httptest.NewRequestWithContext(parent, method, "/mcp", nil)
		called := false
		r.serveProtocolRequest(writer, request, http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			called = true
			check(req.Context())
		}))
		if !called {
			t.Fatalf("protocol handler did not run: HTTP %d %s", writer.Code, writer.Body.String())
		}
	case "middleware":
		handler := r.toolDeadline(func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
			check(ctx)
			return &mcp.CallToolResult{}, nil
		})
		if _, err := handler(parent, "tools/call", nil); err != nil {
			t.Fatal(err)
		}
	case "tool":
		ctx, cancel := r.toolContext(parent)
		defer cancel()
		check(ctx)
	default:
		t.Fatalf("unknown timeout layer %q", layer)
	}
}

func TestHTTPToolTimeoutOverrideAllowsLongerCall(t *testing.T) {
	const httpTimeout = 200 * time.Millisecond
	_, server := startHTTPTestRuntime(t, func(o *HTTPOptions) { o.ToolTimeout = httpTimeout }, nil, func(r *Runtime) {
		mcp.AddTool(r.server, &mcp.Tool{Name: "timeout_probe"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]string, error) {
			if err := waitTransferTestDelay(ctx, 2*httpTimeout); err != nil {
				return nil, nil, err
			}
			return nil, map[string]string{"result": "completed"}, nil
		})
	}, WithToolTimeout(5*time.Second))
	client := connectHTTPTestClient(t, server, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "timeout_probe", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("tool cancelled before the explicit timeout: result=%+v error=%v", result, err)
	}
}
