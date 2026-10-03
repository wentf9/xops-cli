package clicontract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/internal/mcphost"
	"github.com/wentf9/xops-cli/pkg/config"
	"go.uber.org/goleak"
)

var updateMCPContract = flag.Bool("update-mcp-contract", false, "write reviewed MCP tool schemas")

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestMCPToolSchemas(t *testing.T) {
	for _, transport := range []string{"stdio", "http"} {
		t.Run(transport, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			var session *mcp.ClientSession
			if transport == "http" {
				session = connectHTTPContract(t, ctx)
			} else {
				session = connectStdioContract(t, ctx)
			}
			defer closeContractResource(t, session)
			result, err := session.ListTools(ctx, nil)
			if err != nil {
				t.Fatalf("list MCP tools: %v", err)
			}
			if result.NextCursor != "" {
				t.Fatal("tool baseline must capture all pages")
			}
			slices.SortFunc(result.Tools, func(a, b *mcp.Tool) int {
				if a.Name < b.Name {
					return -1
				}
				if a.Name > b.Name {
					return 1
				}
				return 0
			})
			encoded, err := json.MarshalIndent(result.Tools, "", "  ")
			if err != nil {
				t.Fatalf("encode MCP contract: %v", err)
			}
			encoded = append(encoded, '\n')
			name := filepath.Join("testdata", "mcp-"+transport+"-tools.json")
			if *updateMCPContract {
				if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, encoded, 0644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(name)
			if err != nil {
				t.Fatalf("read MCP baseline: %v", err)
			}
			equal, err := sameMCPContract(want, encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !equal {
				t.Fatalf("%s MCP contract changed; review schema/annotations/descriptions before updating %s", transport, name)
			}
		})
	}
}

// Git may check JSON fixtures out with CRLF on Windows. Ignore JSON formatting
// only; string content, field values and array ordering remain significant.
func sameMCPContract(want, got []byte) (bool, error) {
	var expected, actual bytes.Buffer
	if err := json.Compact(&expected, want); err != nil {
		return false, fmt.Errorf("compact expected MCP contract: %w", err)
	}
	if err := json.Compact(&actual, got); err != nil {
		return false, fmt.Errorf("compact actual MCP contract: %w", err)
	}
	return bytes.Equal(expected.Bytes(), actual.Bytes()), nil
}

func contractOptions(t *testing.T, httpOptions *mcpruntime.HTTPOptions) []mcpruntime.Option {
	t.Helper()
	cfg := mcphost.Config{Provider: config.NewProviderWithoutOpenSSH(
		&config.Configuration{Guardrail: &policy.Config{Enabled: false}},
	), HTTP: httpOptions}
	options, err := cfg.RuntimeOptions()
	if err != nil {
		t.Fatal(err)
	}
	return options
}

func connectStdioContract(t *testing.T, ctx context.Context) *mcp.ClientSession {
	t.Helper()
	r, err := mcpruntime.NewRuntime(ctx, contractOptions(t, nil)...)
	if err != nil {
		t.Fatal(err)
	}
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	done := make(chan error, 1)
	// The runtime context/Close stops Run; cleanup always joins this worker.
	go func() { done <- r.Run(serverTransport) }()
	t.Cleanup(func() {
		closeContractResource(t, r)
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				t.Errorf("stop MCP runtime: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("MCP runtime did not stop")
		}
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "core-contract", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("initialize stdio contract: %v", err)
	}
	return session
}

func connectHTTPContract(t *testing.T, ctx context.Context) *mcp.ClientSession {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	opts := mcpruntime.DefaultHTTPOptions()
	opts.Listen = server.Listener.Addr().String()
	opts.PublicURL = "http://" + opts.Listen
	opts.Token = "synthetic-core-contract-token-0123456789"
	opts.StateDir = filepath.Join(t.TempDir(), "transfers")
	r, err := mcpruntime.NewRuntime(ctx, contractOptions(t, &opts)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeContractResource(t, r) })
	server.Config.ReadHeaderTimeout = time.Second
	server.Config.IdleTimeout = time.Second
	server.Config.Handler, err = r.HTTPHandler()
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	base := server.Client().Transport
	client := mcp.NewClient(&mcp.Implementation{Name: "core-contract", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: server.URL + "/mcp", MaxRetries: -1,
		HTTPClient: &http.Client{Transport: contractBearer{base: base, token: opts.Token}, Timeout: 5 * time.Second},
	}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatalf("initialize HTTP contract: %v", err)
	}
	return session
}

type contractBearer struct {
	base  http.RoundTripper
	token string
}

func (b contractBearer) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(cloned)
}

func closeContractResource(t *testing.T, resource io.Closer) {
	t.Helper()
	if err := resource.Close(); err != nil {
		t.Errorf("close contract resource: %v", err)
	}
}
