package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
)

// TestExternalClientProbe is an opt-in, isolated compatibility fixture. The
// caller provides a private artifact directory and creates "done" after real
// client checks. All target files live only in loopback SFTP memory.
func TestExternalClientProbe(t *testing.T) {
	directory := os.Getenv("XOPS_TEST_MCP_PROBE_DIR")
	if directory == "" {
		t.Skip("set XOPS_TEST_MCP_PROBE_DIR for real-client validation")
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		t.Fatal("probe directory must already exist")
	}
	r, server, _ := startTransferRuntime(t, nil, pkgsftp.InMemHandler(), func(r *Runtime) {
		policy := guardrail.New(&config.GuardrailConfig{Enabled: true, ApprovalThreshold: "dangerous", NoElicitFallback: guardrail.FallbackDeny})
		mcp.AddTool(r.server, &mcp.Tool{Name: "xops_probe_approval", Description: "Harmless approval compatibility probe; no remote or filesystem side effects"},
			guardrail.WithGuardrail(policy, "xops_probe_approval", func(struct{}) guardrail.RiskInput { return guardrail.RiskInput{} },
				func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, map[string]bool, error) {
					return nil, map[string]bool{"approved": true}, nil
				}))
		r.httpHandler = probeHTTPHandler(t, directory, r.httpHandler)
	})
	content := bytes.Repeat([]byte{0, 1, 2, 3, 254, 255}, 512)
	source := filepath.Join(directory, "source.bin")
	if err := os.WriteFile(source, content, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	ready := map[string]any{"endpoint": server.URL + "/mcp", "origin": server.URL, "token": httpTestToken,
		"nodeID": "files", "source": source, "size": len(content), "sha256": hex.EncodeToString(digest[:])}
	writeProbeJSON(t, filepath.Join(directory, "ready.json"), ready)
	t.Log("isolated client fixture ready")
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	deadline := time.NewTimer(10 * time.Minute)
	defer deadline.Stop()
	for {
		select {
		case <-t.Context().Done():
			return
		case <-deadline.C:
			t.Fatal("external client fixture timed out")
		case <-timer.C:
			if _, err := os.Stat(filepath.Join(directory, "done")); err == nil {
				statuses := make([]any, 0)
				for _, record := range r.transfers.Records() {
					statuses = append(statuses, record.Status())
				}
				writeProbeJSON(t, filepath.Join(directory, "tasks.json"), statuses)
				return
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		}
	}
}

func probeHTTPHandler(t *testing.T, directory string, next http.Handler) http.Handler {
	var logMu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		event := map[string]any{"method": req.Method, "path": req.URL.Path, "protocolHeader": req.Header.Get("MCP-Protocol-Version")}
		if req.URL.Path == "/mcp" && req.Method == http.MethodPost {
			if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Error(err)
				return
			}
			body, err := io.ReadAll(io.LimitReader(req.Body, (1<<20)+1))
			if err != nil {
				t.Error(err)
				return
			}
			closeTransferTestResource(t, req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
			var rpc struct {
				Method string
				Params struct {
					ProtocolVersion string
					ClientInfo      struct{ Name, Version string }
					Capabilities    map[string]json.RawMessage
					Name            string
				}
			}
			if err := json.Unmarshal(body, &rpc); err == nil {
				event["rpcMethod"], event["tool"] = rpc.Method, rpc.Params.Name
				if rpc.Method == "initialize" {
					event["requestedProtocol"], event["clientName"], event["clientVersion"] = rpc.Params.ProtocolVersion, rpc.Params.ClientInfo.Name, rpc.Params.ClientInfo.Version
					_, event["elicitation"] = rpc.Params.Capabilities["elicitation"]
				}
			}
		}
		logMu.Lock()
		writeProbeEvent(t, filepath.Join(directory, "wire.jsonl"), event)
		logMu.Unlock()
		next.ServeHTTP(w, req)
	})
}

func writeProbeEvent(t *testing.T, path string, event map[string]any) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		t.Error(err)
		return
	}
	defer closeTransferTestResource(t, file)
	if err := json.NewEncoder(file).Encode(event); err != nil {
		t.Error(err)
	}
}

func writeProbeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
