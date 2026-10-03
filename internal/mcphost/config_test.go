package mcphost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/pkg/config"
)

// Runtime construction must preserve the CLI's transport-specific publication
// semantics after removing the old constructors and option wrappers.
func TestRuntimeInventoryPublication(t *testing.T) {
	for _, mode := range []string{"stdio", "http", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			isolateMCPTestEnvironment(t)
			configuration := runtimeTestProvider("node").Snapshot()
			repo, err := config.NewRepositoryWithoutOpenSSH(configuration, &tunnelSnapshotStore{cfg: configuration})
			if err != nil {
				t.Fatal(err)
			}
			host := Config{Provider: repo, Recovery: mode == "recovery"}
			if mode == "http" {
				httpOptions := mcpruntime.DefaultHTTPOptions()
				httpOptions.Token = "synthetic-host-config-token-0123456789"
				httpOptions.StateDir = filepath.Join(t.TempDir(), "transfers")
				httpOptions.PublicURL = "http://127.0.0.1:19876"
				host.HTTP = &httpOptions
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			runtime, err := newTestRuntime(ctx, host)
			if err != nil {
				t.Fatal(err)
			}
			client := protocolClient(t, runtime, "2025-11-25", nil)
			if _, err := repo.UpdateNodeTagsContext(ctx, []string{"node"}, []string{"published"}, true); err != nil {
				t.Fatal(err)
			}
			var output mcpruntime.ListNodesOutput
			if _, err := callTool(ctx, client, "xops_list_nodes", mcpruntime.ListNodesInput{Tag: "published"}, &output); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "stdio" {
				want = 1
			}
			if len(output.Nodes) != want {
				t.Fatalf("%s saw %d published nodes, want %d", mode, len(output.Nodes), want)
			}
		})
	}
}

func TestRuntimeOptionsRequireProvider(t *testing.T) {
	if _, err := (Config{}).RuntimeOptions(); err == nil {
		t.Fatal("missing CLI configuration accepted")
	}
}

func TestRuntimeDefaultAuditPath(t *testing.T) {
	home := isolateMCPTestEnvironment(t)
	configuration := runtimeTestProvider("node").Snapshot()
	configuration.Guardrail = nil
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	runtime, err := newTestRuntime(ctx, Config{Provider: config.NewProviderWithoutOpenSSH(configuration)})
	if err != nil {
		t.Fatal(err)
	}
	client := protocolClient(t, runtime, "2025-11-25", nil)
	var output mcpruntime.ListNodesOutput
	if _, err := callTool(ctx, client, "xops_list_nodes", mcpruntime.ListNodesInput{}, &output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(home, ".xops", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"tool":"xops_list_nodes"`) {
		t.Fatalf("CLI audit did not record the tool: %s", data)
	}
}
