package mcphost

import (
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/config"
)

func TestStdioToolDeadlineConfiguration(t *testing.T) {
	for _, value := range []string{"30m", "0s", "-1s", "invalid"} {
		cfg := runtimeTestProvider("node").Snapshot()
		cfg.MCP = &config.MCPConfig{ToolTimeout: value}
		r, err := newTestRuntime(t.Context(), Config{Provider: config.NewProviderWithoutOpenSSH(cfg)})
		if value == "30m" {
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			if closeErr := r.Close(); closeErr != nil {
				t.Error(closeErr)
			}
			t.Fatalf("invalid stdio deadline accepted: %s", value)
		}
	}
}

func TestHTTPConfiguredLimitsAndZeroRejection(t *testing.T) {
	maxActive := 8
	options, err := HTTPOptionsFromConfig(&config.MCPConfig{MaxActive: &maxActive, StreamIdle: "45s"})
	if err != nil || options.Transfers.MaxActive != 8 || options.StreamIdle != 45*time.Second {
		t.Fatalf("configured limits lost: %+v %v", options, err)
	}
	zero := 0
	for _, cfg := range []*config.MCPConfig{
		{MaxActive: &zero}, {MaxSessions: &zero}, {StreamIdle: "0s"}, {ToolTimeout: "-1s"}, {Retention: "1s"},
	} {
		if _, err := HTTPOptionsFromConfig(cfg); err == nil {
			t.Fatalf("invalid limits accepted: %+v", cfg)
		}
	}
}
