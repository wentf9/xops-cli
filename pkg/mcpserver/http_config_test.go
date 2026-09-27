package mcpserver

import (
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/config"
)

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
