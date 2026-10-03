package mcphost

import (
	"fmt"
	"time"

	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/pkg/config"
)

// HTTPOptionsFromConfig overlays explicit settings. Token loading and the
// default state directory are owned by the CLI composition root.
func HTTPOptionsFromConfig(c *config.MCPConfig) (mcpruntime.HTTPOptions, error) {
	o := mcpruntime.DefaultHTTPOptions()
	if c == nil {
		return o, nil
	}
	if c.Listen != "" {
		o.Listen = c.Listen
	}
	o.PublicURL, o.StateDir = c.PublicURL, c.StateDir
	o.AllowedHosts, o.AllowedOrigins = append([]string(nil), c.AllowedHosts...), append([]string(nil), c.AllowedOrigins...)
	for _, d := range []struct {
		name, raw string
		out       *time.Duration
	}{
		{"header_timeout", c.HeaderTimeout, &o.HeaderTimeout}, {"body_timeout", c.BodyTimeout, &o.BodyTimeout},
		{"stream_idle_timeout", c.StreamIdle, &o.StreamIdle}, {"tool_timeout", c.ToolTimeout, &o.ToolTimeout},
		{"session_timeout", c.SessionTimeout, &o.SessionTimeout}, {"shutdown_timeout", c.ShutdownTimeout, &o.ShutdownTimeout},
		{"transfer_start_window", c.StartWindow, &o.Transfers.StartWindow}, {"transfer_retention", c.Retention, &o.Transfers.Retention},
		{"transfer_timeout", c.TotalTimeout, &o.Transfers.TotalTimeout}, {"commit_timeout", c.CommitTimeout, &o.Transfers.CommitTimeout},
	} {
		if d.raw == "" {
			continue
		}
		parsed, err := time.ParseDuration(d.raw)
		if err != nil || parsed <= 0 {
			return mcpruntime.HTTPOptions{}, fmt.Errorf("mcp.%s must be a positive duration", d.name)
		}
		*d.out = parsed
	}
	for _, l := range []struct{ value, out *int }{
		{c.MaxSessions, &o.MaxSessions}, {c.MaxRequests, &o.MaxRequests}, {c.MaxActive, &o.Transfers.MaxActive},
		{c.MaxPerTarget, &o.Transfers.MaxPerTarget}, {c.MaxReady, &o.Transfers.MaxReady}, {c.MaxRecords, &o.Transfers.MaxRecords},
	} {
		if l.value != nil {
			*l.out = *l.value
		}
	}
	if c.MaxFileBytes != nil {
		o.Transfers.MaxFileBytes = *c.MaxFileBytes
	}
	return o, o.ValidateLimits()
}
