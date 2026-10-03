// Package mcphost adapts CLI configuration, credentials, and local resources
// to the shared MCP runtime. Protocol and execution belong to core/mcp.
package mcphost

import (
	"errors"
	"fmt"
	"time"

	corelog "github.com/wentf9/xops-cli/core/log"
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
)

// Config selects the application services and transport settings for a runtime.
// HTTP and recovery freeze the inventory at startup; stdio resolves each call.
type Config struct {
	Provider config.ConfigProvider
	Registry adapter.CredentialResolver
	Logger   corelog.DebugLogger
	HTTP     *mcpruntime.HTTPOptions
	Recovery bool
}

// RuntimeOptions converts CLI settings into explicit core dependencies.
// It does not open a listener or start a runtime. The caller owns that lifecycle.
func (cfg Config) RuntimeOptions() ([]mcpruntime.Option, error) {
	if cfg.Provider == nil {
		return nil, errors.New("mcp config provider is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = corelog.NopLogger
	}
	if cfg.HTTP != nil || cfg.Recovery {
		if frozen, ok := cfg.Provider.(interface{ Frozen() config.ConfigProvider }); ok {
			cfg.Provider = frozen.Frozen()
		}
	}
	host := newHost(cfg)
	options := []mcpruntime.Option{mcpruntime.WithDependencies(host.dependencies()), mcpruntime.WithLogger(cfg.Logger)}
	if cfg.HTTP != nil {
		options = append(options, mcpruntime.WithHTTP(*cfg.HTTP))
	} else if settings := cfg.Provider.Snapshot().MCP; settings != nil && settings.ToolTimeout != "" {
		timeout, err := time.ParseDuration(settings.ToolTimeout)
		if err != nil || timeout <= 0 {
			return nil, fmt.Errorf("mcp.tool_timeout must be a positive duration")
		}
		options = append(options, mcpruntime.WithToolTimeout(timeout))
	}
	return options, nil
}
