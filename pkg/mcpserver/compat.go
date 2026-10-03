// Package mcpserver retains CLI configuration and credential composition for
// the shared MCP runtime. Protocol and execution code live under core.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	core "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/logger"
	"time"
)

type CreateTunnelInput = core.CreateTunnelInput
type FSBaseOutput = core.FSBaseOutput
type FSCpInput = core.FSCpInput
type FSListInput = core.FSListInput
type FSListOutput = core.FSListOutput
type FSMkdirInput = core.FSMkdirInput
type FSMvInput = core.FSMvInput
type FSRmInput = core.FSRmInput
type FSTouchInput = core.FSTouchInput
type FileInfo = core.FileInfo
type HTTPOptions = core.HTTPOptions
type ListNodesInput = core.ListNodesInput
type ListNodesOutput = core.ListNodesOutput
type ListTunnelsInput = core.ListTunnelsInput
type ListTunnelsOutput = core.ListTunnelsOutput
type NodeInfo = core.NodeInfo
type PrepareDownloadInput = core.PrepareDownloadInput
type PrepareUploadInput = core.PrepareUploadInput
type PreparedTransferOutput = core.PreparedTransferOutput
type ReadFileInput = core.ReadFileInput
type ReadFileOutput = core.ReadFileOutput
type RecoveryEntry = core.RecoveryEntry
type RecoveryOptions = core.RecoveryOptions
type Runtime = core.Runtime
type SshRunInput = core.SshRunInput
type SshRunOutput = core.SshRunOutput
type TransferFileInput = core.TransferFileInput
type TransferFileOutput = core.TransferFileOutput
type TransferTaskInput = core.TransferTaskInput
type TunnelInput = core.TunnelInput
type TunnelOutput = core.TunnelOutput
type WriteFileInput = core.WriteFileInput
type WriteFileOutput = core.WriteFileOutput

type legacyConfig struct {
	provider    config.ConfigProvider
	registry    adapter.CredentialResolver
	logger      logger.DebugLogger
	http        *HTTPOptions
	recovery    bool
	toolTimeout *time.Duration
}
type Option func(*legacyConfig)

func WithConfigProvider(provider config.ConfigProvider) Option {
	return func(c *legacyConfig) { c.provider = provider }
}
func WithCredentialRegistry(registry adapter.CredentialResolver) Option {
	return func(c *legacyConfig) { c.registry = registry }
}
func WithLogger(log logger.DebugLogger) Option { return func(c *legacyConfig) { c.logger = log } }
func WithHTTP(options HTTPOptions) Option      { return func(c *legacyConfig) { c.http = &options } }
func WithToolTimeout(timeout time.Duration) Option {
	return func(c *legacyConfig) { c.toolTimeout = &timeout }
}
func DefaultHTTPOptions() HTTPOptions { return core.DefaultHTTPOptions() }
func FormatMCPError(err error) error  { return core.FormatMCPError(err) }

func legacyOptions(opts []Option) ([]core.Option, error) {
	cfg := legacyConfig{logger: logger.NopLogger}
	for _, option := range opts {
		if option != nil {
			option(&cfg)
		}
	}
	if cfg.provider == nil {
		return nil, errors.New("mcp config provider is required")
	}
	if cfg.http != nil || cfg.recovery {
		if frozen, ok := cfg.provider.(interface{ Frozen() config.ConfigProvider }); ok {
			cfg.provider = frozen.Frozen()
		}
	}
	host := newLegacyHost(cfg)
	coreOptions := []core.Option{core.WithDependencies(host.dependencies()), core.WithLogger(cfg.logger)}
	if cfg.http != nil {
		coreOptions = append(coreOptions, core.WithHTTP(*cfg.http))
	}
	if cfg.toolTimeout != nil {
		coreOptions = append(coreOptions, core.WithToolTimeout(*cfg.toolTimeout))
	} else if cfg.http == nil {
		settings := cfg.provider.Snapshot().MCP
		if settings != nil && settings.ToolTimeout != "" {
			timeout, err := time.ParseDuration(settings.ToolTimeout)
			if err != nil || timeout <= 0 {
				return nil, fmt.Errorf("mcp.tool_timeout must be a positive duration")
			}
			coreOptions = append(coreOptions, core.WithToolTimeout(timeout))
		}
	}
	return coreOptions, nil
}
func NewRuntime(ctx context.Context, opts ...Option) (*Runtime, error) {
	options, err := legacyOptions(opts)
	if err != nil {
		return nil, err
	}
	return core.NewRuntime(ctx, options...)
}
func Serve(ctx context.Context, opts ...Option) (retErr error) {
	runtime, err := NewRuntime(ctx, opts...)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, runtime.Close()) }()
	return runtime.Run(&mcp.StdioTransport{})
}
func RecoverTransfers(ctx context.Context, options RecoveryOptions, opts ...Option) ([]RecoveryEntry, error) {
	// Listing a journal is independent of inventory and credentials.
	if !options.Verify && !options.Cleanup && !options.ResolveUnknown {
		return core.RecoverTransfers(ctx, options)
	}
	// Deferred file tasks originate in HTTP mode. Reconstruct its policy
	// defaults without opening another journal or serving an HTTP transport.
	recoveryOptions := append([]Option{}, opts...)
	recoveryOptions = append(recoveryOptions, func(c *legacyConfig) { c.recovery = true })
	configuration, err := legacyOptions(recoveryOptions)
	if err != nil {
		return nil, err
	}
	return core.RecoverTransfers(ctx, options, configuration...)
}
