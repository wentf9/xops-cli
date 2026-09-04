package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

// FormatMCPError converts internal SSH errors (such as ErrInteractionRequired) into user-friendly MCP errors.
func FormatMCPError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ssh.ErrInteractionRequired) {
		return fmt.Errorf("ssh interaction required (prompts are disabled in MCP mode, please verify host key or configure credentials beforehand): %w", err)
	}
	return err
}

type serverConfig struct {
	logger   logger.DebugLogger
	provider config.ConfigProvider
}

// Option configures the MCP server runtime.
type Option func(*serverConfig)

// WithLogger injects a custom DebugLogger into MCP server and its underlying SSH connector.
func WithLogger(l logger.DebugLogger) Option {
	return func(c *serverConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithConfigProvider injects the configuration used by MCP tools and guardrails.
// Callers must fully load and validate the configuration before starting Serve.
func WithConfigProvider(provider config.ConfigProvider) Option {
	return func(c *serverConfig) {
		c.provider = provider
	}
}

var (
	mcpConnector *ssh.Connector
	mcpProvider  config.ConfigProvider
	mcpMu        sync.RWMutex
)

func getMCPConnector() (*ssh.Connector, error) {
	mcpMu.RLock()
	defer mcpMu.RUnlock()
	if mcpConnector == nil {
		return nil, errors.New("mcp connector is not initialized")
	}
	return mcpConnector, nil
}

func getMCPProvider() (config.ConfigProvider, error) {
	mcpMu.RLock()
	defer mcpMu.RUnlock()
	if mcpProvider == nil {
		return nil, errors.New("mcp config provider is not initialized")
	}
	return mcpProvider, nil
}

// newMCPConnector creates a connector pre-configured to reject all interactive prompts,
// avoiding blocking stdin/stdout and breaking JSON-RPC framing.
func newMCPConnector(ctx context.Context, provider config.ConfigProvider, l logger.DebugLogger) *ssh.Connector {
	var opts []ssh.Option
	if l != nil {
		opts = append(opts, ssh.WithLogger(l))
	} else {
		opts = append(opts, ssh.WithLogger(logger.NopLogger))
	}
	if cfg := provider.Snapshot(); cfg != nil && cfg.PasswordPromptPattern != "" {
		opts = append(opts, ssh.WithPasswordPromptPattern(cfg.PasswordPromptPattern))
	}
	conn := adapter.NewConnector(provider, opts...)
	conn.EnableKeepAlive(ctx, ssh.DefaultKeepAliveInterval, ssh.DefaultKeepAliveTimeout)
	return conn
}

// connectMCPNode connects to an SSH node using the global MCP connector,
// wrapping any internal error with FormatMCPError.
func connectMCPNode(ctx context.Context, nodeID string) (*ssh.Client, error) {
	connector, err := getMCPConnector()
	if err != nil {
		return nil, err
	}
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ssh: %w", FormatMCPError(err))
	}
	return client, nil
}

// getMCPSFTPClient returns a new SFTP client for the node, formatting any connection error.
func getMCPSFTPClient(ctx context.Context, nodeID string) (*sftp.Client, error) {
	sshClient, err := connectMCPNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	sftpClient, err := sftp.NewClient(ctx, sshClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create sftp client: %w", err)
	}
	return sftpClient, nil
}

// Serve runs the MCP server until ctx is canceled. A configuration provider must
// be supplied with WithConfigProvider so configuration failures remain visible to
// the CLI composition root.
func Serve(ctx context.Context, opts ...Option) (retErr error) {
	cfg := &serverConfig{
		logger: logger.NopLogger,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.provider == nil {
		retErr = errors.New("mcp config provider is required")
		return retErr
	}
	var guardrailConfig *config.GuardrailConfig
	if configuration := cfg.provider.Snapshot(); configuration != nil {
		guardrailConfig = configuration.Guardrail
	}
	if err := guardrail.ValidateConfig(guardrailConfig); err != nil {
		return fmt.Errorf("validate mcp guardrail config failed: %w", err)
	}

	mcpMu.Lock()
	if mcpConnector != nil {
		mcpMu.Unlock()
		retErr = errors.New("mcp server is already running")
		return retErr
	}
	mcpProvider = cfg.provider
	mcpConnector = newMCPConnector(ctx, cfg.provider, cfg.logger)
	mcpMu.Unlock()
	defer func() {
		mcpMu.Lock()
		if closeErr := mcpConnector.CloseAll(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close mcp connector failed: %w", closeErr))
		}
		mcpConnector = nil
		mcpProvider = nil
		mcpMu.Unlock()
	}()

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "xops-mcp",
			Version: "v1.0.0",
		},
		&mcp.ServerOptions{
			Capabilities: &mcp.ServerCapabilities{
				Tools: &mcp.ToolCapabilities{ListChanged: true},
			},
		},
	)

	g := guardrail.New(guardrailConfig)

	RegisterTools(server, g)

	transport := &mcp.StdioTransport{}
	runErr := server.Run(ctx, transport)

	if runErr != nil {
		return fmt.Errorf("mcp server error: %w", runErr)
	}
	return nil
}
