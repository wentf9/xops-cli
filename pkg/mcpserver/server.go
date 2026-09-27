package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/mcpserver/transfer"
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
	logger             logger.DebugLogger
	provider           config.ConfigProvider
	credentialRegistry adapter.CredentialResolver
	http               *HTTPOptions
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

// WithCredentialRegistry injects a credential registry so MCP connections can
// resolve stored secrets. When set, the MCP connector is configured with
// WithCredentialSource so SSH nodes can authenticate without interactive prompts.
func WithCredentialRegistry(r adapter.CredentialResolver) Option {
	return func(c *serverConfig) {
		c.credentialRegistry = r
	}
}

// Runtime owns a single MCP server and its SSH resources. Independent runtimes
// can coexist; Close cancels keepalive and closes only this runtime's sessions.
type Runtime struct {
	ctx            context.Context
	cancel         context.CancelFunc
	provider       config.ConfigProvider
	connector      *ssh.Connector
	server         *mcp.Server
	guardrail      *guardrail.Guardrail
	closeOnce      sync.Once
	closeErr       error
	http           *HTTPOptions
	httpHandler    http.Handler
	transfers      *transfer.Manager
	transferDial   func(context.Context, string) (transferRemote, error)
	logger         logger.DebugLogger
	initializeGate chan struct{}
	recoveryDone   <-chan struct{}
}

func (r *Runtime) getMCPConnector() (*ssh.Connector, error) {
	if r == nil || r.connector == nil {
		return nil, errors.New("mcp connector is not initialized")
	}
	if err := r.ctx.Err(); err != nil {
		return nil, fmt.Errorf("mcp runtime is closed: %w", err)
	}
	return r.connector, nil
}

func (r *Runtime) getMCPProvider() (config.ConfigProvider, error) {
	if r == nil || r.provider == nil {
		return nil, errors.New("mcp config provider is not initialized")
	}
	if err := r.ctx.Err(); err != nil {
		return nil, fmt.Errorf("mcp runtime is closed: %w", err)
	}
	return r.provider, nil
}

// newMCPConnector creates a connector pre-configured to reject all interactive prompts,
// avoiding blocking stdin/stdout and breaking JSON-RPC framing.
// When credentialRegistry is non-nil, stored credentials are resolved automatically.
func newMCPConnector(ctx context.Context, provider config.ConfigProvider, l logger.DebugLogger, credentialRegistry adapter.CredentialResolver) *ssh.Connector {
	var sshOpts []ssh.Option
	if l != nil {
		sshOpts = append(sshOpts, ssh.WithLogger(l))
	} else {
		sshOpts = append(sshOpts, ssh.WithLogger(logger.NopLogger))
	}
	if cfg := provider.Snapshot(); cfg != nil && cfg.PasswordPromptPattern != "" {
		sshOpts = append(sshOpts, ssh.WithPasswordPromptPattern(cfg.PasswordPromptPattern))
	}
	adpOpts := []adapter.Option{adapter.WithNonInteractive(true)}
	if credentialRegistry != nil {
		adpOpts = append(adpOpts, adapter.WithCredentialSource(credentialRegistry))
	}
	conn := adapter.NewConnectorWithAdapterOptions(provider, adpOpts, sshOpts...)
	conn.EnableKeepAlive(ctx, ssh.DefaultKeepAliveInterval, ssh.DefaultKeepAliveTimeout)
	return conn
}

// connectMCPNode connects to an SSH node using this runtime’s MCP connector,
// wrapping any internal error with FormatMCPError.
func (r *Runtime) connectMCPNode(ctx context.Context, nodeID string) (*ssh.Client, error) {
	connector, err := r.getMCPConnector()
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
func (r *Runtime) getMCPSFTPClient(ctx context.Context, nodeID string) (*sftp.Client, error) {
	sshClient, err := r.connectMCPNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	sftpClient, err := sftp.NewClient(ctx, sshClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create sftp client: %w", err)
	}
	return sftpClient, nil
}

// NewRuntime validates dependencies before starting any background work. The
// caller owns Close, including when connecting a transport fails.
func NewRuntime(ctx context.Context, opts ...Option) (*Runtime, error) {
	if ctx == nil {
		return nil, errors.New("mcp context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("initialize mcp runtime: %w", err)
	}
	cfg := &serverConfig{logger: logger.NopLogger}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.provider == nil {
		return nil, errors.New("mcp config provider is required")
	}
	// Network tasks retain a fixed inventory and OpenSSH snapshot. Stdio keeps
	// its existing repository update capabilities for learned SSH settings.
	if cfg.http != nil {
		if provider, ok := cfg.provider.(interface{ Frozen() config.ConfigProvider }); ok {
			cfg.provider = provider.Frozen()
		}
	}
	var guardrailConfig *config.GuardrailConfig
	if configuration := cfg.provider.Snapshot(); configuration != nil {
		guardrailConfig = configuration.Guardrail
	}
	if err := guardrail.ValidateConfig(guardrailConfig); err != nil {
		return nil, fmt.Errorf("validate mcp guardrail config failed: %w", err)
	}
	if cfg.http != nil {
		if err := cfg.http.validate(); err != nil {
			return nil, fmt.Errorf("validate MCP HTTP configuration: %w", err)
		}
		if guardrailConfig == nil {
			guardrailConfig = guardrail.DefaultGuardrailConfig()
			guardrailConfig.NoElicitFallback = guardrail.FallbackDeny
		} else if guardrailConfig.NoElicitFallback == "" {
			guardrailConfig.NoElicitFallback = guardrail.FallbackDeny
		}
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	r := &Runtime{ctx: runtimeCtx, cancel: cancel, provider: cfg.provider, guardrail: guardrail.New(guardrailConfig), http: cfg.http, logger: cfg.logger}
	if cfg.http != nil {
		journal, err := transfer.OpenJournal(cfg.http.StateDir)
		if err != nil {
			cancel()
			return nil, err
		}
		manager, err := transfer.NewManager(runtimeCtx, journal, cfg.http.Transfers)
		if err != nil {
			cancel()
			return nil, err
		}
		r.transfers = manager
	}
	r.connector = newMCPConnector(runtimeCtx, cfg.provider, cfg.logger, cfg.credentialRegistry)
	serverOptions := &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}},
	}
	if cfg.http != nil {
		serverOptions.SupportedProtocolVersions = []string{httpProtocolVersion}
	}
	r.server = mcp.NewServer(&mcp.Implementation{Name: "xops-mcp", Version: "v1.0.0"}, serverOptions)
	r.registerTools(r.server, r.guardrail)
	if cfg.http != nil {
		r.server.AddReceivingMiddleware(r.toolDeadline)
		r.httpHandler = r.newHTTPHandler()
		r.startRecoveryCleanup()
	}
	return r, nil
}

// Run serves a transport until it ends or the runtime is closed. It does not
// relinquish the caller's responsibility to close the runtime.
func (r *Runtime) Run(transport mcp.Transport) error {
	if transport == nil {
		return errors.New("mcp transport is required")
	}
	if err := r.ctx.Err(); err != nil {
		return fmt.Errorf("run mcp runtime: %w", err)
	}
	if err := r.server.Run(r.ctx, transport); err != nil {
		return fmt.Errorf("mcp server error: %w", err)
	}
	return nil
}

// Close is idempotent and cancels the runtime before joining its resources.
func (r *Runtime) Close() error {
	r.closeOnce.Do(func() {
		r.cancel()
		duration := 45 * time.Second
		if r.http != nil {
			duration = r.http.ShutdownTimeout
		}
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), duration)
		defer cancel()
		if r.recoveryDone != nil {
			select {
			case <-r.recoveryDone:
			case <-shutdownCtx.Done():
				r.closeErr = errors.Join(r.closeErr, fmt.Errorf("wait for recovery cleanup: %w", shutdownCtx.Err()))
			}
		}
		if r.transfers != nil {
			if err := r.transfers.Shutdown(shutdownCtx); err != nil {
				r.closeErr = errors.Join(r.closeErr, fmt.Errorf("close MCP transfers: %w", err))
			}
		}
		if r.initializeGate != nil {
			select {
			case r.initializeGate <- struct{}{}:
				defer func() { <-r.initializeGate }()
			case <-shutdownCtx.Done():
				r.closeErr = errors.Join(r.closeErr, fmt.Errorf("wait for MCP initialization: %w", shutdownCtx.Err()))
			}
		}
		for session := range r.server.Sessions() {
			if err := session.Close(); err != nil {
				r.closeErr = errors.Join(r.closeErr, fmt.Errorf("close mcp session: %w", err))
			}
		}
		if err := r.connector.CloseAll(); err != nil {
			r.closeErr = errors.Join(r.closeErr, fmt.Errorf("close mcp connector: %w", err))
		}
		if r.transfers != nil && shutdownCtx.Err() != nil {
			// Forced SSH closure unblocks any committing operation whose grace
			// period elapsed. Give handlers a bounded chance to persist Unknown
			// and release the metadata lock before returning the shutdown error.
			forcedCtx, stop := context.WithTimeout(context.WithoutCancel(r.ctx), 2*time.Second)
			defer stop()
			r.closeErr = errors.Join(r.closeErr, r.transfers.Shutdown(forcedCtx))
		}
	})
	return r.closeErr
}

// Serve runs the stdio transport with deterministic runtime cleanup.
func Serve(ctx context.Context, opts ...Option) (retErr error) {
	r, err := NewRuntime(ctx, opts...)
	if err != nil {
		return err
	}
	defer joinCloseError(&retErr, r, "mcp runtime")
	return r.Run(&mcp.StdioTransport{})
}
