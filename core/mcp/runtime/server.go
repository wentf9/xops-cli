// Package runtime owns the shared MCP protocol, tools and task lifetimes.
// Application configuration, credential stores and UI belong to host adapters.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	logger "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/core/ssh"
	"net/http"
	"sync"
	"time"
)

type serverConfig struct {
	logger         logger.DebugLogger
	dependencies   ports.Dependencies
	http           *HTTPOptions
	tunnelRun      tunnel.Runner
	toolTimeout    time.Duration
	toolTimeoutSet bool
}
type Option func(*serverConfig)

func WithLogger(log logger.DebugLogger) Option {
	return func(c *serverConfig) {
		if !ports.Nil(log) {
			c.logger = log
		}
	}
}
func WithDependencies(dependencies ports.Dependencies) Option {
	return func(c *serverConfig) { c.dependencies = dependencies }
}

// WithTunnelRunner supplies a host-owned dedicated runner for compatibility
// adapters. HTTP never enables tunnel tools regardless of this option.
func WithTunnelRunner(run tunnel.Runner) Option { return func(c *serverConfig) { c.tunnelRun = run } }

// WithToolTimeout sets a positive tool deadline for stdio and HTTP. It overrides
// HTTPOptions.ToolTimeout regardless of option order, including HTTP request
// and SDK middleware deadlines. Session and file-transfer limits are independent.
func WithToolTimeout(timeout time.Duration) Option {
	return func(c *serverConfig) { c.toolTimeout = timeout; c.toolTimeoutSet = true }
}

type Runtime struct {
	ctx            context.Context
	cancel         context.CancelFunc
	provider       ports.StateSource
	gate           ports.ExecutionGate
	backend        ports.Backend
	server         *mcp.Server
	guardrail      *guardrail.Guardrail
	http           *HTTPOptions
	httpHandler    http.Handler
	transfers      *transfer.Manager
	transferDial   func(context.Context, string) (transferRemote, error)
	logger         logger.DebugLogger
	initializeGate chan struct{}
	recoveryDone   <-chan struct{}
	tunnels        *tunnel.Manager
	tunnelRun      tunnel.Runner
	toolTimeout    time.Duration
	closeOnce      sync.Once
	closeDone      chan struct{}
	closeErr       error
}

func FormatMCPError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ssh.ErrInteractionRequired) {
		return fmt.Errorf("ssh interaction required (prompts are disabled in MCP mode, please verify host key or configure credentials beforehand): %w", err)
	}
	return err
}

func NewRuntime(ctx context.Context, opts ...Option) (_ *Runtime, retErr error) {
	if ctx == nil {
		return nil, errors.New("mcp context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg := &serverConfig{logger: logger.NopLogger, toolTimeout: 5 * time.Minute}
	for _, option := range opts {
		if option != nil {
			option(cfg)
		}
	}
	if err := cfg.dependencies.Validate(); err != nil {
		return nil, err
	}
	if cfg.toolTimeout <= 0 {
		return nil, errors.New("MCP tool timeout must be positive")
	}
	if cfg.http != nil {
		if err := cfg.http.validate(); err != nil {
			return nil, fmt.Errorf("validate MCP HTTP configuration: %w", err)
		}
		if !cfg.toolTimeoutSet {
			cfg.toolTimeout = cfg.http.ToolTimeout
		}
	}
	initial, err := loadInitialState(ctx, cfg)
	if err != nil {
		return nil, err
	}
	work, cancel := context.WithCancel(ctx)
	r := &Runtime{ctx: work, cancel: cancel, provider: cfg.dependencies.State, gate: cfg.dependencies.Gate,
		guardrail: guardrail.NewWithAuditSink(&initial.Policy, cfg.dependencies.Audit), http: cfg.http, logger: cfg.logger,
		tunnelRun: cfg.tunnelRun, toolTimeout: cfg.toolTimeout, closeDone: make(chan struct{})}
	published := false
	defer func() {
		if !published {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer stop()
			retErr = errors.Join(retErr, r.Shutdown(cleanup))
		}
	}()
	r.backend, err = cfg.dependencies.NewBackend(work)
	if err != nil {
		return nil, fmt.Errorf("initialize MCP execution backend: %w", err)
	}
	if ports.Nil(r.backend) {
		return nil, errors.New("MCP backend factory returned no backend")
	}
	if err := work.Err(); err != nil {
		return nil, fmt.Errorf("MCP startup cancelled: %w", err)
	}
	if cfg.http != nil {
		journal, err := transfer.OpenJournal(cfg.http.StateDir)
		if err != nil {
			return nil, err
		}
		manager, err := transfer.NewManager(work, journal, cfg.http.Transfers)
		if err != nil {
			return nil, err
		}
		r.transfers = manager
	}
	r.initializeTunnels()
	options := &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}}}
	if cfg.http != nil {
		options.SupportedProtocolVersions = []string{httpProtocolVersion}
	}
	r.server = mcp.NewServer(&mcp.Implementation{Name: "xops-mcp", Version: "v1.0.0"}, options)
	r.registerTools(r.server, r.guardrail)
	if cfg.http != nil {
		r.server.AddReceivingMiddleware(r.toolDeadline)
		r.httpHandler = r.newHTTPHandler()
		r.startRecoveryCleanup()
	}
	published = true
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

func (r *Runtime) Close() error {
	duration := 45 * time.Second
	if r.http != nil {
		duration = r.http.ShutdownTimeout
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), duration)
	defer cancel()
	return r.Shutdown(ctx)
}

func (r *Runtime) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return errors.New("MCP shutdown context is required")
	}
	r.closeOnce.Do(func() {
		// The worker ends after all owned resources have been cancelled and joined.
		go func() { r.closeErr = r.shutdown(ctx); close(r.closeDone) }()
	})
	select {
	case <-r.closeDone:
		return r.closeErr
	case <-ctx.Done():
		return fmt.Errorf("wait for MCP shutdown: %w", ctx.Err())
	}
}

func (r *Runtime) shutdown(ctx context.Context) (result error) {
	r.cancel()
	if r.tunnels != nil {
		result = errors.Join(result, r.tunnels.Shutdown(ctx))
	}
	if r.recoveryDone != nil {
		select {
		case <-r.recoveryDone:
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		}
	}
	if r.transfers != nil {
		result = errors.Join(result, r.transfers.Shutdown(ctx))
	}
	if r.initializeGate != nil {
		select {
		case r.initializeGate <- struct{}{}:
			defer func() { <-r.initializeGate }()
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		}
	}
	if r.server != nil {
		for session := range r.server.Sessions() {
			result = errors.Join(result, session.Close())
		}
	}
	if !ports.Nil(r.backend) {
		result = errors.Join(result, r.backend.Shutdown(ctx))
	}
	if r.transfers != nil && ctx.Err() != nil {
		force, stop := context.WithTimeout(context.WithoutCancel(r.ctx), 2*time.Second)
		defer stop()
		result = errors.Join(result, r.transfers.Shutdown(force))
	}
	return result
}

func loadInitialState(ctx context.Context, cfg *serverConfig) (ports.OperationSnapshot, error) {
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	initial, err := cfg.dependencies.State.Resolve(initCtx, ports.ResolveRequest{})
	if err != nil {
		return ports.OperationSnapshot{}, fmt.Errorf("load initial MCP state: %w", err)
	}
	if err := initCtx.Err(); err != nil {
		return ports.OperationSnapshot{}, fmt.Errorf("load initial MCP state: %w", err)
	}
	if initial.DomainID != cfg.dependencies.State.DomainID() {
		return ports.OperationSnapshot{}, errors.New("MCP snapshot publication domain does not match source")
	}
	if err := guardrail.ValidateConfig(&initial.Policy); err != nil {
		return ports.OperationSnapshot{}, fmt.Errorf("validate mcp guardrail config failed: %w", err)
	}
	return initial.Clone(), nil
}
