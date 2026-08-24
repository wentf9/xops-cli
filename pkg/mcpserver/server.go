package mcpserver

import (
	"context"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type mcpInteractionHandler struct{}

var _ ssh.InteractionHandler = (*mcpInteractionHandler)(nil)

func (h *mcpInteractionHandler) PromptPassword(prompt string) (string, error) {
	return "", fmt.Errorf("interactive password prompt is disabled in MCP mode")
}

func (h *mcpInteractionHandler) ConfirmHostKey(hostname string, fingerprint string) (bool, error) {
	return false, fmt.Errorf("interactive host key verification is disabled in MCP mode (please establish trust via CLI first)")
}

var (
	mcpConnector *ssh.Connector
	mcpProvider  config.ConfigProvider
	mcpMu        sync.RWMutex
)

func getMCPConnector() (*ssh.Connector, error) {
	mcpMu.RLock()
	if mcpConnector != nil {
		defer mcpMu.RUnlock()
		return mcpConnector, nil
	}
	mcpMu.RUnlock()

	mcpMu.Lock()
	defer mcpMu.Unlock()
	if mcpConnector != nil {
		return mcpConnector, nil
	}

	_, provider, _, loadErr := utils.GetConfigStore()
	if loadErr != nil {
		return nil, loadErr
	}
	mcpProvider = provider
	mcpConnector = newMCPConnector(provider)
	return mcpConnector, nil
}

func getMCPProvider() (config.ConfigProvider, error) {
	mcpMu.RLock()
	if mcpProvider != nil {
		defer mcpMu.RUnlock()
		return mcpProvider, nil
	}
	mcpMu.RUnlock()

	_, err := getMCPConnector()
	if err != nil {
		return nil, err
	}

	mcpMu.RLock()
	defer mcpMu.RUnlock()
	return mcpProvider, nil
}

// newMCPConnector creates a connector pre-configured to reject all interactive prompts,
// avoiding blocking stdin/stdout and breaking JSON-RPC framing.
func newMCPConnector(provider config.ConfigProvider) *ssh.Connector {
	adp := adapter.NewSSHAdapter(provider)
	conn := ssh.NewConnector(adp, &mcpInteractionHandler{})
	if cfg := provider.GetConfig(); cfg != nil {
		conn.PasswordPromptPattern = cfg.PasswordPromptPattern
	}
	// MCP server 为长驻进程，启用周期心跳主动感知空闲连接断连并驱逐，
	// 下次工具调用自动重建。传 Background 是因为 getMCPConnector 惰性创建
	// 拿不到 Serve 的 ctx；Serve 的两条退出路径（signal 取消 / stdio EOF）
	// 均会执行 Serve 末尾的 CloseAll，心跳清理由 CloseAll 兜底
	conn.EnableKeepAlive(context.Background(), ssh.DefaultKeepAliveInterval, ssh.DefaultKeepAliveTimeout)
	return conn
}

func Serve(ctx context.Context) error {
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

	g := loadGuardrail()

	RegisterTools(server, g)

	transport := &mcp.StdioTransport{}
	runErr := server.Run(ctx, transport)

	mcpMu.Lock()
	if mcpConnector != nil {
		mcpConnector.CloseAll()
		mcpConnector = nil
		mcpProvider = nil
	}
	mcpMu.Unlock()

	if runErr != nil {
		return fmt.Errorf("MCP Server error: %w", runErr)
	}
	return nil
}

// loadGuardrail reads GuardrailConfig from the user config file.
// Falls back to defaults if config is absent or unreadable.
func loadGuardrail() *guardrail.Guardrail {
	_, _, cfg, err := utils.GetConfigStore()
	if err != nil || cfg == nil || cfg.Guardrail == nil {
		return guardrail.New(nil)
	}
	return guardrail.New(cfg.Guardrail)
}
