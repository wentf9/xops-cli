package mcpserver

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
)

// registerTools 统一注册各模块的 MCP 能力，并注入安全护栏
func (r *Runtime) registerTools(server *mcp.Server, g *guardrail.Guardrail) {
	r.registerSSH(server, g)
	r.registerSFTP(server, g)
	r.registerFS(server, g)
	if r.http != nil {
		r.registerTransfers(server)
	} else {
		r.registerTunnels(server)
	}
}
