package runtime

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
)

// registerTools registers the converged minimal MCP toolset with guardrail protection.
func (r *Runtime) registerTools(server *mcp.Server, g *guardrail.Guardrail) {
	r.registerNodes(server)
	r.registerTerminal(server, g)
	r.registerFile(server, g)
	r.registerGUI(server, g)
	r.registerTransfer(server, g)
	if r.http == nil {
		r.registerTunnels(server)
	}
}
