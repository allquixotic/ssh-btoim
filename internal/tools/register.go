package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sean/ssh-btoim/internal/output"
	"github.com/sean/ssh-btoim/internal/session"
	"github.com/sean/ssh-btoim/internal/sshconfig"
)

// RegisterAll wires all MCP tools to the server.
func RegisterAll(server *mcp.Server, mgr *session.Manager, resolver *sshconfig.Resolver, out *output.Handler) {
	registerExec(server, mgr, out)
	registerListHosts(server, mgr, resolver)
	registerListSessions(server, mgr)
	registerDisconnect(server, mgr)
	registerUpload(server, mgr)
}

// errResult creates a CallToolResult indicating a tool-level error.
func errResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: msg},
		},
		IsError: true,
	}
}
