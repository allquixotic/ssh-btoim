package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sean/ssh-btoim/internal/session"
)

type DisconnectInput struct {
	Host string `json:"host,omitempty" jsonschema:"SSH host alias to disconnect. If empty, disconnects all active sessions."`
}

func registerDisconnect(server *mcp.Server, mgr *session.Manager) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "ssh_disconnect",
		Description: "Disconnect an active SSH session, or disconnect all sessions if no host is specified.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args DisconnectInput) (*mcp.CallToolResult, any, error) {
		if args.Host == "" {
			sessions := mgr.ListSessions()
			mgr.DisconnectAll()
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("Disconnected all %d active sessions.", len(sessions))},
				},
			}, nil, nil
		}

		if err := mgr.Disconnect(args.Host); err != nil {
			return errResult(err.Error()), nil, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Disconnected from %s.", args.Host)},
			},
		}, nil, nil
	})
}
