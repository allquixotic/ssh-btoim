package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sean/ssh-btoim/internal/session"
)

type ListSessionsInput struct{}

func registerListSessions(server *mcp.Server, mgr *session.Manager) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "ssh_list_sessions",
		Description: "List all currently active SSH sessions with connection details and timing.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args ListSessionsInput) (*mcp.CallToolResult, any, error) {
		sessions := mgr.ListSessions()
		if len(sessions) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: "No active SSH sessions."},
				},
			}, nil, nil
		}

		var b strings.Builder
		b.WriteString("Active SSH Sessions:\n\n")
		b.WriteString(fmt.Sprintf("  %-20s %-40s %-12s %-15s %s\n", "Host", "HostName", "User", "Connected For", "Last Used"))
		b.WriteString(fmt.Sprintf("  %-20s %-40s %-12s %-15s %s\n", "----", "--------", "----", "-------------", "---------"))

		now := time.Now()
		for _, s := range sessions {
			connDur := now.Sub(s.ConnectedAt).Truncate(time.Second)
			lastUsed := now.Sub(s.LastUsedAt).Truncate(time.Second)
			b.WriteString(fmt.Sprintf("  %-20s %-40s %-12s %-15s %s ago\n",
				s.Alias, s.HostName, s.User, connDur, lastUsed))
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: b.String()},
			},
		}, nil, nil
	})
}
