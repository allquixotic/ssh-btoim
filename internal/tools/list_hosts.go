package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sean/ssh-btoim/internal/session"
	"github.com/sean/ssh-btoim/internal/sshconfig"
)

type ListHostsInput struct{}

func registerListHosts(server *mcp.Server, mgr *session.Manager, resolver *sshconfig.Resolver) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "ssh_list_hosts",
		Description: "List all SSH hosts configured in ~/.ssh/config with their connection details and whether they have an active session.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args ListHostsInput) (*mcp.CallToolResult, any, error) {
		hosts := resolver.ListHosts()
		if len(hosts) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: "No hosts found in ~/.ssh/config"},
				},
			}, nil, nil
		}

		var b strings.Builder
		b.WriteString("SSH Hosts (from ~/.ssh/config):\n\n")
		b.WriteString(fmt.Sprintf("  %-20s %-40s %-12s %-6s %s\n", "Host", "HostName", "User", "Port", "Connected"))
		b.WriteString(fmt.Sprintf("  %-20s %-40s %-12s %-6s %s\n", "----", "--------", "----", "----", "---------"))

		for _, alias := range hosts {
			resolved, err := resolver.Resolve(alias)
			if err != nil {
				continue
			}
			connected := "no"
			if mgr.IsConnected(alias) {
				connected = "yes"
			}
			b.WriteString(fmt.Sprintf("  %-20s %-40s %-12s %-6s %s\n",
				resolved.Alias, resolved.HostName, resolved.User, resolved.Port, connected))
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: b.String()},
			},
		}, nil, nil
	})
}
