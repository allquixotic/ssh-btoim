package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sean/ssh-btoim/internal/output"
	"github.com/sean/ssh-btoim/internal/session"
)

type ExecInput struct {
	Host      string `json:"host" jsonschema:"SSH host alias from ~/.ssh/config or a hostname/IP"`
	Command   string `json:"command" jsonschema:"Shell command to execute on the remote host"`
	Timeout   int    `json:"timeout,omitempty" jsonschema:"Command timeout in seconds (default 300, max 3600)"`
	MaxOutput int    `json:"max_output,omitempty" jsonschema:"Max output bytes to return inline (default 16384). Larger output is written to a temp file."`
}

func registerExec(server *mcp.Server, mgr *session.Manager, out *output.Handler) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "ssh_exec",
		Description: "Execute a shell command on a remote host via SSH. The connection persists across calls for the same host. Commands run in a fresh shell each time — chain with && or ; to preserve working directory.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args ExecInput) (*mcp.CallToolResult, any, error) {
		if args.Host == "" {
			return errResult("host is required"), nil, nil
		}
		if args.Command == "" {
			return errResult("command is required"), nil, nil
		}

		timeout := args.Timeout
		if timeout <= 0 {
			timeout = 300
		}
		if timeout > 3600 {
			timeout = 3600
		}

		ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()

		result, err := mgr.RunCommand(ctx, args.Host, args.Command)
		if err != nil {
			return errResult(fmt.Sprintf("SSH error: %v", err)), nil, nil
		}

		durationStr := result.Duration.Truncate(time.Millisecond).String()
		text := out.FormatResult(result.Stdout, result.Stderr, result.ExitCode, durationStr, args.MaxOutput)

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: text},
			},
		}, nil, nil
	})
}
