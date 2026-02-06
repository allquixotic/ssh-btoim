package tools

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/sftp"
	"github.com/sean/ssh-btoim/internal/session"
)

type UploadInput struct {
	Host        string `json:"host" jsonschema:"SSH host alias"`
	Content     string `json:"content" jsonschema:"File content to upload (text)"`
	RemotePath  string `json:"remote_path" jsonschema:"Absolute path on the remote host where the file should be written"`
	Permissions string `json:"permissions,omitempty" jsonschema:"Unix file permissions as octal string (e.g. 0644). Default: 0644"`
}

func registerUpload(server *mcp.Server, mgr *session.Manager) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "ssh_upload",
		Description: "Upload text content to a file on a remote host via SFTP. Uses the persistent SSH connection.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args UploadInput) (*mcp.CallToolResult, any, error) {
		if args.Host == "" {
			return errResult("host is required"), nil, nil
		}
		if args.RemotePath == "" {
			return errResult("remote_path is required"), nil, nil
		}

		ms, err := mgr.GetOrConnect(ctx, args.Host)
		if err != nil {
			return errResult(fmt.Sprintf("SSH error: %v", err)), nil, nil
		}

		sftpClient, err := sftp.NewClient(ms.Client)
		if err != nil {
			return errResult(fmt.Sprintf("SFTP error: %v", err)), nil, nil
		}
		defer sftpClient.Close()

		f, err := sftpClient.Create(args.RemotePath)
		if err != nil {
			return errResult(fmt.Sprintf("cannot create remote file %s: %v", args.RemotePath, err)), nil, nil
		}

		n, err := f.Write([]byte(args.Content))
		if err != nil {
			f.Close()
			return errResult(fmt.Sprintf("write error: %v", err)), nil, nil
		}
		f.Close()

		// Set permissions
		perm := uint64(0644)
		if args.Permissions != "" {
			parsed, err := strconv.ParseUint(args.Permissions, 8, 32)
			if err == nil {
				perm = parsed
			}
		}
		sftpClient.Chmod(args.RemotePath, os.FileMode(perm))

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Uploaded %d bytes to %s:%s", n, args.Host, args.RemotePath)},
			},
		}, nil, nil
	})
}
