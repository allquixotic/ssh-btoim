package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sean/ssh-btoim/internal/output"
	"github.com/sean/ssh-btoim/internal/session"
	"github.com/sean/ssh-btoim/internal/sshconfig"
	"github.com/sean/ssh-btoim/internal/tools"
)

func main() {
	// All logging goes to stderr — stdout is reserved for MCP JSON-RPC.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[ssh-btoim] ")

	// Parse SSH config
	resolver, err := sshconfig.NewResolver()
	if err != nil {
		log.Fatalf("failed to parse SSH config: %v", err)
	}
	log.Printf("loaded SSH config with %d hosts", len(resolver.ListHosts()))

	// Session manager
	mgr := session.NewManager(resolver)

	// Output handler (temp dir + orphan cleanup)
	out, err := output.NewHandler()
	if err != nil {
		log.Fatalf("failed to initialize output handler: %v", err)
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("received %s, shutting down", sig)
		mgr.DisconnectAll()
		out.Cleanup()
		cancel()
	}()

	// MCP server
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "ssh-btoim",
		Version: "0.1.0",
	}, nil)

	tools.RegisterAll(server, mgr, resolver, out)

	log.Printf("starting MCP server")
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}
