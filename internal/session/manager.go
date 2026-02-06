package session

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sean/ssh-btoim/internal/sshconfig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ManagedSession wraps a persistent SSH client connection.
type ManagedSession struct {
	Client      *ssh.Client
	Alias       string
	Host        *sshconfig.ResolvedHost
	ConnectedAt time.Time
	LastUsedAt  time.Time
	mu          sync.Mutex
}

// SessionInfo is a read-only snapshot of session state.
type SessionInfo struct {
	Alias       string
	HostName    string
	User        string
	Port        string
	ConnectedAt time.Time
	LastUsedAt  time.Time
}

// CommandResult holds the output of a command execution.
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// Manager maintains a pool of persistent SSH connections.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*ManagedSession
	resolver *sshconfig.Resolver
}

// NewManager creates a session manager.
func NewManager(resolver *sshconfig.Resolver) *Manager {
	return &Manager{
		sessions: make(map[string]*ManagedSession),
		resolver: resolver,
	}
}

// GetOrConnect returns an existing session or establishes a new one.
func (m *Manager) GetOrConnect(ctx context.Context, alias string) (*ManagedSession, error) {
	m.mu.RLock()
	ms, exists := m.sessions[alias]
	m.mu.RUnlock()

	if exists {
		// Check if connection is still alive
		_, _, err := ms.Client.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			return ms, nil
		}
		// Connection is dead, remove it
		log.Printf("connection to %s is dead, reconnecting", alias)
		m.mu.Lock()
		delete(m.sessions, alias)
		m.mu.Unlock()
		ms.Client.Close()
	}

	return m.connect(ctx, alias)
}

// connect establishes a new SSH connection.
func (m *Manager) connect(ctx context.Context, alias string) (*ManagedSession, error) {
	host, err := m.resolver.Resolve(alias)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve host %q: %w", alias, err)
	}

	authMethods := m.buildAuthMethods(host)
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication methods available for %q (no ssh-agent, no identity files found)", alias)
	}

	hostKeyCallback, err := m.buildHostKeyCallback()
	if err != nil {
		return nil, fmt.Errorf("host key verification setup failed: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            host.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	addr := net.JoinHostPort(host.HostName, host.Port)
	log.Printf("connecting to %s (%s@%s)", alias, host.User, addr)

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %q (%s): %w", alias, addr, err)
	}

	now := time.Now()
	ms := &ManagedSession{
		Client:      client,
		Alias:       alias,
		Host:        host,
		ConnectedAt: now,
		LastUsedAt:  now,
	}

	m.mu.Lock()
	m.sessions[alias] = ms
	m.mu.Unlock()

	log.Printf("connected to %s", alias)
	return ms, nil
}

// buildAuthMethods assembles authentication methods from agent and identity files.
func (m *Manager) buildAuthMethods(host *sshconfig.ResolvedHost) []ssh.AuthMethod {
	var methods []ssh.AuthMethod

	// 1. SSH agent
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			agentClient := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
		}
	}

	// 2. Identity files from SSH config
	for _, keyPath := range host.IdentityFiles {
		pemBytes, err := os.ReadFile(keyPath)
		if err != nil {
			log.Printf("cannot read key %s: %v", keyPath, err)
			continue
		}
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			// Likely passphrase-protected — can't handle in headless mode
			log.Printf("cannot parse key %s (may need passphrase): %v", keyPath, err)
			continue
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	return methods
}

// buildHostKeyCallback creates a host key verifier using ~/.ssh/known_hosts.
// Unknown hosts are accepted (TOFU). Mismatched keys are rejected.
func (m *Manager) buildHostKeyCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	knownHostsPath := home + "/.ssh/known_hosts"
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		// No known_hosts file — accept all (TOFU, no persistence)
		log.Printf("no known_hosts file found, accepting all host keys")
		return ssh.InsecureIgnoreHostKey(), nil
	}

	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("cannot parse known_hosts: %w", err)
	}

	// Wrap to implement TOFU for unknown hosts
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := hostKeyCallback(hostname, remote, key)
		if err == nil {
			return nil
		}
		// Check if it's an unknown host (not a mismatch)
		keyErr, ok := err.(*knownhosts.KeyError)
		if !ok {
			return err
		}
		if len(keyErr.Want) == 0 {
			// Unknown host — TOFU: accept and persist
			log.Printf("trusting new host key for %s", hostname)
			line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
			f, ferr := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_WRONLY, 0600)
			if ferr == nil {
				fmt.Fprintln(f, line)
				f.Close()
			}
			return nil
		}
		// Key mismatch — security issue
		return fmt.Errorf("SECURITY WARNING: host key mismatch for %s. "+
			"The host key has changed since last recorded in ~/.ssh/known_hosts. "+
			"This could indicate a man-in-the-middle attack. "+
			"To resolve: ssh-keygen -R %s", hostname, hostname)
	}, nil
}

// RunCommand executes a command on a remote host, creating a new ssh.Session.
func (m *Manager) RunCommand(ctx context.Context, alias string, command string) (*CommandResult, error) {
	ms, err := m.GetOrConnect(ctx, alias)
	if err != nil {
		return nil, err
	}

	ms.mu.Lock()
	ms.LastUsedAt = time.Now()
	ms.mu.Unlock()

	session, err := ms.Client.NewSession()
	if err != nil {
		// Connection may be dead — evict and retry once
		log.Printf("session creation failed for %s, retrying: %v", alias, err)
		m.mu.Lock()
		delete(m.sessions, alias)
		m.mu.Unlock()
		ms.Client.Close()

		ms, err = m.GetOrConnect(ctx, alias)
		if err != nil {
			return nil, err
		}
		session, err = ms.Client.NewSession()
		if err != nil {
			return nil, fmt.Errorf("failed to create session after reconnect: %w", err)
		}
	}
	defer session.Close()

	var stdoutBuf, stderrBuf safeBuffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	// Set up context cancellation
	done := make(chan error, 1)
	start := time.Now()

	go func() {
		done <- session.Run(command)
	}()

	var runErr error
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		session.Close()
		runErr = ctx.Err()
	case runErr = <-done:
	}

	duration := time.Since(start)

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else if runErr == context.DeadlineExceeded || runErr == context.Canceled {
			return &CommandResult{
				Stdout:   stdoutBuf.Bytes(),
				Stderr:   stderrBuf.Bytes(),
				ExitCode: -1,
				Duration: duration,
			}, fmt.Errorf("command timed out after %s", duration.Truncate(time.Second))
		} else {
			return nil, fmt.Errorf("command execution failed: %w", runErr)
		}
	}

	return &CommandResult{
		Stdout:   stdoutBuf.Bytes(),
		Stderr:   stderrBuf.Bytes(),
		ExitCode: exitCode,
		Duration: duration,
	}, nil
}

// Disconnect closes a specific session.
func (m *Manager) Disconnect(alias string) error {
	m.mu.Lock()
	ms, exists := m.sessions[alias]
	if exists {
		delete(m.sessions, alias)
	}
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("no active session for %q", alias)
	}

	ms.Client.Close()
	log.Printf("disconnected from %s", alias)
	return nil
}

// DisconnectAll closes all sessions.
func (m *Manager) DisconnectAll() {
	m.mu.Lock()
	sessions := m.sessions
	m.sessions = make(map[string]*ManagedSession)
	m.mu.Unlock()

	for alias, ms := range sessions {
		ms.Client.Close()
		log.Printf("disconnected from %s", alias)
	}
}

// ListSessions returns info about all active sessions.
func (m *Manager) ListSessions() []SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]SessionInfo, 0, len(m.sessions))
	for _, ms := range m.sessions {
		ms.mu.Lock()
		infos = append(infos, SessionInfo{
			Alias:       ms.Alias,
			HostName:    ms.Host.HostName,
			User:        ms.Host.User,
			Port:        ms.Host.Port,
			ConnectedAt: ms.ConnectedAt,
			LastUsedAt:  ms.LastUsedAt,
		})
		ms.mu.Unlock()
	}
	return infos
}

// IsConnected checks if a host has an active session.
func (m *Manager) IsConnected(alias string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.sessions[alias]
	return exists
}

// safeBuffer is a concurrency-safe bytes buffer.
type safeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Hard cap at 512KB to prevent memory exhaustion
	const maxSize = 512 * 1024
	remaining := maxSize - len(b.buf)
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *safeBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf
}
