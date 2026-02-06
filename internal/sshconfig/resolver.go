package sshconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	ssh_config "github.com/kevinburke/ssh_config"
)

// ResolvedHost contains all SSH connection parameters resolved from ~/.ssh/config.
type ResolvedHost struct {
	Alias         string
	HostName      string
	User          string
	Port          string
	IdentityFiles []string
}

// Resolver parses and queries ~/.ssh/config.
type Resolver struct {
	cfg *ssh_config.Config
}

// NewResolver creates a Resolver from ~/.ssh/config.
// If the file doesn't exist, returns a resolver that uses SSH defaults.
func NewResolver() (*Resolver, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}

	configPath := filepath.Join(home, ".ssh", "config")
	f, err := os.Open(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No SSH config — return empty resolver
			return &Resolver{cfg: &ssh_config.Config{}}, nil
		}
		return nil, fmt.Errorf("cannot open %s: %w", configPath, err)
	}
	defer f.Close()

	cfg, err := ssh_config.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("cannot parse %s: %w", configPath, err)
	}

	return &Resolver{cfg: cfg}, nil
}

// Resolve looks up a host alias and returns fully resolved connection parameters.
func (r *Resolver) Resolve(alias string) (*ResolvedHost, error) {
	hostname, err := r.cfg.Get(alias, "HostName")
	if err != nil || hostname == "" {
		hostname = alias
	}

	user, _ := r.cfg.Get(alias, "User")
	if user == "" {
		user = os.Getenv("USER")
		if user == "" {
			user = "root"
		}
	}

	port, _ := r.cfg.Get(alias, "Port")
	if port == "" {
		port = "22"
	}

	identityFiles := r.getIdentityFiles(alias)

	return &ResolvedHost{
		Alias:         alias,
		HostName:      hostname,
		User:          user,
		Port:          port,
		IdentityFiles: identityFiles,
	}, nil
}

// ListHosts returns all non-wildcard Host entries from the SSH config.
func (r *Resolver) ListHosts() []string {
	seen := make(map[string]bool)
	var hosts []string

	for _, host := range r.cfg.Hosts {
		for _, pattern := range host.Patterns {
			name := pattern.String()
			// Skip wildcards and negations
			if strings.ContainsAny(name, "*?!") {
				continue
			}
			if name == "" {
				continue
			}
			if !seen[name] {
				seen[name] = true
				hosts = append(hosts, name)
			}
		}
	}

	sort.Strings(hosts)
	return hosts
}

// getIdentityFiles returns expanded identity file paths for the given host.
func (r *Resolver) getIdentityFiles(alias string) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	identityFiles, _ := r.cfg.GetAll(alias, "IdentityFile")
	var expanded []string
	for _, f := range identityFiles {
		if strings.HasPrefix(f, "~/") {
			f = filepath.Join(home, f[2:])
		}
		// Only include files that exist
		if _, err := os.Stat(f); err == nil {
			expanded = append(expanded, f)
		}
	}
	return expanded
}
