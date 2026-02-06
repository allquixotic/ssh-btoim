package sshconfig

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

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
// It automatically reloads the config when the file's modtime changes.
type Resolver struct {
	mu         sync.RWMutex
	cfg        *ssh_config.Config
	configPath string
	lastMod    time.Time
}

// NewResolver creates a Resolver from ~/.ssh/config.
// If the file doesn't exist, returns a resolver that uses SSH defaults.
func NewResolver() (*Resolver, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}

	r := &Resolver{
		configPath: filepath.Join(home, ".ssh", "config"),
	}

	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

// load parses the SSH config file and updates lastMod.
func (r *Resolver) load() error {
	info, err := os.Stat(r.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			r.cfg = &ssh_config.Config{}
			r.lastMod = time.Time{}
			return nil
		}
		return fmt.Errorf("cannot stat %s: %w", r.configPath, err)
	}

	f, err := os.Open(r.configPath)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", r.configPath, err)
	}
	defer f.Close()

	cfg, err := ssh_config.Decode(f)
	if err != nil {
		return fmt.Errorf("cannot parse %s: %w", r.configPath, err)
	}

	r.cfg = cfg
	r.lastMod = info.ModTime()
	return nil
}

// reloadIfChanged checks the file modtime and reloads if it changed.
func (r *Resolver) reloadIfChanged() {
	info, err := os.Stat(r.configPath)
	if err != nil {
		return
	}
	if info.ModTime().Equal(r.lastMod) {
		return
	}

	log.Printf("SSH config changed, reloading")
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.load(); err != nil {
		log.Printf("failed to reload SSH config: %v", err)
	}
}

// Resolve looks up a host alias and returns fully resolved connection parameters.
func (r *Resolver) Resolve(alias string) (*ResolvedHost, error) {
	r.reloadIfChanged()

	r.mu.RLock()
	defer r.mu.RUnlock()

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
	r.reloadIfChanged()

	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool)
	var hosts []string

	for _, host := range r.cfg.Hosts {
		for _, pattern := range host.Patterns {
			name := pattern.String()
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
// Caller must hold r.mu (at least RLock).
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
		if _, err := os.Stat(f); err == nil {
			expanded = append(expanded, f)
		}
	}
	return expanded
}
