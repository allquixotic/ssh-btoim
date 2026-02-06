package output

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	DefaultMaxInline = 16 * 1024  // 16KB default inline limit
	PreviewSize      = 2 * 1024   // 2KB for head/tail preview
)

// Handler manages output size decisions and temp file lifecycle.
type Handler struct {
	TempDir string // e.g., /tmp/ssh-btoim-12345
}

// NewHandler creates an output handler, sets up the temp directory,
// and cleans up orphaned temp dirs from previous runs.
func NewHandler() (*Handler, error) {
	dir := fmt.Sprintf("/tmp/ssh-btoim-%d", os.Getpid())
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("cannot create temp dir %s: %w", dir, err)
	}

	h := &Handler{TempDir: dir}
	go h.cleanupOrphans()
	return h, nil
}

// FormatResult decides whether to return output inline or write to a temp file.
// maxInline is the per-call limit in bytes (0 means use default).
// Returns the formatted string to include in the MCP tool response.
func (h *Handler) FormatResult(stdout, stderr []byte, exitCode int, durationStr string, maxInline int) string {
	if maxInline <= 0 {
		maxInline = DefaultMaxInline
	}

	totalSize := len(stdout) + len(stderr)
	header := fmt.Sprintf("[Exit Code: %d] [Duration: %s]", exitCode, durationStr)

	if totalSize <= maxInline {
		return h.formatInline(header, stdout, stderr)
	}
	return h.formatToFile(header, stdout, stderr, totalSize)
}

// formatInline returns output directly in the response.
func (h *Handler) formatInline(header string, stdout, stderr []byte) string {
	var b strings.Builder
	b.WriteString(header)

	if len(stdout) > 0 {
		b.WriteString("\n\n--- stdout ---\n")
		b.Write(stdout)
	}
	if len(stderr) > 0 {
		b.WriteString("\n\n--- stderr ---\n")
		b.Write(stderr)
	}
	if len(stdout) == 0 && len(stderr) == 0 {
		b.WriteString("\n\n(no output)")
	}

	return b.String()
}

// formatToFile writes output to a temp file and returns a summary with the path.
func (h *Handler) formatToFile(header string, stdout, stderr []byte, totalSize int) string {
	id := randomID()
	filePath := filepath.Join(h.TempDir, fmt.Sprintf("exec-%s.out", id))

	f, err := os.Create(filePath)
	if err != nil {
		// Fall back to inline with truncation
		log.Printf("cannot create temp file %s: %v, falling back to inline", filePath, err)
		return h.formatInline(header, truncate(stdout, DefaultMaxInline/2), truncate(stderr, DefaultMaxInline/2))
	}
	defer f.Close()

	if len(stdout) > 0 {
		fmt.Fprintln(f, "--- stdout ---")
		f.Write(stdout)
		fmt.Fprintln(f)
	}
	if len(stderr) > 0 {
		fmt.Fprintln(f, "--- stderr ---")
		f.Write(stderr)
		fmt.Fprintln(f)
	}

	// Build summary response
	lines := countLines(stdout) + countLines(stderr)
	var b strings.Builder
	b.WriteString(header)
	b.WriteString(fmt.Sprintf("\n\nOutput exceeded inline limit and was written to: %s", filePath))
	b.WriteString(fmt.Sprintf("\nTotal size: %d bytes (%d lines)", totalSize, lines))

	// Include preview: first and last ~2KB of stdout
	if len(stdout) > 0 {
		b.WriteString("\n\n--- stdout preview (first ~2KB) ---\n")
		b.Write(truncate(stdout, PreviewSize))
		if len(stdout) > PreviewSize*2 {
			b.WriteString("\n\n[...]\n\n--- stdout preview (last ~2KB) ---\n")
			b.Write(stdout[len(stdout)-PreviewSize:])
		}
	}
	if len(stderr) > 0 {
		b.WriteString("\n\n--- stderr preview (first ~2KB) ---\n")
		b.Write(truncate(stderr, PreviewSize))
	}

	b.WriteString("\n\nUse grep to search the file for relevant content, or ask a background agent to summarize it.")

	return b.String()
}

// Cleanup removes the temp directory.
func (h *Handler) Cleanup() {
	if err := os.RemoveAll(h.TempDir); err != nil {
		log.Printf("cannot remove temp dir %s: %v", h.TempDir, err)
	}
}

// cleanupOrphans removes temp directories from crashed previous instances.
func (h *Handler) cleanupOrphans() {
	entries, err := os.ReadDir("/tmp")
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "ssh-btoim-") || !entry.IsDir() {
			continue
		}

		pidStr := strings.TrimPrefix(name, "ssh-btoim-")
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		if pid == os.Getpid() {
			continue
		}

		// Check if the PID is still running
		proc, err := os.FindProcess(pid)
		if err != nil {
			// Process doesn't exist, clean up
			orphanDir := filepath.Join("/tmp", name)
			log.Printf("cleaning up orphaned temp dir %s", orphanDir)
			os.RemoveAll(orphanDir)
			continue
		}

		// On Unix, FindProcess always succeeds. Use Signal(0) to check if process exists.
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			orphanDir := filepath.Join("/tmp", name)
			log.Printf("cleaning up orphaned temp dir %s", orphanDir)
			os.RemoveAll(orphanDir)
		}
	}
}

func truncate(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return b[:max]
}

func countLines(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	// Count the last line if it doesn't end with newline
	if b[len(b)-1] != '\n' {
		n++
	}
	return n
}

func randomID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}
