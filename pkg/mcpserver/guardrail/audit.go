package guardrail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
)

// AuditEntry is a single line in the audit log.
type AuditEntry struct {
	Timestamp time.Time `json:"ts"`
	Tool      string    `json:"tool"`
	NodeID    string    `json:"node,omitempty"`
	Command   string    `json:"command,omitempty"`
	Paths     []string  `json:"paths,omitempty"`
	RiskLevel string    `json:"risk"`
	Decision  string    `json:"decision"`
	Outcome   string    `json:"outcome"` // "executed", "denied", "error"
	Error     string    `json:"error,omitempty"`
}

// AuditLogger writes JSON Lines to a file.
type AuditLogger struct {
	mu   sync.Mutex
	path string
}

// NewAuditLogger creates a logger that writes to the given path.
// The path may contain ~ which is expanded to the user's home directory.
func NewAuditLogger(path string) *AuditLogger {
	return &AuditLogger{path: expandHome(path)}
}

// Log appends an audit entry to the log file.
func (a *AuditLogger) Log(entry AuditEntry) {
	if a == nil || a.path == "" {
		return
	}
	entry.Timestamp = time.Now().UTC()

	data, err := json.Marshal(entry)
	if err != nil {
		logger.Warnf("audit logger: failed to marshal audit entry: %v", err)
		return
	}
	data = append(data, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()

	dir := filepath.Dir(a.path)
	_ = os.MkdirAll(dir, 0700)

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logger.Warnf("audit logger: failed to open log file '%s': %v", a.path, err)
		return
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Write(data); err != nil {
		logger.Warnf("audit logger: failed to write log: %v", err)
	}
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
