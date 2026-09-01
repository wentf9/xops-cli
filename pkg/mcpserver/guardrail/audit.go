package guardrail

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AuditEntry is a single line in the audit log.
type AuditEntry struct {
	Timestamp   time.Time `json:"ts"`
	OperationID string    `json:"op_id"`
	Tool        string    `json:"tool"`
	NodeID      string    `json:"node,omitempty"`
	Command     string    `json:"command,omitempty"`
	Paths       []string  `json:"paths,omitempty"`
	RiskLevel   string    `json:"risk"`
	Decision    string    `json:"decision"`
	Outcome     string    `json:"outcome"` // "intent", "executed", "denied", "error"
	Error       string    `json:"error,omitempty"`
}

// AuditWriter is the interface for writing audit entries.
type AuditWriter interface {
	Log(entry AuditEntry) error
}

// ExecutedPostAuditError indicates the operation has already been executed successfully on the target,
// but the subsequent post-execution audit logging failed. Callers MUST NOT automatically retry.
type ExecutedPostAuditError struct {
	OperationID string
	Err         error
}

func (e *ExecutedPostAuditError) Error() string {
	return fmt.Sprintf("operation %s already executed, but post-execution audit log failed: %v (DO NOT RETRY)", e.OperationID, e.Err)
}

func (e *ExecutedPostAuditError) Unwrap() error {
	return e.Err
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

// Log appends an audit entry to the log file and returns any error encountered.
func (a *AuditLogger) Log(entry AuditEntry) (err error) {
	if a == nil || a.path == "" {
		return nil
	}
	entry.Timestamp = time.Now().UTC()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry failed: %w", err)
	}
	data = append(data, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()

	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create audit directory %q failed: %w", dir, err)
	}

	f, openErr := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if openErr != nil {
		return fmt.Errorf("open audit file %q failed: %w", a.path, openErr)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close audit file %q failed: %w", a.path, closeErr))
		}
	}()

	if _, writeErr := f.Write(data); writeErr != nil {
		return fmt.Errorf("write audit log to %q failed: %w", a.path, writeErr)
	}
	return nil
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
