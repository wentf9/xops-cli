// Package log defines the optional diagnostic output used by shared XOps code.
// It does not inspect terminals or install a process-wide logger.
package log

// DebugLogger implementations must be safe for concurrent calls.
type DebugLogger interface {
	Debug(msg string, args ...any)
	Debugf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debug(string, ...any)  {}
func (nopLogger) Debugf(string, ...any) {}

// NopLogger discards diagnostic output without acquiring resources.
var NopLogger DebugLogger = nopLogger{}
