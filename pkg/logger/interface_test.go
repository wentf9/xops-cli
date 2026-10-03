package logger

import (
	"testing"
)

func TestDefaultLoggerAdapter(t *testing.T) {
	l := DefaultLogger()
	if l == nil {
		t.Fatal("DefaultLogger returned nil")
	}
	// 不应 panic
	l.Debug("adapter test")
	l.Debugf("adapter format %s", "ok")
}
