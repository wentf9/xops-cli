package logger

import (
	"testing"
)

func TestNopLogger(t *testing.T) {
	// 验证 NopLogger 不会 panic，也不产生任何输出
	NopLogger.Debug("test debug", "arg1", 123)
	NopLogger.Debugf("test format %s %d", "abc", 456)
}

func TestDefaultLoggerAdapter(t *testing.T) {
	l := DefaultLogger()
	if l == nil {
		t.Fatal("DefaultLogger returned nil")
	}
	// 不应 panic
	l.Debug("adapter test")
	l.Debugf("adapter format %s", "ok")
}
