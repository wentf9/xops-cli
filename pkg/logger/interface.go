package logger

import corelog "github.com/wentf9/xops-cli/core/log"

// DebugLogger retains the legacy name for the shared diagnostic contract.
type DebugLogger = corelog.DebugLogger

// NopLogger 是默认的空实现实例，保证未注入 Logger 时不发生 nil panic
var NopLogger DebugLogger = corelog.NopLogger

// defaultAdapter 将包级 Debug/Debugf 适配为 DebugLogger 接口
type defaultAdapter struct{}

func (defaultAdapter) Debug(msg string, args ...any) {
	Debug(msg, args...)
}

func (defaultAdapter) Debugf(format string, args ...any) {
	Debugf(format, args...)
}

// DefaultLogger 返回基于当前全局配置的 DebugLogger 适配器
func DefaultLogger() DebugLogger {
	return defaultAdapter{}
}
