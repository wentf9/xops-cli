package logger

// DebugLogger 定义中间层组件可选的 Debug 日志能力
type DebugLogger interface {
	Debug(msg string, args ...any)
	Debugf(format string, args ...any)
}

// nopLogger 提供零开销的默认空实现
type nopLogger struct{}

func (nopLogger) Debug(msg string, args ...any)     {}
func (nopLogger) Debugf(format string, args ...any) {}

// NopLogger 是默认的空实现实例，保证未注入 Logger 时不发生 nil panic
var NopLogger DebugLogger = nopLogger{}

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
