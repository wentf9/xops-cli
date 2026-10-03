package forward

import corelog "github.com/wentf9/xops-cli/core/log"

// ErrorHandler 处理转发过程中的异步错误
type ErrorHandler func(err error)

// Option 用于配置 TCPForwarder 和 UDPForwarder
type Option func(c *config)

type config struct {
	logger       corelog.DebugLogger
	errorHandler ErrorHandler
}

func defaultConfig() *config {
	return &config{
		logger:       corelog.NopLogger,
		errorHandler: nil,
	}
}

// WithLogger 允许调用方注入 DebugLogger 实现（必须支持并发调用）
func WithLogger(l corelog.DebugLogger) Option {
	return func(c *config) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithErrorHandler 允许调用方注入异步错误处理回调（必须支持并发调用）
func WithErrorHandler(h ErrorHandler) Option {
	return func(c *config) {
		c.errorHandler = h
	}
}
