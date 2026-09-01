package forward

import "github.com/wentf9/xops-cli/pkg/logger"

// ErrorHandler 处理转发过程中的异步错误
type ErrorHandler func(err error)

// Option 用于配置 TCPForwarder 和 UDPForwarder
type Option func(c *config)

type config struct {
	logger       logger.DebugLogger
	errorHandler ErrorHandler
}

func defaultConfig() *config {
	return &config{
		logger:       logger.NopLogger,
		errorHandler: nil,
	}
}

// WithLogger 允许调用方注入 DebugLogger 实现（必须支持并发调用）
func WithLogger(l logger.DebugLogger) Option {
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
