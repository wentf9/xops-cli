package ssh

import "github.com/wentf9/xops-cli/pkg/logger"

// Option 用于配置 Connector
type Option func(*Connector)

// WithLogger 配置 Connector 使用的 DebugLogger（必须支持并发调用）
func WithLogger(l logger.DebugLogger) Option {
	return func(c *Connector) {
		if l != nil {
			c.logger = l
		} else {
			c.logger = logger.NopLogger
		}
	}
}

// WithPasswordPromptPattern 配置密码匹配正则
func WithPasswordPromptPattern(pattern string) Option {
	return func(c *Connector) {
		c.PasswordPromptPattern = pattern
	}
}
