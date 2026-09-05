package ssh

import (
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
)

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

// WithInteractionHandler 配置交互处理器（同时设置 SecretPrompter 和 HostKeyConfirmer）
func WithInteractionHandler(handler InteractionHandler) Option {
	return func(c *Connector) {
		if handler != nil {
			c.secretPrompter = handler
			c.hostKeyConfirmer = handler
		} else {
			c.secretPrompter = rejectInteraction{}
			c.hostKeyConfirmer = rejectInteraction{}
		}
	}
}

// WithSecretPrompter 单独配置机密提示器
func WithSecretPrompter(prompter SecretPrompter) Option {
	return func(c *Connector) {
		if prompter != nil {
			c.secretPrompter = prompter
		} else {
			c.secretPrompter = rejectInteraction{}
		}
	}
}

// WithHostKeyConfirmer 单独配置主机密钥确认器
func WithHostKeyConfirmer(confirmer HostKeyConfirmer) Option {
	return func(c *Connector) {
		if confirmer != nil {
			c.hostKeyConfirmer = confirmer
		} else {
			c.hostKeyConfirmer = rejectInteraction{}
		}
	}
}

// WithInteractionTimeout 配置单次交互提示超时时间
func WithInteractionTimeout(timeout time.Duration) Option {
	return func(c *Connector) {
		if timeout > 0 {
			c.interactionTimeout = timeout
		}
	}
}

// WithHandshakeTimeout 配置底层 SSH 握手网络超时时间
func WithHandshakeTimeout(timeout time.Duration) Option {
	return func(c *Connector) {
		if timeout > 0 {
			c.handshakeTimeout = timeout
		}
	}
}

// WithDialer 配置底层直连所使用的自定义 Dialer
func WithDialer(dialer Dialer) Option {
	return func(c *Connector) {
		c.baseDialer = dialer
	}
}

// WithSecretResolver 配置机密解析器（传 nil 时回退到默认 fail-closed resolver）
func WithSecretResolver(resolver SecretResolver) Option {
	return func(c *Connector) {
		if resolver != nil {
			c.secretResolver = resolver
		} else {
			c.secretResolver = rejectSecretResolver{}
		}
	}
}

// WithCredentialRecorder 配置凭据写回记录器（传 nil 时回退到默认 nop recorder）
func WithCredentialRecorder(recorder CredentialRecorder) Option {
	return func(c *Connector) {
		if recorder != nil {
			c.credentialRecorder = recorder
		} else {
			c.credentialRecorder = nopCredentialRecorder{}
		}
	}
}

// WithConnectionProvider 配置连接配置提供者
func WithConnectionProvider(provider ConnectionProvider) Option {
	return func(c *Connector) {
		if provider != nil {
			c.provider = provider
		}
	}
}
