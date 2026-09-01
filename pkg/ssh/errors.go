package ssh

import (
	"errors"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/config"
)

var (
	// ErrHostKeyMismatch 主机密钥不匹配或不受信任
	ErrHostKeyMismatch = errors.New("host key verification failed")
	// ErrPasswordRequired 需要密码但未提供
	ErrPasswordRequired = errors.New("password required but empty")
	// ErrKeyPathRequired 需要私钥路径但未提供
	ErrKeyPathRequired = errors.New("private key path required but empty")
	// ErrAgentNotAvailable SSH Agent 不可用
	ErrAgentNotAvailable = errors.New("ssh-agent socket not available")
	// ErrProxyCycle 代理跳转环路
	ErrProxyCycle = errors.New("proxy jump cycle detected")
)

// ConnectionError 携带节点连接相关的结构化上下文
type ConnectionError struct {
	NodeID   string
	Address  string
	Port     int
	AuthType string
	Err      error
}

func (e *ConnectionError) Error() string {
	if e.AuthType != "" {
		return fmt.Sprintf("connect node %q (%s:%d) via %s failed: %v", e.NodeID, e.Address, e.Port, e.AuthType, e.Err)
	}
	return fmt.Sprintf("connect node %q (%s:%d) failed: %v", e.NodeID, e.Address, e.Port, e.Err)
}

func (e *ConnectionError) Unwrap() error {
	return e.Err
}

// HandshakeError 封装 SSH 协议握手失败的错误
type HandshakeError struct {
	NodeID string
	Err    error
}

func (e *HandshakeError) Error() string {
	return fmt.Sprintf("SSH handshake with node %q failed: %v", e.NodeID, e.Err)
}

func (e *HandshakeError) Unwrap() error {
	return e.Err
}

// ProxyCycleError 封装代理跳板环路错误
type ProxyCycleError struct {
	NodeID string
	Path   []string
}

func (e *ProxyCycleError) Error() string {
	return fmt.Sprintf("proxy jump cycle detected on node %q (path: %v)", e.NodeID, e.Path)
}

// Is 支持与 config.ErrProxyCycle 及 ErrProxyCycle 匹配
func (e *ProxyCycleError) Is(target error) bool {
	return target == config.ErrProxyCycle || target == ErrProxyCycle
}
