package config

import "errors"

var (
	// ErrNodeNotFound 节点不存在错误
	ErrNodeNotFound = errors.New("node not found")
	// ErrHostNotFound 关联的主机配置不存在
	ErrHostNotFound = errors.New("host reference not found")
	// ErrIdentityNotFound 关联的认证身份不存在
	ErrIdentityNotFound = errors.New("identity reference not found")
	// ErrProxyCycle 检测到代理跳转环路
	ErrProxyCycle = errors.New("proxy jump cycle detected")
	// ErrAmbiguousNode means a selector matched more than one node.
	ErrAmbiguousNode = errors.New("node selector is ambiguous")
)

// AmbiguousNodeError reports a selector that resolves to more than one local
// node. Choosing one implicitly would make a command target nondeterministic.
type AmbiguousNodeError struct {
	Selector   string
	Candidates []string
}

func (e *AmbiguousNodeError) Error() string {
	return "node selector is ambiguous: " + e.Selector
}

func (e *AmbiguousNodeError) Unwrap() error {
	return ErrAmbiguousNode
}
