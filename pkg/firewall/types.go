package firewall

import (
	"context"
	"fmt"
)

type Action string

const (
	ActionAllow  Action = "allow"
	ActionDeny   Action = "deny"
	ActionReject Action = "reject"
	ActionDrop   Action = "drop"
)

type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
	ProtocolAny Protocol = "any"
)

// Rule 定义通用防火墙规则
type Rule struct {
	Port     string   // 例如 "80", "8080:8090"
	Service  string   // 例如 "http", "ssh"
	Protocol Protocol // tcp, udp, any
	Action   Action   // allow, deny, reject, drop
	Source   string   // 源 IP 或 CIDR, 为空表示所有
	Comment  string
}

// Firewall 接口定义了防火墙管理的通用操作
type Firewall interface {
	Name() string
	Status(ctx context.Context) (string, error)
	IsOpen(ctx context.Context) (bool, error)
	Enable(ctx context.Context) (string, error)
	Disable(ctx context.Context) (string, error)
	ListRules(ctx context.Context) (string, error)
	AddRule(ctx context.Context, rule Rule) (string, error)
	RemoveRule(ctx context.Context, rule Rule) (string, error)
	Reload(ctx context.Context) (string, error)
}

// BackendError 定义防火墙后端错误
type BackendError struct {
	Backend string
	Err     error
}

func (e *BackendError) Error() string {
	return fmt.Sprintf("[%s] firewall error: %v", e.Backend, e.Err)
}
