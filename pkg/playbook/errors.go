package playbook

import (
	"errors"
	"fmt"
)

// ErrNoTargets 表示未解析到任何可执行的目标节点
var ErrNoTargets = errors.New("no target nodes resolved")

// TargetNotFoundError 表示指定的目标节点或主机在清单中不存在
type TargetNotFoundError struct {
	Target string
}

func (e *TargetNotFoundError) Error() string {
	return fmt.Sprintf("target %q not found in inventory", e.Target)
}
