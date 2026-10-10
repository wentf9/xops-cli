package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/pkg/executor"
)

// DetectFirewall 自动探测系统使用的防火墙后端。
// 要求远端为 Linux/POSIX 环境，依赖 command -v 探针探测底层工具。
// 不支持 Windows 或非 POSIX 执行环境。
func DetectFirewall(ctx context.Context, exec executor.Executor) (Firewall, error) {
	// 探测优先级: firewalld -> ufw -> nftables -> iptables

	// 1. Check firewalld
	if _, err := exec.Run(ctx, "command -v firewall-cmd"); err == nil {
		return NewFirewalldBackend(exec, ""), nil
	}

	// 2. Check ufw
	if _, err := exec.Run(ctx, "command -v ufw"); err == nil {
		return NewUfwBackend(exec), nil
	}

	// 3. Check nft
	if _, err := exec.Run(ctx, "command -v nft"); err == nil {
		return NewNftablesBackend(exec), nil
	}

	// 4. Check iptables
	if _, err := exec.Run(ctx, "command -v iptables"); err == nil {
		return NewIptablesBackend(exec), nil
	}

	return nil, fmt.Errorf("no supported firewall detected")
}

// GetFirewallByName 根据名称获取防火墙后端
func GetFirewallByName(name string, exec executor.Executor) (Firewall, error) {
	switch strings.ToLower(name) {
	case "firewalld":
		return NewFirewalldBackend(exec, ""), nil
	case "ufw":
		return NewUfwBackend(exec), nil
	case "iptables":
		return NewIptablesBackend(exec), nil
	case "nftables":
		return NewNftablesBackend(exec), nil
	default:
		return nil, fmt.Errorf("unsupported firewall type: %s", name)
	}
}
