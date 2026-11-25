//go:build windows

package main

import (
	"os"
	"strings"

	"github.com/wentf9/xops-cli/core/ports"
)

// shutdownSignals 返回 Windows 平台触发 CLI 优雅停机与资源逆序释放的信号集。
func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

// lookupHomeDirOverride 在 Windows 上严格经 ports.EnvPort 优先读取 USERPROFILE（回退 HOME），
// 使 CLI 与隔离测试环境下的主目录解析与原生 Windows 语义一致（零裸 os.Getenv）。
func lookupHomeDirOverride(env ports.EnvPort) string {
	if env == nil {
		return ""
	}
	if v, ok := env.LookupEnv("USERPROFILE"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if v, ok := env.LookupEnv("HOME"); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
