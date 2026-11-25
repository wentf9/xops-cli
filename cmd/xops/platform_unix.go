//go:build unix

package main

import (
	"os"
	"strings"
	"syscall"

	"github.com/wentf9/xops-cli/core/ports"
)

// shutdownSignals 返回 Unix 平台触发 CLI 优雅停机与资源逆序释放的信号集。
func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

// lookupHomeDirOverride 在 Unix 上严格经 ports.EnvPort 读取 HOME，
// 使 CLI 与隔离测试环境下的主目录解析与标准 OpenSSH/POSIX 语义一致（零裸 os.Getenv）。
func lookupHomeDirOverride(env ports.EnvPort) string {
	if env == nil {
		return ""
	}
	if v, ok := env.LookupEnv("HOME"); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
