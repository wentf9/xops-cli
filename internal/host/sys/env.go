package sys

import (
	"os"
	"strings"

	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// SystemEnv 实现 ports.EnvPort，提供只读本机环境变量快照与本机主机/用户/UID/主目录查询；零值恒无效。
//
//xops:opaque
//xops:failclosed
type SystemEnv struct {
	valid bool
}

// NewSystemEnv 构造可用的本机环境变量与身份查询适配器。
func NewSystemEnv() *SystemEnv { return &SystemEnv{valid: true} }

// LookupEnv 查询单个只读环境变量；未初始化或空键返回 ("", false)。
func (e *SystemEnv) LookupEnv(key string) (string, bool) {
	if e == nil || !e.valid || key == "" {
		return "", false
	}
	return os.LookupEnv(key)
}

// Environ 返回当前进程环境变量的独立浅拷贝 map，调用方修改返回 map 不得影响进程环境。
func (e *SystemEnv) Environ() map[string]string {
	if e == nil || !e.valid {
		return nil
	}
	raw := os.Environ()
	out := make(map[string]string, len(raw))
	for _, kv := range raw {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			out[k] = v
		}
	}
	return out
}

// LookupLocalIdentity 查询并校验本机主机名、用户名、可选 UID 与主目录，构造不可变 LocalIdentityInfo。
func (e *SystemEnv) LookupLocalIdentity() (ports.LocalIdentityInfo, error) {
	if e == nil || !e.valid {
		return zeroVal[ports.LocalIdentityInfo](), i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNotInitialized, i18n.Str("component", "SystemEnv"))
	}
	return lookupLocalIdentityOS()
}
