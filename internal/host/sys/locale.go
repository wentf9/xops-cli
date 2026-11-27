package sys

import (
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/ports"
)

// DetectLocale 按既定优先级探测本机默认界面语言，不执行外部进程调用与磁盘 I/O。
//
// 探测优先级从高到低依次为：
//  1. 环境变量 XOPS_LANG
//  2. 环境变量 LC_ALL
//  3. 环境变量 LC_MESSAGES
//  4. 环境变量 LANG
//  5. 操作系统原生区域标签（Windows 经 kernel32 GetUserDefaultLocaleName 查询；非 Windows 为空）
//  6. 默认回退 domi18n.LocaleEn
//
// 设计边界：
//   - 刻意忽略 GNU LANGUAGE 冒号分隔列表，仅遵循单值环境变量与 POSIX 覆盖语义（如 LC_ALL=C 阻断 LANG）；
//   - Unix/macOS 平台仅读取 POSIX 环境变量并在缺失或空白时回退 LocaleEn，严守零 os/exec 与零触盘启动不变量；
//   - 当 env 为 nil 时失败关闭，确定性返回 domi18n.LocaleEn，避免依赖宿主操作系统全局状态。
func DetectLocale(env ports.EnvPort) domi18n.Locale {
	return detectLocaleWithOS(env, detectOSLocaleTag)
}

// detectLocaleWithOS 是供单测注入操作系统区域标签的内部实现核心，确保跨平台探测逻辑 100% 确定性可测。
func detectLocaleWithOS(env ports.EnvPort, osTag func() string) domi18n.Locale {
	if env == nil {
		return domi18n.LocaleEn
	}
	xopsLang := lookupEnvValue(env, "XOPS_LANG")
	lcAll := lookupEnvValue(env, "LC_ALL")
	lcMessages := lookupEnvValue(env, "LC_MESSAGES")
	lang := lookupEnvValue(env, "LANG")

	var hostTag string
	if osTag != nil && allBlankStrings(xopsLang, lcAll, lcMessages, lang) {
		hostTag = osTag()
	}
	return domi18n.ResolveLocale(xopsLang, lcAll, lcMessages, lang, hostTag)
}

func lookupEnvValue(env ports.EnvPort, key string) string {
	val, ok := env.LookupEnv(key)
	if !ok {
		return ""
	}
	return val
}

func allBlankStrings(vals ...string) bool {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}
