package cli

import (
	"fmt"
	"strings"
)

// BuildInfo 封装由组合根（cmd/xops）通过显式依赖注入传入的只读构建元信息（ADR-011 / RFC §6）。
// 字段为空时由 Normalized() 规范回退至确定性占位值，避免零值输出出现空白行。
type BuildInfo struct {
	// Version 为构建版本号（通常由 -X 'main.buildVersion=...' 注入，未注入时回退 module 版本或 "dev"）。
	Version string
	// Commit 为 Git 提交标识（未注入时回退 vcs.revision 或 "unknown"）。
	Commit string
	// BuildTime 为构建时间戳（未注入时回退 vcs.time 或 "unknown"）。
	BuildTime string
	// GoVersion 为编译二进制所使用的 Go 工具链版本（如 "go1.27.0"）。
	GoVersion string
	// Platform 为目标操作系统与架构标识（如 "linux/amd64"）。
	Platform string
}

// Normalized 返回将空白字段规范回退为确定性默认值后的 BuildInfo 副本。
func (b BuildInfo) Normalized() BuildInfo {
	out := BuildInfo{
		Version:   strings.TrimSpace(b.Version),
		Commit:    strings.TrimSpace(b.Commit),
		BuildTime: strings.TrimSpace(b.BuildTime),
		GoVersion: strings.TrimSpace(b.GoVersion),
		Platform:  strings.TrimSpace(b.Platform),
	}
	if out.Version == "" {
		out.Version = "dev"
	}
	if out.Commit == "" {
		out.Commit = "unknown"
	}
	if out.BuildTime == "" {
		out.BuildTime = "unknown"
	}
	if out.GoVersion == "" {
		out.GoVersion = "unknown"
	}
	return out
}

// FormatVersion 将构建元信息渲染为简洁、确定性的多行版本文本，供 `xops version` 直接输出至 stdout。
func FormatVersion(info BuildInfo) string {
	norm := info.Normalized()
	goLine := norm.GoVersion
	if norm.Platform != "" {
		goLine = fmt.Sprintf("%s (%s)", norm.GoVersion, norm.Platform)
	}
	return fmt.Sprintf(
		"xops version %s\ncommit: %s\nbuilt:  %s\ngo:     %s\n",
		norm.Version,
		norm.Commit,
		norm.BuildTime,
		goLine,
	)
}
