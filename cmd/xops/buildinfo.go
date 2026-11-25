package main

import (
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/wentf9/xops-cli/internal/entry/cli"
)

// buildVersion 接收 Makefile LDFLAGS `-X 'main.buildVersion=...'` 注入的只读发布版本号。
//
//xops:buildvar
var buildVersion string

// buildCommit 接收 Makefile LDFLAGS `-X 'main.buildCommit=...'` 注入的只读提交哈希。
//
//xops:buildvar
var buildCommit string

// buildTime 接收 Makefile LDFLAGS `-X 'main.buildTime=...'` 注入的只读构建时间戳。
//
//xops:buildvar
var buildTime string

// currentBuildInfo 读取链接期注入的只读构建变量，并在未注入时回退至 runtime/debug.ReadBuildInfo()。
func currentBuildInfo() cli.BuildInfo {
	bi, _ := debug.ReadBuildInfo()
	return resolveBuildInfo(
		buildVersion,
		buildCommit,
		buildTime,
		bi,
		runtime.Version(),
		runtime.GOOS+"/"+runtime.GOARCH,
	)
}

func resolveBuildInfo(ver, commit, built string, bi *debug.BuildInfo, runtimeVer, platform string) cli.BuildInfo {
	out := cli.BuildInfo{
		Version:   strings.TrimSpace(ver),
		Commit:    strings.TrimSpace(commit),
		BuildTime: strings.TrimSpace(built),
		GoVersion: strings.TrimSpace(runtimeVer),
		Platform:  strings.TrimSpace(platform),
	}
	if bi == nil {
		return out.Normalized()
	}
	if out.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		out.Version = bi.Main.Version
	}
	if bi.GoVersion != "" {
		out.GoVersion = bi.GoVersion
	}
	vcsRev, vcsTime, vcsDirty := extractVCSSettings(bi.Settings)
	if out.Commit == "" && vcsRev != "" {
		out.Commit = vcsRev
		if vcsDirty {
			out.Commit += "-dirty"
		}
	}
	if out.BuildTime == "" && vcsTime != "" {
		out.BuildTime = vcsTime
	}
	return out.Normalized()
}

func extractVCSSettings(settings []debug.BuildSetting) (rev, built string, dirty bool) {
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			rev = strings.TrimSpace(s.Value)
		case "vcs.time":
			built = strings.TrimSpace(s.Value)
		case "vcs.modified":
			dirty = strings.EqualFold(strings.TrimSpace(s.Value), "true")
		}
	}
	return rev, built, dirty
}
