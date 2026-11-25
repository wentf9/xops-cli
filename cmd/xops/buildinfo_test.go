package main

import (
	"bytes"
	"maps"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

type stubEnvPort struct {
	vars map[string]string
	id   ports.LocalIdentityInfo
}

func (s *stubEnvPort) LookupEnv(key string) (string, bool) {
	v, ok := s.vars[key]
	return v, ok
}

func (s *stubEnvPort) Environ() map[string]string {
	return maps.Clone(s.vars)
}

func (s *stubEnvPort) LookupLocalIdentity() (ports.LocalIdentityInfo, error) {
	return s.id, nil
}

func TestResolveBuildInfo_PrecedenceAndFallback(t *testing.T) {
	defer goleak.VerifyNone(t)

	bi := &debug.BuildInfo{
		GoVersion: "go1.27.0",
		Main:      debug.Module{Version: "v2.5.1"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abcdef123456"},
			{Key: "vcs.time", Value: "2026-11-25T01:02:03Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}

	// 显式 ldflags 注入值始终优先于 debug.BuildInfo 回退值。
	explicit := resolveBuildInfo("v2.5.0-dev", "deadbeef", "2026-11-25T00:00:00Z", bi, "go1.27.0", "linux/amd64")
	if explicit.Version != "v2.5.0-dev" || explicit.Commit != "deadbeef" || explicit.BuildTime != "2026-11-25T00:00:00Z" {
		t.Fatalf("显式构建变量未被优先采用: %+v", explicit)
	}

	// 未注入 ldflags 时自动回退至 debug.BuildInfo（含 VCS dirty 标记）。
	fallback := resolveBuildInfo("", "", "", bi, "go1.27.0", "darwin/arm64")
	if fallback.Version != "v2.5.1" || fallback.Commit != "abcdef123456-dirty" || fallback.BuildTime != "2026-11-25T01:02:03Z" || fallback.Platform != "darwin/arm64" {
		t.Fatalf("debug.BuildInfo 回退值异常: %+v", fallback)
	}

	// (devel) 或 nil BuildInfo 时安全回退至 dev / unknown。
	nilFallback := resolveBuildInfo("", "", "", nil, "go1.27.0", "windows/amd64")
	if nilFallback.Version != "dev" || nilFallback.Commit != "unknown" || nilFallback.BuildTime != "unknown" || nilFallback.GoVersion != "go1.27.0" {
		t.Fatalf("nil BuildInfo 回退值异常: %+v", nilFallback)
	}
}

func TestResolveHostDirsAndOpenSSHConfigPath(t *testing.T) {
	defer goleak.VerifyNone(t)

	tmpRoot := t.TempDir()
	defaultHome := filepath.Join(tmpRoot, "default-home")
	overrideHome := filepath.Join(tmpRoot, "override-home")
	customState := filepath.Join(tmpRoot, "custom-xops-home")

	baseID, err := ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{
		LocalHost: "workstation",
		LocalUser: "operator",
		LocalUID:  "1000",
		HomeDir:   defaultHome,
	})
	if err != nil {
		t.Fatalf("NewLocalIdentityInfo 失败: %v", err)
	}

	// 1. 设置 HOME/USERPROFILE 与 XOPS_HOME 时应分别覆盖主目录与状态目录。
	env := newHomeAwareEnv(&stubEnvPort{
		vars: map[string]string{
			"HOME":        overrideHome,
			"USERPROFILE": overrideHome,
			"XOPS_HOME":   customState,
		},
		id: baseID,
	})
	homeDir, stateDir, idInfo, err := resolveHostDirs(env)
	if err != nil {
		t.Fatalf("resolveHostDirs 失败: %v", err)
	}
	wantHome, _ := pathalg.ParseLocalDir(overrideHome)
	wantState, _ := pathalg.ParseLocalDir(customState)
	if !homeDir.Equal(wantHome) || !stateDir.Equal(wantState) || idInfo.HomeDir() != overrideHome {
		t.Fatalf("目录解析失配: home=%s state=%s idHome=%s", homeDir, stateDir, idInfo.HomeDir())
	}

	// 2. 未设置 XOPS_HOME 时默认回退至 <HomeDir>/.xops。
	envDefault := newHomeAwareEnv(&stubEnvPort{
		vars: map[string]string{
			"HOME":        overrideHome,
			"USERPROFILE": overrideHome,
		},
		id: baseID,
	})
	_, defaultStateDir, _, err := resolveHostDirs(envDefault)
	if err != nil {
		t.Fatalf("resolveHostDirs(默认状态目录) 失败: %v", err)
	}
	wantDefaultState, _ := wantHome.JoinComponent(".xops")
	if !defaultStateDir.Equal(wantDefaultState) {
		t.Fatalf("默认状态目录=%s，期望 %s", defaultStateDir, wantDefaultState)
	}

	// 3. 验证默认 ~/.ssh/config 与 ~/ 展开路径解析。
	defCfg, err := resolveOpenSSHConfigPath("", homeDir)
	if err != nil {
		t.Fatalf("resolveOpenSSHConfigPath 默认失败: %v", err)
	}
	if defCfg.Base() != "config" {
		t.Fatalf("默认配置路径=%s，期望以 config 结尾", defCfg)
	}
	tildeCfg, err := resolveOpenSSHConfigPath("~/alt/ssh_config", homeDir)
	if err != nil {
		t.Fatalf("resolveOpenSSHConfigPath(~/) 失败: %v", err)
	}
	if tildeCfg.Base() != "ssh_config" || tildeCfg.Dir().String() != wantHome.String()+"/alt" {
		t.Fatalf("波浪号展开路径=%s，期望 %s/alt/ssh_config", tildeCfg, wantHome)
	}
}

func TestBuildTerminalAdapter_CustomStreamsNonInteractive(t *testing.T) {
	defer goleak.VerifyNone(t)

	var out bytes.Buffer
	term, err := buildTerminalAdapter(strings.NewReader("input"), &out)
	if err != nil {
		t.Fatalf("buildTerminalAdapter(自定义流) 失败: %v", err)
	}
	if term.IsInteractive() {
		t.Fatalf("自定义内存流必须返回非交互终端，避免误探测父进程 TTY")
	}
}
