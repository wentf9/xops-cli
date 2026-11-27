package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/openssh"
)

const (
	xopsHomeEnvKey       = "XOPS_HOME"
	defaultStateDirName  = ".xops"
	defaultSSHDirName    = ".ssh"
	defaultSSHConfigName = "config"
)

// 编译期契约断言：确保组合根内的环境包装器完整满足 ports.EnvPort。
var _ ports.EnvPort = (*homeAwareEnv)(nil)

// homeAwareEnv 包装 sys.SystemEnv，在进程环境显式提供 HOME（Unix）或 USERPROFILE/HOME（Windows）时
// 同步修正 LookupLocalIdentity().HomeDir()，确保 ~/.ssh、known_hosts 与 ~ 模板展开与用户会话环境一致。
//
//xops:opaque
//xops:failclosed
type homeAwareEnv struct {
	base  ports.EnvPort
	valid bool
}

func newHomeAwareEnv(base ports.EnvPort) *homeAwareEnv {
	if base == nil {
		return &homeAwareEnv{}
	}
	return &homeAwareEnv{base: base, valid: true}
}

func (e *homeAwareEnv) LookupEnv(key string) (string, bool) {
	if e == nil || !e.valid {
		return "", false
	}
	return e.base.LookupEnv(key)
}

func (e *homeAwareEnv) Environ() map[string]string {
	if e == nil || !e.valid {
		return nil
	}
	return e.base.Environ()
}

func zeroVal[T any]() (z T) { return z }

func (e *homeAwareEnv) LookupLocalIdentity() (ports.LocalIdentityInfo, error) {
	if e == nil || !e.valid {
		return zeroVal[ports.LocalIdentityInfo](), fmt.Errorf("%w: homeAwareEnv 未初始化", ports.ErrInvalidArgument)
	}
	id, err := e.base.LookupLocalIdentity()
	if err != nil {
		return zeroVal[ports.LocalIdentityInfo](), err
	}
	envHome := lookupHomeDirOverride(e.base)
	if envHome == "" || envHome == id.HomeDir() {
		return id, nil
	}
	return ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{
		LocalHost: id.LocalHost(),
		LocalUser: id.LocalUser(),
		LocalUID:  id.LocalUID(),
		HomeDir:   envHome,
	})
}

func resolveHostDirs(env ports.EnvPort) (homeDir, stateDir pathalg.LocalDir, localID ports.LocalIdentityInfo, err error) {
	localID, err = env.LookupLocalIdentity()
	if err != nil {
		return homeDir, stateDir, localID, fmt.Errorf("resolve local identity failed: %w", err)
	}
	homeDir, err = pathalg.ParseLocalDir(localID.HomeDir())
	if err != nil {
		return homeDir, stateDir, localID, fmt.Errorf("invalid home directory %q: %w", localID.HomeDir(), err)
	}
	if rawHome, ok := env.LookupEnv(xopsHomeEnvKey); ok && strings.TrimSpace(rawHome) != "" {
		stateDir, err = pathalg.ParseLocalDir(strings.TrimSpace(rawHome))
		if err != nil {
			return homeDir, stateDir, localID, fmt.Errorf("invalid %s %q: %w", xopsHomeEnvKey, rawHome, err)
		}
		return homeDir, stateDir, localID, nil
	}
	stateDir, err = homeDir.JoinComponent(defaultStateDirName)
	if err != nil {
		return homeDir, stateDir, localID, fmt.Errorf("resolve default state directory failed: %w", err)
	}
	return homeDir, stateDir, localID, nil
}

func buildOpenSSHSource(
	ctx context.Context,
	overridePath string,
	homeDir pathalg.LocalDir,
	localID ports.LocalIdentityInfo,
	scopedFS ports.ScopedRootFS,
	readFS ports.OperatorReadFS,
) (ports.OpenSSHConfigSource, error) {
	trimmed := strings.TrimSpace(overridePath)
	if strings.EqualFold(trimmed, "none") {
		return nil, nil
	}
	cfgPath, err := resolveOpenSSHConfigPath(trimmed, homeDir)
	if err != nil {
		return nil, err
	}
	if trimmed != "" {
		// 显式 `-F <configfile>` 严格失败关闭：文件不存在、为目录或不可读时立即拒绝，
		// 绝不静默退化为忽略安全选项（默认 ~/.ssh/config 仍保持可选）。
		if err := readFS.WithOperatorRead(ctx, cfgPath, pathalg.SymlinkFollowOperatorSource, func(ports.BoundedReadHandle, int64) error {
			return nil
		}); err != nil {
			return nil, fmt.Errorf("cannot read OpenSSH config file %q: %w", overridePath, err)
		}
	}
	return openssh.NewConfigSource(openssh.SourceSpec{
		ConfigPath:    cfgPath,
		HomeDir:       homeDir.String(),
		LocalIdentity: algebraic.Some(localID),
		Reader:        readFS,
		ScopedFS:      scopedFS,
		SymlinkPolicy: pathalg.SymlinkFollowOperatorSource,
	})
}

func resolveOpenSSHConfigPath(override string, homeDir pathalg.LocalDir) (pathalg.LocalSourcePath, error) {
	if override == "" {
		sshDir, err := homeDir.JoinComponent(defaultSSHDirName)
		if err != nil {
			return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("resolve default .ssh directory failed: %w", err)
		}
		joined, err := sshDir.JoinComponent(defaultSSHConfigName)
		if err != nil {
			return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("resolve default ssh config path failed: %w", err)
		}
		return pathalg.ParseLocalSourcePath(joined.String())
	}
	expanded := expandTildePrefix(override, homeDir)
	p, err := pathalg.ParseLocalSourcePath(expanded)
	if err != nil {
		return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("invalid OpenSSH config file %q: %w", override, err)
	}
	return p, nil
}
