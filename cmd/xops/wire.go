package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/host/audit"
	"github.com/wentf9/xops-cli/internal/host/openssh"
	"github.com/wentf9/xops-cli/internal/host/sys"
)

const (
	xopsHomeEnvKey        = "XOPS_HOME"
	defaultStateDirName   = ".xops"
	defaultSSHDirName     = ".ssh"
	defaultSSHConfigName  = "config"
	engineRollbackTimeout = 5 * time.Second
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

// wireEngine 作为 cmd/xops 组合根的唯一核心运行期装配工厂：
//  1. 装配真实宿主出站适配器（osfs、sys、openssh、audit），并按 stdin/stdout 类型绑定终端适配器；
//  2. 经 ports.EnvPort 解析 XOPS_HOME 或 <HomeDir>/.xops 状态根目录；
//  3. 显式 `-F <configfile>` 在初始化 AuditSink/Engine 前即验证存在且可读（严格失败关闭）；
//  4. 创建 core/engine.Engine 并执行启动期 O(1) 跨进程崩溃审计对账 ReconcileCrashedAudits；
//  5. 返回带有确定性逆序关闭闭包的 cli.EngineHandle（Engine -> AuditSink）。
func wireEngine(ctx context.Context, opts cli.EngineInitOptions, stdin io.Reader, stdout io.Writer) (cli.EngineHandle, error) {
	scopedFS := osfs.NewScopedRootFS()
	readFS := osfs.NewOperatorReadFS()
	clock := sys.NewSystemClock()
	entropy := sys.NewCryptoEntropy()
	env := newHomeAwareEnv(sys.NewSystemEnv())
	proc := sys.NewSystemProcess()
	term, err := buildTerminalAdapter(stdin, stdout)
	if err != nil {
		return cli.EngineHandle{}, fmt.Errorf("initialize terminal adapter failed: %w", err)
	}

	homeDir, stateDir, localID, err := resolveHostDirs(env)
	if err != nil {
		return cli.EngineHandle{}, err
	}
	openSSH, err := buildOpenSSHSource(ctx, opts.OpenSSHConfigFile, homeDir, localID, scopedFS, readFS)
	if err != nil {
		return cli.EngineHandle{}, err
	}
	auditSink, reconciler, err := buildAuditAdapters(scopedFS, stateDir, entropy)
	if err != nil {
		return cli.EngineHandle{}, err
	}
	eng, err := engine.New(engine.Config{
		Profile:        engine.PolicyProfileDirectOperator,
		Guardrail:      engine.DefaultGuardrailConfig(),
		Clock:          clock,
		Entropy:        entropy,
		AuditSink:      auditSink,
		Reconciler:     reconciler,
		ScopedFS:       scopedFS,
		OperatorReadFS: readFS,
		HomeDir:        algebraic.Some(homeDir),
		Env:            env,
		Terminal:       term,
		Process:        proc,
		OpenSSH:        openSSH,
	})
	if err != nil {
		_ = auditSink.Close()
		return cli.EngineHandle{}, err
	}
	if _, err := eng.ReconcileCrashedAudits(ctx); err != nil {
		_ = rollbackEngineAndAudit(ctx, eng, auditSink)
		return cli.EngineHandle{}, fmt.Errorf("startup crash audit reconciliation failed: %w", err)
	}
	return wrapShutdownHandle(eng, auditSink), nil
}

// buildTerminalAdapter 按注入流类型构造本机终端适配器：
//   - 当 stdin 与 stdout 均为非 nil *os.File 时绑定对应 OS 文件句柄（sys.NewFileTerminal）；
//   - 当为自定义缓冲/管道流时构造非交互流终端（sys.NewStreamTerminal），避免误探测父进程 TTY。
func buildTerminalAdapter(stdin io.Reader, stdout io.Writer) (ports.TerminalPort, error) {
	inFile, inOK := stdin.(*os.File)
	outFile, outOK := stdout.(*os.File)
	if inOK && outOK && inFile != nil && outFile != nil {
		return sys.NewFileTerminal(inFile, outFile)
	}
	return sys.NewStreamTerminal(sys.StreamTerminalSpec{
		In:          stdin,
		Out:         stdout,
		Interactive: false,
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
	expanded := override
	if strings.HasPrefix(expanded, "~/") || strings.HasPrefix(expanded, `~\`) {
		expanded = strings.TrimRight(homeDir.String(), `/\`) + "/" + expanded[2:]
	}
	p, err := pathalg.ParseLocalSourcePath(expanded)
	if err != nil {
		return zeroVal[pathalg.LocalSourcePath](), fmt.Errorf("invalid OpenSSH config file %q: %w", override, err)
	}
	return p, nil
}

func buildAuditAdapters(
	scopedFS ports.ScopedRootFS,
	stateDir pathalg.LocalDir,
	entropy ports.Entropy,
) (*audit.FileSink, *audit.FileReconciler, error) {
	sink, err := audit.NewFileSinkFromEntropy(scopedFS, stateDir, entropy)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize audit sink failed: %w", err)
	}
	reconciler, err := audit.NewFileReconciler(audit.ReconcilerSpec{
		ScopedFS: scopedFS,
		RootDir:  stateDir,
	})
	if err != nil {
		_ = sink.Close()
		return nil, nil, fmt.Errorf("initialize audit reconciler failed: %w", err)
	}
	return sink, reconciler, nil
}

func rollbackEngineAndAudit(ctx context.Context, eng *engine.Engine, sink *audit.FileSink) error {
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), engineRollbackTimeout)
	defer cancel()
	return errors.Join(eng.Close(closeCtx), sink.Close())
}

// wrapShutdownHandle 严格按 ADR-001 / ADR-008 逆序关闭法则封装停机闭包：
// 先排空并关闭 Engine（UseCases -> Pool -> SystemBus），再释放 AuditSink（清空、解锁并删除 .lock）。
func wrapShutdownHandle(eng *engine.Engine, sink *audit.FileSink) cli.EngineHandle {
	var once sync.Once
	var closeErr error
	return cli.EngineHandle{
		Runner: eng,
		Close: func(closeCtx context.Context) error {
			once.Do(func() {
				engErr := eng.Close(closeCtx)
				auditErr := sink.Close()
				closeErr = errors.Join(engErr, auditErr)
			})
			return closeErr
		},
	}
}
