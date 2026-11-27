package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdasset"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdops"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdssh"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdtransfer"
)

const defaultShutdownTimeout = 5 * time.Second

// AppConfig 是构造完整 CLI 入站调度器 App 的全显式依赖注入规格。
// 必填字段与 Wave 1 完全一致；新增子入口与宿主只读钩子均为可选字段，调用时若为 nil 一律失败关闭。
type AppConfig struct {
	// BuildInfo 为由组合根注入的只读构建元信息。
	BuildInfo BuildInfo
	// EngineFactory 为按需初始化核心引擎的工厂回调（必填，仅在需要 Engine 的命令触发）。
	EngineFactory EngineFactory
	// Stdin 为命令标准输入流（为 nil 时使用空读取器）。
	Stdin io.Reader
	// Stdout 为命令标准输出流（必填）。
	Stdout io.Writer
	// Stderr 为命令标准错误流（必填）。
	Stderr io.Writer
	// ShutdownTimeout 可选配置命令退出期等待引擎与审计落盘收敛的最大时长（None 默认 5s）。
	ShutdownTimeout algebraic.Option[algebraic.Duration]

	// RunTUI 为可选注入的 Bubble Tea v2 交互式终端工作台启动回调（供 `xops tui` 调用）。
	RunTUI TUIRunner
	// RunSFTPShell 为可选注入的交互式 SFTP Shell 启动回调（供 `xops sftp <target>` 调用）。
	RunSFTPShell SFTPShellRunner
	// RunMCP 为可选注入的 MCP 服务器启动回调（供 `xops mcp` 调用）。
	RunMCP MCPRunner
	// RunMuxDaemon 为可选注入的 ControlMaster 后台守护启动回调（供 `xops ssh -f` / `xops mux daemon` 调用）。
	RunMuxDaemon MuxDaemonRunner
	// ReadAuditLog 为可选注入的本地审计日志只读查询钩子（供 `xops audit list/tail/inspect` 调用）。
	ReadAuditLog AuditLogReader
	// ReadOperatorFile 为可选注入的操作员本地文件受控只读钩子（供 playbook/config import/sftp write 调用）。
	ReadOperatorFile OperatorFileReader
	// ResolveWorkDir 为可选注入的当前工作目录解析钩子（供 scp 下载解析相对路径，零直调 os.Getwd）。
	ResolveWorkDir WorkDirResolver
}

// App 是 XOps v2 的极薄 CLI 入站调度器（零业务逻辑、零全局状态、零 os.Exit）；
// 零值恒未初始化并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type App struct {
	buildInfo       BuildInfo
	engineFactory   EngineFactory
	stdin           io.Reader
	stdout          io.Writer
	stderr          io.Writer
	shutdownTimeout time.Duration
	hooks           clikit.SubEntryHooks
	valid           bool
}

// NewApp 校验必填流与引擎工厂并构造不可变 CLI App 实例。
func NewApp(cfg AppConfig) (*App, error) {
	if cfg.EngineFactory == nil {
		return nil, fmt.Errorf("%w: EngineFactory 不能为 nil", ErrInvalidConfig)
	}
	if cfg.Stdout == nil || cfg.Stderr == nil {
		return nil, fmt.Errorf("%w: Stdout 与 Stderr 不能为 nil", ErrInvalidConfig)
	}
	timeout := defaultShutdownTimeout
	if d, ok := cfg.ShutdownTimeout.Get(); ok {
		if !d.IsPositive() {
			return nil, fmt.Errorf("%w: ShutdownTimeout 必须为正时长", ErrInvalidConfig)
		}
		timeout = d.Std()
	}
	stdin := cfg.Stdin
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	return &App{
		buildInfo:       cfg.BuildInfo.Normalized(),
		engineFactory:   cfg.EngineFactory,
		stdin:           stdin,
		stdout:          cfg.Stdout,
		stderr:          cfg.Stderr,
		shutdownTimeout: timeout,
		hooks: clikit.SubEntryHooks{
			RunTUI:           cfg.RunTUI,
			RunSFTPShell:     cfg.RunSFTPShell,
			RunMCP:           cfg.RunMCP,
			RunMuxDaemon:     cfg.RunMuxDaemon,
			ReadAuditLog:     cfg.ReadAuditLog,
			ReadOperatorFile: cfg.ReadOperatorFile,
			ResolveWorkDir:   cfg.ResolveWorkDir,
		},
		valid: true,
	}, nil
}

// Run 解析全局前置选项与子命令，驱动对应命令族执行器并返回确定性进程退出码（不调用 os.Exit）。
func (a *App) Run(ctx context.Context, args []string) int {
	if a == nil || !a.valid {
		return clikit.ExitGeneral
	}
	rt := a.newRuntime(clikit.CommonFlags{})
	if ctx == nil {
		rt.WriteErr("cli: context 不能为 nil")
		return clikit.ExitGeneral
	}
	global, rest, err := clikit.ParseGlobalPrefix(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, global.JSON, err)
	}
	rt.Global = global
	if len(rest) == 0 {
		writeRootHelp(a.stdout)
		return clikit.ExitOK
	}
	cmd, subArgs := rest[0], rest[1:]
	switch cmd {
	case "-h", "--help", "help":
		return a.runHelp(rt, subArgs)
	case "version", "-V", "--version":
		return a.runVersion(rt, subArgs)
	default:
		return a.dispatchCommand(ctx, rt, cmd, subArgs)
	}
}

func (a *App) newRuntime(global clikit.CommonFlags) *clikit.Runtime {
	return &clikit.Runtime{
		Stdin:           a.stdin,
		Stdout:          a.stdout,
		Stderr:          a.stderr,
		EngineFactory:   a.engineFactory,
		ShutdownTimeout: a.shutdownTimeout,
		Hooks:           a.hooks,
		Global:          global,
	}
}

func (a *App) dispatchCommand(ctx context.Context, rt *clikit.Runtime, cmd string, subArgs []string) int {
	switch cmd {
	case "ssh":
		return cmdssh.RunSSH(ctx, rt, subArgs)
	case "exec":
		return cmdssh.RunExec(ctx, rt, subArgs)
	case "tunnel", "forward":
		return cmdssh.RunTunnel(ctx, rt, subArgs)
	case "mux":
		return cmdssh.RunMux(ctx, rt, subArgs)
	case "scp":
		return cmdtransfer.RunSCP(ctx, rt, subArgs)
	case "sftp":
		return cmdtransfer.RunSFTP(ctx, rt, subArgs)
	case "hosts", "host", "inventory":
		return cmdasset.RunHosts(ctx, rt, subArgs)
	case "creds", "cred", "vault":
		return cmdasset.RunVault(ctx, rt, subArgs)
	case "config":
		return cmdasset.RunConfig(ctx, rt, subArgs)
	case "playbook", "play":
		return cmdops.RunPlaybook(ctx, rt, subArgs)
	case "doctor":
		return cmdops.RunDoctor(ctx, rt, subArgs)
	case "audit":
		return cmdops.RunAudit(ctx, rt, subArgs)
	case "mcp":
		return cmdops.RunMCP(ctx, rt, subArgs)
	case "tui":
		return cmdops.RunTUI(ctx, rt, subArgs)
	default:
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(subArgs)), fmt.Errorf("%w: unknown command %q (run 'xops --help' for usage)", ErrUsage, cmd))
	}
}

func (a *App) runHelp(rt *clikit.Runtime, args []string) int {
	if len(args) == 0 {
		writeRootHelp(a.stdout)
		return clikit.ExitOK
	}
	if len(args) > 1 {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), fmt.Errorf("%w: help accepts at most one topic, got %q", ErrUsage, strings.Join(args, " ")))
	}
	text, ok := lookupHelpTopic(args[0])
	if !ok {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), fmt.Errorf("%w: unknown help topic %q", ErrUsage, args[0]))
	}
	_, _ = io.WriteString(a.stdout, text)
	return clikit.ExitOK
}

// runVersion 仅渲染显式注入的 BuildInfo（支持 --json），绝不初始化 Engine 或触碰任何本地状态目录。
func (a *App) runVersion(rt *clikit.Runtime, args []string) int {
	jsonOut := rt.EffectiveJSON(clikit.HasJSONFlag(args))
	for _, arg := range args {
		switch arg {
		case "-h", "--help":
			writeVersionHelp(a.stdout)
			return clikit.ExitOK
		case "--json", "--json=true", "--json=false", "--json=1", "--json=0", "--json=yes", "--json=no":
			// 已由 HasJSONFlag 统一求值（支持末次覆盖语义）。
		default:
			return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: version accepts only --json or --help, got %q", ErrUsage, arg))
		}
	}
	return rt.WriteResult(jsonOut, NewVersionView(a.buildInfo), func(w io.Writer) {
		_, _ = io.WriteString(w, FormatVersion(a.buildInfo))
	})
}
