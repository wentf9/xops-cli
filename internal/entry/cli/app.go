package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/engine"
)

const defaultShutdownTimeout = 5 * time.Second

// SessionRunner 定义 CLI 入站层驱动核心 SSH 执行所需的最小引擎契约（由 *engine.Engine 原生实现）。
type SessionRunner interface {
	RunSSH(ctx context.Context, req engine.RunSSHRequest) (execution.ExecutionOutcome, error)
	Close(ctx context.Context) error
}

// EngineInitOptions 描述 CLI 命令按需初始化核心引擎时透传给组合根的只读覆盖项。
// 通过该值结构体传递 `-F <configfile>` 等宿主路径参数，确保 internal/entry/cli 零引用 host/openssh 或 core/osfs。
type EngineInitOptions struct {
	// OpenSSHConfigFile 为 `-F <configfile>` 指定的 OpenSSH 配置文件覆盖路径（空串沿用默认配置，"none" 禁用）。
	OpenSSHConfigFile string
}

// EngineHandle 封装按需创建的运行期引擎及其确定性逆序关闭回调。
// 当 Close 非空时，CLI 优先调用 Close 以允许组合根按 Engine -> AuditSink 严格逆序关闭全部宿主资源。
type EngineHandle struct {
	// Runner 为核心 SSH 会话执行入口（非 nil）。
	Runner SessionRunner
	// Close 为组合根提供的完整逆序停机回调；为 nil 时回退调用 Runner.Close。
	Close func(ctx context.Context) error
}

// EngineFactory 按需为需要运行期核心的命令构造 EngineHandle（`xops version` 与 `--help` 严禁触发调用）。
type EngineFactory func(ctx context.Context, opts EngineInitOptions) (EngineHandle, error)

// AppConfig 是构造 CLI 入站调度器 App 的全显式依赖注入规格。
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
}

// App 是 XOps v2 Walking Skeleton 的极薄 CLI 入站调度器（零业务逻辑、零全局状态、零 os.Exit）；
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
		valid:           true,
	}, nil
}

// Run 解析命令行子命令与参数，驱动对应动作并返回确定性进程退出码（不调用 os.Exit）。
func (a *App) Run(ctx context.Context, args []string) int {
	if a == nil || !a.valid {
		return exitCodeGeneralError
	}
	if ctx == nil {
		a.writeErr("cli: context 不能为 nil")
		return exitCodeGeneralError
	}
	if len(args) == 0 {
		a.writeRootHelp()
		return exitCodeOK
	}
	switch args[0] {
	case "-h", "--help", "help":
		return a.runHelp(args[1:])
	case "version", "-V", "--version":
		return a.runVersion(args[1:])
	case "ssh":
		return a.runSSH(ctx, args[1:])
	default:
		a.writeErr(fmt.Sprintf("unknown command %q (run 'xops --help' for usage)", args[0]))
		return exitCodeUsage
	}
}

func (a *App) runHelp(args []string) int {
	if len(args) == 0 {
		a.writeRootHelp()
		return exitCodeOK
	}
	switch args[0] {
	case "ssh":
		a.writeSSHHelp()
		return exitCodeOK
	case "version":
		a.writeVersionHelp()
		return exitCodeOK
	default:
		a.writeErr(fmt.Sprintf("unknown help topic %q", args[0]))
		return exitCodeUsage
	}
}

// runVersion 仅渲染显式注入的 BuildInfo，绝不初始化 Engine 或触碰任何本地状态目录。
func (a *App) runVersion(args []string) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		a.writeVersionHelp()
		return exitCodeOK
	}
	if len(args) > 0 {
		a.writeErr(fmt.Sprintf("version accepts no arguments, got %q", strings.Join(args, " ")))
		return exitCodeUsage
	}
	_, _ = io.WriteString(a.stdout, FormatVersion(a.buildInfo))
	return exitCodeOK
}

func (a *App) runSSH(ctx context.Context, args []string) (exitCode int) {
	parsed, err := ParseSSHArgs(args)
	if err != nil {
		a.writeErr(err.Error())
		return exitCodeUsage
	}
	if parsed.ShowHelp {
		a.writeSSHHelp()
		return exitCodeOK
	}
	if err := ctx.Err(); err != nil {
		a.writeErr(err.Error())
		return exitCodeSSHError
	}

	handle, err := a.engineFactory(ctx, EngineInitOptions{
		OpenSSHConfigFile: parsed.ConfigFile,
	})
	if err != nil {
		a.writeErr(err.Error())
		return exitCodeSSHError
	}
	if handle.Runner == nil {
		if handle.Close != nil {
			_ = a.closeHandle(ctx, handle)
		}
		a.writeErr("cli: EngineFactory 返回了 nil SessionRunner")
		return exitCodeGeneralError
	}
	defer func() {
		if closeErr := a.closeHandle(ctx, handle); closeErr != nil {
			a.writeErr("shutdown failed: " + closeErr.Error())
			if exitCode == exitCodeOK {
				exitCode = exitCodeGeneralError
			}
		}
	}()

	outcome, runErr := handle.Runner.RunSSH(ctx, engine.RunSSHRequest{
		TargetSpec:  parsed.TargetSpec,
		CLIOptions:  parsed.CLIOptions,
		CommandArgs: parsed.CommandArgs,
		Stdin:       a.stdin,
		Stdout:      a.stdout,
		Stderr:      a.stderr,
		RequestTTY:  parsed.RequestTTY,
	})
	code, diag, _ := mapOutcomeToExit(outcome, runErr)
	if diag != "" {
		a.writeErr(diag)
	}
	return code
}

// closeHandle 使用剥离取消但带有限超时的上下文关闭运行期句柄，
// 确保即便用户按下 Ctrl+C 取消操作上下文，仍能按严格逆序排空连接池并安全释放审计锁。
func (a *App) closeHandle(ctx context.Context, handle EngineHandle) error {
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.shutdownTimeout)
	defer cancel()
	if handle.Close != nil {
		return handle.Close(closeCtx)
	}
	return handle.Runner.Close(closeCtx)
}

func (a *App) writeErr(msg string) {
	_, _ = fmt.Fprintf(a.stderr, "xops: %s\n", strings.TrimSpace(msg))
}

func (a *App) writeRootHelp() {
	_, _ = io.WriteString(a.stdout, `Usage:
  xops <command> [flags]

Commands:
  ssh       Connect to a remote host or execute a remote command over SSH
  version   Print XOps build version metadata
  help      Show help for a command

Run 'xops <command> --help' for details on a specific command.
`)
}

func (a *App) writeVersionHelp() {
	_, _ = io.WriteString(a.stdout, `Usage:
  xops version

Print XOps version, commit, build time, and Go toolchain metadata without initializing Engine state.
`)
}

func (a *App) writeSSHHelp() {
	_, _ = io.WriteString(a.stdout, `Usage:
  xops ssh [flags] [user@]host [command [args...]]

Flags:
  -p <port>           Port to connect to on the remote host
  -l <user>           Login name on the remote machine
  -i <identity_file>  Private key file for public key authentication (repeatable)
  -J <proxy_jump>     Jump host destination chain (e.g. jump1,jump2)
  -o <Key=Value>      OpenSSH option override (repeatable)
  -t                  Force pseudo-terminal allocation (-tt forces even without local TTY)
  -T                  Disable pseudo-terminal allocation
  -F <configfile>     Alternative per-user OpenSSH configuration file ("none" to disable)
  -h, --help          Show this help message
`)
}
