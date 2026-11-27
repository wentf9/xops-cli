package cli

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdasset"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdops"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdssh"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdtransfer"
	"github.com/wentf9/xops-cli/internal/i18n"
)

const defaultShutdownTimeout = 5 * time.Second

// AppConfig 是构造完整 CLI 入站调度器 App 的全显式依赖注入规格。
// 必填字段与 Wave 1 完全一致；新增国际化词库、默认语言、子入口与宿主只读钩子均为可选字段，
// 子入口/钩子调用时若为 nil 一律失败关闭，Catalog 为 nil 时经内置 embed.FS 自动内存兜底英文。
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
	// Catalog 为可选注入的国际化双语词库只读快照（nil 时经内置 embed.FS 内存加载，零触盘）。
	Catalog *i18n.Catalog
	// DefaultLocale 为宿主探测的默认界面语言（零值或非法时回退 LocaleEn）。
	DefaultLocale domi18n.Locale

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
	catalog         *i18n.Catalog
	defaultLocale   domi18n.Locale
	hooks           clikit.SubEntryHooks
	valid           bool
}

// NewApp 校验必填流与引擎工厂并构造不可变 CLI App 实例。
func NewApp(cfg AppConfig) (*App, error) {
	if cfg.EngineFactory == nil {
		return nil, i18n.EF(ErrInvalidConfig, i18n.KeyCLINilEngineFactory)
	}
	if cfg.Stdout == nil || cfg.Stderr == nil {
		return nil, i18n.EF(ErrInvalidConfig, i18n.KeyCLINilStdStreams)
	}
	timeout, err := resolveShutdownTimeout(cfg.ShutdownTimeout)
	if err != nil {
		return nil, err
	}
	cat, err := resolveAppCatalog(cfg.Catalog)
	if err != nil {
		return nil, err
	}
	defLocale := cfg.DefaultLocale
	if !defLocale.IsValid() {
		defLocale = domi18n.LocaleEn
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
		catalog:         cat,
		defaultLocale:   defLocale,
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

func resolveShutdownTimeout(opt algebraic.Option[algebraic.Duration]) (time.Duration, error) {
	d, ok := opt.Get()
	if !ok {
		return defaultShutdownTimeout, nil
	}
	if !d.IsPositive() {
		return 0, i18n.EF(ErrInvalidConfig, i18n.KeyCLIShutdownTimeoutPositive)
	}
	return d.Std(), nil
}

func resolveAppCatalog(cat *i18n.Catalog) (*i18n.Catalog, error) {
	if cat != nil && cat.IsValid() {
		return cat, nil
	}
	loaded, err := i18n.LoadCatalog()
	if err != nil {
		return nil, i18n.WrapS(ErrInvalidConfig, err, i18n.KeyCLIInvalidConfig)
	}
	return loaded, nil
}

// Run 统一执行命令/选项感知 `--lang` 扫描、全局前置选项解析与子命令分发，并返回确定性退出码（不调用 os.Exit）。
func (a *App) Run(ctx context.Context, args []string) int {
	if a == nil || !a.valid {
		return clikit.ExitGeneral
	}
	rt := a.newRuntime(clikit.CommonFlags{}, a.defaultLocale)
	if ctx == nil {
		rt.WriteErr(rt.Loc().RenderError(i18n.E(i18n.KeyCLINilContext)))
		return clikit.ExitGeneral
	}
	scannedLoc, langErr := clikit.ScanLangFlag(args)
	if langErr != nil {
		return rt.Fail(clikit.ExitUsage, clikit.HasJSONFlag(args), langErr)
	}
	effectiveLocale := a.defaultLocale
	if loc, ok := scannedLoc.Get(); ok && loc.IsValid() {
		effectiveLocale = loc
	}
	rt.Localizer = a.catalog.For(effectiveLocale)
	global, rest, err := clikit.ParseGlobalPrefix(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, global.JSON, err)
	}
	global.Locale = algebraic.Some(effectiveLocale)
	rt.Global = global
	if len(rest) == 0 {
		writeRootHelp(a.stdout, rt.Loc())
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

func (a *App) newRuntime(global clikit.CommonFlags, locale domi18n.Locale) *clikit.Runtime {
	return &clikit.Runtime{
		Stdin:           a.stdin,
		Stdout:          a.stdout,
		Stderr:          a.stderr,
		EngineFactory:   a.engineFactory,
		ShutdownTimeout: a.shutdownTimeout,
		Hooks:           a.hooks,
		Global:          global,
		Catalog:         a.catalog,
		Localizer:       a.catalog.For(locale),
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
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(subArgs)), i18n.EF(ErrUsage, i18n.KeyCLIUnknownCommand, i18n.BoundStr("cmd", cmd)))
	}
}

func (a *App) runHelp(rt *clikit.Runtime, args []string) int {
	topics, err := parseHelpArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if len(topics) == 0 {
		writeRootHelp(a.stdout, rt.Loc())
		return clikit.ExitOK
	}
	if len(topics) > 1 {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), i18n.EF(ErrUsage, i18n.KeyCLIHelpTooManyTopics, i18n.BoundStr("args", strings.Join(topics, " "))))
	}
	text, ok := lookupHelpTopic(rt.Loc(), topics[0])
	if !ok {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), i18n.EF(ErrUsage, i18n.KeyCLIUnknownHelpTopic, i18n.BoundStr("topic", topics[0])))
	}
	_, _ = io.WriteString(a.stdout, text)
	return clikit.ExitOK
}

func parseHelpArgs(args []string) ([]string, error) {
	var cf clikit.CommonFlags
	var topics []string
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		tok := cur.Peek()
		if tok == "--" {
			cur.Next()
			topics = append(topics, cur.Rest()...)
			break
		}
		if tok == "-h" {
			cur.Next()
			continue
		}
		if name, _, _, isLong := clikit.ParseLongFlagName(tok); isLong && (name == "lang" || name == "help" || name == "json") {
			if _, err := clikit.TryConsumeCommonLongFlag(cur, &cf); err != nil {
				return nil, err
			}
			continue
		}
		topics = append(topics, cur.Next())
	}
	return topics, nil
}

// runVersion 仅渲染显式注入的 BuildInfo（支持 --json / --lang / --help），绝不初始化 Engine 或触碰任何本地状态目录。
func (a *App) runVersion(rt *clikit.Runtime, args []string) int {
	var cf clikit.CommonFlags
	jsonErrMode := rt.EffectiveJSON(clikit.HasJSONFlag(args))
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		tok := cur.Peek()
		if tok == "-h" || tok == "--help" {
			writeVersionHelp(a.stdout, rt.Loc())
			return clikit.ExitOK
		}
		if name, _, _, isLong := clikit.ParseLongFlagName(tok); isLong && (name == "json" || name == "lang" || name == "help") {
			if _, err := clikit.TryConsumeCommonLongFlag(cur, &cf); err != nil {
				return rt.Fail(clikit.ExitUsage, jsonErrMode, err)
			}
			if cf.ShowHelp {
				writeVersionHelp(a.stdout, rt.Loc())
				return clikit.ExitOK
			}
			continue
		}
		return rt.Fail(clikit.ExitUsage, jsonErrMode, i18n.EF(ErrUsage, i18n.KeyCLIVersionInvalidArg, i18n.BoundStr("arg", tok)))
	}
	jsonOut := rt.EffectiveJSON(cf.JSON)
	return rt.WriteResult(jsonOut, NewVersionView(a.buildInfo), func(w io.Writer) {
		_, _ = io.WriteString(w, FormatVersionLocalized(rt.Loc(), a.buildInfo))
	})
}
