package clikit

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type pathalgRemotePath = pathalg.RemotePath

// EngineInitOptions 描述 CLI 按需初始化核心引擎时透传给组合根的只读覆盖参数。
// 通过该值结构体隔离宿主路径与策略装配，确保 internal/entry/cli 零引用 internal/host/** 或 core/osfs。
type EngineInitOptions struct {
	// OpenSSHConfigFile 为 `-F <configfile>` 指定的 OpenSSH 配置文件覆盖路径（空串沿用默认配置，"none" 禁用）。
	OpenSSHConfigFile string
	// PolicyProfile 为 `--policy` 指定的安全策略配置档（零值 PolicyProfileInvalid 表示沿用宿主默认配置档）。
	PolicyProfile engine.PolicyProfile
	// Locale 为当前 CLI 生效的界面语言（供组合根同步宿主交互适配器 Localizer；零值表示沿用默认）。
	Locale domi18n.Locale
}

// EngineHandle 封装按需创建的运行期引擎及其确定性逆序关闭回调。
// 当 Close 非空时，CLI 优先调用 Close 以允许组合根按 Engine -> Pool -> Vault -> Store -> Audit 严格逆序停机。
type EngineHandle struct {
	// Runner 为核心引擎执行入口（非 nil；*engine.Engine 原生满足全部具名能力接口）。
	Runner SessionRunner
	// Close 为组合根提供的完整逆序停机回调；为 nil 时回退调用 Runner.Close。
	Close func(ctx context.Context) error
}

// EngineFactory 按需为需要运行期核心的命令构造 EngineHandle（`version`/`help`/`playbook validate` 严禁触发）。
type EngineFactory func(ctx context.Context, opts EngineInitOptions) (EngineHandle, error)

// TUIStartRequest 描述通过回调启动 Bubble Tea v2 终端工作台的强类型参数。
type TUIStartRequest struct {
	InitOptions     EngineInitOptions
	Locale          domi18n.Locale
	InitialNode     string
	RefreshInterval algebraic.Option[algebraic.Duration]
	NoAltScreen     bool
	Stdin           io.Reader
	Stdout          io.Writer
	Stderr          io.Writer
}

// TUIRunner 为由组合根注入的交互式 TUI 子入口启动回调。
type TUIRunner func(ctx context.Context, req TUIStartRequest) error

// SFTPShellStartRequest 描述通过回调启动交互式 SFTP Shell 的强类型参数。
type SFTPShellStartRequest struct {
	InitOptions EngineInitOptions
	Locale      domi18n.Locale
	TargetSpec  string
	CLIOptions  option.OptionLayer
	InitialDir  string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
}

// SFTPShellRunner 为由组合根注入的交互式 SFTP Shell 子入口启动回调。
type SFTPShellRunner func(ctx context.Context, req SFTPShellStartRequest) error

// MCPStartRequest 描述通过回调启动 MCP 服务器（stdio / Streamable HTTP）的强类型参数。
type MCPStartRequest struct {
	InitOptions          EngineInitOptions
	Locale               domi18n.Locale
	Transport            string // "stdio" | "http"
	ListenAddr           string
	TransferRoot         algebraic.Option[pathalg.LocalDir]
	ArtifactRoot         algebraic.Option[pathalg.LocalDir]
	AllowNonLoopbackHTTP bool
	HTTPAllowedOrigins   []string
	HTTPAllowedHosts     []string
	Stdin                io.Reader
	Stdout               io.Writer
	Stderr               io.Writer
}

// MCPRunner 为由组合根注入的 MCP 服务子入口启动回调。
type MCPRunner func(ctx context.Context, req MCPStartRequest) error

// MuxDaemonStartRequest 描述通过回调启动 ControlMaster/ControlPersist 后台守护进程的强类型参数。
type MuxDaemonStartRequest struct {
	InitOptions EngineInitOptions
	Locale      domi18n.Locale
	TargetSpec  string
	CLIOptions  option.OptionLayer
	Forwards    []engine.ForwardSpec
	SocketPath  algebraic.Option[pathalg.LocalSourcePath]
	Stdout      io.Writer
	Stderr      io.Writer
}

// MuxDaemonRunner 为由组合根注入的多路复用守护进程子入口启动回调。
type MuxDaemonRunner func(ctx context.Context, req MuxDaemonStartRequest) error

// AuditQueryRequest 描述向宿主只读审计查询钩子发起过滤检索的强类型请求。
type AuditQueryRequest struct {
	Limit       int
	Tail        bool
	Phase       string
	Outcome     string
	OperationID algebraic.Option[security.OperationID]
	TraceID     algebraic.Option[security.TraceID]
	NodeID      string
}

// AuditRecordView 描述单条脱敏审计日志记录的规范 JSON/v2 只读视图（零裸 time.Duration、零 SecretBox）。
type AuditRecordView struct {
	ProcessID   string                               `json:"process_id"`
	TraceID     security.TraceID                     `json:"trace_id"`
	OperationID security.OperationID                 `json:"operation_id"`
	Phase       string                               `json:"phase"`
	Outcome     string                               `json:"outcome"`
	Risk        security.RiskLevel                   `json:"risk"`
	Decision    security.DecisionKind                `json:"decision"`
	Capability  security.CapabilityKind              `json:"capability"`
	Tool        string                               `json:"tool"`
	Action      string                               `json:"action"`
	NodeID      string                               `json:"node_id,omitzero"`
	Timestamp   time.Time                            `json:"timestamp"`
	Duration    algebraic.Option[algebraic.Duration] `json:"duration,omitzero"`
	ErrorCode   string                               `json:"error_code,omitzero"`
	Reason      string                               `json:"reason,omitzero"`
}

// AuditQueryResult 封装宿主审计日志只读查询钩子的分页与截断统计结果。
type AuditQueryResult struct {
	TotalMatched int               `json:"total_matched"`
	Truncated    bool              `json:"truncated,omitzero"`
	Entries      []AuditRecordView `json:"entries"`
}

// AuditLogReader 为由组合根注入的本地审计日志只读查询钩子（底层经 ScopedRootFS 读取 audit.jsonl）。
type AuditLogReader func(ctx context.Context, req AuditQueryRequest) (AuditQueryResult, error)

// OperatorFileReader 为由组合根注入的受控操作员只读文件钩子（底层经 OperatorReadFS 读取并限流）。
type OperatorFileReader func(ctx context.Context, path pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, maxBytes int64) ([]byte, error)

// WorkDirResolver 为由组合根注入的当前工作目录解析钩子，避免入口层直接调用 os.Getwd。
type WorkDirResolver func() (pathalg.LocalDir, error)

// SubEntryHooks 汇总由组合根显式注入的可选子入口启动器与宿主只读钩子（nil 一律失败关闭）。
type SubEntryHooks struct {
	RunTUI           TUIRunner
	RunSFTPShell     SFTPShellRunner
	RunMCP           MCPRunner
	RunMuxDaemon     MuxDaemonRunner
	ReadAuditLog     AuditLogReader
	ReadOperatorFile OperatorFileReader
	ResolveWorkDir   WorkDirResolver
}

// Runtime 聚合单次命令分发期间只读的 I/O 流、全局标志、引擎按需工厂、国际化词库与注入钩子。
type Runtime struct {
	Stdin           io.Reader
	Stdout          io.Writer
	Stderr          io.Writer
	EngineFactory   EngineFactory
	ShutdownTimeout time.Duration
	Hooks           SubEntryHooks
	Global          CommonFlags
	Catalog         *i18n.Catalog
	Localizer       *i18n.Localizer
	// PreScannedJSON 保存由 App.Run（或 PrepareSubcommand 直接回退路径）通过命令感知词法预扫描算出的
	// 全命令行末次生效 `--json` 开关；为 Some 时跨全局/中置/子命令强制服从末次覆盖语义，
	// 为 None 时回退为 Global.JSON || localJSON 以兼容直接构造 Runtime 的单元测试。
	PreScannedJSON algebraic.Option[bool]
}

// EnsureLocalizer 返回可用的不可变 Localizer；作为纯渲染路径兜底辅助，当 loc 为 nil 或无效时从内置词库回退英文
// （纯内存、零触盘，确保诊断与错误渲染路径永不因 Localizer 缺失而丢失信息；构造期配置校验仍由 cli.NewApp 严格失败关闭）。
// 若极端情况下内置词库不可用则返回 nil（*i18n.Localizer 对 nil 接收者严格安全失败关闭）。
func EnsureLocalizer(loc *i18n.Localizer) *i18n.Localizer {
	if loc != nil && loc.IsValid() {
		return loc
	}
	if def, err := i18n.DefaultLocalizer(); err == nil && def.IsValid() {
		return def
	}
	return nil
}

// Loc 返回当前运行期绑定的不可变 Localizer；渲染期若未显式设置或收到无效零值，
// 按「已绑定有效 Localizer -> 有效 Catalog + Global.Locale -> 内置英文词库 DefaultLocalizer」顺序安全回退
// （与 cli.NewApp 对非 nil 无效 Catalog 的构造期失败关闭互补，保障报错渲染绝不递归失败）。
func (r *Runtime) Loc() *i18n.Localizer {
	if r != nil && r.Localizer != nil && r.Localizer.IsValid() {
		return r.Localizer
	}
	if r != nil && r.Catalog != nil && r.Catalog.IsValid() {
		if loc, ok := r.Global.Locale.Get(); ok && loc.IsValid() {
			return r.Catalog.For(loc)
		}
		return r.Catalog.For(domi18n.LocaleEn)
	}
	return EnsureLocalizer(nil)
}

// WithPrefix 返回浅拷贝的 Runtime，将多级命令前置通用标志（--json / --policy / --lang / -F / --ssh-config）
// 合并至副本的 Global 字段（不修改原 Runtime）。
// 当原 Runtime 已由 App.Run 经全命令行预扫描锁定权威最终语言（Global.Locale.IsSome() 且合法）时，
// 严禁以二级子命令之前的中置 prefix.Locale 覆写 Global.Locale 或 Localizer；
// 仅在 Global.Locale.IsNone()（如绕过 App.Run 直接调用子命令入口的单测）时回退应用 prefix.Locale 并同步 Localizer。
func (r *Runtime) WithPrefix(prefix CommonFlags) *Runtime {
	if r == nil {
		return nil
	}
	cp := *r
	cp.Global = MergeCommonFlags(r.Global, prefix)
	if baseLoc, ok := r.Global.Locale.Get(); ok && baseLoc.IsValid() {
		cp.Global.Locale = algebraic.Some(baseLoc)
		return &cp
	}
	if loc, ok := prefix.Locale.Get(); ok && loc.IsValid() {
		if resolved := resolvePrefixLocalizer(cp.Catalog, loc); resolved != nil {
			cp.Localizer = resolved
		}
	}
	return &cp
}

// SubcommandDispatch 保存多级命令前置通用标志消费与二级动作词提取的分发结果。
type SubcommandDispatch struct {
	RT       *Runtime
	Sub      string
	Rest     []string
	ExitCode int
	Handled  bool
}

// PrepareSubcommand 在多级子命令入口统一消费前置通用标志并合并至副本 Runtime：
//   - 前置标志报错时按全命令行/命令感知末次 JSON 开关输出错误并返回 Handled=true；
//   - 遇到 -h / --help / help 或无二级动作词时输出本地化帮助并返回 ExitOK 与 Handled=true；
//   - 其余情况返回合并后的 Runtime、二级子命令词 Sub、剩余参数 Rest 与 Handled=false。
func (r *Runtime) PrepareSubcommand(
	cmd string,
	args []string,
	helpText func(*i18n.Localizer) string,
) SubcommandDispatch {
	prefix, rem, err := ConsumeSubcommandPrefix(args)
	if err != nil {
		return SubcommandDispatch{
			ExitCode: r.Fail(ExitUsage, r.effectiveJSONForCommand(cmd, args), err),
			Handled:  true,
		}
	}
	next := r.applySubcommandPrefix(cmd, args, prefix)
	if prefix.ShowHelp || len(rem) == 0 || rem[0] == "help" {
		if helpText != nil {
			_, _ = io.WriteString(next.Stdout, helpText(next.Loc()))
		}
		return SubcommandDispatch{ExitCode: ExitOK, Handled: true}
	}
	return SubcommandDispatch{RT: next, Sub: rem[0], Rest: rem[1:]}
}

// EffectiveLocale 返回当前运行期生效的显示语言标识（优先 Localizer，其次 Global.Locale，回退 LocaleEn）。
func (r *Runtime) EffectiveLocale() domi18n.Locale {
	if r != nil && r.Localizer != nil && r.Localizer.IsValid() {
		return r.Localizer.Locale()
	}
	if r != nil {
		if loc, ok := r.Global.Locale.Get(); ok && loc.IsValid() {
			return loc
		}
	}
	return domi18n.LocaleEn
}

// EffectiveInitOptions 合并全局与命令级 `-F` / `--policy` 覆盖项及生效语言，生成最终 EngineInitOptions。
func (r *Runtime) EffectiveInitOptions(localCfg string, localPolicy engine.PolicyProfile) EngineInitOptions {
	cfg := r.Global.ConfigFile
	if strings.TrimSpace(localCfg) != "" {
		cfg = localCfg
	}
	pol := r.Global.Policy
	if localPolicy.IsValid() {
		pol = localPolicy
	}
	return EngineInitOptions{
		OpenSSHConfigFile: cfg,
		PolicyProfile:     pol,
		Locale:            r.EffectiveLocale(),
	}
}

// EffectiveJSON 计算当前命令的最终 `--json` 输出开关：
// 若已通过全命令行预扫描确定末次生效结果（PreScannedJSON.IsSome()），直接采用该权威值以保证
// 跨全局/中置/子命令的 `--json` 与 `--json=false` 严格服从末次覆盖；否则回退为 Global.JSON || localJSON。
func (r *Runtime) EffectiveJSON(localJSON bool) bool {
	if r == nil {
		return localJSON
	}
	if v, ok := r.PreScannedJSON.Get(); ok {
		return v
	}
	return r.Global.JSON || localJSON
}

// WithEngine 在同步作用域内按需构造核心 EngineHandle、执行 fn 并在退出时以剥离取消的有限超时上下文严格逆序关闭。
// 若业务成功但关闭阶段失败，强制失败关闭将退出码提升为非零。
//
//xops:syncclosure
func (r *Runtime) WithEngine(ctx context.Context, opts EngineInitOptions, failCode int, jsonOut bool, fn func(SessionRunner) int) (exitCode int) {
	if err := ctx.Err(); err != nil {
		return r.Fail(failCode, jsonOut, err)
	}
	handle, err := r.EngineFactory(ctx, opts)
	if err != nil {
		return r.Fail(failCode, jsonOut, err)
	}
	if handle.Runner == nil {
		if handle.Close != nil {
			_ = r.closeHandle(ctx, handle)
		}
		return r.Fail(ExitGeneral, jsonOut, i18n.EF(ErrInvalidConfig, i18n.KeyCLINilSessionRunner))
	}
	defer func() {
		if closeErr := r.closeHandle(ctx, handle); closeErr != nil {
			loc := r.Loc()
			r.WriteErr(loc.T(i18n.KeyCLIShutdownFailed, i18n.BoundStr("err", loc.RenderError(closeErr))))
			if exitCode == ExitOK {
				exitCode = ExitGeneral
			}
		}
	}()
	return fn(handle.Runner)
}

func (r *Runtime) closeHandle(ctx context.Context, handle EngineHandle) error {
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.ShutdownTimeout)
	defer cancel()
	if handle.Close != nil {
		return handle.Close(closeCtx)
	}
	return handle.Runner.Close(closeCtx)
}

// WriteErr 向 Stderr 输出带统一 `xops: ` 前缀的单行诊断文本。
func (r *Runtime) WriteErr(msg string) {
	_, _ = fmt.Fprintf(r.Stderr, "xops: %s\n", strings.TrimSpace(msg))
}

// Fail 按当前输出模式与生效语言渲染错误诊断（JSON 模式写入规范 ErrorEnvelope，文本模式写 Stderr）并返回退出码。
func (r *Runtime) Fail(exitCode int, jsonOut bool, err error) int {
	if exitCode == ExitOK {
		exitCode = ExitGeneral
	}
	loc := r.Loc()
	if jsonOut {
		WriteJSONErrorLocalized(r.Stdout, loc, exitCode, err)
		return exitCode
	}
	if err != nil {
		r.WriteErr(loc.RenderError(err))
		if rc, ok := engine.ExtractReferenceConflict(err); ok && rc.IsValid() {
			r.writeRefConflictText(loc, rc)
		}
		if ch, ok := engine.ExtractApprovalChallenge(err); ok && ch.IsValid() {
			r.WriteErr(loc.T(
				i18n.KeyCLIApprovalRequired,
				i18n.BoundStr("digest", ch.EnvelopeDigest().String()),
				i18n.Bool("escalated", ch.Escalated()),
				ch.ReasonParam("reason"),
			))
		}
	}
	return exitCode
}

func (r *Runtime) writeRefConflictText(loc *i18n.Localizer, rc engine.ReferenceConflict) {
	for _, ref := range rc.AssetReferences() {
		r.WriteErr(loc.T(
			i18n.KeyCLIRefAsset,
			i18n.Str("location", ref.Location.String()),
			i18n.BoundStr("node", ref.FromNode.String()),
			i18n.BoundStr("target", ref.Target),
		))
	}
	for _, ref := range rc.SecretReferences() {
		r.WriteErr(loc.T(
			i18n.KeyCLIRefSecret,
			i18n.Str("location", ref.Location.String()),
			i18n.BoundStr("owner", ref.OwnerID),
			i18n.BoundStr("ref", ref.Ref.String()),
		))
	}
}

// WriteResult 根据 jsonOut 开关将结构化结果输出为规范 JSON/v2 或调用文本渲染回调。
//
//xops:syncclosure
func (r *Runtime) WriteResult(jsonOut bool, payload any, renderText func(io.Writer)) int {
	if jsonOut {
		if err := WriteJSON(r.Stdout, payload); err != nil {
			loc := r.Loc()
			r.WriteErr(loc.T(i18n.KeyCLIMarshalJSONFailed, i18n.BoundStr("err", loc.RenderError(err))))
			return ExitGeneral
		}
		return ExitOK
	}
	if renderText != nil {
		renderText(r.Stdout)
	}
	return ExitOK
}

// ReadLocalInput 从操作员文件（经注入的 ReadOperatorFile 钩子）或 Stdin（路径为 "-" 时）有界读取字节载荷。
func (r *Runtime) ReadLocalInput(ctx context.Context, rawPath string, policy pathalg.SymlinkPolicy, maxBytes int64) ([]byte, string, error) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" || trimmed == "-" {
		data, err := ReadBounded(r.Stdin, maxBytes)
		if err != nil {
			return nil, "", err
		}
		return data, "<stdin>", nil
	}
	if r.Hooks.ReadOperatorFile == nil {
		return nil, "", i18n.EF(ErrNotConfigured, i18n.KeyCLIHookNotConfigured, i18n.Str("hook", "ReadOperatorFile"))
	}
	srcPath, err := pathalg.ParseLocalSourcePath(trimmed)
	if err != nil {
		return nil, "", i18n.WrapS(ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Msg("field", i18n.NewMessage(i18n.KeyCLIFieldLocalFilePath)), i18n.BoundStr("value", trimmed))
	}
	data, err := r.Hooks.ReadOperatorFile(ctx, srcPath, policy, maxBytes)
	if err != nil {
		return nil, "", err
	}
	return data, srcPath.String(), nil
}

// ReadBounded 从任意 io.Reader 读取至多 maxBytes 字节，超过上限严格失败关闭。
func ReadBounded(r io.Reader, maxBytes int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	if maxBytes <= 0 {
		maxBytes = 16 << 20
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, i18n.EF(engine.ErrLimitExceeded, i18n.KeyCLIInputTooLarge, i18n.Int64("max", maxBytes))
	}
	return data, nil
}
