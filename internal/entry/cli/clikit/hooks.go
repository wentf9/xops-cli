package clikit

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
)

type pathalgRemotePath = pathalg.RemotePath

// EngineInitOptions 描述 CLI 按需初始化核心引擎时透传给组合根的只读覆盖参数。
// 通过该值结构体隔离宿主路径与策略装配，确保 internal/entry/cli 零引用 internal/host/** 或 core/osfs。
type EngineInitOptions struct {
	// OpenSSHConfigFile 为 `-F <configfile>` 指定的 OpenSSH 配置文件覆盖路径（空串沿用默认配置，"none" 禁用）。
	OpenSSHConfigFile string
	// PolicyProfile 为 `--policy` 指定的安全策略配置档（零值 PolicyProfileInvalid 表示沿用宿主默认配置档）。
	PolicyProfile engine.PolicyProfile
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

// Runtime 聚合单次命令分发期间只读的 I/O 流、全局标志、引擎按需工厂与注入钩子。
type Runtime struct {
	Stdin           io.Reader
	Stdout          io.Writer
	Stderr          io.Writer
	EngineFactory   EngineFactory
	ShutdownTimeout time.Duration
	Hooks           SubEntryHooks
	Global          CommonFlags
}

// EffectiveInitOptions 合并全局与命令级 `-F` / `--policy` 覆盖项，生成最终 EngineInitOptions。
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
	}
}

// EffectiveJSON 返回全局与命令级 `--json` 标志的逻辑并集。
func (r *Runtime) EffectiveJSON(localJSON bool) bool {
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
		return r.Fail(ExitGeneral, jsonOut, fmt.Errorf("%w: EngineFactory 返回了 nil SessionRunner", ErrInvalidConfig))
	}
	defer func() {
		if closeErr := r.closeHandle(ctx, handle); closeErr != nil {
			r.WriteErr("shutdown failed: " + closeErr.Error())
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

// Fail 按当前输出模式渲染错误诊断（JSON 模式写入规范 ErrorEnvelope，文本模式写 Stderr）并返回退出码。
func (r *Runtime) Fail(exitCode int, jsonOut bool, err error) int {
	if exitCode == ExitOK {
		exitCode = ExitGeneral
	}
	if jsonOut {
		WriteJSONError(r.Stdout, exitCode, err)
		return exitCode
	}
	if err != nil {
		r.WriteErr(err.Error())
		if rc, ok := engine.ExtractReferenceConflict(err); ok && rc.IsValid() {
			r.writeRefConflictText(rc)
		}
		if ch, ok := engine.ExtractApprovalChallenge(err); ok && ch.IsValid() {
			r.WriteErr(fmt.Sprintf("approval required: digest=%s escalated=%v reason=%s", ch.EnvelopeDigest(), ch.Escalated(), ch.Reason()))
		}
	}
	return exitCode
}

func (r *Runtime) writeRefConflictText(rc engine.ReferenceConflict) {
	for _, ref := range rc.AssetReferences() {
		r.WriteErr(fmt.Sprintf("  referenced by %s node=%s target=%s", ref.Location, ref.FromNode, ref.Target))
	}
	for _, ref := range rc.SecretReferences() {
		r.WriteErr(fmt.Sprintf("  secret referenced at %s owner=%s ref=%s", ref.Location, ref.OwnerID, ref.Ref))
	}
}

// WriteResult 根据 jsonOut 开关将结构化结果输出为规范 JSON/v2 或调用文本渲染回调。
//
//xops:syncclosure
func (r *Runtime) WriteResult(jsonOut bool, payload any, renderText func(io.Writer)) int {
	if jsonOut {
		if err := WriteJSON(r.Stdout, payload); err != nil {
			r.WriteErr("marshal json failed: " + err.Error())
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
		return nil, "", fmt.Errorf("%w: 未注入 ReadOperatorFile 钩子，无法读取本地文件 %q（可使用 '-' 从 stdin 读取）", ErrNotConfigured, trimmed)
	}
	srcPath, err := pathalg.ParseLocalSourcePath(trimmed)
	if err != nil {
		return nil, "", fmt.Errorf("%w: 本地文件路径 %q 非法: %w", ErrUsage, trimmed, err)
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
		return nil, fmt.Errorf("%w: 输入超过最大允许大小 %d 字节", engine.ErrLimitExceeded, maxBytes)
	}
	return data, nil
}
