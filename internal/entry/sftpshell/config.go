package sftpshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
)

const (
	defaultPrompt       = "sftp> "
	defaultStreamBuffer = 64
	defaultMaxReadBytes = 4 << 20
	maxLineBytes        = 1 << 20
)

// 本包导出的不可变哨兵错误，供组合根 cmd/xops、entry/cli 与测试通过 errors.Is 精确区分故障类别。
var (
	ErrNilContext      = errors.New("sftpshell: context 不能为 nil")
	ErrInvalidConfig   = errors.New("sftpshell: 无效的 SFTP Shell Config 配置")
	ErrNotInitialized  = errors.New("sftpshell: Shell 未初始化")
	ErrCommandCanceled = errors.New("sftpshell: 当前命令已被取消")
	ErrSyntax          = errors.New("sftpshell: 命令语法无效")
)

// TransferClient 定义交互式 SFTP Shell 消费 core/engine 门面所需的最小强类型契约（由 *engine.Engine 原生实现）。
type TransferClient interface {
	ResolveTarget(ctx context.Context, req engine.ResolveTargetRequest) (engine.ResolvedTarget, error)
	NewOperationStream(ctx context.Context, buffer int) (*events.OperationStream, error)
	SCPUpload(ctx context.Context, req engine.SCPUploadRequest) (engine.SCPUploadResult, error)
	SCPDownload(ctx context.Context, req engine.SCPDownloadRequest) (engine.SCPDownloadResult, error)
	ReadRemoteFile(ctx context.Context, req engine.RemoteFileReadRequest) (engine.ReadFileResult, error)
	WriteRemoteFile(ctx context.Context, req engine.RemoteFileWriteRequest) (engine.WriteFileResult, error)
	StatRemoteFile(ctx context.Context, req engine.RemoteStatRequest) (engine.RemoteFileStat, error)
	RenameRemoteFile(ctx context.Context, req engine.RemoteRenameRequest) error
	ListRemoteDir(ctx context.Context, req engine.RemotePathOpRequest) (engine.ListDirResult, error)
	MkdirRemoteAll(ctx context.Context, req engine.RemotePathOpRequest) error
	RemoveRemoteFile(ctx context.Context, req engine.RemotePathOpRequest) error
	RemoveRemoteDir(ctx context.Context, req engine.RemotePathOpRequest) error
	ChmodRemote(ctx context.Context, req engine.RemotePathOpRequest) error
	ChtimesRemote(ctx context.Context, req engine.RemotePathOpRequest) error
	RealPathRemote(ctx context.Context, req engine.RemotePathOpRequest) (pathalg.RemotePath, error)
	ReadLinkRemote(ctx context.Context, req engine.RemotePathOpRequest) (string, error)
}

// 编译期契约断言：确保 *engine.Engine 原生满足 TransferClient。
var _ TransferClient = (*engine.Engine)(nil)

// LocalDirEntry 描述本机目录列举条目，供 lls 命令格式化输出（0 core/osfs 与 0 core/ports 依赖）。
type LocalDirEntry struct {
	Name    string
	IsDir   bool
	Size    int64
	Mode    fs.FileMode
	ModTime time.Time
}

// LocalFS 为 sftpshell 提供可选的本机目录只读探测与列举回调（由 Wave 2 组合根注入安全适配器）。
// 当 LocalFS 为 nil 时，lpwd/lcd 仍基于纯 pathalg.LocalDir 代数正常工作，lls 返回明确的不支持提示。
type LocalFS interface {
	ReadDir(ctx context.Context, dir pathalg.LocalDir) ([]LocalDirEntry, error)
	IsDir(ctx context.Context, dir pathalg.LocalDir) (bool, error)
}

// Config 定义交互式 SFTP Shell 入口 Run 的全显式依赖注入配置（零全局状态、零隐式 OS 调用）。
type Config struct {
	// Engine 为核心引擎门面（必填，通常直接传入 *engine.Engine）。
	Engine TransferClient

	// Target 与 TargetSpec 必须二选一指定远端目标；指定 TargetSpec 时可附带 CLIOptions 覆写。
	Target     engine.ResolvedTarget
	TargetSpec string
	CLIOptions option.OptionLayer

	// Stdin、Stdout、Stderr 分别为交互命令输入、正常输出与错误输出流（Stdout 与 Stderr 必填）。
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Prompt 指定交互提示符文本（空串默认 "sftp> "）。
	Prompt string
	// InitialRemoteDir 可选指定初始远端工作目录（None 时自动探测远端 RealPath(".")）。
	InitialRemoteDir algebraic.Option[pathalg.RemotePath]
	// InitialLocalDir 可选指定初始本机工作目录（None 时默认为 "."）。
	InitialLocalDir algebraic.Option[pathalg.LocalDir]
	// LocalFS 为可选本机目录查询回调（用于 lls 与 lcd 目录存在性校验）。
	LocalFS LocalFS

	// ScopedLocalOnly 为 true 时，put 使用 NewScopedUploadSource（沙箱模式）；默认使用 NewOperatorUploadSource。
	ScopedLocalOnly bool
	// SymlinkPolicy 控制本地/远端传输软链策略（零值 pathalg.SymlinkReject 严格失败关闭）。
	SymlinkPolicy pathalg.SymlinkPolicy

	// InterruptCh 为可选单命令取消信号通道：收到信号时仅取消当前在途命令并恢复提示符，不退出整个 Shell。
	InterruptCh <-chan struct{}
	// CommandTimeout 可选为每条交互命令施加单次超时上限。
	CommandTimeout algebraic.Option[algebraic.Duration]
	// StreamBuffer 指定为 put/get 创建 OperationStream 时的缓冲容量（0 默认 64）。
	StreamBuffer int
	// ShowProgress 控制是否将传输进度事件输出到 Stderr。
	ShowProgress bool
}

// Run 校验配置并启动交互式 SFTP Shell 命令循环，直至用户执行 exit/quit、输入 EOF 或会话上下文取消。
func Run(ctx context.Context, cfg Config) error {
	if ctx == nil {
		return ErrNilContext
	}
	sh, err := NewShell(cfg)
	if err != nil {
		return err
	}
	return sh.Run(ctx)
}

func validateConfig(cfg Config) error {
	if cfg.Engine == nil {
		return fmt.Errorf("%w: Engine 不能为 nil", ErrInvalidConfig)
	}
	if cfg.Stdout == nil || cfg.Stderr == nil {
		return fmt.Errorf("%w: Stdout 与 Stderr 不能为 nil", ErrInvalidConfig)
	}
	hasTarget, hasSpec := !cfg.Target.IsZero(), strings.TrimSpace(cfg.TargetSpec) != ""
	if hasTarget == hasSpec {
		return fmt.Errorf("%w: Target 与 TargetSpec 必须二选一", ErrInvalidConfig)
	}
	if hasTarget && (!cfg.Target.IsValid() || !cfg.CLIOptions.IsUnset()) {
		return fmt.Errorf("%w: 预解析 Target 无效或禁止同时指定 CLIOptions", ErrInvalidConfig)
	}
	if err := cfg.CLIOptions.Validate(); err != nil {
		return fmt.Errorf("%w: CLIOptions 无效: %w", ErrInvalidConfig, err)
	}
	return validateOptionalConfig(cfg)
}

func validateOptionalConfig(cfg Config) error {
	if r, ok := cfg.InitialRemoteDir.Get(); ok && !r.IsValid() {
		return fmt.Errorf("%w: InitialRemoteDir 无效", ErrInvalidConfig)
	}
	if l, ok := cfg.InitialLocalDir.Get(); ok && !l.IsValid() {
		return fmt.Errorf("%w: InitialLocalDir 无效", ErrInvalidConfig)
	}
	if !cfg.SymlinkPolicy.IsValid() {
		return fmt.Errorf("%w: SymlinkPolicy 无效", ErrInvalidConfig)
	}
	if d, ok := cfg.CommandTimeout.Get(); ok && !d.IsPositive() {
		return fmt.Errorf("%w: CommandTimeout 必须为正时长", ErrInvalidConfig)
	}
	if cfg.StreamBuffer < 0 {
		return fmt.Errorf("%w: StreamBuffer 不能为负", ErrInvalidConfig)
	}
	return nil
}

// zeroVal 返回类型 T 的零值，用于在错误返回路径替代对跨包 //xops:opaque 类型的空复合字面量构造。
func zeroVal[T any]() (z T) { return z }
