package muxdaemon

import (
	"context"
	"io"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/engine"
)

// DaemonClient 定义 muxdaemon 驱动所需的最小核心引擎多路复用与转发契约；
// *engine.Engine 原生实现全部方法。
type DaemonClient interface {
	StartControlMaster(ctx context.Context, req engine.ControlMasterRequest) (engine.ControlMasterInfo, error)
	StopControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) error
	StartForward(ctx context.Context, req engine.StartForwardRequest) (engine.ForwardInfo, error)
	StopForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) error
}

// 编译期契约断言：确保 core/engine.Engine 完整满足 DaemonClient。
var _ DaemonClient = (*engine.Engine)(nil)

// ReadyForward 描述守护进程就绪时已成功绑定的单条受管转发摘要。
type ReadyForward struct {
	Spec      engine.ForwardSpec
	BoundAddr string
}

// ReadyInfo 描述 ControlMaster 与全部初始转发成功启动后的只读就绪快照。
type ReadyInfo struct {
	TargetSpec       string
	SocketPath       string
	ReusedExisting   bool
	MasterPID        uint32
	EffectivePersist option.ControlPersistSpec
	Forwards         []ReadyForward
}

// Config 定义 muxdaemon.Run 的显式只读启动配置（零裸 time.Duration、零值严格失败关闭）。
type Config struct {
	// Client 为核心引擎多路复用与转发客户端（必填，生产路径直接传入 *engine.Engine）。
	Client DaemonClient
	// TargetSpec 为目标节点或 SSH 目的地规格（与 Target 至少提供一项）。
	TargetSpec string
	// Target 为可选预解析目标快照。
	Target engine.ResolvedTarget
	// CLIOptions 为 CLI/调用方注入的 Tier-1 选项层（若未设置 ControlMaster 将自动补全 ControlMaster=yes）。
	CLIOptions option.OptionLayer
	// SocketPath 为可选显式 ControlPath 套接字路径（当 CLIOptions 未指定 ControlPath 时补全）。
	SocketPath algebraic.Option[pathalg.LocalSourcePath]
	// Forwards 为随守护进程一同托管的可选转发规则列表（-L/-R/-D/-w）。
	Forwards []engine.ForwardSpec

	// Stdout / Stderr 为可选只读状态与错误输出流。
	Stdout io.Writer
	Stderr io.Writer

	// ShutdownTimeout 限制停机清理转发与 ControlMaster 的最大宽限期（未设置默认 5s）。
	ShutdownTimeout algebraic.Option[algebraic.Duration]
	// OnReady 可选就绪回调，在主控套接字与全部初始转发成功启动后、进入阻塞等待前同步调用。
	OnReady func(info ReadyInfo)
}
