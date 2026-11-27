package cli

import (
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdssh"
)

// 以下类型别名将 clikit 与 cmdssh 的稳定契约统一暴露于根 cli 包，
// 保持 Wave 1 cmd/xops 100% 源码兼容，同时为 Wave 2 组合根接线提供强类型回调与初始化选项。
type (
	// SessionRunner 定义 CLI 入站层驱动核心 SSH 执行与关闭的最小引擎契约（*engine.Engine 原生实现）。
	SessionRunner = clikit.SessionRunner
	// EngineInitOptions 描述 CLI 命令按需初始化核心引擎时透传给组合根的只读覆盖项（含 -F 与 --policy）。
	EngineInitOptions = clikit.EngineInitOptions
	// EngineHandle 封装按需创建的运行期引擎及其确定性逆序关闭回调。
	EngineHandle = clikit.EngineHandle
	// EngineFactory 按需为需要运行期核心的命令构造 EngineHandle。
	EngineFactory = clikit.EngineFactory

	// TUIStartRequest 描述通过回调启动交互式 TUI 子入口的强类型参数。
	TUIStartRequest = clikit.TUIStartRequest
	// TUIRunner 为组合根注入的 TUI 子入口启动回调。
	TUIRunner = clikit.TUIRunner

	// SFTPShellStartRequest 描述通过回调启动交互式 SFTP Shell 子入口的强类型参数。
	SFTPShellStartRequest = clikit.SFTPShellStartRequest
	// SFTPShellRunner 为组合根注入的交互式 SFTP Shell 启动回调。
	SFTPShellRunner = clikit.SFTPShellRunner

	// MCPStartRequest 描述通过回调启动 MCP 服务器子入口的强类型参数。
	MCPStartRequest = clikit.MCPStartRequest
	// MCPRunner 为组合根注入的 MCP 服务器启动回调。
	MCPRunner = clikit.MCPRunner

	// MuxDaemonStartRequest 描述通过回调启动 ControlMaster/ControlPersist 后台守护进程的强类型参数。
	MuxDaemonStartRequest = clikit.MuxDaemonStartRequest
	// MuxDaemonRunner 为组合根注入的多路复用守护进程启动回调。
	MuxDaemonRunner = clikit.MuxDaemonRunner

	// AuditQueryRequest 描述向宿主只读审计查询钩子发起过滤检索的强类型请求。
	AuditQueryRequest = clikit.AuditQueryRequest
	// AuditRecordView 描述单条脱敏审计记录的规范 JSON/v2 视图。
	AuditRecordView = clikit.AuditRecordView
	// AuditQueryResult 描述审计日志只读查询钩子的返回结果。
	AuditQueryResult = clikit.AuditQueryResult
	// AuditLogReader 为组合根注入的本地审计日志只读查询钩子。
	AuditLogReader = clikit.AuditLogReader

	// OperatorFileReader 为组合根注入的受控操作员只读文件钩子（底层经 OperatorReadFS 读取）。
	OperatorFileReader = clikit.OperatorFileReader
	// WorkDirResolver 为组合根注入的当前工作目录解析钩子，避免入口层直接调用 os.Getwd。
	WorkDirResolver = clikit.WorkDirResolver

	// SSHCommandArgs 描述 `xops ssh` 解析后的强类型参数与 OpenSSH CLI 选项覆盖层。
	SSHCommandArgs = cmdssh.SSHCommandArgs
)

// ParseSSHArgs 解析 `xops ssh` 的 OpenSSH 风格短选项、长选项、目标主机与远端命令参数。
func ParseSSHArgs(args []string) (SSHCommandArgs, error) {
	return cmdssh.ParseSSHArgs(args)
}
