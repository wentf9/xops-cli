package i18n

import domi18n "github.com/wentf9/xops-cli/core/domain/i18n"

// 本文件声明交互式 SFTP Shell（internal/entry/sftpshell）及守护进程入口
// （internal/entry/mcpcmd、internal/entry/muxdaemon）的强类型 MessageID 常量。
// 守护进程机器英文就绪行（xops-mcp: ready / mux daemon ready）保持稳定契约不本地化。
const (
	// SFTP Shell 5 个哨兵、配置与语法错误键（登记于 sftpAndDaemonErrorKeys + fallback_sftp_spec.go）。
	KeySFTPNilContext               domi18n.MessageID = "sftpshell.err.nil_context"                // 上下文为 nil（哨兵）
	KeySFTPInvalidConfig            domi18n.MessageID = "sftpshell.err.invalid_config"             // SFTP Shell 配置无效（哨兵）
	KeySFTPNotInitialized           domi18n.MessageID = "sftpshell.err.not_initialized"            // Shell 未初始化（哨兵）
	KeySFTPCommandCanceled          domi18n.MessageID = "sftpshell.err.command_canceled"           // 当前单条命令被取消（哨兵）
	KeySFTPSyntax                   domi18n.MessageID = "sftpshell.err.syntax"                     // 交互命令语法非法（哨兵）
	KeySFTPConfigNilEngine          domi18n.MessageID = "sftpshell.err.config_nil_engine"          // Engine 为 nil
	KeySFTPConfigNilStdStreams      domi18n.MessageID = "sftpshell.err.config_nil_std_streams"     // Stdout 或 Stderr 为 nil
	KeySFTPConfigTargetXOR          domi18n.MessageID = "sftpshell.err.config_target_xor"          // Target 与 TargetSpec 须二选一
	KeySFTPConfigTargetConflict     domi18n.MessageID = "sftpshell.err.config_target_conflict"     // 预解析 Target 无效或与 CLIOptions 冲突
	KeySFTPConfigInvalidField       domi18n.MessageID = "sftpshell.err.config_invalid_field"       // 指定配置字段非法
	KeySFTPConfigScopedSymlink      domi18n.MessageID = "sftpshell.err.config_scoped_symlink"      // 沙箱模式禁用 FollowOperatorSource
	KeySFTPConfigTimeoutPositive    domi18n.MessageID = "sftpshell.err.config_timeout_positive"    // CommandTimeout 非正时长
	KeySFTPConfigStreamBufNeg       domi18n.MessageID = "sftpshell.err.config_stream_buf_neg"      // StreamBuffer 为负
	KeySFTPConfigDefaultLocalDir    domi18n.MessageID = "sftpshell.err.config_default_local_dir"   // 初始化默认本地目录失败
	KeySFTPInitialRemoteNotDir      domi18n.MessageID = "sftpshell.err.initial_remote_not_dir"     // 初始远端路径非目录
	KeySFTPUnclosedQuote            domi18n.MessageID = "sftpshell.err.unclosed_quote"             // 命令行存在未闭合引号或悬空转义
	KeySFTPEmptyRemotePath          domi18n.MessageID = "sftpshell.err.empty_remote_path"          // 远端路径为空
	KeySFTPEmptyLocalPath           domi18n.MessageID = "sftpshell.err.empty_local_path"           // 本地路径为空
	KeySFTPDisallowedLocalPrefix    domi18n.MessageID = "sftpshell.err.disallowed_local_prefix"    // 禁止的 UNC/设备命名空间/根相对前缀
	KeySFTPDisallowedDriveRel       domi18n.MessageID = "sftpshell.err.disallowed_drive_rel"       // 禁止的盘符相对路径
	KeySFTPDisallowedPOSIXBackslash domi18n.MessageID = "sftpshell.err.disallowed_posix_backslash" // POSIX 绝对路径混用反斜杠
	KeySFTPLocalRelEscape           domi18n.MessageID = "sftpshell.err.local_rel_escape"           // 相对本地目录禁止向上穿越 '..'
	KeySFTPScopedAbsForbidden       domi18n.MessageID = "sftpshell.err.scoped_abs_forbidden"       // 沙箱模式禁止绝对本地路径
	KeySFTPScopedEscape             domi18n.MessageID = "sftpshell.err.scoped_escape"              // 沙箱模式禁止通过 '..' 越界
	KeySFTPInvalidLocalComponent    domi18n.MessageID = "sftpshell.err.invalid_local_component"    // 本地路径分量非法
	KeySFTPScopedUploadRoot         domi18n.MessageID = "sftpshell.err.scoped_upload_root"         // 沙箱模式上传源不能为 '.'
	KeySFTPInvalidDownloadDest      domi18n.MessageID = "sftpshell.err.invalid_download_dest"      // 下载目标路径无效
	KeySFTPCannotInferLocalName     domi18n.MessageID = "sftpshell.err.cannot_infer_local_name"    // 无法从远端路径推导本地文件名
	KeySFTPEmptyPerm                domi18n.MessageID = "sftpshell.err.empty_perm"                 // 权限值为空
	KeySFTPInvalidPerm              domi18n.MessageID = "sftpshell.err.invalid_perm"               // 八进制权限非法
	KeySFTPEmptyTimestamp           domi18n.MessageID = "sftpshell.err.empty_timestamp"            // 时间戳为空
	KeySFTPInvalidTimestamp         domi18n.MessageID = "sftpshell.err.invalid_timestamp"          // 时间戳格式无法解析
	KeySFTPTimestampOutOfRange      domi18n.MessageID = "sftpshell.err.timestamp_out_of_range"     // 时间戳超出 RFC3339 年份范围
	KeySFTPLineTooLong              domi18n.MessageID = "sftpshell.err.line_too_long"              // 单行命令超过字节上限
	KeySFTPUnknownCommand           domi18n.MessageID = "sftpshell.err.unknown_command"            // 未知交互命令
	KeySFTPNoArgsAllowed            domi18n.MessageID = "sftpshell.err.no_args_allowed"            // 命令不接受参数
	KeySFTPUsage                    domi18n.MessageID = "sftpshell.err.usage"                      // 交互命令用法提示错误
	KeySFTPRemoteNotDir             domi18n.MessageID = "sftpshell.err.remote_not_dir"             // 远端路径不是目录
	KeySFTPLocalNotDir              domi18n.MessageID = "sftpshell.err.local_not_dir"              // 本地路径不是目录或不存在
	KeySFTPLocalFSUnavailable       domi18n.MessageID = "sftpshell.err.localfs_unavailable"        // 未注入 LocalFS 无法列举本地目录
	KeySFTPUnknownOption            domi18n.MessageID = "sftpshell.err.unknown_option"             // 命令包含未知选项
	KeySFTPListTooManyPaths         domi18n.MessageID = "sftpshell.err.list_too_many_paths"        // ls/lls 路径参数超过 1 个
	KeySFTPUnknownHelpTopic         domi18n.MessageID = "sftpshell.err.unknown_help_topic"         // 未知帮助主题
	KeySFTPMkdirMissingMode         domi18n.MessageID = "sftpshell.err.mkdir_missing_mode"         // mkdir -m 缺少权限参数

	// SFTP Shell 交互输出、错误格式化与帮助键（纯展示类，仅存于 sftpshell.yaml）。
	KeySFTPMsgCanceled         domi18n.MessageID = "sftpshell.msg.canceled"           // 命令取消返回提示符提示
	KeySFTPMsgTimeout          domi18n.MessageID = "sftpshell.msg.timeout"            // 命令超时返回提示符提示
	KeySFTPMsgRemoteIsDirHint  domi18n.MessageID = "sftpshell.msg.remote_is_dir_hint" // 删除目录建议改用 rmdir 提示
	KeySFTPMsgOutcomeUnknown   domi18n.MessageID = "sftpshell.msg.outcome_unknown"    // 未知终态禁盲目重试警告
	KeySFTPMsgApprovalRequired domi18n.MessageID = "sftpshell.msg.approval_required"  // 需要审批摘要提示
	KeySFTPOutputStat          domi18n.MessageID = "sftpshell.output.stat"            // stat/lstat 多行元数据输出
	KeySFTPOutputUploaded      domi18n.MessageID = "sftpshell.output.uploaded"        // put 上传完成输出行
	KeySFTPOutputDownloaded    domi18n.MessageID = "sftpshell.output.downloaded"      // get 下载完成输出行
	KeySFTPOutputWrote         domi18n.MessageID = "sftpshell.output.wrote"           // write 原子写完成输出行
	KeySFTPOutputProgress      domi18n.MessageID = "sftpshell.output.progress"        // 传输进度流输出行
	KeySFTPHelpSummary         domi18n.MessageID = "sftpshell.help.summary"           // SFTP Shell 总览帮助文档
	KeySFTPHelpPut             domi18n.MessageID = "sftpshell.help.put"               // put 命令主题帮助
	KeySFTPHelpGet             domi18n.MessageID = "sftpshell.help.get"               // get 命令主题帮助
	KeySFTPHelpMV              domi18n.MessageID = "sftpshell.help.mv"                // mv/rename 命令主题帮助
	KeySFTPHelpChmod           domi18n.MessageID = "sftpshell.help.chmod"             // chmod 命令主题帮助
	KeySFTPHelpChtimes         domi18n.MessageID = "sftpshell.help.chtimes"           // chtimes 命令主题帮助
	KeySFTPHelpWrite           domi18n.MessageID = "sftpshell.help.write"             // write 命令主题帮助
	KeySFTPHelpStat            domi18n.MessageID = "sftpshell.help.stat"              // stat 命令主题帮助
	KeySFTPHelpLstat           domi18n.MessageID = "sftpshell.help.lstat"             // lstat 命令主题帮助
	KeySFTPHelpGeneric         domi18n.MessageID = "sftpshell.help.generic"           // 其余内置命令通用帮助引导

	// MCP 服务器入口（internal/entry/mcpcmd）哨兵与运行期错误键。
	KeyMCPNilContext              domi18n.MessageID = "mcpcmd.err.nil_context"               // 上下文为 nil（哨兵）
	KeyMCPInvalidConfig           domi18n.MessageID = "mcpcmd.err.invalid_config"            // MCP 入口配置无效（哨兵）
	KeyMCPInvalidTransport        domi18n.MessageID = "mcpcmd.err.invalid_transport"         // 不支持的 MCP 传输模式（哨兵）
	KeyMCPInvalidTransportValue   domi18n.MessageID = "mcpcmd.err.invalid_transport_value"   // 指定传输模式值非法
	KeyMCPCreateServerFailed      domi18n.MessageID = "mcpcmd.err.create_server_failed"      // 构造 MCPServer 失败
	KeyMCPNilServer               domi18n.MessageID = "mcpcmd.err.nil_server"                // ServerFactory 返回 nil
	KeyMCPPrepareFailed           domi18n.MessageID = "mcpcmd.err.prepare_failed"            // MCPServer.Prepare 启动自检失败
	KeyMCPNoEngineOrFactory       domi18n.MessageID = "mcpcmd.err.no_engine_or_factory"      // Engine 与 ServerFactory 同时为空
	KeyMCPShutdownTimeoutPositive domi18n.MessageID = "mcpcmd.err.shutdown_timeout_positive" // ShutdownTimeout 非正时长
	KeyMCPStdioNilStreams         domi18n.MessageID = "mcpcmd.err.stdio_nil_streams"         // stdio 传输缺少 Stdin/Stdout
	KeyMCPStdioForbidsListener    domi18n.MessageID = "mcpcmd.err.stdio_forbids_listener"    // stdio 传输禁止传 HTTP Listener
	KeyMCPHTTPMissingEndpoint     domi18n.MessageID = "mcpcmd.err.http_missing_endpoint"     // http 传输缺少 ListenAddr/Listener

	// ControlMaster 守护进程入口（internal/entry/muxdaemon）哨兵与运行期错误键。
	KeyMuxDaemonNilContext              domi18n.MessageID = "muxdaemon.err.nil_context"               // 上下文为 nil（哨兵）
	KeyMuxDaemonInvalidConfig           domi18n.MessageID = "muxdaemon.err.invalid_config"            // muxdaemon 配置无效（哨兵）
	KeyMuxDaemonNilClient               domi18n.MessageID = "muxdaemon.err.nil_client"                // Client 为 nil
	KeyMuxDaemonNilBackend              domi18n.MessageID = "muxdaemon.err.nil_backend"               // backend 为 nil
	KeyMuxDaemonMissingTarget           domi18n.MessageID = "muxdaemon.err.missing_target"            // TargetSpec 与 Target 均为空
	KeyMuxDaemonInvalidForward          domi18n.MessageID = "muxdaemon.err.invalid_forward"           // 转发规则元素无效
	KeyMuxDaemonShutdownTimeoutPositive domi18n.MessageID = "muxdaemon.err.shutdown_timeout_positive" // ShutdownTimeout 非正时长
	KeyMuxDaemonInvalidSocketPath       domi18n.MessageID = "muxdaemon.err.invalid_socket_path"       // SocketPath 无效
	KeyMuxDaemonInvalidControlPath      domi18n.MessageID = "muxdaemon.err.invalid_control_path"      // ControlPath 非法
	KeyMuxDaemonInvalidCLIOpts          domi18n.MessageID = "muxdaemon.err.invalid_cli_opts"          // CLIOptions 校验失败
	KeyMuxDaemonNilDoneChan             domi18n.MessageID = "muxdaemon.err.nil_done_chan"             // 句柄 Done() 返回 nil
	KeyMuxDaemonStopForwardFailed       domi18n.MessageID = "muxdaemon.err.stop_forward_failed"       // 停机关闭转发句柄失败
	KeyMuxDaemonStopMasterFailed        domi18n.MessageID = "muxdaemon.err.stop_master_failed"        // 停机关闭 ControlMaster 失败
)

func sftpAndDaemonErrorKeys() []domi18n.MessageID {
	return []domi18n.MessageID{
		KeySFTPNilContext, KeySFTPInvalidConfig, KeySFTPNotInitialized, KeySFTPCommandCanceled, KeySFTPSyntax,
		KeySFTPConfigNilEngine, KeySFTPConfigNilStdStreams, KeySFTPConfigTargetXOR, KeySFTPConfigTargetConflict,
		KeySFTPConfigInvalidField, KeySFTPConfigScopedSymlink, KeySFTPConfigTimeoutPositive, KeySFTPConfigStreamBufNeg,
		KeySFTPConfigDefaultLocalDir, KeySFTPInitialRemoteNotDir, KeySFTPUnclosedQuote, KeySFTPEmptyRemotePath,
		KeySFTPEmptyLocalPath, KeySFTPDisallowedLocalPrefix, KeySFTPDisallowedDriveRel, KeySFTPDisallowedPOSIXBackslash,
		KeySFTPLocalRelEscape, KeySFTPScopedAbsForbidden, KeySFTPScopedEscape, KeySFTPInvalidLocalComponent,
		KeySFTPScopedUploadRoot, KeySFTPInvalidDownloadDest, KeySFTPCannotInferLocalName, KeySFTPEmptyPerm,
		KeySFTPInvalidPerm, KeySFTPEmptyTimestamp, KeySFTPInvalidTimestamp, KeySFTPTimestampOutOfRange,
		KeySFTPLineTooLong, KeySFTPUnknownCommand, KeySFTPNoArgsAllowed, KeySFTPUsage, KeySFTPRemoteNotDir,
		KeySFTPLocalNotDir, KeySFTPLocalFSUnavailable, KeySFTPUnknownOption, KeySFTPListTooManyPaths,
		KeySFTPUnknownHelpTopic, KeySFTPMkdirMissingMode,
		KeyMCPNilContext, KeyMCPInvalidConfig, KeyMCPInvalidTransport, KeyMCPInvalidTransportValue,
		KeyMCPCreateServerFailed, KeyMCPNilServer, KeyMCPPrepareFailed, KeyMCPNoEngineOrFactory,
		KeyMCPShutdownTimeoutPositive, KeyMCPStdioNilStreams, KeyMCPStdioForbidsListener, KeyMCPHTTPMissingEndpoint,
		KeyMuxDaemonNilContext, KeyMuxDaemonInvalidConfig, KeyMuxDaemonNilClient, KeyMuxDaemonNilBackend,
		KeyMuxDaemonMissingTarget, KeyMuxDaemonInvalidForward, KeyMuxDaemonShutdownTimeoutPositive,
		KeyMuxDaemonInvalidSocketPath, KeyMuxDaemonInvalidControlPath, KeyMuxDaemonInvalidCLIOpts,
		KeyMuxDaemonNilDoneChan, KeyMuxDaemonStopForwardFailed, KeyMuxDaemonStopMasterFailed,
	}
}

func sftpDisplayKeys() []domi18n.MessageID {
	return []domi18n.MessageID{
		KeySFTPMsgCanceled, KeySFTPMsgTimeout, KeySFTPMsgRemoteIsDirHint, KeySFTPMsgOutcomeUnknown,
		KeySFTPMsgApprovalRequired, KeySFTPOutputStat, KeySFTPOutputUploaded, KeySFTPOutputDownloaded,
		KeySFTPOutputWrote, KeySFTPOutputProgress, KeySFTPHelpSummary, KeySFTPHelpPut, KeySFTPHelpGet,
		KeySFTPHelpMV, KeySFTPHelpChmod, KeySFTPHelpChtimes, KeySFTPHelpWrite, KeySFTPHelpStat,
		KeySFTPHelpLstat, KeySFTPHelpGeneric,
	}
}
