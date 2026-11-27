package rootcatalog

// 本文件收录 SFTP Shell、MCP/Mux 守护入口、TUI 工作台与本地交互提示键的规范英文兜底模板、错误键与纯展示键清单。
func lookupSFTPTUIInteract(id string) string {
	switch id {
	case "sftpshell.err.nil_context":
		return "sftpshell: context must not be nil"
	case "sftpshell.err.invalid_config":
		return "sftpshell: invalid SFTP Shell configuration"
	case "sftpshell.err.not_initialized":
		return "sftpshell: Shell is not initialized"
	case "sftpshell.err.command_canceled":
		return "sftpshell: current command was canceled"
	case "sftpshell.err.syntax":
		return "sftpshell: invalid command syntax"
	case "sftpshell.err.config_nil_engine":
		return "Engine must not be nil"
	case "sftpshell.err.config_nil_std_streams":
		return "Stdout and Stderr must not be nil"
	case "sftpshell.err.config_target_xor":
		return "Target and TargetSpec are mutually exclusive and one is required"
	case "sftpshell.err.config_target_conflict":
		return "pre-resolved Target is invalid or cannot be combined with CLIOptions"
	case "sftpshell.err.config_invalid_field":
		return "invalid {field}"
	case "sftpshell.err.config_scoped_symlink":
		return "SymlinkFollowOperatorSource is forbidden in ScopedLocalOnly mode"
	case "sftpshell.err.config_timeout_positive":
		return "CommandTimeout must be positive"
	case "sftpshell.err.config_stream_buf_neg":
		return "StreamBuffer must not be negative"
	case "sftpshell.err.config_default_local_dir":
		return "failed to initialize default local directory"
	case "sftpshell.err.initial_remote_not_dir":
		return "initial remote path {path} is not a directory ({type})"
	case "sftpshell.err.unclosed_quote":
		return "unclosed quote or dangling escape"
	case "sftpshell.err.empty_remote_path":
		return "remote path must not be empty"
	case "sftpshell.err.empty_local_path":
		return "local path must not be empty"
	case "sftpshell.err.disallowed_local_prefix":
		return "local path {path} uses a forbidden UNC, device namespace, or root-relative backslash prefix"
	case "sftpshell.err.disallowed_drive_rel":
		return "local path {path} is a forbidden drive-relative path"
	case "sftpshell.err.disallowed_posix_backslash":
		return "POSIX absolute path {path} must not contain backslashes"
	case "sftpshell.err.local_rel_escape":
		return "cannot traverse '..' above relative local directory {dir}"
	case "sftpshell.err.scoped_abs_forbidden":
		return "absolute local path {path} is forbidden in ScopedLocalOnly mode"
	case "sftpshell.err.scoped_escape":
		return "local path cannot traverse '..' outside sandbox root"
	case "sftpshell.err.invalid_local_component":
		return "invalid local path component {component}"
	case "sftpshell.err.scoped_upload_root":
		return "ScopedLocalOnly upload source cannot be sandbox root '.'"
	case "sftpshell.err.invalid_download_dest":
		return "invalid download destination path"
	case "sftpshell.err.cannot_infer_local_name":
		return "cannot infer local filename from remote path {path}; specify destination explicitly"
	case "sftpshell.err.empty_perm":
		return "permission must not be empty"
	case "sftpshell.err.invalid_perm":
		return "invalid octal permission {value} (must be in 0001..0777)"
	case "sftpshell.err.empty_timestamp":
		return "timestamp must not be empty"
	case "sftpshell.err.invalid_timestamp":
		return "cannot parse timestamp {value} (supports RFC3339, YYYY-MM-DDTHH:MM:SS, or Unix seconds)"
	case "sftpshell.err.timestamp_out_of_range":
		return "timestamp {value} is outside RFC3339 year range [1,9999]"
	case "sftpshell.err.line_too_long":
		return "command line exceeds maximum length of {max} bytes (line discarded)"
	case "sftpshell.err.unknown_command":
		return "unknown command {cmd} (type 'help' for available commands)"
	case "sftpshell.err.no_args_allowed":
		return "{cmd} accepts no arguments"
	case "sftpshell.err.usage":
		return "usage: {usage}"
	case "sftpshell.err.remote_not_dir":
		return "remote path {path} is not a directory ({type})"
	case "sftpshell.err.local_not_dir":
		return "local path {path} is not a directory or does not exist"
	case "sftpshell.err.localfs_unavailable":
		return "LocalFS is not configured; cannot list local directory"
	case "sftpshell.err.unknown_option":
		return "{cmd}: unknown option {option}"
	case "sftpshell.err.list_too_many_paths":
		return "ls/lls accepts at most one path argument"
	case "sftpshell.err.unknown_help_topic":
		return "unknown help topic {topic}"
	case "sftpshell.err.mkdir_missing_mode":
		return "mkdir -m requires a permission argument"
	case "mcpcmd.err.nil_context":
		return "mcpcmd: context must not be nil"
	case "mcpcmd.err.invalid_config":
		return "mcpcmd: invalid MCP entry configuration"
	case "mcpcmd.err.invalid_transport":
		return "mcpcmd: unsupported MCP transport mode"
	case "mcpcmd.err.invalid_transport_value":
		return "unsupported transport {value} (only stdio or http is supported)"
	case "mcpcmd.err.create_server_failed":
		return "create mcp server failed"
	case "mcpcmd.err.nil_server":
		return "ServerFactory returned nil MCPServerContract"
	case "mcpcmd.err.prepare_failed":
		return "mcp server prepare failed"
	case "mcpcmd.err.no_engine_or_factory":
		return "Engine and ServerFactory cannot both be nil"
	case "mcpcmd.err.shutdown_timeout_positive":
		return "ShutdownTimeout must be positive"
	case "mcpcmd.err.stdio_nil_streams":
		return "stdio transport requires non-nil Stdin and Stdout"
	case "mcpcmd.err.stdio_forbids_listener":
		return "stdio transport does not allow an HTTP Listener"
	case "mcpcmd.err.http_missing_endpoint":
		return "http transport requires ListenAddr or Listener"
	case "muxdaemon.err.nil_context":
		return "muxdaemon: context must not be nil"
	case "muxdaemon.err.invalid_config":
		return "muxdaemon: invalid muxdaemon configuration"
	case "muxdaemon.err.nil_client":
		return "Client must not be nil"
	case "muxdaemon.err.nil_backend":
		return "backend must not be nil"
	case "muxdaemon.err.missing_target":
		return "TargetSpec or Target must be specified"
	case "muxdaemon.err.invalid_forward":
		return "Forwards[{index}] is invalid"
	case "muxdaemon.err.shutdown_timeout_positive":
		return "ShutdownTimeout must be positive"
	case "muxdaemon.err.invalid_socket_path":
		return "invalid SocketPath"
	case "muxdaemon.err.invalid_control_path":
		return "invalid ControlPath"
	case "muxdaemon.err.invalid_cli_opts":
		return "CLIOptions validation failed"
	case "muxdaemon.err.nil_done_chan":
		return "{source}.Done() returned nil"
	case "muxdaemon.err.stop_forward_failed":
		return "stop forward {addr} failed"
	case "muxdaemon.err.stop_master_failed":
		return "stop control master {socket} failed"
	case "tui.err.nil_context":
		return "tui: context must not be nil"
	case "tui.err.invalid_config":
		return "tui: invalid TUI configuration"
	case "tui.err.invalid_event":
		return "tui: received invalid or unsupported event variant"
	case "tui.err.terminal_restore":
		return "tui: failed to restore terminal state"
	case "tui.err.takeover_disabled":
		return "tui: interactive session takeover callback is not configured"
	case "tui.err.config_no_source":
		return "Engine, Projection, SystemBus, and OperationStreams cannot all be empty"
	case "tui.err.config_invalid_view":
		return "invalid InitialView ({view})"
	case "tui.err.config_out_of_bounds":
		return "window size, buffer capacity, or sample limit is out of bounds"
	case "tui.err.config_invalid_cli_opts":
		return "invalid CLIOptions"
	case "tui.err.config_nil_op_stream":
		return "OperationStreams[{index}] must not be nil"
	case "tui.err.config_metrics_interval":
		return "MetricsInterval must be positive"
	case "tui.err.config_invalid_log_target":
		return "invalid DefaultLogTarget"
	case "tui.err.event_empty":
		return "event is nil or failed validation"
	case "tui.err.event_unsupported_type":
		return "unsupported event type {type}"
	case "tui.err.no_host_for_metrics":
		return "no host selected for metrics stream"
	case "tui.err.no_host_for_logs":
		return "no host selected for log stream"
	case "tui.err.no_host_for_takeover":
		return "no host selected for interactive session"
	case "tui.err.action_queue_busy":
		return "action queue busy; try again"
	case "tui.err.inventory":
		return "inventory"
	case "tui.err.stream":
		return "{kind} stream ({target})"
	case "tui.err.takeover":
		return "session ({target})"
	case "tui.stream_kind.metrics":
		return "metrics"
	case "tui.stream_kind.logs":
		return "logs"
	case "interact.err.nil_file_handles":
		return "input and output file handles must not be nil"
	case "interact.err.nil_stream_handles":
		return "StreamSpec In and Out must not be nil"
	case "interact.err.invalid_request":
		return "{kind} is invalid"
	case "interact.err.empty_text":
		return "text input must not be empty"
	case "interact.err.empty_secret":
		return "secret input must not be empty"
	case "interact.err.line_too_long":
		return "input line length exceeds limit of {max} bytes"
	case "interact.err.unix_read_termios":
		return "failed to read Unix terminal termios"
	case "interact.err.unix_disable_echo":
		return "failed to disable Unix terminal echo"
	case "interact.err.unix_wake_pipe":
		return "failed to create terminal wakeup pipe"
	case "interact.err.win_read_console":
		return "failed to read Windows console input mode"
	case "interact.err.win_disable_echo":
		return "failed to disable Windows console echo"
	case "interact.err.win_cancel_event":
		return "failed to create Windows cancel event"
	case "interact.vault.init.title":
		return "Vault init"
	case "interact.vault.unlock.title":
		return "Vault unlock"
	case "interact.vault.master.prompt":
		return "Master passphrase"
	case "interact.vault.confirm.title":
		return "Confirm Vault Passphrase"
	case "interact.vault.confirm.prompt":
		return "Confirm master passphrase"
	case "interact.vault.enroll_password.title":
		return "Enroll SSH Password"
	case "interact.vault.enroll_password.prompt":
		return "Enter SSH login password"
	case "interact.vault.node_privilege.title":
		return "Set Node Privilege Secret"
	case "interact.vault.node_privilege.prompt":
		return "Enter sudo/su/doas privilege password"
	case "interact.vault.rotate.title":
		return "Rotate Secret"
	case "interact.vault.rotate.prompt":
		return "Enter new secret value"
	case "interact.vault.enroll_key.title":
		return "Private Key Passphrase"
	case "interact.vault.enroll_key.prompt":
		return "Enter private key passphrase"
	default:
		return ""
	}
}

func errorKeysSFTPTUIInteract() []string {
	return []string{
		"sftpshell.err.nil_context",
		"sftpshell.err.invalid_config",
		"sftpshell.err.not_initialized",
		"sftpshell.err.command_canceled",
		"sftpshell.err.syntax",
		"sftpshell.err.config_nil_engine",
		"sftpshell.err.config_nil_std_streams",
		"sftpshell.err.config_target_xor",
		"sftpshell.err.config_target_conflict",
		"sftpshell.err.config_invalid_field",
		"sftpshell.err.config_scoped_symlink",
		"sftpshell.err.config_timeout_positive",
		"sftpshell.err.config_stream_buf_neg",
		"sftpshell.err.config_default_local_dir",
		"sftpshell.err.initial_remote_not_dir",
		"sftpshell.err.unclosed_quote",
		"sftpshell.err.empty_remote_path",
		"sftpshell.err.empty_local_path",
		"sftpshell.err.disallowed_local_prefix",
		"sftpshell.err.disallowed_drive_rel",
		"sftpshell.err.disallowed_posix_backslash",
		"sftpshell.err.local_rel_escape",
		"sftpshell.err.scoped_abs_forbidden",
		"sftpshell.err.scoped_escape",
		"sftpshell.err.invalid_local_component",
		"sftpshell.err.scoped_upload_root",
		"sftpshell.err.invalid_download_dest",
		"sftpshell.err.cannot_infer_local_name",
		"sftpshell.err.empty_perm",
		"sftpshell.err.invalid_perm",
		"sftpshell.err.empty_timestamp",
		"sftpshell.err.invalid_timestamp",
		"sftpshell.err.timestamp_out_of_range",
		"sftpshell.err.line_too_long",
		"sftpshell.err.unknown_command",
		"sftpshell.err.no_args_allowed",
		"sftpshell.err.usage",
		"sftpshell.err.remote_not_dir",
		"sftpshell.err.local_not_dir",
		"sftpshell.err.localfs_unavailable",
		"sftpshell.err.unknown_option",
		"sftpshell.err.list_too_many_paths",
		"sftpshell.err.unknown_help_topic",
		"sftpshell.err.mkdir_missing_mode",
		"mcpcmd.err.nil_context",
		"mcpcmd.err.invalid_config",
		"mcpcmd.err.invalid_transport",
		"mcpcmd.err.invalid_transport_value",
		"mcpcmd.err.create_server_failed",
		"mcpcmd.err.nil_server",
		"mcpcmd.err.prepare_failed",
		"mcpcmd.err.no_engine_or_factory",
		"mcpcmd.err.shutdown_timeout_positive",
		"mcpcmd.err.stdio_nil_streams",
		"mcpcmd.err.stdio_forbids_listener",
		"mcpcmd.err.http_missing_endpoint",
		"muxdaemon.err.nil_context",
		"muxdaemon.err.invalid_config",
		"muxdaemon.err.nil_client",
		"muxdaemon.err.nil_backend",
		"muxdaemon.err.missing_target",
		"muxdaemon.err.invalid_forward",
		"muxdaemon.err.shutdown_timeout_positive",
		"muxdaemon.err.invalid_socket_path",
		"muxdaemon.err.invalid_control_path",
		"muxdaemon.err.invalid_cli_opts",
		"muxdaemon.err.nil_done_chan",
		"muxdaemon.err.stop_forward_failed",
		"muxdaemon.err.stop_master_failed",
		"tui.err.nil_context",
		"tui.err.invalid_config",
		"tui.err.invalid_event",
		"tui.err.terminal_restore",
		"tui.err.takeover_disabled",
		"tui.err.config_no_source",
		"tui.err.config_invalid_view",
		"tui.err.config_out_of_bounds",
		"tui.err.config_invalid_cli_opts",
		"tui.err.config_nil_op_stream",
		"tui.err.config_metrics_interval",
		"tui.err.config_invalid_log_target",
		"tui.err.event_empty",
		"tui.err.event_unsupported_type",
		"tui.err.no_host_for_metrics",
		"tui.err.no_host_for_logs",
		"tui.err.no_host_for_takeover",
		"tui.err.action_queue_busy",
		"tui.err.inventory",
		"tui.err.stream",
		"tui.err.takeover",
		"tui.stream_kind.metrics",
		"tui.stream_kind.logs",
		"interact.err.nil_file_handles",
		"interact.err.nil_stream_handles",
		"interact.err.invalid_request",
		"interact.err.empty_text",
		"interact.err.empty_secret",
		"interact.err.line_too_long",
		"interact.err.unix_read_termios",
		"interact.err.unix_disable_echo",
		"interact.err.unix_wake_pipe",
		"interact.err.win_read_console",
		"interact.err.win_disable_echo",
		"interact.err.win_cancel_event",
		"interact.vault.init.title",
		"interact.vault.unlock.title",
		"interact.vault.master.prompt",
		"interact.vault.confirm.title",
		"interact.vault.confirm.prompt",
		"interact.vault.enroll_password.title",
		"interact.vault.enroll_password.prompt",
		"interact.vault.node_privilege.title",
		"interact.vault.node_privilege.prompt",
		"interact.vault.rotate.title",
		"interact.vault.rotate.prompt",
		"interact.vault.enroll_key.title",
		"interact.vault.enroll_key.prompt",
	}
}

func displayKeysSFTPTUIInteract() []string {
	return []string{
		"sftpshell.msg.canceled",
		"sftpshell.msg.timeout",
		"sftpshell.msg.remote_is_dir_hint",
		"sftpshell.msg.outcome_unknown",
		"sftpshell.msg.approval_required",
		"sftpshell.output.stat",
		"sftpshell.output.uploaded",
		"sftpshell.output.downloaded",
		"sftpshell.output.wrote",
		"sftpshell.output.progress",
		"sftpshell.help.summary",
		"sftpshell.help.put",
		"sftpshell.help.get",
		"sftpshell.help.mv",
		"sftpshell.help.chmod",
		"sftpshell.help.chtimes",
		"sftpshell.help.write",
		"sftpshell.help.stat",
		"sftpshell.help.lstat",
		"sftpshell.help.generic",
		"tui.window_title",
		"tui.brand",
		"tui.view.hosts",
		"tui.view.metrics",
		"tui.view.logs",
		"tui.view.operations",
		"tui.view.help",
		"tui.view.invalid",
		"tui.header.meta",
		"tui.banner.halted",
		"tui.banner.halted_default_reason",
		"tui.banner.unknown_outcome",
		"tui.filter.label",
		"tui.filter.editing",
		"tui.hosts.title",
		"tui.hosts.empty",
		"tui.stream.idle",
		"tui.stream.streaming",
		"tui.metrics.title",
		"tui.metrics.empty",
		"tui.metrics.frame_summary",
		"tui.metrics.disks",
		"tui.metrics.top_processes",
		"tui.logs.title",
		"tui.logs.empty",
		"tui.logs.truncated",
		"tui.ops.title",
		"tui.ops.empty",
		"tui.ops.status.running",
		"tui.ops.status.ok",
		"tui.ops.status.failed",
		"tui.ops.status.unknown",
		"tui.help.title",
		"tui.help.body",
		"tui.footer.err_prefix",
		"tui.footer.help",
		"tui.sort.cpu",
		"tui.sort.mem",
		"tui.lang.en",
		"tui.lang.zh",
		"tui.status.ready",
		"tui.status.language_switched",
		"tui.status.metrics_updated",
		"tui.status.gate_halted",
		"tui.status.filter_mode",
		"tui.status.filter_cleared",
		"tui.status.filter_applied",
		"tui.status.refreshing_inventory",
		"tui.status.inventory_failed",
		"tui.status.inventory_loaded",
		"tui.status.starting_metrics",
		"tui.status.starting_logs",
		"tui.status.stopping_streams",
		"tui.status.process_sort",
		"tui.status.stream_err",
		"tui.status.stream_active",
		"tui.status.stream_idle",
		"tui.status.takeover_err",
		"tui.status.takeover_done",
		"interact.risk.unknown",
		"interact.risk.safe",
		"interact.risk.moderate",
		"interact.risk.dangerous",
		"interact.approval.banner",
		"interact.approval.digest_label",
	}
}
