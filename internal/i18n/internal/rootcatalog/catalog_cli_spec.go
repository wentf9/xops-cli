package rootcatalog

// 本文件收录 CLI 命令族（哨兵、标志解析、退出状态与命令校验）的规范英文兜底模板、错误键与纯展示键清单。
func lookupCLI(id string) string {
	switch id {
	case "cli.err.invalid_config":
		return "cli: invalid AppConfig"
	case "cli.err.app_not_initialized":
		return "cli: App is not initialized"
	case "cli.err.usage":
		return "cli: invalid command-line arguments"
	case "cli.err.not_configured":
		return "cli: host capability callback is not configured"
	case "cli.err.unsupported_runner":
		return "cli: engine runner does not support this command capability"
	case "cli.err.nil_context":
		return "cli: context must not be nil"
	case "cli.err.nil_engine_factory":
		return "EngineFactory must not be nil"
	case "cli.err.nil_std_streams":
		return "Stdout and Stderr must not be nil"
	case "cli.err.shutdown_timeout_positive":
		return "ShutdownTimeout must be positive"
	case "cli.err.nil_session_runner":
		return "EngineFactory returned nil SessionRunner"
	case "cli.err.capability_required":
		return "requires {capability} capability interface"
	case "cli.err.hook_not_configured":
		return "host callback {hook} is not configured"
	case "cli.err.input_too_large":
		return "input exceeds maximum allowed size of {max} bytes"
	case "cli.err.unknown_command":
		return "unknown command {cmd} (run 'xops --help' for usage)"
	case "cli.err.unknown_subcommand":
		return "unknown {cmd} subcommand {sub}"
	case "cli.err.help_too_many_topics":
		return "help accepts at most one topic, got {args}"
	case "cli.err.unknown_help_topic":
		return "unknown help topic {topic}"
	case "cli.err.version_invalid_arg":
		return "version accepts only --json, --lang, or --help, got {arg}"
	case "cli.err.missing_short_value":
		return "option -{flag} requires a value"
	case "cli.err.missing_long_value":
		return "option --{flag} requires a value"
	case "cli.err.help_no_value":
		return "--help does not accept a value"
	case "cli.err.unknown_short_flag":
		return "unknown short option -{flag}"
	case "cli.err.unknown_long_flag":
		return "unknown option {flag}"
	case "cli.err.unexpected_arg":
		return "unexpected argument {arg}"
	case "cli.err.empty_config_file":
		return "-F config file path must not be empty"
	case "cli.err.invalid_bool_flag":
		return "invalid boolean value {value} for --{flag}"
	case "cli.err.invalid_positive_int":
		return "{flag} requires a positive integer, got {value}"
	case "cli.err.invalid_nonneg_int":
		return "{flag} requires a non-negative integer, got {value}"
	case "cli.err.invalid_duration":
		return "{flag} requires a positive duration (e.g. 30s, 5m), got {value}"
	case "cli.err.empty_perm":
		return "{flag} permission must not be empty"
	case "cli.err.invalid_octal_perm":
		return "{flag} requires a valid octal permission (0001..0777), got {value}"
	case "cli.err.invalid_key_value":
		return "{flag} requires KEY=VALUE format, got {value}"
	case "cli.err.invalid_flag_value":
		return "invalid {flag} value {value}"
	case "cli.err.invalid_flag_value_enum":
		return "{flag} must be one of {allowed}, got {value}"
	case "cli.err.invalid_field":
		return "invalid {field} {value}"
	case "cli.err.invalid_launch_profile":
		return "invalid launch profile combination"
	case "cli.err.invalid_option_layer":
		return "CLI option layer validation failed"
	case "cli.err.missing_required_flag":
		return "{cmd} requires {flag}"
	case "cli.err.mutually_exclusive_flags":
		return "{flag_a} and {flag_b} cannot be specified together"
	case "cli.err.exactly_one_flag_required":
		return "must specify exactly one of {flag_a} or {flag_b}"
	case "cli.err.arg_count_exact":
		return "{cmd} requires exactly {count} argument(s): {usage}"
	case "cli.err.arg_count_at_least":
		return "{cmd} requires at least {count} argument(s): {usage}"
	case "cli.err.interactive_no_json":
		return "interactive {mode} does not support --json output"
	case "cli.exit.invalid_outcome":
		return "ssh execution failed: invalid execution outcome"
	case "cli.exit.unexpected_outcome":
		return "unexpected execution outcome type {type}"
	case "cli.exit.invalid_status":
		return "ssh execution finished with invalid exit status"
	case "cli.exit.unreadable_code":
		return "ssh execution finished with unreadable exit code"
	case "cli.exit.unexpected_status":
		return "unexpected exit status type {type}"
	case "cli.exit.signal":
		return "remote process terminated by signal {signal}"
	case "cli.exit.signal_core":
		return "remote process terminated by signal {signal} (core dumped)"
	case "cli.exit.signal_msg":
		return "remote process terminated by signal {signal}: {message}"
	case "cli.exit.signal_core_msg":
		return "remote process terminated by signal {signal} (core dumped): {message}"
	case "cli.exit.unknown_status":
		return "remote process exited without exit status"
	case "cli.exit.unknown_status_reason":
		return "remote process exited without exit status: {reason}"
	case "cli.exit.not_started":
		return "ssh failed before start ({phase})"
	case "cli.exit.not_started_reason":
		return "ssh failed before start ({phase}): {reason}"
	case "cli.exit.outcome_unknown":
		return "ssh outcome unknown ({phase}; do not blindly retry)"
	case "cli.exit.outcome_unknown_reason":
		return "ssh outcome unknown ({phase}; do not blindly retry): {reason}"
	case "cli.err.forward_empty":
		return "forward specification must not be empty"
	case "cli.err.forward_invalid_dir":
		return "unsupported forward direction {dir}"
	case "cli.err.forward_invalid_spec":
		return "invalid forward specification {spec}"
	case "cli.err.forward_invalid_port":
		return "invalid port {port}"
	case "cli.err.tun_empty":
		return "-w TUN device specification must not be empty"
	case "cli.err.tun_invalid_unit":
		return "TUN device unit {value} must be 'any' or a non-negative integer"
	case "cli.err.ssh_missing_target":
		return "missing target host [user@]host"
	case "cli.err.ssh_flag_conflict_cmd":
		return "{flag} cannot be combined with remote command arguments"
	case "cli.err.ssh_control_conflict_bg":
		return "-O control mode cannot be combined with -f background mode"
	case "cli.err.ssh_bg_requires_forward":
		return "-f background mode requires -N, -M, or at least one forward (-L/-R/-D/-w)"
	case "cli.err.ssh_nocmd_requires_forward":
		return "-N mode requires -M or at least one forward (-L/-R/-D/-w)"
	case "cli.err.ssh_stdio_fwd_unsupported":
		return "-W host:port stdio forwarding is not yet supported; use -J ProxyJump or -O proxy"
	case "cli.err.mux_requires_single_forward":
		return "mux {action} requires exactly one forward specification (-L/-R/-D/-w)"
	case "cli.err.tunnel_requires_forward":
		return "tunnel requires at least one forward specification (-L/-R/-D/-w)"
	case "cli.err.exec_missing_target":
		return "exec requires a target host or selector (--all/--nodes/--tags)"
	case "cli.err.exec_missing_command":
		return "exec requires a remote command"
	case "cli.err.exec_batch_priv_unsupported":
		return "batch exec does not support interactive --sudo/--su/--doas; use single target or playbook"
	case "cli.err.exec_plan_failed":
		return "failed to build command plan"
	case "cli.err.exec_selector_invalid":
		return "invalid target selector"
	case "cli.err.scp_endpoint_mismatch":
		return "scp requires one local path and one [user@]host:<remote_path> endpoint"
	case "cli.err.scp_download_symlink_policy":
		return "scp download only allows --symlink-policy=reject or contained_relative"
	case "cli.err.scp_recursive_symlink_policy":
		return "recursive upload (-r) only allows --symlink-policy=reject"
	case "cli.err.scp_local_root_relative":
		return "local source must be a sandbox-relative path when --local-root is set"
	case "cli.err.scp_recursive_dot_abs":
		return "recursive upload of '.' requires an absolute working directory or explicit --local-root"
	case "cli.err.scp_no_remote_base":
		return "remote path {path} has no filename component to infer local destination"
	case "cli.err.sftp_recover_usage":
		return "sftp recover requires 0 arguments (recover all) or <target> <transfer_id>"
	case "cli.err.vault_identity_exists":
		return "identity {id} already exists (pass --replace to overwrite)"
	case "cli.err.vault_node_not_found":
		return "node {id} not found"
	case "cli.err.playbook_decode_failed":
		return "failed to parse playbook {source}"
	case "cli.err.playbook_empty":
		return "playbook input is empty"
	case "cli.err.playbook_must_be_object":
		return "playbook top-level document must be an object, not an array"
	case "cli.err.playbook_yaml_failed":
		return "playbook YAML decode failed"
	case "cli.err.playbook_yaml_dup_key":
		return "playbook YAML contains duplicate key {key}"
	case "cli.err.playbook_yaml_no_alias":
		return "playbook YAML aliases are not allowed"
	default:
		return ""
	}
}

func errorKeysCLI() []string {
	return []string{
		"cli.err.invalid_config",
		"cli.err.app_not_initialized",
		"cli.err.usage",
		"cli.err.not_configured",
		"cli.err.unsupported_runner",
		"cli.err.nil_context",
		"cli.err.nil_engine_factory",
		"cli.err.nil_std_streams",
		"cli.err.shutdown_timeout_positive",
		"cli.err.nil_session_runner",
		"cli.err.capability_required",
		"cli.err.hook_not_configured",
		"cli.err.input_too_large",
		"cli.err.unknown_command",
		"cli.err.unknown_subcommand",
		"cli.err.help_too_many_topics",
		"cli.err.unknown_help_topic",
		"cli.err.version_invalid_arg",
		"cli.err.missing_short_value",
		"cli.err.missing_long_value",
		"cli.err.help_no_value",
		"cli.err.unknown_short_flag",
		"cli.err.unknown_long_flag",
		"cli.err.unexpected_arg",
		"cli.err.empty_config_file",
		"cli.err.invalid_bool_flag",
		"cli.err.invalid_positive_int",
		"cli.err.invalid_nonneg_int",
		"cli.err.invalid_duration",
		"cli.err.empty_perm",
		"cli.err.invalid_octal_perm",
		"cli.err.invalid_key_value",
		"cli.err.invalid_flag_value",
		"cli.err.invalid_flag_value_enum",
		"cli.err.invalid_field",
		"cli.err.invalid_launch_profile",
		"cli.err.invalid_option_layer",
		"cli.err.missing_required_flag",
		"cli.err.mutually_exclusive_flags",
		"cli.err.exactly_one_flag_required",
		"cli.err.arg_count_exact",
		"cli.err.arg_count_at_least",
		"cli.err.interactive_no_json",
		"cli.exit.invalid_outcome",
		"cli.exit.unexpected_outcome",
		"cli.exit.invalid_status",
		"cli.exit.unreadable_code",
		"cli.exit.unexpected_status",
		"cli.exit.signal",
		"cli.exit.signal_core",
		"cli.exit.signal_msg",
		"cli.exit.signal_core_msg",
		"cli.exit.unknown_status",
		"cli.exit.unknown_status_reason",
		"cli.exit.not_started",
		"cli.exit.not_started_reason",
		"cli.exit.outcome_unknown",
		"cli.exit.outcome_unknown_reason",
		"cli.err.forward_empty",
		"cli.err.forward_invalid_dir",
		"cli.err.forward_invalid_spec",
		"cli.err.forward_invalid_port",
		"cli.err.tun_empty",
		"cli.err.tun_invalid_unit",
		"cli.err.ssh_missing_target",
		"cli.err.ssh_flag_conflict_cmd",
		"cli.err.ssh_control_conflict_bg",
		"cli.err.ssh_bg_requires_forward",
		"cli.err.ssh_nocmd_requires_forward",
		"cli.err.ssh_stdio_fwd_unsupported",
		"cli.err.mux_requires_single_forward",
		"cli.err.tunnel_requires_forward",
		"cli.err.exec_missing_target",
		"cli.err.exec_missing_command",
		"cli.err.exec_batch_priv_unsupported",
		"cli.err.exec_plan_failed",
		"cli.err.exec_selector_invalid",
		"cli.err.scp_endpoint_mismatch",
		"cli.err.scp_download_symlink_policy",
		"cli.err.scp_recursive_symlink_policy",
		"cli.err.scp_local_root_relative",
		"cli.err.scp_recursive_dot_abs",
		"cli.err.scp_no_remote_base",
		"cli.err.sftp_recover_usage",
		"cli.err.vault_identity_exists",
		"cli.err.vault_node_not_found",
		"cli.err.playbook_decode_failed",
		"cli.err.playbook_empty",
		"cli.err.playbook_must_be_object",
		"cli.err.playbook_yaml_failed",
		"cli.err.playbook_yaml_dup_key",
		"cli.err.playbook_yaml_no_alias",
	}
}

func displayKeysCLI() []string {
	return []string{
		"cli.help.root",
		"cli.help.version",
		"cli.help.ssh",
		"cli.help.exec",
		"cli.help.tunnel",
		"cli.help.mux",
		"cli.help.scp",
		"cli.help.sftp",
		"cli.help.hosts",
		"cli.help.vault",
		"cli.help.config",
		"cli.help.playbook",
		"cli.help.doctor",
		"cli.help.audit",
		"cli.help.mcp",
		"cli.help.tui",
		"cli.version.output",
		"cli.msg.shutdown_failed",
		"cli.msg.marshal_json_failed",
		"cli.msg.cleanup_failed",
		"cli.msg.command_failed",
		"cli.msg.approval_required",
		"cli.msg.ref_asset",
		"cli.msg.ref_secret",
		"cli.exit.join_diag",
		"cli.ssh.master_active",
		"cli.ssh.forward_listening",
		"cli.exec.batch_summary",
		"cli.exec.batch_node_header",
		"cli.exec.status.ok",
		"cli.exec.status.failed",
		"cli.exec.status.not_started",
		"cli.exec.status.completed",
		"cli.exec.status.unknown",
		"cli.scp.uploaded",
		"cli.scp.downloaded",
		"cli.sftp.stat",
		"cli.sftp.wrote",
		"cli.sftp.patched",
		"cli.sftp.action_ok",
		"cli.sftp.renamed",
		"cli.sftp.chmod_ok",
		"cli.sftp.recovered_one",
		"cli.sftp.recover_uncertain_inspect",
		"cli.sftp.recovered_all",
		"cli.sftp.recover_entry",
		"cli.sftp.recover_error",
		"cli.sftp.recover_uncertain_no_retry",
		"cli.config.no_formats",
		"cli.config.import_summary",
		"cli.config.import_label.plan",
		"cli.config.import_label.import",
		"cli.config.import_warn_line",
		"cli.hosts.resolved",
		"cli.hosts.dag_valid",
		"cli.hosts.found_refs",
		"cli.hosts.mutation_ok",
		"cli.hosts.all_summary",
		"cli.vault.status",
		"cli.vault.status_detail",
		"cli.vault.action_ok",
		"cli.vault.locked",
		"cli.vault.doctor_summary",
		"cli.vault.saga_result",
		"cli.vault.saga_uncertain",
		"cli.vault.refs_summary",
		"cli.vault.deleted",
		"cli.vault.gc_complete",
		"cli.vault.enrolled",
		"cli.audit.reconcile_summary",
		"cli.audit.entries_summary",
		"cli.doctor.vault_no_cap",
		"cli.doctor.vault_not_configured",
		"cli.doctor.summary",
		"cli.doctor.inventory",
		"cli.doctor.vault",
		"cli.doctor.vault_note",
		"cli.playbook.valid",
		"cli.playbook.summary",
		"cli.playbook.unknown_warning",
	}
}
