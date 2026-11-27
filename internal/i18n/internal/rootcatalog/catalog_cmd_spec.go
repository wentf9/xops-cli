package rootcatalog

// 本文件收录组合根 cmd/xops 及 CLI 嵌套字段/目录目标/组件标签键的规范英文兜底模板与键清单。
func lookupCmdAndLabels(id string) string {
	switch id {
	case "cmd.err.config_decode_failed":
		return "failed to decode config field {field}"
	case "cmd.err.config_invalid_value":
		return "invalid config {field} value {value}"
	case "cmd.err.audit_log_in_home_dir":
		return "policy.guardrail.audit_log {path} cannot place audit root directly in home directory; use a path under state directory or a dedicated private directory"
	case "cmd.err.env_not_initialized":
		return "homeAwareEnv is not initialized"
	case "cmd.err.resolve_dir_failed":
		return "failed to resolve {target}"
	case "cmd.err.invalid_dir_path":
		return "invalid {target} path {path}"
	case "cmd.err.openssh_config_unreadable":
		return "cannot read OpenSSH config file {path}"
	case "cmd.err.takeover_invalid_outcome":
		return "interactive ssh takeover returned invalid outcome"
	case "cmd.err.takeover_not_started":
		return "interactive ssh takeover not started ({phase}/{code}): {reason}"
	case "cmd.err.takeover_outcome_unknown":
		return "interactive ssh takeover outcome unknown ({phase}/{code}): {reason}"
	case "cmd.err.audit_read_failed":
		return "failed to read audit log"
	case "cmd.err.audit_line_invalid":
		return "audit log line {line} is invalid"
	case "cmd.err.file_too_large":
		return "file {path} exceeds maximum allowed size of {max} bytes"
	case "cmd.err.file_size_exceeds_limit":
		return "file {path} size {size} bytes exceeds limit {max} bytes"
	case "cmd.err.shutdown_stage_failed":
		return "shutdown {stage} failed"
	case "cmd.err.vault_unknown_default":
		return "vault.default_store {store} is not a known default store"
	case "cmd.err.vault_unsupported_kind":
		return "unsupported vault store {name} kind {kind}"
	case "cmd.err.init_component_failed":
		return "failed to initialize {component}"
	case "cmd.err.load_config_failed":
		return "failed to load config.yaml"
	case "cmd.err.reconcile_failed":
		return "startup crash audit reconciliation failed"
	case "cli.field.local_file_path":
		return "local file path"
	case "cli.field.control_socket_path":
		return "control socket path"
	case "cli.field.remote_dest_path":
		return "remote destination path"
	case "cli.field.remote_source_path":
		return "remote source path"
	case "cli.field.local_source_path":
		return "local source path"
	case "cli.field.local_rel_path":
		return "local relative path"
	case "cli.field.local_dir_name":
		return "local directory name"
	case "cli.field.local_dest_path":
		return "local destination path"
	case "cli.field.local_dest_filename":
		return "local destination filename"
	case "cli.field.local_dest_rel_path":
		return "local destination relative path"
	case "cli.field.remote_path":
		return "remote path"
	case "cli.field.old_path":
		return "old path"
	case "cli.field.new_path":
		return "new path"
	case "cli.field.transfer_id":
		return "transfer_id"
	case "cli.field.tag":
		return "tag"
	case "cli.field.alias":
		return "alias"
	case "cli.field.secret_ref":
		return "secret ref"
	case "cmd.target.audit_log_dir":
		return "policy.guardrail.audit_log dir"
	case "cmd.target.audit_log_file":
		return "policy.guardrail.audit_log file"
	case "cmd.target.local_identity":
		return "local identity"
	case "cmd.target.home_dir":
		return "home directory"
	case "cmd.target.default_state_dir":
		return "default state directory"
	case "cmd.target.default_ssh_dir":
		return "default .ssh directory"
	case "cmd.target.default_ssh_config":
		return "default ssh config"
	case "cmd.target.openssh_config":
		return "OpenSSH config"
	case "cmd.target.initial_remote_dir":
		return "initial remote dir"
	case "cmd.target.working_dir":
		return "working directory"
	case "cmd.target.default_vault_dir":
		return "default vault directory"
	case "cmd.target.vault_store":
		return "vault store {name}"
	case "cmd.comp.inventory_store":
		return "inventory store"
	case "cmd.comp.wal_journal_store":
		return "WAL journal store"
	case "cmd.comp.terminal_adapter":
		return "terminal adapter"
	case "cmd.comp.interaction_adapter":
		return "interaction adapter"
	case "cmd.comp.sshfp_lookup_adapter":
		return "sshfp lookup adapter"
	case "cmd.comp.openssh_importer":
		return "openssh importer"
	case "cmd.comp.csv_importer":
		return "csv importer"
	case "cmd.comp.process_instance_id":
		return "process instance id"
	case "cmd.comp.audit_sink":
		return "audit sink"
	case "cmd.comp.audit_reconciler":
		return "audit reconciler"
	case "cmd.comp.default_offline_vault":
		return "default offline vault"
	case "cmd.comp.platform_keychain_vault":
		return "platform os_keychain vault"
	case "cmd.comp.router_vault":
		return "router vault"
	case "cmd.comp.configured_router_vault":
		return "configured router vault"
	case "cmd.comp.offline_aead_vault":
		return "offline_aead vault {name}"
	case "cmd.comp.os_keychain_vault":
		return "os_keychain vault {name}"
	case "cmd.comp.external_helper_vault":
		return "external_helper vault {name}"
	default:
		return ""
	}
}

func errorKeysCmdAndLabels() []string {
	return []string{
		"cmd.err.config_decode_failed",
		"cmd.err.config_invalid_value",
		"cmd.err.audit_log_in_home_dir",
		"cmd.err.env_not_initialized",
		"cmd.err.resolve_dir_failed",
		"cmd.err.invalid_dir_path",
		"cmd.err.openssh_config_unreadable",
		"cmd.err.takeover_invalid_outcome",
		"cmd.err.takeover_not_started",
		"cmd.err.takeover_outcome_unknown",
		"cmd.err.audit_read_failed",
		"cmd.err.audit_line_invalid",
		"cmd.err.file_too_large",
		"cmd.err.file_size_exceeds_limit",
		"cmd.err.shutdown_stage_failed",
		"cmd.err.vault_unknown_default",
		"cmd.err.vault_unsupported_kind",
		"cmd.err.init_component_failed",
		"cmd.err.load_config_failed",
		"cmd.err.reconcile_failed",
		"cli.field.local_file_path",
		"cli.field.control_socket_path",
		"cli.field.remote_dest_path",
		"cli.field.remote_source_path",
		"cli.field.local_source_path",
		"cli.field.local_rel_path",
		"cli.field.local_dir_name",
		"cli.field.local_dest_path",
		"cli.field.local_dest_filename",
		"cli.field.local_dest_rel_path",
		"cli.field.remote_path",
		"cli.field.old_path",
		"cli.field.new_path",
		"cli.field.transfer_id",
		"cli.field.tag",
		"cli.field.alias",
		"cli.field.secret_ref",
		"cmd.target.audit_log_dir",
		"cmd.target.audit_log_file",
		"cmd.target.local_identity",
		"cmd.target.home_dir",
		"cmd.target.default_state_dir",
		"cmd.target.default_ssh_dir",
		"cmd.target.default_ssh_config",
		"cmd.target.openssh_config",
		"cmd.target.initial_remote_dir",
		"cmd.target.working_dir",
		"cmd.target.default_vault_dir",
		"cmd.target.vault_store",
		"cmd.comp.inventory_store",
		"cmd.comp.wal_journal_store",
		"cmd.comp.terminal_adapter",
		"cmd.comp.interaction_adapter",
		"cmd.comp.sshfp_lookup_adapter",
		"cmd.comp.openssh_importer",
		"cmd.comp.csv_importer",
		"cmd.comp.process_instance_id",
		"cmd.comp.audit_sink",
		"cmd.comp.audit_reconciler",
		"cmd.comp.default_offline_vault",
		"cmd.comp.platform_keychain_vault",
		"cmd.comp.router_vault",
		"cmd.comp.configured_router_vault",
		"cmd.comp.offline_aead_vault",
		"cmd.comp.os_keychain_vault",
		"cmd.comp.external_helper_vault",
	}
}
