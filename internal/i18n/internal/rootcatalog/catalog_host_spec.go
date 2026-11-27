package rootcatalog

// 本文件收录本地宿主适配器层（audit/openssh/store/yamlcodec/sys/vault）全部错误与哨兵键的规范英文兜底模板与键清单。
func lookupHost(id string) string {
	switch id {
	case "host.common.not_initialized":
		return "{component} is not initialized"
	case "host.common.nil_dependency":
		return "{field} must not be nil"
	case "host.common.invalid_field":
		return "{field} is invalid"
	case "host.common.invalid_secret_ref":
		return "invalid secret reference"
	case "host.common.invalid_secret_box":
		return "invalid SecretBox"
	case "host.common.limit_out_of_range":
		return "{field}={value} is out of allowed range (1..{max})"
	case "host.common.duration_must_be_positive":
		return "{field} must be a positive duration"
	case "host.common.value_must_be_non_negative":
		return "{field} must not be negative"
	case "host.common.value_must_be_non_zero":
		return "{field} must not be zero"
	case "host.common.path_is_symlink":
		return "path {path} is a symlink"
	case "host.common.path_not_dir":
		return "path {path} is not a directory"
	case "host.common.path_not_regular":
		return "path {path} is not a regular file"
	case "host.common.size_exceeds_limit":
		return "size exceeds maximum limit of {max} bytes"
	case "host.common.read_failed":
		return "failed to read {path}"
	case "host.audit.corrupt_log":
		return "audit: audit log record is corrupt or malformed"
	case "host.audit.unreconciled_lock":
		return "process lock file {path} contains unreconciled entries; run crash reconciliation or use a new ProcessInstanceID"
	case "host.audit.lock_io_failed":
		return "process lock log I/O failed"
	case "host.audit.lock_compact_failed":
		return "failed to compact process lock after drain"
	case "host.audit.line_unmarshal_failed":
		return "failed to unmarshal audit log line {line}"
	case "host.audit.append_aborted_failed":
		return "failed to append AbortedByCrash entry"
	case "host.openssh.include_cycle":
		return "openssh: include cycle detected"
	case "host.openssh.include_depth_exceeded":
		return "openssh: include nesting depth exceeded"
	case "host.openssh.invalid_config":
		return "openssh: invalid OpenSSH config file or directive"
	case "host.openssh.include_needs_home":
		return "expanding include path {pattern} requires a valid HomeDir"
	case "host.openssh.include_glob_needs_fs":
		return "wildcard Include {pattern} requires ScopedFS"
	case "host.openssh.include_glob_dotdot":
		return "wildcard include path {pattern} must not contain '..' segments"
	case "host.openssh.invalid_glob":
		return "invalid include wildcard pattern {pattern}"
	case "host.openssh.match_missing_criteria":
		return "Match directive is missing valid criteria"
	case "host.openssh.match_modifier_invalid":
		return "Match {modifier} has invalid negation, assignment, duplication, or ordering"
	case "host.openssh.match_criterion_missing_arg":
		return "Match criterion {keyword} is missing a valid argument"
	case "host.openssh.include_depth_at":
		return "openssh: Include nesting depth exceeded at {path} (depth={depth})"
	case "host.openssh.include_cycle_at":
		return "include cycle at {path}"
	case "host.openssh.include_files_exceeded":
		return "included file count exceeds limit of {max}"
	case "host.openssh.file_too_large":
		return "{path} exceeds maximum size of {max} bytes"
	case "host.openssh.line_error":
		return "openssh: invalid configuration at {file}:{line}"
	case "host.openssh.invalid_clause":
		return "{file}:{line}: invalid {clause} directive"
	case "host.openssh.directive_missing_value":
		return "directive {key} is missing a value"
	case "host.openssh.unclosed_quote":
		return "unclosed quote"
	case "host.openssh.diag.include_skipped":
		return "line {line}: Include \"{patterns}\" skipped in stream-only import (local files are not expanded)"
	case "host.openssh.diag.match_canonical_ignored":
		return "line {line}: Match canonical block ignored (fail-closed by security policy)"
	case "host.openssh.diag.match_exec_ignored":
		return "line {line}: Match exec block ignored (fail-closed; external commands are never executed)"
	case "host.store.unsupported_schema_version":
		return "store: unsupported config schema version (only version: 2 is supported)"
	case "host.store.plaintext_secret_forbidden":
		return "store: plaintext passwords or secrets are forbidden in config or import sources"
	case "host.store.invalid_csv":
		return "store: invalid CSV import format or record field"
	case "host.store.corrupt_journal_frame":
		return "store: WAL record frame format or CRC32 check failed"
	case "host.store.csv_empty":
		return "CSV input is empty or contains no data rows"
	case "host.store.csv_too_many_rows":
		return "CSV row count exceeds limit of {max}"
	case "host.store.csv_forbidden_column":
		return "forbidden plaintext secret column {column}"
	case "host.store.csv_dup_or_empty_column":
		return "CSV header contains empty or duplicate column {column}"
	case "host.store.csv_missing_required_columns":
		return "CSV header must include name/alias, address/host, and user columns"
	case "host.store.csv_unknown_column":
		return "unknown CSV column {column}"
	case "host.store.csv_column_count_mismatch":
		return "CSV row {row} has {got} columns, expected {want}"
	case "host.store.csv_row_invalid_field":
		return "CSV row {row} has invalid {field}"
	case "host.store.csv_invalid_port":
		return "port {port} is outside valid range 1..65535"
	case "host.store.csv_cert_requires_key":
		return "cert_path requires key_path to be set"
	case "host.store.openssh_no_nodes":
		return "no importable host nodes found in OpenSSH config stream"
	case "host.store.revision_overflow":
		return "config revision reached uint64 maximum"
	case "host.store.wal_generation_corrupt":
		return "WAL generation {generation} is corrupt"
	case "host.store.wal_empty":
		return "WAL file for generation {generation} is empty"
	case "host.store.wal_truncated_line":
		return "WAL line {line} is missing trailing newline (possible truncated write)"
	case "host.store.wal_line_error":
		return "WAL line {line}"
	case "host.store.wal_marshal_failed":
		return "failed to marshal canonical WAL journal record"
	case "host.store.wal_invalid_frame":
		return "malformed WAL frame header or CRC32 format"
	case "host.store.wal_crc_mismatch":
		return "WAL CRC32 checksum mismatch"
	case "host.store.wal_payload_failed":
		return "WAL payload unmarshal, digest, or ownership verification failed"
	case "host.store.import_warn.alias_skipped":
		return "alias does not satisfy managed NodeID naming rules; skipped"
	case "host.store.import_warn.host_unresolved":
		return "missing resolvable HostName or valid host; skipped"
	case "host.store.import_warn.user_missing":
		return "missing User and no default username configured; skipped"
	case "host.store.import_warn.cert_without_key_skipped":
		return "no usable literal IdentityFile; skipped unbound CertificateFile"
	case "host.store.import_warn.unsupported_directive":
		return "skipped unsupported {directive} \"{value}\" for direct import"
	case "host.yaml.unsupported_schema_version":
		return "yamlcodec: unsupported config schema version (only version: 2 is supported)"
	case "host.yaml.section_key":
		return "{section}.{key}"
	case "host.yaml.empty_config":
		return "config file is empty"
	case "host.yaml.decode_failed":
		return "failed to decode YAML vNext document"
	case "host.yaml.invalid_version":
		return "unsupported schema version {version} (expected 2)"
	case "host.yaml.multiple_docs":
		return "config file must contain a single YAML document"
	case "host.yaml.node_override_invalid":
		return "policy.guardrail.node_overrides rule must be a non-empty string or mapping"
	case "host.yaml.duplicate_field":
		return "{section} contains duplicate field {field}"
	case "host.yaml.unknown_field":
		return "{section} contains unknown field {field}"
	case "host.yaml.node_override_field_invalid":
		return "node_overrides[{pattern}].{field} is invalid"
	case "host.yaml.invalid_field_value":
		return "{field}={value} is invalid"
	case "host.yaml.vault_store_invalid":
		return "vault.stores.{name} has invalid name or kind {kind}"
	case "host.yaml.vault_default_undeclared":
		return "vault.default_store={store} is not declared in vault.stores"
	case "host.yaml.passphrase_binding_pair":
		return "passphrase_ref and key_fingerprint must be specified together"
	case "host.yaml.invalid_field_combo":
		return "invalid field combination for {kind}"
	case "host.yaml.literal_path_required":
		return "literal_path requires a valid literal path"
	case "host.yaml.algo_missing_tokens":
		return "algorithm policy {op} requires non-empty tokens"
	case "host.yaml.algo_invalid_token":
		return "algorithm token {token} contains invalid operator prefix, whitespace, or comma"
	case "host.yaml.path_item_invalid":
		return "invalid state=set path entry {entry}"
	case "host.yaml.env_pattern_prefix":
		return "env filter {field} pattern {pattern} must not start with '-'"
	case "host.sys.orphaned_process_group":
		return "sys: current process is in an orphaned process group or is a session leader; suspend is forbidden"
	case "host.sys.input_canceled":
		return "sys: terminal input read canceled by scope end"
	case "host.sys.hostname_failed":
		return "failed to query local hostname"
	case "host.sys.syscall_failed":
		return "{call} failed"
	case "host.sys.terminal_stream_required":
		return "interactive stream terminal requires In, Out, and SizeFn"
	case "host.sys.terminal_size_failed":
		return "failed to query terminal window size"
	case "host.sys.terminal_non_positive_size":
		return "Windows console returned non-positive size {cols}x{rows}"
	case "host.sys.terminal_raw_mode_failed":
		return "failed to configure raw terminal mode"
	case "host.sys.cancel_handle_failed":
		return "failed to create cancel wakeup handle"
	case "host.agent.invalid_sign_args":
		return "public key fingerprint and signing algorithm must both be valid"
	case "host.agent.disabled":
		return "SSH agent is explicitly disabled"
	case "host.agent.env_unset":
		return "environment variable {env} is not set"
	case "host.agent.key_not_found":
		return "matching public key fingerprint not found in SSH agent"
	case "host.sshfp.dns_rcode":
		return "DNS server {server} returned error RCODE={rcode}"
	case "host.sshfp.no_servers":
		return "no usable DNS servers configured or discovered"
	case "host.sshfp.invalid_server_addr":
		return "invalid DNS server address {addr}"
	case "host.sshfp.win_adapters_failed":
		return "failed to query Windows adapter DNS server list"
	case "host.sshfp.invalid_dns_name":
		return "invalid DNS query domain name or label length"
	case "host.sshfp.dns_header_mismatch":
		return "DNS response transaction ID or QR flag mismatch"
	case "host.sshfp.dns_bad_qdcount":
		return "DNS response QDCOUNT={count} must equal 1"
	case "host.sshfp.dns_question_mismatch":
		return "DNS Question ({name}, {qtype}, {qclass}) does not match query"
	case "host.sshfp.dns_wire_malformed":
		return "malformed or truncated DNS wire packet"
	case "host.sshfp.cname_loop":
		return "DNS CNAME chain contains a loop"
	case "host.sshfp.cname_too_deep":
		return "DNS CNAME chain exceeds maximum hop limit of {max}"
	case "host.tun.darwin_l3_only":
		return "macOS native utun only supports L3 point-to-point tunnels"
	case "host.tun.platform_unsupported":
		return "native local TUN/TAP devices are not supported on this platform"
	case "host.tun.invalid_ip_version":
		return "invalid utun L3 frame IP version byte ({byte})"
	case "host.vault.router_empty":
		return "RouterVault requires at least one store backend or DefaultStore"
	case "host.vault.router_invalid_store":
		return "vault store {name} or its backend implementation is invalid"
	case "host.vault.store_not_registered":
		return "vault store {name} is not registered"
	case "host.vault.helper_protocol":
		return "vault/helper: invalid helper protocol frame"
	case "host.vault.helper_read_only":
		return "external credential helper is in read-only mode"
	case "host.vault.helper_non_zero_exit":
		return "external credential helper exited with non-zero status"
	case "host.vault.helper_base64_failed":
		return "failed to decode Base64 secret payload from helper"
	case "host.vault.helper_bad_response":
		return "external credential helper returned empty, oversized, or invalid JSON response"
	case "host.vault.kdf_params_invalid":
		return "Argon2id parameters out of range (t={time}, m={memory_kib} KiB, p={threads})"
	case "host.vault.kdf_subprocess_failed":
		return "isolated KDF subprocess execution failed"
	case "host.vault.keychain_load_framework":
		return "failed to load {framework}"
	case "host.vault.keychain_resolve_symbol":
		return "failed to resolve macOS Keychain symbol {symbol}"
	case "host.vault.keychain_os_status":
		return "macOS Keychain returned OSStatus={status}"
	case "host.vault.offline_meta_decode":
		return "failed to decode offline vault metadata"
	case "host.vault.offline_unsupported_format":
		return "unsupported offline vault format version or KDF"
	case "host.vault.offline_item_decode":
		return "failed to decode offline vault item"
	case "host.vault.offline_corrupt_field":
		return "offline vault field {field} is corrupt or invalid"
	case "host.vault.offline_aead_failed":
		return "offline vault ciphertext authentication failed"
	case "host.vault.ss_invalid_dh_key":
		return "Secret Service DH server public key length or subgroup is invalid"
	case "host.vault.ss_invalid_ciphertext":
		return "Secret Service AES-CBC ciphertext, IV, or PKCS#7 padding is invalid"
	case "host.vault.ss_dbus_invalid_addr":
		return "D-Bus session address must be a single valid local unix:path= address"
	case "host.vault.ss_dbus_abstract_denied":
		return "security policy rejects D-Bus unix:abstract sockets without filesystem permissions"
	case "host.vault.ss_dbus_unknown_param":
		return "unknown D-Bus address parameter {param}"
	case "host.vault.ss_env_required":
		return "EnvPort is required when BusAddress is not explicitly specified"
	case "host.vault.ss_connect_failed":
		return "failed to validate or connect to D-Bus session bus"
	case "host.vault.ss_handshake_failed":
		return "D-Bus {step} handshake failed"
	case "host.vault.ss_bad_dbus_value":
		return "unexpected D-Bus response value type for {member}"
	case "host.vault.ss_dbus_call_failed":
		return "Secret Service D-Bus call failed"
	case "host.vault.wincred_call_failed":
		return "Windows Credential Manager call failed"
	default:
		return ""
	}
}

func errorKeysHost() []string {
	return []string{
		"host.common.not_initialized",
		"host.common.nil_dependency",
		"host.common.invalid_field",
		"host.common.invalid_secret_ref",
		"host.common.invalid_secret_box",
		"host.common.limit_out_of_range",
		"host.common.duration_must_be_positive",
		"host.common.value_must_be_non_negative",
		"host.common.value_must_be_non_zero",
		"host.common.path_is_symlink",
		"host.common.path_not_dir",
		"host.common.path_not_regular",
		"host.common.size_exceeds_limit",
		"host.common.read_failed",
		"host.audit.corrupt_log",
		"host.audit.unreconciled_lock",
		"host.audit.lock_io_failed",
		"host.audit.lock_compact_failed",
		"host.audit.line_unmarshal_failed",
		"host.audit.append_aborted_failed",
		"host.openssh.include_cycle",
		"host.openssh.include_depth_exceeded",
		"host.openssh.invalid_config",
		"host.openssh.include_needs_home",
		"host.openssh.include_glob_needs_fs",
		"host.openssh.include_glob_dotdot",
		"host.openssh.invalid_glob",
		"host.openssh.match_missing_criteria",
		"host.openssh.match_modifier_invalid",
		"host.openssh.match_criterion_missing_arg",
		"host.openssh.include_depth_at",
		"host.openssh.include_cycle_at",
		"host.openssh.include_files_exceeded",
		"host.openssh.file_too_large",
		"host.openssh.line_error",
		"host.openssh.invalid_clause",
		"host.openssh.directive_missing_value",
		"host.openssh.unclosed_quote",
		"host.openssh.diag.include_skipped",
		"host.openssh.diag.match_canonical_ignored",
		"host.openssh.diag.match_exec_ignored",
		"host.store.unsupported_schema_version",
		"host.store.plaintext_secret_forbidden",
		"host.store.invalid_csv",
		"host.store.corrupt_journal_frame",
		"host.store.csv_empty",
		"host.store.csv_too_many_rows",
		"host.store.csv_forbidden_column",
		"host.store.csv_dup_or_empty_column",
		"host.store.csv_missing_required_columns",
		"host.store.csv_unknown_column",
		"host.store.csv_column_count_mismatch",
		"host.store.csv_row_invalid_field",
		"host.store.csv_invalid_port",
		"host.store.csv_cert_requires_key",
		"host.store.openssh_no_nodes",
		"host.store.revision_overflow",
		"host.store.wal_generation_corrupt",
		"host.store.wal_empty",
		"host.store.wal_truncated_line",
		"host.store.wal_line_error",
		"host.store.wal_marshal_failed",
		"host.store.wal_invalid_frame",
		"host.store.wal_crc_mismatch",
		"host.store.wal_payload_failed",
		"host.store.import_warn.alias_skipped",
		"host.store.import_warn.host_unresolved",
		"host.store.import_warn.user_missing",
		"host.store.import_warn.cert_without_key_skipped",
		"host.store.import_warn.unsupported_directive",
		"host.yaml.unsupported_schema_version",
		"host.yaml.section_key",
		"host.yaml.empty_config",
		"host.yaml.decode_failed",
		"host.yaml.invalid_version",
		"host.yaml.multiple_docs",
		"host.yaml.node_override_invalid",
		"host.yaml.duplicate_field",
		"host.yaml.unknown_field",
		"host.yaml.node_override_field_invalid",
		"host.yaml.invalid_field_value",
		"host.yaml.vault_store_invalid",
		"host.yaml.vault_default_undeclared",
		"host.yaml.passphrase_binding_pair",
		"host.yaml.invalid_field_combo",
		"host.yaml.literal_path_required",
		"host.yaml.algo_missing_tokens",
		"host.yaml.algo_invalid_token",
		"host.yaml.path_item_invalid",
		"host.yaml.env_pattern_prefix",
		"host.sys.orphaned_process_group",
		"host.sys.input_canceled",
		"host.sys.hostname_failed",
		"host.sys.syscall_failed",
		"host.sys.terminal_stream_required",
		"host.sys.terminal_size_failed",
		"host.sys.terminal_non_positive_size",
		"host.sys.terminal_raw_mode_failed",
		"host.sys.cancel_handle_failed",
		"host.agent.invalid_sign_args",
		"host.agent.disabled",
		"host.agent.env_unset",
		"host.agent.key_not_found",
		"host.sshfp.dns_rcode",
		"host.sshfp.no_servers",
		"host.sshfp.invalid_server_addr",
		"host.sshfp.win_adapters_failed",
		"host.sshfp.invalid_dns_name",
		"host.sshfp.dns_header_mismatch",
		"host.sshfp.dns_bad_qdcount",
		"host.sshfp.dns_question_mismatch",
		"host.sshfp.dns_wire_malformed",
		"host.sshfp.cname_loop",
		"host.sshfp.cname_too_deep",
		"host.tun.darwin_l3_only",
		"host.tun.platform_unsupported",
		"host.tun.invalid_ip_version",
		"host.vault.router_empty",
		"host.vault.router_invalid_store",
		"host.vault.store_not_registered",
		"host.vault.helper_protocol",
		"host.vault.helper_read_only",
		"host.vault.helper_non_zero_exit",
		"host.vault.helper_base64_failed",
		"host.vault.helper_bad_response",
		"host.vault.kdf_params_invalid",
		"host.vault.kdf_subprocess_failed",
		"host.vault.keychain_load_framework",
		"host.vault.keychain_resolve_symbol",
		"host.vault.keychain_os_status",
		"host.vault.offline_meta_decode",
		"host.vault.offline_unsupported_format",
		"host.vault.offline_item_decode",
		"host.vault.offline_corrupt_field",
		"host.vault.offline_aead_failed",
		"host.vault.ss_invalid_dh_key",
		"host.vault.ss_invalid_ciphertext",
		"host.vault.ss_dbus_invalid_addr",
		"host.vault.ss_dbus_abstract_denied",
		"host.vault.ss_dbus_unknown_param",
		"host.vault.ss_env_required",
		"host.vault.ss_connect_failed",
		"host.vault.ss_handshake_failed",
		"host.vault.ss_bad_dbus_value",
		"host.vault.ss_dbus_call_failed",
		"host.vault.wincred_call_failed",
	}
}
