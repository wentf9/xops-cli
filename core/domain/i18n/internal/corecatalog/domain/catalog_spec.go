package domain

import "slices"

// Lookup 返回core/domain/** 领域子包键对应的规范英文兜底模板；未命中返回空串。
func Lookup(id string) string {
	switch id {
	case "algebraic.empty_slice":
		return "algebraic: NonEmpty requires at least one element"
	case "algebraic.invalid_duration":
		return "algebraic: invalid Duration text format"
	case "algebraic.duration_overflow":
		return "algebraic: Duration addition overflow"
	case "algebraic.nil_receiver":
		return "algebraic: unmarshal receiver must not be nil"
	case "algebraic.nil_callback":
		return "algebraic: callback must not be nil"
	case "execution.invalid_launch_dialect":
		return "execution: invalid LaunchDialect"
	case "execution.invalid_interpreter":
		return "execution: invalid Interpreter"
	case "execution.invalid_login_mode":
		return "execution: invalid LoginMode"
	case "execution.invalid_launch_profile":
		return "execution: invalid LaunchProfile"
	case "execution.unsupported_combination":
		return "execution: unsupported launch dialect, interpreter, login mode, or work_dir combination"
	case "execution.not_posix_bourne":
		return "execution: launch profile does not satisfy POSIX Bourne interpreter requirement"
	case "execution.invalid_plan_kind":
		return "execution: invalid PlanKind"
	case "execution.invalid_command_plan":
		return "execution: invalid CommandPlan"
	case "execution.invalid_env_var":
		return "execution: invalid environment variable key or value"
	case "execution.invalid_shell_quote":
		return "execution: text contains illegal control characters or unquotable sequences"
	case "execution.invalid_phase":
		return "execution: invalid execution phase"
	case "execution.invalid_exit_status":
		return "execution: invalid ExitStatus"
	case "execution.invalid_outcome":
		return "execution: invalid ExecutionOutcome"
	case "execution.nil_writer":
		return "execution: canonical writer must not be nil"
	case "execution.nil_receiver":
		return "execution: unmarshal receiver must not be nil"
	case "execution.script_pty_forbidden":
		return "script plan delivers body via stdin and cannot enable PTY"
	case "execution.script_interpreter":
		return "script plan requires an explicit POSIX or PowerShell interpreter"
	case "execution.profile_mismatch":
		return "incompatible launch profile (dialect={dialect}, interpreter={interpreter})"
	case "execution.login_unsupported":
		return "interpreter {interpreter} does not support login mode {mode}"
	case "execution.quote_forbidden_char":
		return "{field} contains forbidden control or unquotable characters"
	case "fsm.invalid_state":
		return "fsm: invalid or uninitialized state"
	case "fsm.invalid_input":
		return "fsm: invalid or uninitialized input"
	case "fsm.illegal_transition":
		return "fsm: illegal state transition for current state"
	case "fsm.invalid_context":
		return "fsm: invalid state machine context"
	case "fsm.invalid_durability":
		return "fsm: invalid DurabilityStatus"
	case "fsm.invalid_outcome":
		return "fsm: invalid SideEffectOutcome"
	case "fsm.invalid_journal":
		return "fsm: invalid transfer journal record"
	case "fsm.corrupt_journal":
		return "fsm: corrupt, out-of-order, or tampered transfer journal"
	case "fsm.transfer_size_exceeded":
		return "fsm: transfer size exceeds 10 GiB limit or offset overflows"
	case "fsm.invalid_chunk_offset":
		return "fsm: non-contiguous chunk offset or invalid length"
	case "fsm.invalid_approval_envelope":
		return "fsm: approval envelope does not match context or binding"
	case "fsm.invalid_ensure_step":
		return "fsm: invalid Ensure step parameters"
	case "fsm.invalid_enroll_lease":
		return "fsm: invalid pending enrollment lease context"
	case "fsm.nil_writer":
		return "fsm: canonical writer must not be nil"
	case "fsm.nil_receiver":
		return "fsm: unmarshal receiver must not be nil"
	case "fsm.terminal_state":
		return "terminal state {state} accepts no input"
	case "fsm.expected_input":
		return "state {state} only accepts {expected}"
	case "fsm.journal_split_brain":
		return "journal generation split-brain: lower generation committed while higher generation uncommitted"
	case "fsm.journal_rollback_forbidden":
		return "cannot roll back from corrupt higher-generation active journal to older staging journal"
	case "fsm.journal_both_corrupt":
		return "both active and staging journals are corrupt"
	case "fsm.chunk_remaining_exceeded":
		return "chunk length {length} exceeds remaining {remaining} bytes"
	case "fsm.time_before_staged":
		return "operation timestamp precedes staged_at"
	case "fsm.lease_not_expired":
		return "enrollment lease has not expired yet"
	case "inventory.invalid_id":
		return "inventory: invalid asset identifier"
	case "inventory.invalid_key_spec":
		return "inventory: invalid private key, certificate, or fingerprint specification"
	case "inventory.invalid_challenge_rule":
		return "inventory: invalid keyboard-interactive challenge rule"
	case "inventory.invalid_auth_method":
		return "inventory: invalid AuthMethod"
	case "inventory.auth_composite_too_deep":
		return "inventory: AuthComposite nesting depth exceeded"
	case "inventory.invalid_node_origin":
		return "inventory: invalid NodeOrigin"
	case "inventory.invalid_host":
		return "inventory: invalid Host entity"
	case "inventory.invalid_identity":
		return "inventory: invalid Identity entity"
	case "inventory.invalid_node":
		return "inventory: invalid Node entity"
	case "inventory.invalid_graph":
		return "inventory: invalid inventory Graph"
	case "inventory.duplicate_asset_id":
		return "inventory: duplicate asset identifier or alias collision"
	case "inventory.missing_asset_ref":
		return "inventory: node references missing Host or Identity"
	case "inventory.missing_proxy_hop":
		return "inventory: ProxyJump references missing hop target"
	case "inventory.proxy_jump_cycle":
		return "inventory: cross-namespace ProxyJump cycle detected"
	case "inventory.proxy_jump_depth_exceeded":
		return "inventory: ProxyJump chain depth exceeds limit"
	case "inventory.unknown_secret_store":
		return "inventory: secret reference points to unregistered store"
	case "inventory.invalid_import_bundle":
		return "inventory: invalid ImportBundle"
	case "inventory.nil_writer":
		return "inventory: canonical writer must not be nil"
	case "inventory.nil_receiver":
		return "inventory: unmarshal receiver must not be nil"
	case "inventory.cycle_detected":
		return "detected {count} proxy jump cycle(s) (first: {first})"
	case "inventory.alias_conflict":
		return "alias {alias} conflicts between {first} and {second}"
	case "inventory.hop_unknown":
		return "node {node} references unknown proxy hop {hop}"
	case "inventory.regex_compile_failed":
		return "failed to compile challenge regex"
	case "inventory.node_missing_asset_ref":
		return "inventory: node {node} references missing host or identity"
	case "netaddr.invalid_host":
		return "netaddr: invalid network host"
	case "netaddr.invalid_zone":
		return "netaddr: invalid IPv6 zone identifier"
	case "netaddr.invalid_port":
		return "netaddr: invalid port number"
	case "netaddr.invalid_host_port":
		return "netaddr: invalid HostPort"
	case "netaddr.invalid_endpoint":
		return "netaddr: invalid SSH Endpoint"
	case "netaddr.nil_receiver":
		return "netaddr: unmarshal receiver must not be nil"
	case "netaddr.brackets_malformed":
		return "malformed bracketed address {value}"
	case "netaddr.host_port_format":
		return "address {value} must be in <host>:<port> or [<ipv6>]:<port> format"
	case "netaddr.port_format":
		return "invalid port {value}: must be an integer in [1, 65535] without leading zeros"
	case "netaddr.hostname_invalid":
		return "invalid hostname {value}: {reason}"
	case "netaddr.reason.length":
		return "length out of range"
	case "netaddr.reason.edge_dot":
		return "leading or trailing dot"
	case "netaddr.reason.numeric_tld":
		return "numeric final label"
	case "netaddr.reason.label_length":
		return "invalid label length"
	case "netaddr.reason.edge_hyphen":
		return "leading or trailing hyphen in label"
	case "netaddr.reason.illegal_char":
		return "illegal character in label"
	case "option.invalid_option":
		return "option: invalid OpenSSH option"
	case "option.unknown_option":
		return "option: unknown or unsupported OpenSSH option"
	case "option.invalid_origin":
		return "option: invalid policy origin classification"
	case "option.invalid_endpoint":
		return "option: invalid target endpoint"
	case "option.invalid_path_list":
		return "option: invalid path list"
	case "option.invalid_algo_policy":
		return "option: invalid algorithm policy"
	case "option.empty_algorithm_list":
		return "option: resolved algorithm list is empty"
	case "option.invalid_proxy_route":
		return "option: invalid proxy route"
	case "option.invalid_control_policy":
		return "option: invalid ControlPolicy"
	case "option.invalid_env_filter":
		return "option: invalid environment variable filter rule"
	case "option.invalid_percent_input":
		return "option: invalid OpenSSH token or %C hash input"
	case "option.nil_receiver":
		return "option: codec target or encoder must not be nil"
	case "option.quoted_syntax":
		return "invalid quoted syntax in {option}"
	case "option.duration_invalid":
		return "invalid OpenSSH duration {value}"
	case "option.template_invalid":
		return "invalid OpenSSH token template in {option}"
	case "pathalg.invalid_component":
		return "pathalg: invalid local path component"
	case "pathalg.invalid_remote_name":
		return "pathalg: invalid remote name"
	case "pathalg.invalid_remote_path":
		return "pathalg: invalid remote path"
	case "pathalg.invalid_local_dest":
		return "pathalg: invalid local sandbox destination path"
	case "pathalg.invalid_local_dir":
		return "pathalg: invalid local root directory path"
	case "pathalg.invalid_local_source":
		return "pathalg: invalid local read-only source path"
	case "pathalg.invalid_symlink_policy":
		return "pathalg: invalid symlink policy"
	case "pathalg.unsafe_symlink":
		return "pathalg: unsafe symbolic link"
	case "pathalg.name_collision":
		return "pathalg: Unicode or case-folding path name collision"
	case "pathalg.invalid_utf8":
		return "pathalg: invalid UTF-8 encoding"
	case "pathalg.invalid_protected_rule":
		return "pathalg: invalid protected path rule"
	case "pathalg.invalid_glob":
		return "pathalg: invalid glob pattern"
	case "pathalg.nil_receiver":
		return "pathalg: unmarshal receiver must not be nil"
	case "pathalg.traversal_forbidden":
		return "path traversal segment {segment} is forbidden"
	case "pathalg.reserved_name":
		return "path component {value} uses a reserved Windows device name"
	case "pathalg.forbidden_char":
		return "path {value} contains forbidden character {char}"
	case "pathalg.glob_unclosed":
		return "unclosed character class in glob pattern"
	case "pathalg.glob_range_invalid":
		return "invalid character range {lo}-{hi} in glob pattern"
	case "pathalg.reason.sep_or_traversal":
		return "contains path separator or traversal segment"
	case "pathalg.reason.edge_slash":
		return "contains leading or trailing slash"
	case "pathalg.reason.disallowed_prefix":
		return "uses disallowed platform path prefix"
	case "pathalg.reason.drive_relative":
		return "drive-relative Windows path is forbidden"
	case "pathalg.reason.bare_drive_root":
		return "bare drive root path is forbidden"
	case "pathalg.reason.bare_root":
		return "bare filesystem root path is forbidden"
	case "pathalg.reason.current_dir":
		return "current directory '.' is forbidden"
	case "pathalg.reason.must_be_absolute":
		return "path must be absolute"
	case "pathalg.reason.abs_rel_mismatch":
		return "cannot compute relative path across absolute and relative paths"
	case "pathalg.reason.unresolvable_relative_base":
		return "cannot resolve against relative base path"
	case "pathalg.reason.escapes_root":
		return "symbolic link target escapes sandbox root"
	case "pathalg.reason.non_relative_or_char":
		return "symbolic link target must be relative and free of forbidden characters"
	case "pathalg.reason.ancestor_is_symlink":
		return "ancestor path component is a symbolic link"
	case "pathalg.reason.chain_escapes_root":
		return "symbolic link chain escapes sandbox root"
	case "plan.invalid_digest":
		return "plan: invalid SHA-256 digest"
	case "plan.invalid_transport_policy":
		return "plan: invalid TransportPolicySpec"
	case "plan.invalid_hop_spec":
		return "plan: invalid HopSpec"
	case "plan.invalid_connection_plan":
		return "plan: invalid SealedConnectionPlan"
	case "plan.tampered_plan_digest":
		return "plan: encoded plan or hop Merkle digest does not match recomputed value"
	case "plan.invalid_handle_kind":
		return "plan: invalid HandleKind"
	case "plan.invalid_handle_id":
		return "plan: invalid HandleID"
	case "plan.invalid_managed_handle":
		return "plan: invalid ManagedHandle"
	case "plan.nil_entropy":
		return "plan: entropy reader must not be nil"
	case "plan.nil_writer":
		return "plan: canonical writer must not be nil"
	case "plan.nil_receiver":
		return "plan: unmarshal receiver must not be nil"
	case "plan.hop_index_discontinuous":
		return "hops[{index}].hop_index={actual} is not contiguous"
	case "plan.digest_verify_failed":
		return "{field} digest verification failed"
	case "playbook.unsupported_version":
		return "playbook: unsupported playbook schema version (only version=2 is supported)"
	case "playbook.invalid_playbook_id":
		return "playbook: invalid PlaybookID"
	case "playbook.invalid_step_id":
		return "playbook: invalid StepID"
	case "playbook.invalid_on_error_policy":
		return "playbook: invalid OnErrorPolicy"
	case "playbook.invalid_file_mode":
		return "playbook: invalid POSIX FileMode"
	case "playbook.invalid_target_selector":
		return "playbook: invalid TargetSelector"
	case "playbook.invalid_step_action":
		return "playbook: invalid StepAction"
	case "playbook.invalid_ensure_check":
		return "playbook: StepEnsure.Check only allows read-only shell or script actions"
	case "playbook.nested_ensure_forbidden":
		return "playbook: nested StepEnsure is forbidden"
	case "playbook.invalid_step":
		return "playbook: invalid Step definition"
	case "playbook.duplicate_step_id":
		return "playbook: duplicate StepID in playbook"
	case "playbook.invalid_playbook":
		return "playbook: invalid Playbook definition"
	case "playbook.tampered_digest":
		return "playbook: encoded canonical digest does not match recomputed value"
	case "playbook.invalid_var":
		return "playbook: invalid environment or template variable key or value"
	case "playbook.invalid_step_status":
		return "playbook: invalid StepStatus"
	case "playbook.invalid_node_status":
		return "playbook: invalid NodeStatus"
	case "playbook.invalid_step_record":
		return "playbook: invalid StepExecutionRecord"
	case "playbook.outcome_status_mismatch":
		return "playbook: ExecutionOutcome conflicts with StepStatus (OutcomeUnknown cannot be downgraded)"
	case "playbook.duplicate_step_record":
		return "playbook: duplicate step execution record for the same node and step"
	case "playbook.unknown_step_id":
		return "playbook: execution record references StepID not present in playbook"
	case "playbook.empty_report":
		return "playbook: execution record list is empty"
	case "playbook.nil_writer":
		return "playbook: canonical writer must not be nil"
	case "playbook.nil_receiver":
		return "playbook: unmarshal receiver must not be nil"
	case "playbook.selector_overlap":
		return "include and exclude node selectors overlap"
	case "playbook.octal_mode_invalid":
		return "invalid octal file mode {value}"
	case "secret.invalid":
		return "secret: SecretBox is invalid or uninitialized"
	case "secret.wiped":
		return "secret: SecretBox has been wiped"
	case "secret.nil_callback":
		return "secret: scoped callback must not be nil"
	case "secret.invalid_ref":
		return "secret: invalid secret Ref"
	case "secret.nil_receiver":
		return "secret: unmarshal receiver must not be nil"
	case "secret.ref_format":
		return "secret reference {value} must use <store>/<item> format"
	case "security.invalid_verdict":
		return "security: invalid Verdict"
	case "security.invalid_risk_level":
		return "security: invalid RiskLevel"
	case "security.invalid_decision":
		return "security: invalid GuardrailDecision"
	case "security.invalid_capability":
		return "security: invalid Capability"
	case "security.invalid_glob":
		return "security: invalid glob pattern"
	case "security.invalid_node_override":
		return "security: invalid NodeOverrides rule"
	case "security.invalid_trace_id":
		return "security: invalid TraceID"
	case "security.invalid_operation_id":
		return "security: invalid OperationID"
	case "security.nil_entropy":
		return "security: entropy reader must not be nil"
	case "security.invalid_digest":
		return "security: invalid SHA-256 Digest"
	case "security.invalid_operation_binding":
		return "security: invalid OperationBinding"
	case "security.invalid_approval_envelope":
		return "security: invalid ApprovalEnvelope"
	case "security.invalid_scope_snapshot":
		return "security: invalid ScopeSnapshot"
	case "security.nil_writer":
		return "security: canonical writer must not be nil"
	case "security.nil_receiver":
		return "security: unmarshal receiver must not be nil"
	case "security.escalation_reasons":
		return "invalid scope escalation reasons"
	default:
		return ""
	}
}

// AllKeys 返回本分片注册的全部消息键（按字典序升序排列，每次返回独立切片副本）。
func AllKeys() []string {
	keys := []string{
		"algebraic.empty_slice",
		"algebraic.invalid_duration",
		"algebraic.duration_overflow",
		"algebraic.nil_receiver",
		"algebraic.nil_callback",
		"execution.invalid_launch_dialect",
		"execution.invalid_interpreter",
		"execution.invalid_login_mode",
		"execution.invalid_launch_profile",
		"execution.unsupported_combination",
		"execution.not_posix_bourne",
		"execution.invalid_plan_kind",
		"execution.invalid_command_plan",
		"execution.invalid_env_var",
		"execution.invalid_shell_quote",
		"execution.invalid_phase",
		"execution.invalid_exit_status",
		"execution.invalid_outcome",
		"execution.nil_writer",
		"execution.nil_receiver",
		"execution.script_pty_forbidden",
		"execution.script_interpreter",
		"execution.profile_mismatch",
		"execution.login_unsupported",
		"execution.quote_forbidden_char",
		"fsm.invalid_state",
		"fsm.invalid_input",
		"fsm.illegal_transition",
		"fsm.invalid_context",
		"fsm.invalid_durability",
		"fsm.invalid_outcome",
		"fsm.invalid_journal",
		"fsm.corrupt_journal",
		"fsm.transfer_size_exceeded",
		"fsm.invalid_chunk_offset",
		"fsm.invalid_approval_envelope",
		"fsm.invalid_ensure_step",
		"fsm.invalid_enroll_lease",
		"fsm.nil_writer",
		"fsm.nil_receiver",
		"fsm.terminal_state",
		"fsm.expected_input",
		"fsm.journal_split_brain",
		"fsm.journal_rollback_forbidden",
		"fsm.journal_both_corrupt",
		"fsm.chunk_remaining_exceeded",
		"fsm.time_before_staged",
		"fsm.lease_not_expired",
		"inventory.invalid_id",
		"inventory.invalid_key_spec",
		"inventory.invalid_challenge_rule",
		"inventory.invalid_auth_method",
		"inventory.auth_composite_too_deep",
		"inventory.invalid_node_origin",
		"inventory.invalid_host",
		"inventory.invalid_identity",
		"inventory.invalid_node",
		"inventory.invalid_graph",
		"inventory.duplicate_asset_id",
		"inventory.missing_asset_ref",
		"inventory.missing_proxy_hop",
		"inventory.proxy_jump_cycle",
		"inventory.proxy_jump_depth_exceeded",
		"inventory.unknown_secret_store",
		"inventory.invalid_import_bundle",
		"inventory.nil_writer",
		"inventory.nil_receiver",
		"inventory.cycle_detected",
		"inventory.alias_conflict",
		"inventory.hop_unknown",
		"inventory.regex_compile_failed",
		"inventory.node_missing_asset_ref",
		"netaddr.invalid_host",
		"netaddr.invalid_zone",
		"netaddr.invalid_port",
		"netaddr.invalid_host_port",
		"netaddr.invalid_endpoint",
		"netaddr.nil_receiver",
		"netaddr.brackets_malformed",
		"netaddr.host_port_format",
		"netaddr.port_format",
		"netaddr.hostname_invalid",
		"netaddr.reason.length",
		"netaddr.reason.edge_dot",
		"netaddr.reason.numeric_tld",
		"netaddr.reason.label_length",
		"netaddr.reason.edge_hyphen",
		"netaddr.reason.illegal_char",
		"option.invalid_option",
		"option.unknown_option",
		"option.invalid_origin",
		"option.invalid_endpoint",
		"option.invalid_path_list",
		"option.invalid_algo_policy",
		"option.empty_algorithm_list",
		"option.invalid_proxy_route",
		"option.invalid_control_policy",
		"option.invalid_env_filter",
		"option.invalid_percent_input",
		"option.nil_receiver",
		"option.quoted_syntax",
		"option.duration_invalid",
		"option.template_invalid",
		"pathalg.invalid_component",
		"pathalg.invalid_remote_name",
		"pathalg.invalid_remote_path",
		"pathalg.invalid_local_dest",
		"pathalg.invalid_local_dir",
		"pathalg.invalid_local_source",
		"pathalg.invalid_symlink_policy",
		"pathalg.unsafe_symlink",
		"pathalg.name_collision",
		"pathalg.invalid_utf8",
		"pathalg.invalid_protected_rule",
		"pathalg.invalid_glob",
		"pathalg.nil_receiver",
		"pathalg.traversal_forbidden",
		"pathalg.reserved_name",
		"pathalg.forbidden_char",
		"pathalg.glob_unclosed",
		"pathalg.glob_range_invalid",
		"pathalg.reason.sep_or_traversal",
		"pathalg.reason.edge_slash",
		"pathalg.reason.disallowed_prefix",
		"pathalg.reason.drive_relative",
		"pathalg.reason.bare_drive_root",
		"pathalg.reason.bare_root",
		"pathalg.reason.current_dir",
		"pathalg.reason.must_be_absolute",
		"pathalg.reason.abs_rel_mismatch",
		"pathalg.reason.unresolvable_relative_base",
		"pathalg.reason.escapes_root",
		"pathalg.reason.non_relative_or_char",
		"pathalg.reason.ancestor_is_symlink",
		"pathalg.reason.chain_escapes_root",
		"plan.invalid_digest",
		"plan.invalid_transport_policy",
		"plan.invalid_hop_spec",
		"plan.invalid_connection_plan",
		"plan.tampered_plan_digest",
		"plan.invalid_handle_kind",
		"plan.invalid_handle_id",
		"plan.invalid_managed_handle",
		"plan.nil_entropy",
		"plan.nil_writer",
		"plan.nil_receiver",
		"plan.hop_index_discontinuous",
		"plan.digest_verify_failed",
		"playbook.unsupported_version",
		"playbook.invalid_playbook_id",
		"playbook.invalid_step_id",
		"playbook.invalid_on_error_policy",
		"playbook.invalid_file_mode",
		"playbook.invalid_target_selector",
		"playbook.invalid_step_action",
		"playbook.invalid_ensure_check",
		"playbook.nested_ensure_forbidden",
		"playbook.invalid_step",
		"playbook.duplicate_step_id",
		"playbook.invalid_playbook",
		"playbook.tampered_digest",
		"playbook.invalid_var",
		"playbook.invalid_step_status",
		"playbook.invalid_node_status",
		"playbook.invalid_step_record",
		"playbook.outcome_status_mismatch",
		"playbook.duplicate_step_record",
		"playbook.unknown_step_id",
		"playbook.empty_report",
		"playbook.nil_writer",
		"playbook.nil_receiver",
		"playbook.selector_overlap",
		"playbook.octal_mode_invalid",
		"secret.invalid",
		"secret.wiped",
		"secret.nil_callback",
		"secret.invalid_ref",
		"secret.nil_receiver",
		"secret.ref_format",
		"security.invalid_verdict",
		"security.invalid_risk_level",
		"security.invalid_decision",
		"security.invalid_capability",
		"security.invalid_glob",
		"security.invalid_node_override",
		"security.invalid_trace_id",
		"security.invalid_operation_id",
		"security.nil_entropy",
		"security.invalid_digest",
		"security.invalid_operation_binding",
		"security.invalid_approval_envelope",
		"security.invalid_scope_snapshot",
		"security.nil_writer",
		"security.nil_receiver",
		"security.escalation_reasons",
	}
	slices.Sort(keys)
	return keys
}
