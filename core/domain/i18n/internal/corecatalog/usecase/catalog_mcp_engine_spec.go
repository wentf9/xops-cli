package usecase

// lookupMCPEngine 返回 core/internal/mcpruntime/** 与 core/engine 键对应的规范英文兜底模板；未命中返回空串。
func lookupMCPEngine(id string) string {
	switch id {
	case "mcp.invalid_config":
		return "mcpruntime: invalid ServerConfig"
	case "mcp.server_not_initialized":
		return "mcpruntime: MCP server is not initialized"
	case "mcp.server_closed":
		return "mcpruntime: MCP server is closed"
	case "mcp.non_loopback_address":
		return "mcpruntime: only loopback bind addresses (127.0.0.1 / ::1 / localhost) are allowed by default"
	case "mcp.message_too_large":
		return "mcpruntime: inbound MCP message exceeds maximum byte limit"
	case "mcp.startup_reconcile_failed":
		return "mcpruntime: startup crash audit reconciliation failed"
	case "mcp.startup_recovery_failed":
		return "mcpruntime: startup transfer journal recovery failed"
	case "mcp.protocol.parse_json":
		return "mcpruntime/protocol: JSON syntax parse failed"
	case "mcp.protocol.invalid_jsonrpc":
		return "mcpruntime/protocol: invalid JSON-RPC 2.0 message"
	case "mcp.protocol.invalid_request_id":
		return "mcpruntime/protocol: invalid JSON-RPC RequestID"
	case "mcp.protocol.invalid_mcp_message":
		return "mcpruntime/protocol: invalid MCP protocol payload"
	case "mcp.protocol.invalid_approval":
		return "mcpruntime/protocol: invalid approval submission payload"
	case "mcp.protocol.invalid_schema":
		return "mcpruntime/protocol: invalid built-in tool JSON Schema"
	case "mcp.protocol.invalid_params":
		return "mcpruntime/protocol: invalid tool or method parameters"
	case "mcp.protocol.tool_not_found":
		return "mcpruntime/protocol: unregistered MCP tool"
	case "mcp.protocol.outcome_unknown":
		return "mcpruntime/protocol: remote execution outcome is unknown; automatic retry is forbidden"
	case "mcp.protocol.outcome_unknown_detail":
		return "mcp: remote execution outcome is unknown ({code}); automatic retry is forbidden"
	case "mcp.protocol.outcome_unknown_reason":
		return "mcp: remote execution outcome is unknown ({code}: {reason}); automatic retry is forbidden"
	case "mcp.tools.invalid_config":
		return "mcpruntime/tools: invalid RegistryConfig"
	case "mcp.tools.not_initialized":
		return "mcpruntime/tools: Registry is not initialized"
	case "mcp.tools.service_unavailable":
		return "mcpruntime/tools: required usecase service is not configured"
	case "mcp.tools.handle_not_found":
		return "mcpruntime/tools: managed handle token not found"
	case "mcp.http.header_missing":
		return "missing required HTTP header {header}"
	case "mcp.http.header_rejected":
		return "unauthorized or invalid HTTP header {header}: {value}"
	case "mcp.http.session_missing":
		return "Mcp-Session-Id session does not exist or is closed"
	case "mcp.corrupt_journal_limit":
		return "found {count} corrupt transfer journal(s) with FailOnCorruptJournal enabled"
	case "mcp.protocol.id_type":
		return "JSON-RPC id must be a non-empty string or exact integer"
	case "mcp.non_loopback_bind":
		return "mcpruntime: refusing non-loopback HTTP listen address {addr} (only 127.0.0.1 / ::1 / localhost are allowed by default)"
	case "mcp.non_loopback_host":
		return "mcpruntime: host {host} is not a loopback address (only 127.0.0.1 / ::1 / localhost are allowed by default)"
	case "mcp.invalid_listen_addr":
		return "invalid MCP HTTP listen address {addr}"
	case "mcp.protocol.marshal_failed":
		return "failed to marshal MCP {target}"
	case "mcp.protocol.schema_canon_failed":
		return "failed to canonicalize tool schema for {tool}"
	case "mcp.tools.unknown_tool":
		return "unknown MCP tool {tool}"
	case "mcp.tools.unknown_tool_action":
		return "unknown action {action} for MCP tool {tool}"
	case "mcp.tools.batch_exec_stdin_unsupported":
		return "batch_exec does not support stdin input"
	case "mcp.http.listen_failed":
		return "failed to listen on MCP HTTP address {addr}"
	case "mcp.http.read_body_failed":
		return "failed to read MCP HTTP request body"
	case "mcp.http.transfer_path_invalid":
		return "invalid MCP transfer stream path {path}"
	case "engine.nil_context":
		return "engine: context must not be nil"
	case "engine.invalid_config":
		return "engine: invalid Engine Config"
	case "engine.not_initialized":
		return "engine: Engine is not initialized"
	case "engine.closed":
		return "engine: Engine is closed"
	case "engine.halted":
		return "engine: security gate entered irreversible Halted state"
	case "engine.invalid_request":
		return "engine: invalid request parameters"
	case "engine.invalid_profile":
		return "engine: invalid PolicyProfile"
	case "engine.invalid_fallback":
		return "engine: invalid NoElicitFallback policy"
	case "engine.invalid_request_tty":
		return "engine: invalid RequestTTY mode"
	case "engine.reconciler_unavailable":
		return "engine: AuditReconciler port is not configured"
	case "engine.vault_unavailable":
		return "engine: SecretVault port is not configured"
	case "engine.mcp_server_not_initialized":
		return "engine: MCPServer is not initialized"
	case "engine.projection_not_initialized":
		return "engine: Projection is not initialized"
	case "engine.approval_required":
		return "engine: operation requires two-step approval confirmation"
	case "engine.approval_rejected":
		return "engine: operator rejected two-step approval challenge"
	case "engine.authorization_denied":
		return "engine: operation denied by guardrail or permission policy"
	case "engine.scope_escalated":
		return "engine: scope escalation or path drift detected during canonicalization"
	case "engine.not_found":
		return "engine: target resource not found"
	case "engine.already_exists":
		return "engine: target resource already exists"
	case "engine.revision_conflict":
		return "engine: inventory revision CAS conflict"
	case "engine.still_referenced":
		return "engine: target asset or secret is still referenced; refusing deletion"
	case "engine.import_conflict":
		return "engine: import preflight detected conflicts; refusing write"
	case "engine.uncertain_durability":
		return "engine: change applied with uncertain durability; retry and secret deletion are forbidden"
	case "engine.outcome_unknown":
		return "engine: side-effect outcome is unknown; automatic retry is forbidden"
	case "engine.vault_locked":
		return "engine: secret vault is locked"
	case "engine.secret_not_found":
		return "engine: secret entry not found"
	case "engine.auth_failed":
		return "engine: remote authentication or credential verification failed"
	case "engine.host_key_unknown":
		return "engine: unknown remote host key rejected by policy"
	case "engine.host_key_mismatch":
		return "engine: remote host key fingerprint conflicts with trust store"
	case "engine.host_key_revoked":
		return "engine: remote host key has been revoked"
	case "engine.dial_failed":
		return "engine: failed to establish remote transport connection"
	case "engine.control_master_disabled":
		return "engine: ControlPolicy effective projection disabled multiplexing"
	case "engine.mux_unavailable":
		return "engine: ControlMaster multiplex socket is unavailable"
	case "engine.handle_not_found":
		return "engine: managed session handle not found or already released"
	case "engine.handle_revoked":
		return "engine: managed handle or connection lease has been revoked"
	case "engine.interaction_unavailable":
		return "engine: interactive input is unavailable in current environment"
	case "engine.interaction_canceled":
		return "engine: operator canceled interaction request"
	case "engine.remote_anchor_mismatch":
		return "engine: remote file FSTAT type or (dev,ino) anchor mismatch"
	case "engine.remote_is_dir":
		return "engine: remote target is a directory"
	case "engine.not_regular_file":
		return "engine: target path is not a regular file"
	case "engine.patch_conflict":
		return "engine: remote file patch match failed or ambiguous"
	case "engine.digest_mismatch":
		return "engine: file SHA-256 digest verification mismatch"
	case "engine.symlink_rejected":
		return "engine: symbolic link rejected by security policy"
	case "engine.corrupt_data":
		return "engine: persisted data or transfer journal is corrupt"
	case "engine.limit_exceeded":
		return "engine: data size or object count exceeds safety limit"
	case "engine.unsupported":
		return "engine: capability is not supported by current configuration or adapter"
	case "engine.init_component_failed":
		return "failed to initialize {component}"
	case "engine.hostkey_unobserved":
		return "handshake completed without observing a verified host key fingerprint for {endpoint}"
	case "engine.known_hosts_dir_missing":
		return "KnownHostsDir is missing and default ~/.ssh could not be derived"
	case "engine.hostkey_observer_unsupported":
		return "dialer does not support host key trust observation"
	default:
		return ""
	}
}

func keysMCPEngine() []string {
	return []string{
		"mcp.invalid_config",
		"mcp.server_not_initialized",
		"mcp.server_closed",
		"mcp.non_loopback_address",
		"mcp.message_too_large",
		"mcp.startup_reconcile_failed",
		"mcp.startup_recovery_failed",
		"mcp.protocol.parse_json",
		"mcp.protocol.invalid_jsonrpc",
		"mcp.protocol.invalid_request_id",
		"mcp.protocol.invalid_mcp_message",
		"mcp.protocol.invalid_approval",
		"mcp.protocol.invalid_schema",
		"mcp.protocol.invalid_params",
		"mcp.protocol.tool_not_found",
		"mcp.protocol.outcome_unknown",
		"mcp.protocol.outcome_unknown_detail",
		"mcp.protocol.outcome_unknown_reason",
		"mcp.tools.invalid_config",
		"mcp.tools.not_initialized",
		"mcp.tools.service_unavailable",
		"mcp.tools.handle_not_found",
		"mcp.http.header_missing",
		"mcp.http.header_rejected",
		"mcp.http.session_missing",
		"mcp.corrupt_journal_limit",
		"mcp.protocol.id_type",
		"mcp.non_loopback_bind",
		"mcp.non_loopback_host",
		"mcp.invalid_listen_addr",
		"mcp.protocol.marshal_failed",
		"mcp.protocol.schema_canon_failed",
		"mcp.tools.unknown_tool",
		"mcp.tools.unknown_tool_action",
		"mcp.tools.batch_exec_stdin_unsupported",
		"mcp.http.listen_failed",
		"mcp.http.read_body_failed",
		"mcp.http.transfer_path_invalid",
		"engine.nil_context",
		"engine.invalid_config",
		"engine.not_initialized",
		"engine.closed",
		"engine.halted",
		"engine.invalid_request",
		"engine.invalid_profile",
		"engine.invalid_fallback",
		"engine.invalid_request_tty",
		"engine.reconciler_unavailable",
		"engine.vault_unavailable",
		"engine.mcp_server_not_initialized",
		"engine.projection_not_initialized",
		"engine.approval_required",
		"engine.approval_rejected",
		"engine.authorization_denied",
		"engine.scope_escalated",
		"engine.not_found",
		"engine.already_exists",
		"engine.revision_conflict",
		"engine.still_referenced",
		"engine.import_conflict",
		"engine.uncertain_durability",
		"engine.outcome_unknown",
		"engine.vault_locked",
		"engine.secret_not_found",
		"engine.auth_failed",
		"engine.host_key_unknown",
		"engine.host_key_mismatch",
		"engine.host_key_revoked",
		"engine.dial_failed",
		"engine.control_master_disabled",
		"engine.mux_unavailable",
		"engine.handle_not_found",
		"engine.handle_revoked",
		"engine.interaction_unavailable",
		"engine.interaction_canceled",
		"engine.remote_anchor_mismatch",
		"engine.remote_is_dir",
		"engine.not_regular_file",
		"engine.patch_conflict",
		"engine.digest_mismatch",
		"engine.symlink_rejected",
		"engine.corrupt_data",
		"engine.limit_exceeded",
		"engine.unsupported",
		"engine.init_component_failed",
		"engine.hostkey_unobserved",
		"engine.known_hosts_dir_missing",
		"engine.hostkey_observer_unsupported",
	}
}
