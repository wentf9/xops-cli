package usecase

import "slices"

// Lookup 返回usecase/**、mcpruntime/** 与 engine 键对应的规范英文兜底模板；未命中返回空串。
func Lookup(id string) string {
	switch id {
	case "uc.automation.nil_context":
		return "usecase/automation: context must not be nil"
	case "uc.automation.invalid_config":
		return "usecase/automation: invalid ServiceConfig"
	case "uc.automation.not_initialized":
		return "usecase/automation: Service is not initialized"
	case "uc.automation.invalid_request":
		return "usecase/automation: invalid automation request"
	case "uc.automation.no_targets":
		return "usecase/automation: no target nodes matched selector"
	case "uc.automation.operator_read_unavailable":
		return "usecase/automation: OperatorReadFS is not configured"
	case "uc.automation.scoped_fs_unavailable":
		return "usecase/automation: ScopedRootFS is not configured"
	case "uc.automation.inventory_unavailable":
		return "usecase/automation: InventoryService is not configured"
	case "uc.automation.template_render":
		return "usecase/automation: template parse or render failed"
	case "uc.automation.batch_failed":
		return "usecase/automation: one or more nodes failed during batch execution"
	case "uc.automation.playbook_failed":
		return "usecase/automation: one or more playbook steps failed"
	case "uc.automation.playbook_aborted":
		return "usecase/automation: playbook execution aborted by policy"
	case "uc.automation.uncertain_outcome":
		return "usecase/automation: execution outcome is unknown; retry is forbidden"
	case "uc.automation.uncertain_durability":
		return "usecase/automation: remote change applied with uncertain durability; retry is forbidden"
	case "uc.automation.unsupported_action":
		return "usecase/automation: unsupported playbook step action"
	case "uc.automation.symlink_policy_denied":
		return "usecase/automation: symlink policy denied read or remote expansion exceeded limit"
	case "uc.automation.sandbox_abs_forbidden":
		return "sandbox mode forbids absolute local source path {path}"
	case "uc.automation.snapshot_missing":
		return "missing {kind} source snapshot for {source}"
	case "uc.automation.remote_exists":
		return "remote destination {path} already exists (overwrite=false)"
	case "uc.automation.batch_counts":
		return "batch completed with {succeeded} succeeded and {failed} failed"
	case "uc.credential.nil_context":
		return "usecase/credential: context must not be nil"
	case "uc.credential.nil_callback":
		return "usecase/credential: callback must not be nil"
	case "uc.credential.invalid_config":
		return "usecase/credential: invalid ServiceConfig"
	case "uc.credential.not_initialized":
		return "usecase/credential: Service is not initialized"
	case "uc.credential.invalid_request":
		return "usecase/credential: invalid credential request"
	case "uc.credential.invalid_secret_box":
		return "usecase/credential: SecretBox is invalid or wiped"
	case "uc.credential.vault_control_unavailable":
		return "usecase/credential: VaultControlPort is not configured"
	case "uc.credential.store_unavailable":
		return "usecase/credential: InventoryStore is not configured"
	case "uc.credential.interaction_unavailable":
		return "usecase/credential: interactive secret input is unavailable"
	case "uc.credential.passphrase_confirm_mismatch":
		return "usecase/credential: passphrase confirmation does not match"
	case "uc.credential.secret_still_referenced":
		return "usecase/credential: secret is still referenced; refusing deletion"
	case "uc.credential.saga_rolled_back":
		return "usecase/credential: credential mutation saga rolled back"
	case "uc.credential.uncertain_durability":
		return "usecase/credential: commit applied with uncertain durability; retry and secret deletion are forbidden"
	case "uc.credential.saga_uncertain":
		return "usecase/credential: credential mutation saga outcome is unknown; automatic retry is forbidden"
	case "uc.credential.secret_referenced_detail":
		return "secret {ref} still has {count} reference(s) (first: {location}/{owner})"
	case "uc.credential.store_unknown":
		return "secret store {store} is not registered in KnownStores"
	case "uc.credential.ref_not_in_graph":
		return "secret {ref} is not referenced in inventory graph"
	case "uc.credential.saga_step_limit":
		return "vault saga exceeded maximum transitions ({max})"
	case "uc.inventory.nil_context":
		return "usecase/inventory: context must not be nil"
	case "uc.inventory.invalid_config":
		return "usecase/inventory: invalid ServiceConfig"
	case "uc.inventory.not_initialized":
		return "usecase/inventory: Service is not initialized"
	case "uc.inventory.invalid_target":
		return "usecase/inventory: invalid target specification"
	case "uc.inventory.unsupported_origin":
		return "usecase/inventory: unsupported target origin kind"
	case "uc.inventory.missing_username":
		return "usecase/inventory: unable to determine target SSH username"
	case "uc.inventory.no_auth_method":
		return "usecase/inventory: no usable SSH authentication method under current policy"
	case "uc.inventory.proxy_jump_cycle":
		return "usecase/inventory: ProxyJump chain contains a cycle"
	case "uc.inventory.proxy_jump_depth_exceeded":
		return "usecase/inventory: ProxyJump depth or hop count exceeds safety limit"
	case "uc.inventory.nil_callback":
		return "usecase/inventory: callback must not be nil"
	case "uc.inventory.invalid_request":
		return "usecase/inventory: invalid inventory request"
	case "uc.inventory.store_unavailable":
		return "usecase/inventory: InventoryStore is not configured"
	case "uc.inventory.gate_unavailable":
		return "usecase/inventory: Gate authorizer is not configured"
	case "uc.inventory.vault_unavailable":
		return "usecase/inventory: SecretVault or CredentialService is not configured"
	case "uc.inventory.key_signer_unavailable":
		return "usecase/inventory: KeySignerPort is not configured"
	case "uc.inventory.interaction_unavailable":
		return "usecase/inventory: interactive input is unavailable"
	case "uc.inventory.clock_unavailable":
		return "usecase/inventory: Clock port is not configured"
	case "uc.inventory.asset_not_found":
		return "usecase/inventory: target asset not found"
	case "uc.inventory.asset_already_exists":
		return "usecase/inventory: target asset identifier already exists"
	case "uc.inventory.asset_still_referenced":
		return "usecase/inventory: target asset is still referenced; refusing deletion"
	case "uc.inventory.secret_still_referenced":
		return "usecase/inventory: secret or store still has active or pending references"
	case "uc.inventory.unknown_import_format":
		return "usecase/inventory: unregistered import format"
	case "uc.inventory.import_conflict":
		return "usecase/inventory: import preflight detected conflicts; refusing write"
	case "uc.inventory.commit_not_applied":
		return "usecase/inventory: configuration CAS commit was not applied"
	case "uc.inventory.uncertain_durability":
		return "usecase/inventory: CAS commit applied with uncertain durability; retry and secret deletion are forbidden"
	case "uc.inventory.commit_outcome_unknown":
		return "usecase/inventory: CAS commit outcome is unknown; automatic retry is forbidden"
	case "uc.inventory.lease_expired":
		return "usecase/inventory: pending enrollment lease expired or out of scope"
	case "uc.inventory.enrollment_aborted":
		return "usecase/inventory: pending enrollment aborted"
	case "uc.inventory.enrollment_uncertain":
		return "usecase/inventory: pending enrollment ended in uncertain state; secret pin retained"
	case "uc.inventory.key_fingerprint_mismatch":
		return "usecase/inventory: private key fingerprint mismatches expected fingerprint"
	case "uc.inventory.asset_referenced_detail":
		return "{kind} {id} is still referenced by {count} item(s)"
	case "uc.inventory.secret_referenced_detail":
		return "{subject} still has {count} reference(s)"
	case "uc.inventory.template_forbidden_token":
		return "expanded path template {template} contains forbidden token sequence"
	case "uc.inventory.env_var_missing":
		return "environment variable {name} is unset or empty"
	case "uc.inventory.import_conflict_count":
		return "detected {count} import conflict(s)"
	case "uc.inventory.fingerprint_mismatch":
		return "fingerprint mismatch: got {actual}, expected {expected}"
	case "uc.inventory.hop_cycle":
		return "proxy jump cycle detected at {target} ({key})"
	case "uc.inventory.node_not_found":
		return "managed node {node} not found"
	case "uc.inventory.username_hint":
		return "specify SSH username via user@, -l, or OpenSSH User"
	case "uc.inventory.target_malformed":
		return "malformed target {target}: {reason}"
	case "uc.observability.nil_context":
		return "usecase/observability: context must not be nil"
	case "uc.observability.invalid_config":
		return "usecase/observability: invalid ServiceConfig or ProjectionConfig"
	case "uc.observability.not_initialized":
		return "usecase/observability: Service is not initialized"
	case "uc.observability.invalid_request":
		return "usecase/observability: invalid observability or GUI request"
	case "uc.observability.posix_shell_required":
		return "usecase/observability: target node requires a POSIX Bourne compatible shell"
	case "uc.observability.invalid_log_target":
		return "usecase/observability: invalid remote log target or container name"
	case "uc.observability.invalid_gui_input":
		return "usecase/observability: invalid or unsafe GUI input parameter"
	case "uc.observability.screenshot_invalid":
		return "usecase/observability: remote screenshot payload missing, unsupported, or exceeded safety bounds"
	case "uc.observability.scoped_fs_unavailable":
		return "usecase/observability: ScopedRootFS is not configured"
	case "uc.observability.forwarder_unavailable":
		return "usecase/observability: ForwarderPort is not configured"
	case "uc.observability.projection_closed":
		return "usecase/observability: Projection is not initialized or closed"
	case "uc.observability.uncertain_outcome":
		return "usecase/observability: remote operation outcome is unknown; retry is forbidden"
	case "uc.observability.symlink_policy_denied":
		return "usecase/observability: remote symlink expansion exceeded limit or denied by policy"
	case "uc.observability.log_limit_reached":
		return "usecase/observability: remote follow log reached max_bytes limit"
	case "uc.observability.coords_range":
		return "normalized coordinates ({x},{y}) must be in [0, 1000]"
	case "uc.observability.image_dimensions":
		return "image dimensions {width}x{height} exceed safety limit"
	case "uc.observability.image_format":
		return "unsupported image format (only PNG, JPEG, and WebP are supported)"
	case "uc.observability.screenshot_marker":
		return "screenshot payload is missing start or end marker"
	case "uc.observability.non_loopback_denied":
		return "binding non-loopback address {addr} is forbidden by default"
	case "uc.session.nil_context":
		return "usecase/session: context must not be nil"
	case "uc.session.invalid_config":
		return "usecase/session: invalid ServiceConfig"
	case "uc.session.not_initialized":
		return "usecase/session: Service is not initialized"
	case "uc.session.invalid_request":
		return "usecase/session: invalid session request"
	case "uc.session.invalid_request_tty":
		return "usecase/session: invalid RequestTTY mode"
	case "uc.session.port_unavailable":
		return "usecase/session: required outbound port is not configured"
	case "uc.session.invalid_probe_result":
		return "usecase/session: invalid remote shell probe result"
	case "uc.session.escalation_scope_changed":
		return "usecase/session: privilege escalation canonical scope validation failed or drifted"
	case "uc.session.pty_closed":
		return "usecase/session: persistent PTY session is closed or revoked"
	case "uc.session.control_master_disabled":
		return "usecase/session: ControlPolicy effective projection disabled multiplexing"
	case "uc.session.mux_master_unavailable":
		return "usecase/session: ControlMaster is unavailable or connection refused"
	case "uc.session.mux_persist_expired":
		return "usecase/session: ControlPersist timeout expired"
	case "uc.session.escalation_drift":
		return "privilege escalation scope drifted or tightened ({reason})"
	case "uc.session.mux_disabled_detail":
		return "ControlMaster is disabled (EffectiveMaster={mode})"
	case "uc.session.mux_ask_requires_tty":
		return "ControlMaster ask/autoask requires an interactive terminal"
	case "uc.session.mux_rejected":
		return "operator declined to start or share ControlMaster"
	case "uc.session.control_path_tilde":
		return "rejected unexpanded leading ~ in control socket path {path}"
	case "uc.transfer.nil_context":
		return "usecase/transfer: context must not be nil"
	case "uc.transfer.invalid_config":
		return "usecase/transfer: invalid ServiceConfig"
	case "uc.transfer.not_initialized":
		return "usecase/transfer: Service is not initialized"
	case "uc.transfer.invalid_request":
		return "usecase/transfer: invalid transfer request"
	case "uc.transfer.operator_read_unavailable":
		return "usecase/transfer: OperatorReadFS is not configured"
	case "uc.transfer.scoped_fs_unavailable":
		return "usecase/transfer: ScopedRootFS is not configured"
	case "uc.transfer.journal_store_unavailable":
		return "usecase/transfer: JournalStore is not configured"
	case "uc.transfer.patch_conflict":
		return "usecase/transfer: remote file patch conflict"
	case "uc.transfer.patch_no_match":
		return "usecase/transfer: patch target text not found"
	case "uc.transfer.patch_ambiguous":
		return "usecase/transfer: patch target text matched multiple locations"
	case "uc.transfer.uncertain_commit":
		return "usecase/transfer: transfer is in TransferUncertainCommit; retry and cleanup are forbidden"
	case "uc.transfer.corrupt_journal":
		return "usecase/transfer: transfer journal is corrupt or violates recovery invariants"
	case "uc.transfer.not_found":
		return "usecase/transfer: transfer task not found"
	case "uc.transfer.handle_mismatch":
		return "usecase/transfer: transfer handle does not match target task"
	case "uc.transfer.symlink_policy_denied":
		return "usecase/transfer: symbolic link rejected by security policy"
	case "uc.transfer.remote_object_unsupported":
		return "usecase/transfer: unsupported remote object type"
	case "uc.transfer.digest_mismatch":
		return "usecase/transfer: SHA-256 digest mismatch"
	case "uc.transfer.terminal":
		return "transfer {id} is already in terminal state {state}"
	case "uc.transfer.dual_active":
		return "transfer {id} has an active handle for the same generation"
	case "uc.transfer.gen_rollback":
		return "generation {gen} is corrupt or uncertain; rollback to older generation is forbidden"
	case "uc.transfer.gen_uncertain":
		return "generation {gen} is in UncertainCommit; retry and cleanup are forbidden"
	case "uc.transfer.patch_multi_match":
		return "Edits[{index}] matched {count} locations"
	case "uc.transfer.symlink_policy":
		return "symlink policy {policy} forbids {path}"
	case "uc.transfer.remote_drift":
		return "remote path {path} canonicalized to unauthorized target {target}"
	case "uc.transfer.remote_dir_cycle":
		return "detected remote directory cycle at {path}"
	case "uc.transfer.remote_abs_required":
		return "remote working or parent directory must be absolute"
	case "uc.transfer.remote_symlink_hops":
		return "remote symlink expansion exceeded limit {limit}"
	case "uc.transfer.remote_not_regular":
		return "remote path {path} has unsupported type {kind}"
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
	default:
		return ""
	}
}

// AllKeys 返回本分片注册的全部消息键（按字典序升序排列，每次返回独立切片副本）。
func AllKeys() []string {
	keys := []string{
		"uc.automation.nil_context",
		"uc.automation.invalid_config",
		"uc.automation.not_initialized",
		"uc.automation.invalid_request",
		"uc.automation.no_targets",
		"uc.automation.operator_read_unavailable",
		"uc.automation.scoped_fs_unavailable",
		"uc.automation.inventory_unavailable",
		"uc.automation.template_render",
		"uc.automation.batch_failed",
		"uc.automation.playbook_failed",
		"uc.automation.playbook_aborted",
		"uc.automation.uncertain_outcome",
		"uc.automation.uncertain_durability",
		"uc.automation.unsupported_action",
		"uc.automation.symlink_policy_denied",
		"uc.automation.sandbox_abs_forbidden",
		"uc.automation.snapshot_missing",
		"uc.automation.remote_exists",
		"uc.automation.batch_counts",
		"uc.credential.nil_context",
		"uc.credential.nil_callback",
		"uc.credential.invalid_config",
		"uc.credential.not_initialized",
		"uc.credential.invalid_request",
		"uc.credential.invalid_secret_box",
		"uc.credential.vault_control_unavailable",
		"uc.credential.store_unavailable",
		"uc.credential.interaction_unavailable",
		"uc.credential.passphrase_confirm_mismatch",
		"uc.credential.secret_still_referenced",
		"uc.credential.saga_rolled_back",
		"uc.credential.uncertain_durability",
		"uc.credential.saga_uncertain",
		"uc.credential.secret_referenced_detail",
		"uc.credential.store_unknown",
		"uc.credential.ref_not_in_graph",
		"uc.credential.saga_step_limit",
		"uc.inventory.nil_context",
		"uc.inventory.invalid_config",
		"uc.inventory.not_initialized",
		"uc.inventory.invalid_target",
		"uc.inventory.unsupported_origin",
		"uc.inventory.missing_username",
		"uc.inventory.no_auth_method",
		"uc.inventory.proxy_jump_cycle",
		"uc.inventory.proxy_jump_depth_exceeded",
		"uc.inventory.nil_callback",
		"uc.inventory.invalid_request",
		"uc.inventory.store_unavailable",
		"uc.inventory.gate_unavailable",
		"uc.inventory.vault_unavailable",
		"uc.inventory.key_signer_unavailable",
		"uc.inventory.interaction_unavailable",
		"uc.inventory.clock_unavailable",
		"uc.inventory.asset_not_found",
		"uc.inventory.asset_already_exists",
		"uc.inventory.asset_still_referenced",
		"uc.inventory.secret_still_referenced",
		"uc.inventory.unknown_import_format",
		"uc.inventory.import_conflict",
		"uc.inventory.commit_not_applied",
		"uc.inventory.uncertain_durability",
		"uc.inventory.commit_outcome_unknown",
		"uc.inventory.lease_expired",
		"uc.inventory.enrollment_aborted",
		"uc.inventory.enrollment_uncertain",
		"uc.inventory.key_fingerprint_mismatch",
		"uc.inventory.asset_referenced_detail",
		"uc.inventory.secret_referenced_detail",
		"uc.inventory.template_forbidden_token",
		"uc.inventory.env_var_missing",
		"uc.inventory.import_conflict_count",
		"uc.inventory.fingerprint_mismatch",
		"uc.inventory.hop_cycle",
		"uc.inventory.node_not_found",
		"uc.inventory.username_hint",
		"uc.inventory.target_malformed",
		"uc.observability.nil_context",
		"uc.observability.invalid_config",
		"uc.observability.not_initialized",
		"uc.observability.invalid_request",
		"uc.observability.posix_shell_required",
		"uc.observability.invalid_log_target",
		"uc.observability.invalid_gui_input",
		"uc.observability.screenshot_invalid",
		"uc.observability.scoped_fs_unavailable",
		"uc.observability.forwarder_unavailable",
		"uc.observability.projection_closed",
		"uc.observability.uncertain_outcome",
		"uc.observability.symlink_policy_denied",
		"uc.observability.log_limit_reached",
		"uc.observability.coords_range",
		"uc.observability.image_dimensions",
		"uc.observability.image_format",
		"uc.observability.screenshot_marker",
		"uc.observability.non_loopback_denied",
		"uc.session.nil_context",
		"uc.session.invalid_config",
		"uc.session.not_initialized",
		"uc.session.invalid_request",
		"uc.session.invalid_request_tty",
		"uc.session.port_unavailable",
		"uc.session.invalid_probe_result",
		"uc.session.escalation_scope_changed",
		"uc.session.pty_closed",
		"uc.session.control_master_disabled",
		"uc.session.mux_master_unavailable",
		"uc.session.mux_persist_expired",
		"uc.session.escalation_drift",
		"uc.session.mux_disabled_detail",
		"uc.session.mux_ask_requires_tty",
		"uc.session.mux_rejected",
		"uc.session.control_path_tilde",
		"uc.transfer.nil_context",
		"uc.transfer.invalid_config",
		"uc.transfer.not_initialized",
		"uc.transfer.invalid_request",
		"uc.transfer.operator_read_unavailable",
		"uc.transfer.scoped_fs_unavailable",
		"uc.transfer.journal_store_unavailable",
		"uc.transfer.patch_conflict",
		"uc.transfer.patch_no_match",
		"uc.transfer.patch_ambiguous",
		"uc.transfer.uncertain_commit",
		"uc.transfer.corrupt_journal",
		"uc.transfer.not_found",
		"uc.transfer.handle_mismatch",
		"uc.transfer.symlink_policy_denied",
		"uc.transfer.remote_object_unsupported",
		"uc.transfer.digest_mismatch",
		"uc.transfer.terminal",
		"uc.transfer.dual_active",
		"uc.transfer.gen_rollback",
		"uc.transfer.gen_uncertain",
		"uc.transfer.patch_multi_match",
		"uc.transfer.symlink_policy",
		"uc.transfer.remote_drift",
		"uc.transfer.remote_dir_cycle",
		"uc.transfer.remote_abs_required",
		"uc.transfer.remote_symlink_hops",
		"uc.transfer.remote_not_regular",
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
		"mcp.tools.invalid_config",
		"mcp.tools.not_initialized",
		"mcp.tools.service_unavailable",
		"mcp.tools.handle_not_found",
		"mcp.http.header_missing",
		"mcp.http.header_rejected",
		"mcp.http.session_missing",
		"mcp.corrupt_journal_limit",
		"mcp.protocol.id_type",
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
	}
	slices.Sort(keys)
	return keys
}
