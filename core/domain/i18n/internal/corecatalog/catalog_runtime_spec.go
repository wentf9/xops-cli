package corecatalog

// 本文件收录 Wave 3C（core/internal/{pool,gate,sshnet/**}）全部键的规范英文兜底模板。
func lookupRuntime(id string) string {
	switch id {
	case "pool.not_initialized":
		return "pool: connection pool is not initialized"
	case "pool.invalid_config":
		return "pool: invalid pool configuration"
	case "pool.closed":
		return "pool: connection pool is closed"
	case "pool.gate_halted":
		return "pool: security gate entered Halted state"
	case "pool.nil_context":
		return "pool: context must not be nil"
	case "pool.nil_callback":
		return "pool: scoped callback must not be nil"
	case "pool.invalid_plan":
		return "pool: invalid connection plan or digest"
	case "pool.empty_plan_list":
		return "pool: multi-lease plan list must not be empty"
	case "pool.capacity_exceeded":
		return "pool: pool capacity exceeded with no evictable idle connections"
	case "pool.parent_epoch_changed":
		return "pool: parent hop epoch changed; refusing stale connection publish"
	case "pool.invalid_transport_conn":
		return "pool: dialed transport connection is invalid or digest mismatches"
	case "pool.lease_invalid":
		return "pool: invalid connection lease"
	case "pool.lease_expired":
		return "pool: connection lease expired outside its scope"
	case "pool.lease_revoked":
		return "pool: connection lease has been revoked"
	case "pool.hop_retired":
		return "pool: transport connection has been retired"
	case "pool.teardown_escalated":
		return "pool: connection teardown timed out and escalated to root hop"
	case "pool.invalid_resource":
		return "pool: invalid managed resource"
	case "pool.invalid_handle":
		return "pool: invalid managed handle"
	case "pool.handle_not_found":
		return "pool: managed handle not found or already released"
	case "pool.handle_revoked":
		return "pool: managed handle has been revoked"
	case "pool.handle_generation_mismatch":
		return "pool: managed handle generation mismatch"
	case "pool.handle_binding_mismatch":
		return "pool: managed handle binding mismatch"
	case "pool.handle_type_mismatch":
		return "pool: managed resource type mismatch"
	case "pool.handle_limit_exceeded":
		return "pool: managed handle limit exceeded"
	case "pool.fast_path_miss":
		return "pool: full-chain fast path missed"
	case "gate.nil_context":
		return "gate: context must not be nil"
	case "gate.nil_authorizer":
		return "gate: authorizer must not be nil"
	case "gate.nil_callback":
		return "gate: WithAuthorized callback must not be nil"
	case "gate.invalid_config":
		return "gate: invalid GateConfig"
	case "gate.invalid_policy":
		return "gate: invalid GuardrailPolicy"
	case "gate.invalid_profile":
		return "gate: invalid PolicyProfileKind"
	case "gate.invalid_fallback":
		return "gate: invalid NoElicitFallback policy"
	case "gate.invalid_request":
		return "gate: invalid GateRequest"
	case "gate.invalid_outcome":
		return "gate: invalid ExecutionOutcome"
	case "gate.capability_mismatch":
		return "gate: phantom capability type mismatches OperationBinding.Capability"
	case "gate.not_initialized":
		return "gate: gate is not initialized"
	case "gate.halted":
		return "gate: gate entered irreversible Halted state"
	case "gate.invalid_permit":
		return "gate: Authorized permit is invalid or uninitialized"
	case "gate.permit_revoked":
		return "gate: Authorized permit revoked or used outside scope"
	case "gate.authorization_denied":
		return "gate: operation denied by guardrail policy"
	case "gate.approval_required":
		return "gate: explicit user approval challenge required"
	case "gate.approval_rejected":
		return "gate: user rejected approval challenge"
	case "gate.approval_expired":
		return "gate: approval challenge envelope expired or not yet active"
	case "gate.approval_replayed":
		return "gate: approval challenge envelope or nonce already consumed"
	case "gate.approval_mismatch":
		return "gate: approval challenge envelope mismatches operation, capability, or binding"
	case "gate.approval_invalidated":
		return "gate: approval challenge token has been invalidated"
	case "gate.pending_limit_exceeded":
		return "gate: active pending approval challenge limit exceeded"
	case "gate.scope_escalated":
		return "gate: scope escalation or protected path redirect detected during canonicalization"
	case "gate.audit_stage_failed":
		return "gate: append-only StageOperation failed"
	case "gate.audit_pre_write_failed":
		return "gate: audit pre-write failed; refusing side effect"
	case "gate.audit_unstage_failed":
		return "gate: UnstageOperation failed after terminal audit closure"
	case "gate.reconciler_unavailable":
		return "gate: AuditReconciler port is not configured"
	case "gate.operation_panicked":
		return "gate: authorized callback panicked"
	case "gate.operation_aborted":
		return "gate: authorized callback aborted abnormally"
	case "gate.execution_outcome":
		return "gate: execution outcome={outcome}"
	case "gate.operation_panicked_detail":
		return "gate: authorized callback panicked: {panic}"
	case "gate.approval_challenge_detail":
		return "gate: approval challenge required (op={op}, escalated={escalated}): {reason}"
	case "gate.approval_pending_missing":
		return "no matching pending approval challenge found"
	case "gate.approval_round2_mismatch":
		return "round-2 approval submission does not match pending challenge"
	case "gate.abstract_capability":
		return "WithAuthorized requires a concrete Capability type"
	case "gate.invalid_clock_time":
		return "clock returned an invalid timestamp"
	case "sshnet.priv.handshake_ended_before_ready":
		return "sshnet/priv: remote stream ended before privilege ready frame arrived"
	case "sshnet.probe.failed":
		return "sshnet/probe: remote shell probe failed or produced untrusted result"
	case "sshnet.dial.parent_required":
		return "multi-hop connection requires an active parent hop connection"
	case "sshnet.dial.no_auth_methods":
		return "no usable SSH authentication method could be built"
	case "sshnet.dial.empty_algo_intersection":
		return "no common SSH algorithm between policy and transport"
	case "sshnet.dial.challenge_unmatched":
		return "keyboard-interactive prompt {prompt} matched no automatic rule and interaction is unavailable"
	case "sshnet.dial.challenge_cmd_failed":
		return "challenge response command failed"
	case "sshnet.dial.totp_invalid":
		return "invalid TOTP configuration or secret"
	case "sshnet.dial.tcp_failed":
		return "TCP dial to {addr} failed"
	case "sshnet.dial.direct_tcpip_failed":
		return "failed to open direct-tcpip channel via parent hop"
	case "sshnet.keysigner.passphrase_required":
		return "private key is encrypted and no bound passphrase secret is configured"
	case "sshnet.keysigner.fingerprint_mismatch":
		return "private key fingerprint does not match KeyPassphraseBinding"
	case "sshnet.keysigner.no_keys_found":
		return "no usable local private key found"
	case "sshnet.keysigner.not_found":
		return "no signer found for key fingerprint {fingerprint}"
	case "sshnet.keysigner.invalid_cert":
		return "file {path} is not a valid SSH certificate"
	case "sshnet.forward.non_loopback_denied":
		return "binding non-loopback address {addr} requires GatewayPorts"
	case "sshnet.forward.socks5_header":
		return "invalid SOCKS5 protocol header"
	case "sshnet.forward.socks5_no_auth":
		return "SOCKS5 client does not support no-auth method"
	case "sshnet.forward.socks5_cmd_rejected":
		return "SOCKS5 only supports CONNECT, rejected command {cmd}"
	case "sshnet.hostkey.cert_tofu_forbidden":
		return "cannot record raw SSH host certificate {key} via TOFU"
	case "sshnet.hostkey.line_malformed":
		return "malformed known_hosts entry: {reason}"
	case "sshnet.mux.ext_not_negotiated":
		return "ControlMaster did not negotiate xops-stream-mux extension"
	case "sshnet.mux.proto_version":
		return "unsupported PROTOCOL.mux version {version} (only v4 is supported)"
	case "sshnet.mux.unexpected_frame":
		return "unexpected PROTOCOL.mux frame type {actual} (expected {expected})"
	case "sshnet.mux.frame_truncated":
		return "truncated PROTOCOL.mux frame"
	case "sshnet.mux.pty_size_invalid":
		return "PTY dimensions {cols}x{rows} are out of range"
	case "sshnet.priv.dialect_posix_only":
		return "privilege escalation only supports POSIX dialect (rejected {dialect})"
	case "sshnet.priv.handshake_timeout":
		return "timed out waiting for remote privilege escalation handshake"
	case "sshnet.priv.password_required":
		return "remote privilege escalation requires a password"
	case "sshnet.priv.auth_rejected":
		return "remote privilege escalation authentication rejected"
	case "sshnet.probe.no_dialect":
		return "stage 1 failed to detect a supported launch dialect"
	case "sshnet.probe.no_interpreter":
		return "stage 2 found no compatible interpreter for dialect {dialect}"
	case "sshnet.probe.frame_invalid":
		return "invalid or incomplete stage 2 probe frame"
	case "sshnet.sftp.status_code":
		return "sftp: status={code}"
	case "sshnet.sftp.status_code_detail":
		return "sftp: status={code} ({detail})"
	case "sshnet.sftp.proto_version":
		return "unsupported SFTP protocol version {version} (only v3 is supported)"
	case "sshnet.sftp.unexpected_packet":
		return "unexpected SFTP packet type {actual} (expected {expected})"
	case "sshnet.sftp.packet_truncated":
		return "truncated or malformed SFTP packet"
	case "sshnet.sftp.not_symlink":
		return "{path} is not a symbolic link"
	default:
		return ""
	}
}

func keysRuntime() []string {
	return []string{
		"pool.not_initialized",
		"pool.invalid_config",
		"pool.closed",
		"pool.gate_halted",
		"pool.nil_context",
		"pool.nil_callback",
		"pool.invalid_plan",
		"pool.empty_plan_list",
		"pool.capacity_exceeded",
		"pool.parent_epoch_changed",
		"pool.invalid_transport_conn",
		"pool.lease_invalid",
		"pool.lease_expired",
		"pool.lease_revoked",
		"pool.hop_retired",
		"pool.teardown_escalated",
		"pool.invalid_resource",
		"pool.invalid_handle",
		"pool.handle_not_found",
		"pool.handle_revoked",
		"pool.handle_generation_mismatch",
		"pool.handle_binding_mismatch",
		"pool.handle_type_mismatch",
		"pool.handle_limit_exceeded",
		"pool.fast_path_miss",
		"gate.nil_context",
		"gate.nil_authorizer",
		"gate.nil_callback",
		"gate.invalid_config",
		"gate.invalid_policy",
		"gate.invalid_profile",
		"gate.invalid_fallback",
		"gate.invalid_request",
		"gate.invalid_outcome",
		"gate.capability_mismatch",
		"gate.not_initialized",
		"gate.halted",
		"gate.invalid_permit",
		"gate.permit_revoked",
		"gate.authorization_denied",
		"gate.approval_required",
		"gate.approval_rejected",
		"gate.approval_expired",
		"gate.approval_replayed",
		"gate.approval_mismatch",
		"gate.approval_invalidated",
		"gate.pending_limit_exceeded",
		"gate.scope_escalated",
		"gate.audit_stage_failed",
		"gate.audit_pre_write_failed",
		"gate.audit_unstage_failed",
		"gate.reconciler_unavailable",
		"gate.operation_panicked",
		"gate.operation_aborted",
		"gate.execution_outcome",
		"gate.operation_panicked_detail",
		"gate.approval_challenge_detail",
		"gate.approval_pending_missing",
		"gate.approval_round2_mismatch",
		"gate.abstract_capability",
		"gate.invalid_clock_time",
		"sshnet.priv.handshake_ended_before_ready",
		"sshnet.probe.failed",
		"sshnet.dial.parent_required",
		"sshnet.dial.no_auth_methods",
		"sshnet.dial.empty_algo_intersection",
		"sshnet.dial.challenge_unmatched",
		"sshnet.dial.challenge_cmd_failed",
		"sshnet.dial.totp_invalid",
		"sshnet.dial.tcp_failed",
		"sshnet.dial.direct_tcpip_failed",
		"sshnet.keysigner.passphrase_required",
		"sshnet.keysigner.fingerprint_mismatch",
		"sshnet.keysigner.no_keys_found",
		"sshnet.keysigner.not_found",
		"sshnet.keysigner.invalid_cert",
		"sshnet.forward.non_loopback_denied",
		"sshnet.forward.socks5_header",
		"sshnet.forward.socks5_no_auth",
		"sshnet.forward.socks5_cmd_rejected",
		"sshnet.hostkey.cert_tofu_forbidden",
		"sshnet.hostkey.line_malformed",
		"sshnet.mux.ext_not_negotiated",
		"sshnet.mux.proto_version",
		"sshnet.mux.unexpected_frame",
		"sshnet.mux.frame_truncated",
		"sshnet.mux.pty_size_invalid",
		"sshnet.priv.dialect_posix_only",
		"sshnet.priv.handshake_timeout",
		"sshnet.priv.password_required",
		"sshnet.priv.auth_rejected",
		"sshnet.probe.no_dialect",
		"sshnet.probe.no_interpreter",
		"sshnet.probe.frame_invalid",
		"sshnet.sftp.status_code",
		"sshnet.sftp.status_code_detail",
		"sshnet.sftp.proto_version",
		"sshnet.sftp.unexpected_packet",
		"sshnet.sftp.packet_truncated",
		"sshnet.sftp.not_symlink",
	}
}
