package corecatalog

// 本文件收录 Wave 3B（core/ports、core/events、core/osfs 与 foundation/{actor,trace}）全部键的规范英文兜底模板。
func lookupPorts(id string) string {
	switch id {
	case "ports.nil_context":
		return "ports: context must not be nil"
	case "ports.nil_callback":
		return "ports: scoped callback must not be nil"
	case "ports.nil_receiver":
		return "ports: unmarshal receiver must not be nil"
	case "ports.invalid_argument":
		return "ports: invalid port argument"
	case "ports.unsupported":
		return "ports: operation is not supported by adapter"
	case "ports.closed":
		return "ports: port or session is closed"
	case "ports.not_found":
		return "ports: target resource not found"
	case "ports.already_exists":
		return "ports: target resource already exists"
	case "ports.permission_denied":
		return "ports: permission denied or rejected by policy"
	case "ports.limit_exceeded":
		return "ports: data exceeds safety size or count limit"
	case "ports.revision_conflict":
		return "ports: inventory revision CAS conflict"
	case "ports.corrupt_data":
		return "ports: persisted data is corrupt or failed integrity check"
	case "ports.invalid_revision":
		return "ports: invalid Revision"
	case "ports.invalid_durability":
		return "ports: invalid DurabilityOutcome"
	case "ports.invalid_lock_mode":
		return "ports: invalid LockMode"
	case "ports.invalid_read_limits":
		return "ports: invalid ReadLimits"
	case "ports.lock_busy":
		return "ports: file lock is held by another owner"
	case "ports.not_regular_file":
		return "ports: target path is not a regular file"
	case "ports.symlink_rejected":
		return "ports: symbolic link rejected by security policy"
	case "ports.handle_expired":
		return "ports: scoped handle has expired"
	case "ports.vault_locked":
		return "ports: secret vault is locked"
	case "ports.secret_not_found":
		return "ports: secret entry not found"
	case "ports.secret_verify_failed":
		return "ports: constant-time read-back verification failed after secret write"
	case "ports.host_key_mismatch":
		return "ports: remote host key fingerprint mismatches trust store"
	case "ports.host_key_unknown":
		return "ports: unknown remote host key rejected by policy"
	case "ports.host_key_revoked":
		return "ports: remote host key has been revoked"
	case "ports.signer_unavailable":
		return "ports: key signer or SSH agent is unavailable"
	case "ports.dial_failed":
		return "ports: failed to establish remote transport connection"
	case "ports.auth_failed":
		return "ports: remote authentication failed"
	case "ports.mux_unavailable":
		return "ports: multiplex control socket is unavailable"
	case "ports.remote_anchor_mismatch":
		return "ports: remote file FSTAT type or (dev,ino) anchor mismatch"
	case "ports.remote_is_dir":
		return "ports: remote target is a directory"
	case "ports.audit_write_failed":
		return "ports: audit log write failed"
	case "ports.audit_post_write":
		return "ports: audit post-write terminal record failed"
	case "ports.audit_halted":
		return "ports: audit gate entered Halted state"
	case "ports.invalid_audit_entry":
		return "ports: invalid AuditEntry"
	case "ports.invalid_process_instance_id":
		return "ports: invalid ProcessInstanceID"
	case "ports.interaction_unavailable":
		return "ports: user interaction is unavailable in current environment"
	case "ports.interaction_canceled":
		return "ports: user canceled or rejected interaction request"
	case "ports.entropy_short_read":
		return "ports: entropy source short read"
	case "ports.invalid_tty_size":
		return "ports: invalid TerminalSize"
	case "ports.audit_post_write_op":
		return "ports: audit post-write failed (op={op})"
	case "ports.prompt_msg_invalid":
		return "structured prompt message is invalid or exceeds safety bounds"
	case "ports.mod_time_out_of_range":
		return "modification time is outside RFC 3339 year bounds"
	case "ports.durability_spec":
		return "invalid durability outcome fields for status {status}"
	case "ports.tun_spec_conflict":
		return "ForwardTUN specification conflicts with bind_addr or target_addr"
	case "events.nil_context":
		return "events: context must not be nil"
	case "events.nil_receiver":
		return "events: unmarshal receiver must not be nil"
	case "events.nil_writer":
		return "events: output writer must not be nil"
	case "events.invalid_event":
		return "events: invalid event instance or variant fields"
	case "events.invalid_event_meta":
		return "events: invalid EventMeta"
	case "events.invalid_event_kind":
		return "events: invalid EventKind"
	case "events.invalid_event_class":
		return "events: invalid EventClass"
	case "events.invalid_backpressure":
		return "events: invalid BackpressurePolicy"
	case "events.invalid_severity":
		return "events: invalid Severity"
	case "events.invalid_output_stream":
		return "events: invalid OutputStreamKind"
	case "events.invalid_audit_stage":
		return "events: invalid AuditStage"
	case "events.invalid_pool_action":
		return "events: invalid PoolEventAction"
	case "events.invalid_diagnostic_scope":
		return "events: invalid DiagnosticScope"
	case "events.invalid_fsm_machine":
		return "events: invalid FSMMachineKind"
	case "events.unsupported_event_class":
		return "events: event class is not supported by this channel"
	case "events.operation_mismatch":
		return "events: event TraceID or OperationID mismatches stream binding"
	case "events.invalid_stream_config":
		return "events: invalid OperationStream configuration"
	case "events.stream_not_initialized":
		return "events: OperationStream is not initialized"
	case "events.stream_closed":
		return "events: OperationStream is closed"
	case "events.invalid_fold_func":
		return "events: Fold reducer function must not be nil"
	case "events.invalid_audit_config":
		return "events: invalid AuditDispatcher configuration"
	case "events.nil_audit_writer":
		return "events: AuditWriter must not be nil"
	case "events.audit_dispatcher_not_initialized":
		return "events: AuditDispatcher is not initialized"
	case "events.audit_halted":
		return "events: AuditDispatcher entered Halted state"
	case "events.audit_dispatch_failed":
		return "events: synchronous audit dispatch failed"
	case "events.invalid_bus_config":
		return "events: invalid SystemBus configuration"
	case "events.bus_not_initialized":
		return "events: SystemBus is not initialized"
	case "events.bus_closed":
		return "events: SystemBus is closed"
	case "events.bus_subscriber_limit":
		return "events: SystemBus subscriber limit reached"
	case "events.subscription_not_initialized":
		return "events: SystemSubscription is not initialized"
	case "events.class_mismatch":
		return "channel requires {expected} event, got {actual}"
	case "events.audit_conflict":
		return "audit stage {stage} conflicts with decision {decision}"
	case "events.outcome_conflict":
		return "event status conflicts with execution outcome"
	case "events.json_object_required":
		return "event JSON payload must be an object"
	case "osfs.slot_occupied":
		return "osfs: control socket slot is already occupied"
	case "osfs.not_socket":
		return "osfs: target path is not a local AF_UNIX socket"
	case "osfs.invalid_control_path":
		return "osfs: invalid control socket path"
	case "osfs.control_path_too_long":
		return "osfs: control socket path exceeds platform sun_path limit"
	case "osfs.unauthorized_peer":
		return "osfs: local AF_UNIX peer identity verification failed"
	case "osfs.unsupported_peer_cred":
		return "osfs: peer credential query is not supported on this platform"
	case "osfs.insecure_permissions":
		return "osfs: object permissions or DACL violate security invariants"
	case "osfs.same_file_mismatch":
		return "osfs: handle and path SameFile anchor mismatch"
	case "osfs.not_regular_file":
		return "{path} is not a regular file"
	case "osfs.not_directory":
		return "{path} is not a directory"
	case "osfs.symlink_detected":
		return "{path} is a symbolic link or reparse point"
	case "osfs.not_unix_socket":
		return "{path} is not a local AF_UNIX socket"
	case "osfs.peer_uid_mismatch":
		return "peer UID {actual} does not match current EUID {expected}"
	case "osfs.peer_sid_mismatch":
		return "peer process PID {pid} user SID is not trusted"
	case "osfs.named_pipe_invalid":
		return "invalid Windows named pipe path {path}"
	case "osfs.dacl_check_failed":
		return "{path} failed owner-only DACL verification"
	case "osfs.path_platform_mismatch":
		return "path {path} is not supported on this platform"
	case "osfs.lock_target_replaced":
		return "lock target {path} was concurrently replaced"
	case "osfs.append_newline":
		return "AppendLine input must not contain embedded newlines"
	case "osfs.stale_probe_failed":
		return "cannot confirm stale socket {path} (status={status})"
	case "actor.not_initialized":
		return "actor: DualActor is not initialized"
	case "actor.already_started":
		return "actor: DualActor is already running"
	case "actor.stopped":
		return "actor: DualActor has stopped"
	case "actor.invalid_config":
		return "actor: invalid DualActor configuration"
	case "actor.nil_context":
		return "actor: context must not be nil"
	case "trace.invalid_lease_scope":
		return "trace: invalid LeaseScope"
	case "trace.nil_context":
		return "trace: context must not be nil"
	case "trace.reentrant_lease":
		return "trace: active lease scope already present in context; reentrant lease acquisition is forbidden"
	case "trace.reentrant_detail":
		return "active lease scope already held (domain={domain}, lease={lease})"
	default:
		return ""
	}
}

func keysPorts() []string {
	return []string{
		"ports.nil_context",
		"ports.nil_callback",
		"ports.nil_receiver",
		"ports.invalid_argument",
		"ports.unsupported",
		"ports.closed",
		"ports.not_found",
		"ports.already_exists",
		"ports.permission_denied",
		"ports.limit_exceeded",
		"ports.revision_conflict",
		"ports.corrupt_data",
		"ports.invalid_revision",
		"ports.invalid_durability",
		"ports.invalid_lock_mode",
		"ports.invalid_read_limits",
		"ports.lock_busy",
		"ports.not_regular_file",
		"ports.symlink_rejected",
		"ports.handle_expired",
		"ports.vault_locked",
		"ports.secret_not_found",
		"ports.secret_verify_failed",
		"ports.host_key_mismatch",
		"ports.host_key_unknown",
		"ports.host_key_revoked",
		"ports.signer_unavailable",
		"ports.dial_failed",
		"ports.auth_failed",
		"ports.mux_unavailable",
		"ports.remote_anchor_mismatch",
		"ports.remote_is_dir",
		"ports.audit_write_failed",
		"ports.audit_post_write",
		"ports.audit_halted",
		"ports.invalid_audit_entry",
		"ports.invalid_process_instance_id",
		"ports.interaction_unavailable",
		"ports.interaction_canceled",
		"ports.entropy_short_read",
		"ports.invalid_tty_size",
		"ports.audit_post_write_op",
		"ports.prompt_msg_invalid",
		"ports.mod_time_out_of_range",
		"ports.durability_spec",
		"ports.tun_spec_conflict",
		"events.nil_context",
		"events.nil_receiver",
		"events.nil_writer",
		"events.invalid_event",
		"events.invalid_event_meta",
		"events.invalid_event_kind",
		"events.invalid_event_class",
		"events.invalid_backpressure",
		"events.invalid_severity",
		"events.invalid_output_stream",
		"events.invalid_audit_stage",
		"events.invalid_pool_action",
		"events.invalid_diagnostic_scope",
		"events.invalid_fsm_machine",
		"events.unsupported_event_class",
		"events.operation_mismatch",
		"events.invalid_stream_config",
		"events.stream_not_initialized",
		"events.stream_closed",
		"events.invalid_fold_func",
		"events.invalid_audit_config",
		"events.nil_audit_writer",
		"events.audit_dispatcher_not_initialized",
		"events.audit_halted",
		"events.audit_dispatch_failed",
		"events.invalid_bus_config",
		"events.bus_not_initialized",
		"events.bus_closed",
		"events.bus_subscriber_limit",
		"events.subscription_not_initialized",
		"events.class_mismatch",
		"events.audit_conflict",
		"events.outcome_conflict",
		"events.json_object_required",
		"osfs.slot_occupied",
		"osfs.not_socket",
		"osfs.invalid_control_path",
		"osfs.control_path_too_long",
		"osfs.unauthorized_peer",
		"osfs.unsupported_peer_cred",
		"osfs.insecure_permissions",
		"osfs.same_file_mismatch",
		"osfs.not_regular_file",
		"osfs.not_directory",
		"osfs.symlink_detected",
		"osfs.not_unix_socket",
		"osfs.peer_uid_mismatch",
		"osfs.peer_sid_mismatch",
		"osfs.named_pipe_invalid",
		"osfs.dacl_check_failed",
		"osfs.path_platform_mismatch",
		"osfs.lock_target_replaced",
		"osfs.append_newline",
		"osfs.stale_probe_failed",
		"actor.not_initialized",
		"actor.already_started",
		"actor.stopped",
		"actor.invalid_config",
		"actor.nil_context",
		"trace.invalid_lease_scope",
		"trace.nil_context",
		"trace.reentrant_lease",
		"trace.reentrant_detail",
	}
}
