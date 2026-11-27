package runtime

// lookupPoolGate 返回 pool 与 gate（含规范护栏原因封闭集）键对应的规范英文兜底模板；未命中返回空串。
func lookupPoolGate(id string) string {
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
	case "gate.unknown_approval_phase":
		return "gate: unexpected approval phase {phase}"
	case "gate.protected_path_check_failed":
		return "gate: protected path check failed"
	case "gate.approval_digest_mismatch":
		return "gate: approval response digest does not match envelope"
	case "gate.round2_canonicalize_required":
		return "gate: approval invalidated because Round-2 canonicalization callback is missing"
	case "gate.canonical_binding_invalid":
		return "gate: canonicalized operation binding is invalid or capability drifted"
	case "gate.reason.nil_decision":
		return "nil or uninitialized guardrail decision"
	case "gate.reason.empty_decisions":
		return "no guardrail decision evaluated"
	case "gate.reason.unknown_risk":
		return "operation risk level is unknown or invalid"
	case "gate.reason.invalid_threshold":
		return "approval threshold is unknown or invalid"
	case "gate.reason.risk_meets_threshold":
		return "operation risk meets or exceeds approval threshold"
	case "gate.reason.risk_below_threshold":
		return "operation risk is below approval threshold"
	case "gate.reason.invalid_overrides":
		return "node overrides set is uninitialized or invalid"
	case "gate.reason.node_override_allow":
		return "node override permits threshold evaluation"
	case "gate.reason.node_override_unknown_risk":
		return "node override approval floor with unknown risk"
	case "gate.reason.node_override_approval":
		return "node override requires explicit approval"
	case "gate.reason.node_override_deny":
		return "node override denies operation"
	case "gate.reason.lexical_verdict_denied":
		return "lexical verdict denied"
	case "gate.reason.lexical_guardrail_denied":
		return "lexical guardrail denied"
	case "gate.reason.invalid_lexical_decision":
		return "invalid lexical guardrail decision"
	case "gate.reason.round2_canon_failed":
		return "round2 canonicalization probe failed"
	case "gate.reason.canonical_binding_drifted":
		return "canonical identity or non-path binding drifted"
	case "gate.reason.round2_escalation_failed":
		return "round2 probe failed during escalation check"
	case "gate.reason.effective_verdict_denied":
		return "effective verdict denied"
	case "gate.reason.canonical_guardrail_denied":
		return "canonical guardrail denied"
	case "gate.reason.canonical_scope_escalated":
		return "canonical_scope_escalated"
	case "gate.reason.invalid_canonical_decision":
		return "invalid canonical guardrail decision"
	case "gate.reason.user_rejected":
		return "user rejected approval challenge"
	case "gate.reason.token_expired_or_mismatch":
		return "approval token expired or binding mismatch"
	case "gate.reason.token_digest_mismatch":
		return "approval token digest mismatch"
	case "gate.reason.round2_probe_failed":
		return "round2 probe failed"
	case "gate.reason.post_challenge_drift":
		return "post-challenge canonical scope escalated or binding drifted"
	case "gate.reason.invalid_profile":
		return "invalid policy profile"
	case "gate.reason.verdict_denied":
		return "security verdict denied"
	case "gate.reason.direct_operator_allow":
		return "direct operator profile allow"
	case "gate.reason.unexpected_decision":
		return "unexpected guardrail decision"
	case "gate.reason.protected_path":
		return "operation touches protected path"
	case "gate.reason.guardrail_denied":
		return "guardrail denied"
	case "gate.reason.canonical_denied":
		return "canonical denied"
	case "gate.reason.approval_required":
		return "approval required"
	case "gate.reason.scope_escalated":
		return "scope escalated"
	case "gate.reason.token_invalidated":
		return "token invalidated"
	case "gate.reason.authorization_denied":
		return "authorization denied"
	case "gate.reason.gate_halted":
		return "gate halted"
	case "gate.reason.privilege_escalation":
		return "privilege escalation requires approval"
	case "gate.reason.pre_escalation_baseline":
		return "pre-escalation baseline"
	case "gate.reason.invalid_audit_event":
		return "audit event is invalid"
	default:
		return ""
	}
}

func keysPoolGate() []string {
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
		"gate.unknown_approval_phase",
		"gate.protected_path_check_failed",
		"gate.approval_digest_mismatch",
		"gate.round2_canonicalize_required",
		"gate.canonical_binding_invalid",
		"gate.reason.nil_decision",
		"gate.reason.empty_decisions",
		"gate.reason.unknown_risk",
		"gate.reason.invalid_threshold",
		"gate.reason.risk_meets_threshold",
		"gate.reason.risk_below_threshold",
		"gate.reason.invalid_overrides",
		"gate.reason.node_override_allow",
		"gate.reason.node_override_unknown_risk",
		"gate.reason.node_override_approval",
		"gate.reason.node_override_deny",
		"gate.reason.lexical_verdict_denied",
		"gate.reason.lexical_guardrail_denied",
		"gate.reason.invalid_lexical_decision",
		"gate.reason.round2_canon_failed",
		"gate.reason.canonical_binding_drifted",
		"gate.reason.round2_escalation_failed",
		"gate.reason.effective_verdict_denied",
		"gate.reason.canonical_guardrail_denied",
		"gate.reason.canonical_scope_escalated",
		"gate.reason.invalid_canonical_decision",
		"gate.reason.user_rejected",
		"gate.reason.token_expired_or_mismatch",
		"gate.reason.token_digest_mismatch",
		"gate.reason.round2_probe_failed",
		"gate.reason.post_challenge_drift",
		"gate.reason.invalid_profile",
		"gate.reason.verdict_denied",
		"gate.reason.direct_operator_allow",
		"gate.reason.unexpected_decision",
		"gate.reason.protected_path",
		"gate.reason.guardrail_denied",
		"gate.reason.canonical_denied",
		"gate.reason.approval_required",
		"gate.reason.scope_escalated",
		"gate.reason.token_invalidated",
		"gate.reason.authorization_denied",
		"gate.reason.gate_halted",
		"gate.reason.privilege_escalation",
		"gate.reason.pre_escalation_baseline",
		"gate.reason.invalid_audit_event",
	}
}
