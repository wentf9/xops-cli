package common

import "slices"

// Lookup 返回i18n 基础设施、通用错误与交互提示键对应的规范英文兜底模板；未命中返回空串。
func Lookup(id string) string {
	switch id {
	case "i18n.locale.invalid":
		return "i18n: invalid locale"
	case "i18n.locale.invalid_value":
		return "i18n: invalid locale {value}"
	case "i18n.param.invalid":
		return "i18n: invalid message parameter"
	case "i18n.param.invalid_key":
		return "i18n: invalid parameter key {key}"
	case "i18n.param.invalid_kind":
		return "i18n: invalid parameter kind {kind}"
	case "i18n.param.invalid_value":
		return "i18n: invalid parameter value for {key}"
	case "i18n.param.depth_exceeded":
		return "i18n: nested message depth exceeds maximum {max}"
	case "i18n.message.invalid":
		return "i18n: invalid message"
	case "i18n.message.too_many_params":
		return "i18n: message parameter count exceeds maximum {max}"
	case "i18n.message.duplicate_param":
		return "i18n: duplicate parameter key {key}"
	case "i18n.template.invalid":
		return "i18n: invalid message template"
	case "i18n.template.unclosed":
		return "i18n: unclosed placeholder in message template"
	case "i18n.template.unescaped_brace":
		return "i18n: unescaped closing brace in message template"
	case "i18n.template.invalid_key":
		return "i18n: invalid placeholder key {key}"
	case "i18n.nil_receiver":
		return "i18n: unmarshal target receiver must not be nil"
	case "common.nil_context":
		return "context must not be nil"
	case "common.not_initialized":
		return "component is not initialized"
	case "common.invalid_argument":
		return "invalid argument"
	case "common.limit_exceeded":
		return "limit exceeded"
	case "common.nil_callback":
		return "callback must not be nil"
	case "common.not_found":
		return "resource not found"
	case "common.already_exists":
		return "resource already exists"
	case "common.canceled":
		return "operation canceled"
	case "common.timeout":
		return "operation timed out"
	case "common.permission_denied":
		return "permission denied"
	case "common.internal_error":
		return "internal error"
	case "common.error_join":
		return "{head}: {tail}"
	case "common.field_required":
		return "{field} is required"
	case "common.field_invalid":
		return "invalid {field}: {value}"
	case "common.field_value_invalid":
		return "{field} is invalid"
	case "common.field_empty":
		return "{field} must not be empty"
	case "common.field_positive":
		return "{field} must be positive"
	case "common.field_negative":
		return "{field} cannot be negative"
	case "common.field_range":
		return "{field} value {value} is out of range [{min}, {max}]"
	case "common.field_max_exceeded":
		return "{field} value {value} exceeds maximum {max}"
	case "common.field_nil":
		return "{field} must not be nil"
	case "common.index_invalid":
		return "{field}[{index}] is invalid"
	case "common.index_value_invalid":
		return "{field}[{index}] value {value} is invalid"
	case "common.duplicate_item":
		return "duplicate {kind}: {value}"
	case "common.mismatch":
		return "{field} mismatch: expected {expected}, got {actual}"
	case "common.state_forbidden":
		return "cannot {action} in state {state}"
	case "common.unknown_value":
		return "unknown {kind}: {value}"
	case "common.value_invalid":
		return "invalid value: {value}"
	case "common.op_failed":
		return "{op} failed"
	case "common.op_target_failed":
		return "{op} failed for {target}"
	case "common.path_forbidden":
		return "path {path} is rejected: {reason}"
	case "common.not_supported":
		return "{feature} is not supported"
	case "common.missing_dep":
		return "{component} is required"
	case "common.component_closed":
		return "{component} is not initialized or already closed"
	case "common.count_limit":
		return "{kind} count {count} exceeds limit {limit}"
	case "common.size_limit":
		return "{kind} size {size} exceeds limit {limit}"
	case "common.json_null_forbidden":
		return "JSON null is not a valid value"
	case "common.json_trailing_data":
		return "unexpected trailing JSON content"
	case "common.json_missing_field":
		return "missing required field {field}"
	case "common.json_variant_invalid":
		return "invalid field combination for variant {variant}"
	case "common.mutually_exclusive":
		return "{first} and {second} are mutually exclusive"
	case "common.one_of_required":
		return "exactly one of {options} must be specified"
	case "common.invalid_text_chars":
		return "{field} is too long or contains invalid UTF-8 or control characters"
	case "common.invalid_utf8":
		return "input contains invalid UTF-8"
	case "common.base64_decode_failed":
		return "base64 decoding failed"
	case "common.zero_entropy":
		return "entropy source returned all-zero bytes"
	case "common.perm_invalid":
		return "invalid file permission mode {perm}"
	case "common.either_missing_dep":
		return "{first} or {second} is required"
	case "common.unsupported_variant":
		return "unsupported {type} variant"
	case "common.id_gen_failed":
		return "failed to generate {kind}"
	case "common.path_template_failed":
		return "failed to expand path template {target}"
	case "common.detail":
		return "{detail}"
	case "interact.hostkey.title":
		return "SSH Host Key Verification"
	case "interact.hostkey.body":
		return "Trust unknown SSH host key {algorithm} ({fingerprint}) for {endpoint}?"
	case "interact.ssh_challenge.title":
		return "SSH Challenge"
	case "interact.ssh_challenge.response":
		return "Response:"
	case "interact.ssh_challenge.banner_response":
		return "{banner} | Response:"
	case "interact.enroll_key.title":
		return "Private Key Passphrase"
	case "interact.enroll_key.body":
		return "Enter passphrase for encrypted private key"
	case "interact.privilege.title":
		return "Privilege Escalation"
	case "interact.privilege.body":
		return "Enter {method} password for {node}"
	case "interact.mux.confirm_title":
		return "ControlMaster Confirmation"
	case "interact.mux.start_body":
		return "Start ControlMaster listener"
	case "interact.mux.reuse_body":
		return "Reuse active ControlMaster connection"
	case "interact.mux.attach_body":
		return "Attach to active ControlMaster via DialMux"
	default:
		return ""
	}
}

// AllKeys 返回本分片注册的全部消息键（按字典序升序排列，每次返回独立切片副本）。
func AllKeys() []string {
	keys := []string{
		"i18n.locale.invalid",
		"i18n.locale.invalid_value",
		"i18n.param.invalid",
		"i18n.param.invalid_key",
		"i18n.param.invalid_kind",
		"i18n.param.invalid_value",
		"i18n.param.depth_exceeded",
		"i18n.message.invalid",
		"i18n.message.too_many_params",
		"i18n.message.duplicate_param",
		"i18n.template.invalid",
		"i18n.template.unclosed",
		"i18n.template.unescaped_brace",
		"i18n.template.invalid_key",
		"i18n.nil_receiver",
		"common.nil_context",
		"common.not_initialized",
		"common.invalid_argument",
		"common.limit_exceeded",
		"common.nil_callback",
		"common.not_found",
		"common.already_exists",
		"common.canceled",
		"common.timeout",
		"common.permission_denied",
		"common.internal_error",
		"common.error_join",
		"common.field_required",
		"common.field_invalid",
		"common.field_value_invalid",
		"common.field_empty",
		"common.field_positive",
		"common.field_negative",
		"common.field_range",
		"common.field_max_exceeded",
		"common.field_nil",
		"common.index_invalid",
		"common.index_value_invalid",
		"common.duplicate_item",
		"common.mismatch",
		"common.state_forbidden",
		"common.unknown_value",
		"common.value_invalid",
		"common.op_failed",
		"common.op_target_failed",
		"common.path_forbidden",
		"common.not_supported",
		"common.missing_dep",
		"common.component_closed",
		"common.count_limit",
		"common.size_limit",
		"common.json_null_forbidden",
		"common.json_trailing_data",
		"common.json_missing_field",
		"common.json_variant_invalid",
		"common.mutually_exclusive",
		"common.one_of_required",
		"common.invalid_text_chars",
		"common.invalid_utf8",
		"common.base64_decode_failed",
		"common.zero_entropy",
		"common.perm_invalid",
		"common.either_missing_dep",
		"common.unsupported_variant",
		"common.id_gen_failed",
		"common.path_template_failed",
		"common.detail",
		"interact.hostkey.title",
		"interact.hostkey.body",
		"interact.ssh_challenge.title",
		"interact.ssh_challenge.response",
		"interact.ssh_challenge.banner_response",
		"interact.enroll_key.title",
		"interact.enroll_key.body",
		"interact.privilege.title",
		"interact.privilege.body",
		"interact.mux.confirm_title",
		"interact.mux.start_body",
		"interact.mux.reuse_body",
		"interact.mux.attach_body",
	}
	slices.Sort(keys)
	return keys
}
