package runtime

// lookupSSHNet 返回 core/internal/sshnet/** 全部哨兵与协议上下文键的规范英文兜底模板；未命中返回空串。
func lookupSSHNet(id string) string {
	switch id {
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
	case "sshnet.dial.read_password_failed":
		return "failed to read password secret"
	case "sshnet.dial.login_password_unavailable":
		return "login password secret or SecretVault is not configured"
	case "sshnet.dial.proxy_cmd_expand_failed":
		return "failed to expand ProxyCommand tokens"
	case "sshnet.dial.proxy_cmd_parse_failed":
		return "failed to parse ProxyCommand"
	case "sshnet.dial.proxy_cmd_start_failed":
		return "failed to start ProxyCommand"
	case "sshnet.dial.proxy_cmd_unclosed_quote":
		return "ProxyCommand contains an unclosed quote"
	case "sshnet.dial.hostkey_record_failed":
		return "failed to record host key to known_hosts"
	case "sshnet.dial.unknown_host_trust_status":
		return "unknown host key verification status: {status}"
	case "sshnet.dial.subsystem_unsupported":
		return "SSH subsystem {subsystem} is not supported"
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
	case "sshnet.keysigner.read_key_failed":
		return "failed to read private key {target}"
	case "sshnet.keysigner.parse_key_failed":
		return "failed to parse private key"
	case "sshnet.keysigner.decrypt_key_failed":
		return "failed to decrypt encrypted private key"
	case "sshnet.keysigner.read_cert_failed":
		return "failed to read SSH certificate {target}"
	case "sshnet.keysigner.parse_cert_failed":
		return "failed to parse SSH certificate {target}"
	case "sshnet.keysigner.resolve_home_failed":
		return "failed to resolve user home directory"
	case "sshnet.keysigner.parse_pubkey_failed":
		return "failed to parse public key"
	case "sshnet.keysigner.sign_failed":
		return "failed to sign SSH data with private key"
	case "sshnet.forward.non_loopback_denied":
		return "binding non-loopback address {addr} requires GatewayPorts"
	case "sshnet.forward.socks5_header":
		return "invalid SOCKS5 protocol header"
	case "sshnet.forward.socks5_no_auth":
		return "SOCKS5 client does not support no-auth method"
	case "sshnet.forward.socks5_cmd_rejected":
		return "SOCKS5 only supports CONNECT, rejected command {cmd}"
	case "sshnet.forward.direction_unsupported":
		return "unsupported forward direction {direction}"
	case "sshnet.forward.listen_tcp_failed":
		return "failed to listen on local TCP address {addr}"
	case "sshnet.forward.listen_socks5_failed":
		return "failed to listen on local SOCKS5 address {addr}"
	case "sshnet.forward.socks5_atyp_unsupported":
		return "unsupported SOCKS5 address type {atyp}"
	case "sshnet.forward.bind_addr_invalid":
		return "invalid bind address {addr}"
	case "sshnet.forward.bind_port_invalid":
		return "invalid bind port {port}"
	case "sshnet.forward.target_addr_invalid":
		return "invalid forwarding target address or path"
	case "sshnet.forward.socks5_domain_invalid":
		return "invalid SOCKS5 target domain {domain}"
	case "sshnet.hostkey.cert_tofu_forbidden":
		return "cannot record raw SSH host certificate {key} via TOFU"
	case "sshnet.hostkey.line_malformed":
		return "malformed known_hosts entry: {reason}"
	case "sshnet.hostkey.reason.bad_marker":
		return "invalid marker"
	case "sshnet.hostkey.reason.missing_host":
		return "missing host field"
	case "sshnet.hostkey.reason.missing_alg":
		return "missing algorithm field"
	case "sshnet.hostkey.reason.missing_key":
		return "missing public key field"
	case "sshnet.hostkey.reason.bad_key_base64":
		return "invalid base64 public key"
	case "sshnet.hostkey.reason.malformed_hash":
		return "malformed hashed host field"
	case "sshnet.hostkey.reason.bad_hash_salt":
		return "invalid hashed host salt"
	case "sshnet.hostkey.reason.bad_hash_digest":
		return "invalid hashed host digest"
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
	case "sshnet.mux.remote_error":
		return "mux: remote error: {detail}"
	case "sshnet.mux.control_action_unsupported":
		return "unsupported ControlMaster action {action}"
	case "sshnet.mux.tun_dynamic_unsupported":
		return "ControlMaster does not support dynamic TUN forwarding"
	case "sshnet.mux.handshake_failed":
		return "PROTOCOL.mux handshake failed"
	case "sshnet.mux.alive_check_failed":
		return "ControlMaster alive check failed"
	case "sshnet.mux.session_check_failed":
		return "ControlMaster handshake or alive check failed"
	case "sshnet.mux.raw_subsystem_unsupported":
		return "ControlMaster does not support raw subsystem {subsystem}"
	case "sshnet.mux.packet_too_large":
		return "PROTOCOL.mux outbound packet size {size} exceeds limit {limit}"
	case "sshnet.priv.dialect_posix_only":
		return "privilege escalation only supports POSIX dialect (rejected {dialect})"
	case "sshnet.priv.handshake_timeout":
		return "timed out waiting for remote privilege escalation handshake"
	case "sshnet.priv.password_required":
		return "remote privilege escalation requires a password"
	case "sshnet.priv.auth_rejected":
		return "remote privilege escalation authentication rejected"
	case "sshnet.priv.token_gen_failed":
		return "failed to generate privilege handshake tokens"
	case "sshnet.priv.build_cmd_failed":
		return "failed to build privilege escalation command"
	case "sshnet.priv.quote_arg_failed":
		return "failed to quote privilege escalation argument"
	case "sshnet.priv.method_unsupported":
		return "unsupported privilege escalation method {method}"
	case "sshnet.priv.write_password_failed":
		return "failed to write privilege escalation password"
	case "sshnet.probe.no_dialect":
		return "stage 1 failed to detect a supported launch dialect"
	case "sshnet.probe.no_interpreter":
		return "stage 2 found no compatible interpreter for dialect {dialect}"
	case "sshnet.probe.frame_invalid":
		return "invalid or incomplete stage 2 probe frame"
	case "sshnet.probe.stage2_dialect_unsupported":
		return "stage 2 shell probe is not supported for dialect {dialect}"
	case "sshnet.probe.stage2_enum_failed":
		return "stage 2 interpreter enumeration failed for dialect {dialect}"
	case "sshnet.probe.output_limit":
		return "remote shell probe output size {size} exceeds limit {limit}"
	case "sshnet.probe.session_start_failed":
		return "failed to start remote shell probe session ({code})"
	case "sshnet.probe.session_exec_failed":
		return "remote shell probe session execution failed ({code})"
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
	case "sshnet.sftp.temp_suffix_failed":
		return "failed to generate remote temporary filename suffix"
	case "sshnet.sftp.dir_not_empty":
		return "remote directory {path} is not empty or cannot be removed"
	case "sshnet.sftp.dir_entries_limit":
		return "remote directory entry count {count} exceeds limit {limit}"
	case "sshnet.sftp.remote_size_limit":
		return "remote file or stream size {size} exceeds limit {limit}"
	default:
		return ""
	}
}

func keysSSHNet() []string {
	return []string{
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
		"sshnet.dial.read_password_failed",
		"sshnet.dial.login_password_unavailable",
		"sshnet.dial.proxy_cmd_expand_failed",
		"sshnet.dial.proxy_cmd_parse_failed",
		"sshnet.dial.proxy_cmd_start_failed",
		"sshnet.dial.proxy_cmd_unclosed_quote",
		"sshnet.dial.hostkey_record_failed",
		"sshnet.dial.unknown_host_trust_status",
		"sshnet.dial.subsystem_unsupported",
		"sshnet.keysigner.passphrase_required",
		"sshnet.keysigner.fingerprint_mismatch",
		"sshnet.keysigner.no_keys_found",
		"sshnet.keysigner.not_found",
		"sshnet.keysigner.invalid_cert",
		"sshnet.keysigner.read_key_failed",
		"sshnet.keysigner.parse_key_failed",
		"sshnet.keysigner.decrypt_key_failed",
		"sshnet.keysigner.read_cert_failed",
		"sshnet.keysigner.parse_cert_failed",
		"sshnet.keysigner.resolve_home_failed",
		"sshnet.keysigner.parse_pubkey_failed",
		"sshnet.keysigner.sign_failed",
		"sshnet.forward.non_loopback_denied",
		"sshnet.forward.socks5_header",
		"sshnet.forward.socks5_no_auth",
		"sshnet.forward.socks5_cmd_rejected",
		"sshnet.forward.direction_unsupported",
		"sshnet.forward.listen_tcp_failed",
		"sshnet.forward.listen_socks5_failed",
		"sshnet.forward.socks5_atyp_unsupported",
		"sshnet.forward.bind_addr_invalid",
		"sshnet.forward.bind_port_invalid",
		"sshnet.forward.target_addr_invalid",
		"sshnet.forward.socks5_domain_invalid",
		"sshnet.hostkey.cert_tofu_forbidden",
		"sshnet.hostkey.line_malformed",
		"sshnet.hostkey.reason.bad_marker",
		"sshnet.hostkey.reason.missing_host",
		"sshnet.hostkey.reason.missing_alg",
		"sshnet.hostkey.reason.missing_key",
		"sshnet.hostkey.reason.bad_key_base64",
		"sshnet.hostkey.reason.malformed_hash",
		"sshnet.hostkey.reason.bad_hash_salt",
		"sshnet.hostkey.reason.bad_hash_digest",
		"sshnet.mux.ext_not_negotiated",
		"sshnet.mux.proto_version",
		"sshnet.mux.unexpected_frame",
		"sshnet.mux.frame_truncated",
		"sshnet.mux.pty_size_invalid",
		"sshnet.mux.remote_error",
		"sshnet.mux.control_action_unsupported",
		"sshnet.mux.tun_dynamic_unsupported",
		"sshnet.mux.handshake_failed",
		"sshnet.mux.alive_check_failed",
		"sshnet.mux.session_check_failed",
		"sshnet.mux.raw_subsystem_unsupported",
		"sshnet.mux.packet_too_large",
		"sshnet.priv.dialect_posix_only",
		"sshnet.priv.handshake_timeout",
		"sshnet.priv.password_required",
		"sshnet.priv.auth_rejected",
		"sshnet.priv.token_gen_failed",
		"sshnet.priv.build_cmd_failed",
		"sshnet.priv.quote_arg_failed",
		"sshnet.priv.method_unsupported",
		"sshnet.priv.write_password_failed",
		"sshnet.probe.no_dialect",
		"sshnet.probe.no_interpreter",
		"sshnet.probe.frame_invalid",
		"sshnet.probe.stage2_dialect_unsupported",
		"sshnet.probe.stage2_enum_failed",
		"sshnet.probe.output_limit",
		"sshnet.probe.session_start_failed",
		"sshnet.probe.session_exec_failed",
		"sshnet.sftp.status_code",
		"sshnet.sftp.status_code_detail",
		"sshnet.sftp.proto_version",
		"sshnet.sftp.unexpected_packet",
		"sshnet.sftp.packet_truncated",
		"sshnet.sftp.not_symlink",
		"sshnet.sftp.temp_suffix_failed",
		"sshnet.sftp.dir_not_empty",
		"sshnet.sftp.dir_entries_limit",
		"sshnet.sftp.remote_size_limit",
	}
}
