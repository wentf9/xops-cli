package usecase

// lookupDoctor 返回只读诊断 DoctorFinding（credential/doctor.go 与 inventory/import_doctor.go）的规范英文兜底模板。
func lookupDoctor(id string) string {
	switch id {
	case "uc.doctor.vault_unavailable":
		return "SecretVault is not configured; skipping read-only secret probe"
	case "uc.doctor.vault_status_failed":
		return "failed to query vault status"
	case "uc.doctor.vault_locked_skip":
		return "vault is locked; skipping read-only secret probe"
	case "uc.doctor.vault_uninitialized":
		return "vault is not initialized"
	case "uc.doctor.vault_state_invalid":
		return "vault returned invalid state"
	case "uc.doctor.store_load_graph_failed":
		return "failed to load inventory graph"
	case "uc.doctor.unknown_secret_store":
		return "{owner} ({location}) references unregistered secret store {store}"
	case "uc.doctor.secret_not_found":
		return "referenced secret entry is missing from vault"
	case "uc.doctor.vault_locked_probe":
		return "vault is locked; unable to probe secret entry"
	case "uc.doctor.secret_probe_failed":
		return "read-only secret probe failed"
	case "uc.doctor.pending_secret_pin":
		return "secret is pinned by pending enrollment lease to prevent GC: {owner}"
	case "uc.doctor.store_load_snapshot_failed":
		return "failed to load inventory store snapshot"
	case "uc.doctor.proxy_dag_invalid":
		return "cross-namespace ProxyJump DAG validation failed"
	case "uc.doctor.unused_host":
		return "Host is not referenced by any Node"
	case "uc.doctor.unused_identity":
		return "Identity is not referenced by any Node"
	case "uc.doctor.openssh_read_failed":
		return "failed to read OpenSSH read-only configuration"
	case "uc.doctor.openssh_alias_shadowed":
		return "managed node ID or alias shadows OpenSSH Host alias"
	case "uc.doctor.openssh_jump_invalid":
		return "invalid OpenSSH virtual host jump configuration"
	case "uc.doctor.key_signer_unavailable":
		return "KeySignerPort is not configured; skipping private key verification"
	case "uc.doctor.unknown_auth_method":
		return "identity uses an unknown or invalid authentication method"
	case "uc.doctor.private_key_inspect_failed":
		return "failed to verify private key ({path})"
	case "uc.doctor.private_key_fp_mismatch":
		return "encrypted private key fingerprint does not match configured binding"
	default:
		return ""
	}
}

func keysDoctor() []string {
	return []string{
		"uc.doctor.vault_unavailable",
		"uc.doctor.vault_status_failed",
		"uc.doctor.vault_locked_skip",
		"uc.doctor.vault_uninitialized",
		"uc.doctor.vault_state_invalid",
		"uc.doctor.store_load_graph_failed",
		"uc.doctor.unknown_secret_store",
		"uc.doctor.secret_not_found",
		"uc.doctor.vault_locked_probe",
		"uc.doctor.secret_probe_failed",
		"uc.doctor.pending_secret_pin",
		"uc.doctor.store_load_snapshot_failed",
		"uc.doctor.proxy_dag_invalid",
		"uc.doctor.unused_host",
		"uc.doctor.unused_identity",
		"uc.doctor.openssh_read_failed",
		"uc.doctor.openssh_alias_shadowed",
		"uc.doctor.openssh_jump_invalid",
		"uc.doctor.key_signer_unavailable",
		"uc.doctor.unknown_auth_method",
		"uc.doctor.private_key_inspect_failed",
		"uc.doctor.private_key_fp_mismatch",
	}
}
