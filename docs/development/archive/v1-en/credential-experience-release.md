# Credential experience release-note draft

Status: implemented in the working branch; final native validation and release pending. This is not a claim about a released binary.

## Download, connect, and remember credentials

The target release uses the built-in offline credential store with an automatically generated key-file by default. No system credential backend configuration or initialization command is required. Login passwords, sudo/su passwords, and private-key passphrases are saved after their corresponding verification succeeds; one-time codes are never saved. Use `--remember never` or global `remember_prompted: never` to disable automatic saving and automatic migration.

Save errors do not terminate successful connections; a notice explains that the credential was not saved. Read failures allow temporary interactive input, while unattended execution returns an error. Default protection relies on local permissions; obtaining both key-file and ciphertext permits decryption.

## Upgrades automatically migrate legacy credentials

Normal usage entry points detect legacy configuration, prepare offline storage, copy and verify credentials, and then switch references without a preliminary manual migration command. Failure preserves usable legacy configuration. Existing manually chosen backends are not overridden.

Startup automatic migration always enforces the non-interactive boundary. It cannot open unlock prompts before MCP, Playbook, or other commands run. Stores requiring interaction produce a migration warning and preserve current configuration; explicit migration remains available.

Legacy configuration, secret.key, and migration recovery material are retained, not automatically deleted. Validate SSH, SFTP, exec, escalation, and automation before explicitly completing cleanup according to the final recovery instructions. The legacy security boundary remains until cleanup. Read-only commands do not trigger migration.

## Trying another backend

Add a system, pass, or helper destination to the existing configuration. Run `xops credential migrate --dry-run --to system`, then `xops credential migrate --to system`. References and the default store switch after read-back verification; the recording policy remains unchanged. Dry-run does not guarantee write access.

Return with `xops credential migrate --dry-run --to file` and `xops credential migrate --to file`. Existing key-files are reused. Rerun the original command after interruption. Concurrent edits are not overwritten; use `--restart` to archive the old plan and replan from current configuration.

Source credentials and configuration backups remain. `finalize-migration` only cleans v1 legacy material, not source credentials or v2 backups. See the [migration guide](../guide/migration) for configuration, recovery, and return examples. Local round-trip and fault-injection tests passed; actual system backend availability depends on local services. Final native validation remains pending.
