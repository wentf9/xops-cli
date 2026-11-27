# Troubleshooting

This guide covers the most common operational errors in XOps v2 across configuration, vaults, guardrails, audit circuit breaking, MCP sandboxing, SFTP/SCP transfers, and ControlMaster multiplexing.

## 1. Configuration Rejected (`version: 2`, Unknown Fields, or Permissions)

- **Symptom**: Errors mentioning unsupported schema version, unknown YAML fields, trailing documents, or unsafe directory permissions.
- **Cause & Fix**:
  1. XOps v2 reads `~/.xops/config.yaml` (override with `XOPS_HOME`) using strict **`version: 2`** and `KnownFields(true)`. Legacy v1 `xops_config.yaml` and plaintext password keys are never supported.
  2. Validate field names against the [Config Schema v2 Reference](../reference/config), or rebuild inventory via `xops config import --format openssh|csv`.
  3. Ensure `~/.xops` has owner-only permissions (`0700` on Unix, protected Owner-Only DACL on Windows), and never place `policy.guardrail.audit_log` directly in the bare `$HOME` directory.

## 2. `AuthPrivateKey` Fails with `ErrSignerUnavailable` Under MCP

- **Symptom**: A node connects normally with `xops ssh` using a local private key file, but fails under `xops mcp serve` with `ErrSignerUnavailable`.
- **Cause**: MCP mode physically sets **`OperatorReadFS == nil`** to prevent reading arbitrary host files (including `~/.ssh/id_ed25519`).
- **Fix**:
  1. Load your private key into **`ssh-agent`** (`ssh-add ~/.ssh/id_ed25519` on Unix with `SSH_AUTH_SOCK` exported to the MCP process; on Windows, start the `ssh-agent` service so `\\.\pipe\openssh-ssh-agent` is active and run `ssh-add`).
  2. Configure the node's Identity as `kind: agent` (or include `agent` in a `composite` auth chain).

## 3. Vault Locked, Uninitialized, or Linux Secret Service Unavailable

- **Diagnose**:

  ```bash
  xops creds status --json
  xops doctor --json
  ```

- **Offline Vault (`offline_aead`)**:
  - `Uninitialized`: Run `xops creds init` (**never delete `vault.meta.json` and re-init over existing `items/*.enc` files**).
  - `Locked`: Offline vault unlock lives only in process memory; for unattended batch runs or MCP, use `os_keychain`, `external_helper`, or `ssh-agent`.
- **Linux `os_keychain`**: Requires an active D-Bus user session (`DBUS_SESSION_BUS_ADDRESS`) and a running Secret Service daemon (GNOME Keyring / KWallet). In headless SSH/container environments, switch to `offline_aead` or `external_helper`.

## 4. `outcome_unknown` (`do_not_retry: true`) or `uncertain_durability`

- **Symptom**: Execution exits `255` with `OutcomeUnknown` / `do_not_retry: true`, or a `xops creds` saga returns `uncertain_durability: true`.
- **Rule (Never Blindly Retry)**:
  1. **Remote `OutcomeUnknown`**: The command may already have taken effect before the channel dropped. Verify remote state with read-only checks (`xops sftp stat`, read-only `xops exec`) and `xops audit tail` before deciding whether to re-run.
  2. **Vault `UncertainDurability` (`Applied && !Durable`)**: Do not retry or delete old/new credentials automatically. Run `xops creds doctor` and `xops hosts list` to verify what persisted on disk, then clean up safely with `xops creds gc`.

## 5. `strict_agent` Triggers `engine_halted` (`SECURITY GATE HALTED`)

- **Symptom**: MCP endpoints return HTTP `503` (`code: "gate_halted"`), or CLI/TUI reports `engine_halted`.
- **Cause**: Under `strict_agent`, a post-write failure to `audit.jsonl` (disk full, permission change, or corrupted directory) irreversibly halts the Engine and revokes all active managed handles.
- **Fix**:
  1. Check free disk space and permissions on `~/.xops/` and `audit.jsonl`.
  2. Run `xops audit reconcile --json` to reconcile stale locks and inspect recent events via `xops audit tail --limit 20`.
  3. Restart the MCP server / Engine process once underlying storage health is restored.

## 6. Host Key Verification Failures (`host_key_unknown` / `host_key_mismatch` / `host_key_revoked`)

- Under non-interactive batch, Playbook, or MCP runs, default `StrictHostKeyChecking=ask` fails closed on unknown host keys (`host_key_unknown`). Verify the fingerprint once via interactive `xops ssh <target>` to record it in `known_hosts`.
- On `host_key_mismatch` or `host_key_revoked`, verify whether the server was legitimately rebuilt before updating `known_hosts`; never disable host-key checks blindly.

## 7. SFTP / SCP Symlink Rejection, Anchor Mismatch, or Transfer Recovery

- **`symlink_rejected`**: Downloads and recursive uploads (`scp -r`) reject escaping symlinks by default; only single-file uploads may opt into `--symlink-policy follow_operator_source`, while downloads allow only `reject` or `contained_relative`.
- **`remote_anchor_mismatch` / `patch_conflict`**: The remote file's type or `(dev, ino)` changed during `sftp patch` or atomic write; re-read the file and re-apply your edit cleanly.
- **Interrupted Transfers**: Run `xops sftp recover --json` to inspect dual-generation WAL journals. Resume healthy pending transfers with `scp --resume` or MCP `transfer` `resume`; inspect remote digests manually before touching any `TransferUncertainCommit` entry.

## 8. ControlMaster Socket Issues or Daemon Exit

- Probe an existing control socket with `xops mux check -S <socket> <target>`; starting a new master via `xops mux start` automatically probes and cleans stale sockets left by crashed masters.
- If `xops ssh -f` or `xops mux daemon` exits immediately, verify that neither `ControlMaster=ask/autoask` nor interactive password prompts are required—daemon mode has no interactive stdin and fails closed rather than hanging.
