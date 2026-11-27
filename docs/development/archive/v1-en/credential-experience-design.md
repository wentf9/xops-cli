# Zero-configuration credential experience

Status: decisions accepted and implemented in the working branch; final native acceptance and release pending. This document does not describe current binary behavior. Historical ADRs remain intact. These decisions replace the former defaults of no persistence, explicit initialization, and manual upgrades; they do not change the offline store v1 format contract.

## Goal and accepted decisions

Restore “download the binary, connect, and remember credentials after the first input”, prioritizing compatibility across Linux, Windows, and macOS.

| Area | Accepted behavior |
| --- | --- |
| Default backend | Use encrypted-file with key-file directly; do not probe system stores to choose a default |
| Advanced configuration | system, pass, and helper require manual selection; preserve existing explicit choices |
| Initialization | Prepare configuration, directories, store, and key-file on first persistence use, without an init command |
| Key files | Generate a missing key for a new store; validate and reuse existing keys; never overwrite invalid, unreadable, or mismatched keys |
| Remembered secrets | Login passwords, sudo/su passwords, and private-key passphrases, stored separately by purpose; never OTPs |
| User control | Provide per-invocation and global controls to disable saving; exact option names remain to be specified |
| Automatic upgrade | Copy and verify legacy credentials before switching references; retain legacy configuration and secret.key |

Both the default key and ciphertext reside locally. Protection depends on account and filesystem permissions; anyone obtaining both can decrypt. Master passphrases and other backends remain advanced options. Final user documentation must explain paths, permissions, and recovery materials.

A missing key for an existing store is a recovery failure, not an invitation to generate a replacement. Automatic generation applies only to confirmed new-store initialization. Interrupted initialization must reuse already generated material and never overwrite the original store.

## Connection, verification, and saving

First interactive use: confirm host fingerprint → enter authentication material → verify successfully → save automatically → read automatically on later connections. Persistence is not a prerequisite for a successful connection. A brief first-save notice is acceptable; routine connections must not add backend selection steps.

| Event | Behavior |
| --- | --- |
| Saving fails after a successful connection | Keep the connection; report that the secret was not saved and may be requested next time |
| Stored credential cannot be read | Allow temporary interactive input; do not overwrite damaged stores or keys, or silently switch backends |
| Server explicitly rejects password authentication | Allow interactive retry; update only after the new password succeeds, retaining the previous record on failure |
| Private-key decryption fails | Allow interactive retry; save or update only after actually decrypting the corresponding key |
| sudo/su verification fails | Follow the escalation interaction flow; save only after successful escalation verification, separately from login passwords |
| Network failure, timeout, or fingerprint error | Return the relevant error; do not classify it as an expired password or update credentials |
| Unattended execution lacks readable credentials | Return a clear error without waiting for input |

Final SSH connection success alone cannot validate an entered password or key passphrase: an agent, another key, or another method may have authenticated. Saving must be tied to the actual successful verification. Do not treat all keyboard-interactive responses as reusable passwords. Cancellation and timeouts must terminate retries; retry limits and integration with existing authentication policy need implementation design.

The accepted policy is that per-invocation `--remember never` or global `remember_prompted: never` disables automatic connection-credential creation/updates and automatic migration. Existing credentials remain readable; explicit credential-form submissions and migration commands remain available.

## Automatic upgrades and backend migration

Normal usage entry points encountering eligible legacy configuration prepare the destination, copy credentials, and verify reads before switching references after confirmed durable configuration publication. Read-only paths such as help, completion, doctor, and dry-run must not migrate merely by loading configuration. Use consistent triggers across entry points, not an SSH-only upgrade path.

Migration failure preserves usable legacy configuration and must not block the original connection flow. Retain legacy configuration, secret.key, and migration state for recovery. Interrupted work must be safely retryable without blindly rolling back committed state. Never finalize automatically: users validate real connections before explicit cleanup. Until cleanup, two copies remain and the legacy storage security boundary still applies.

Preserve manually selected backends. Automatic migration upgrades legacy configuration; it does not move credentials to the offline store when a selected backend is temporarily unavailable. Before implementing, inspect how existing v2 configuration distinguishes an unset backend from an explicit none choice so that upgrades preserve user intent.

Advanced users must be able to migrate automatically upgraded v2 offline credentials to another configured writable backend and back again. Flow: configure target → dry-run → explicit execution → read-back verification and reference switch → real connection validation → separate source cleanup. Preserve source data on failure. Changing the default backend is not equivalent to migrating existing references.

The v1 configuration migration command must not be presented as already supporting general v2 backend migration without implementation and testing. Define command, recovery, and cleanup semantics explicitly.

## Implementation boundaries

Reuse backup, read-back, journal, CAS, and durability mechanisms. Preserve separate secrets/references, permission checks, and recovery guarantees. Reusable packages return structured results and errors; composition roots such as CLI and TUI present prompts. Never expose secrets in configuration, logs, arguments, or errors.

Coverage includes CLI, TUI, SSH, SFTP/SCP, exec, Playbook, MCP, and task-specific identity overrides. Decide whether to prompt from actual interaction capability rather than command names alone. See the [implementation plan](./credential-experience-plan) and [release-note draft](./credential-experience-release).
