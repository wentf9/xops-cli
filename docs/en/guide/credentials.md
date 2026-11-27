# Credential Routing and Vault

XOps v2 enforces **zero plaintext secrets in config files and CLI flags**. `~/.xops/config.yaml` and import bundles store only `<store>/<item>` secret references (`SecretRef`). Actual secret bytes are routed through a multi-backend `RouterVault` and consumed exclusively inside single-goroutine scoped `SecretBox` closures that `clear()` buffers on exit.

## 1. Four Supported Vault Backends

Declare one or more named stores under `vault.stores` in `~/.xops/config.yaml` and select `vault.default_store`. If `vault.stores` is omitted, XOps automatically wires default `offline` (`offline_aead`) and `os_keychain` stores with `offline` as the default backend.

| `kind` | Implementation | Best For |
| --- | --- | --- |
| `offline_aead` | Built-in offline encrypted dirfd vault (Argon2id + XChaCha20-Poly1305 AEAD; see [Offline Encrypted Vault](./offline-store)) | Zero external dependencies on headless servers, containers, and air-gapped hosts |
| `os_keychain` | Native platform keychain (`CGO_ENABLED=0` pure Go):<br>- **Windows**: Windows Credential Manager (`CREDENTIALW`)<br>- **macOS**: `Security.framework` Keychain (`purego`)<br>- **Linux**: FreeDesktop Secret Service over D-Bus (`godbus`, DH AES-128-CBC with `plain` fallback)<br>- Other OSes (e.g. FreeBSD): returns `unsupported` | Desktop workstations needing seamless unlock across interactive and unattended runs |
| `external_helper` | Stdin/stdout JSON v2 subprocess protocol for external secret managers (`pass`, 1Password CLI, Bitwarden, corporate KMS wrappers) | Team-shared secret managers and enterprise KMS integration |
| `none` | Explicitly disabled slot; every read/write fails closed with `unsupported` | Pure `ssh-agent` or zero-stored-secret compliance environments |

### Multi-Backend Config Example (`~/.xops/config.yaml`)

```yaml
version: 2
vault:
  default_store: offline
  remember_prompted: ask # always | ask | never
  stores:
    offline:
      kind: offline_aead
      path: ~/.xops/vault
    keychain:
      kind: os_keychain
    corp_kms:
      kind: external_helper
      command: /usr/local/bin/xops-kms-helper
      args: ["--profile", "prod"]
      timeout: 15s
    disabled_slot:
      kind: none
```

## 2. `xops creds` / `xops vault` Lifecycle Commands

Primary command: `xops creds` (aliases: `cred`, `vault`). All subcommands support `--json` and `--policy`:

```bash
# Inspect vault lifecycle state (Uninitialized / Locked / Unlocked) and known stores
xops creds status --json

# Interactively initialize, unlock, and lock the offline vault
xops creds init
xops creds unlock
xops creds lock

# Read-only health check across all inventory references (--skip-probe checks metadata only)
xops creds doctor
xops creds doctor --skip-probe --json

# Find every inventory location referencing a secret (password, passphrase, privilege, TOTP, challenge)
xops creds refs offline/web01-pass

# Delete an unreferenced secret (refuses with still_referenced if still in use)
xops creds delete offline/unused-item

# Safe garbage collection for candidate refs (retains referenced entries; reports deleted/retained/missing)
xops creds gc offline/cand-1 offline/cand-2 --json
```

### Interactive Enrollment and Atomic Rotation (Zero Plaintext Flags)

XOps v2 never accepts plaintext passwords on the command line. Enrollment and rotation run interactively through `VaultSagaFSM`:

```bash
# 1. Enroll a login password and atomically create/replace a password Identity
xops creds enroll-password --id id-app --user app --store offline --desc "App login" --tag prod
# Or target an explicit ref and replace an existing identity:
xops creds enroll-password --id id-app --user app --ref offline/app-login --replace

# 2. Enroll an encrypted private key passphrase: verifies decryption and binds key_fingerprint (INV-F1)
xops creds enroll-key --id id-deploy --user deploy --key-path ~/.ssh/id_ed25519 --store offline
# Optional certificate path and expected fingerprint verification:
xops creds enroll-key --id id-deploy --user deploy \
  --key-path ~/.ssh/id_ed25519 --cert-path ~/.ssh/id_ed25519-cert.pub \
  --fingerprint SHA256:... --store offline --replace

# 3. Bind a sudo/su/doas privilege secret to a node
xops creds set-node-privilege --node web-01 --store offline

# 4. Atomically rotate a secret across all 5 reference locations in the inventory graph
xops creds rotate offline/old-pass --store offline
xops creds rotate offline/old-pass --new-ref keychain/new-pass --expected-revision <rev>
```

## 3. VaultSagaFSM and `UncertainDurability` Safety Rules

Credential enrollment and rotation span multiple durable stores (vault write + readback verification, CAS commit to `config.yaml`, then old-secret cleanup). `VaultSagaFSM` classifies failure states strictly:

- **Confirmed not applied (`NotApplied`)**: Automatically compensates by deleting the newly created unreferenced secret (`compensated: true`).
- **Applied with uncertain durability (`Applied && !Durable` → `uncertain_durability: true`, `do_not_retry: true`)**: For example, when rename succeeded but directory sync returned an error. XOps **neither retries nor deletes old or new credentials** and instructs you to inspect disk state and run `xops creds doctor`.

## 4. External Credential Helper Protocol (`external_helper`)

With `kind: external_helper`, XOps communicates with the helper over `stdin`/`stdout` using strict JSON v2 frames (plaintext travels only via `stdin` pipe, never argv or env, bounded by response-size and timeout limits):

**Requests (XOps → helper `stdin`)**:

```json
{"protocol_version":2,"non_interactive":true,"action":"get","store":"corp_kms","item":"web-pass"}
```

```json
{"protocol_version":2,"non_interactive":true,"action":"store","store":"corp_kms","item":"web-pass","secret_b64":"<base64>"}
```

```json
{"protocol_version":2,"non_interactive":true,"action":"erase","store":"corp_kms","item":"web-pass"}
```

**Responses (helper `stdout` → XOps; unknown JSON members are rejected)**:

- `get` success: `{"secret_b64":"<base64>"}`
- `store` / `erase` success: `{"code":"ok"}` (or exit 0 with empty stdout)
- Controlled error codes: `not_found`, `locked`, `denied`, `unavailable`, `invalid`. XOps maps only controlled codes and **never echoes arbitrary helper stderr/diagnostics** to prevent secret reflection.
- Every `store` is immediately followed by a `get` readback verified with constant-time `SecretBox.Equal`.
