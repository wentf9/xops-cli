# Offline Encrypted Vault (`offline_aead`)

XOps v2's built-in offline encrypted vault (`kind: offline_aead`) is designed for headless servers, containers, portable workstations, and strict security environments. It uses a clean-room **v2 on-disk format (`format_version: 2`)** backed 100% by `*os.Root` sandboxing and sidecar file locking.

## 1. Cryptographic Design

- **Master Passphrase KDF (KEK)**: **Argon2id** (production defaults: `time = 3`, `memory = 64 MiB`, `threads = 1`, 16-byte CSPRNG salt, 32-byte KEK). Supports optional isolated KDF subprocess execution to keep large KDF working memory off the main process heap.
- **Envelope Encryption (DEK Wrapping)**: Generates a random 32-byte Data Encryption Key (DEK) on initialization, wrapped under the KEK using **XChaCha20-Poly1305 AEAD** (24-byte random nonce + domain-separated AAD `xops-vault-v2:dek`) and stored in `vault.meta.json`.
- **Per-Item AEAD Encryption**: Each secret gets a fresh 24-byte nonce encrypted under the DEK with XChaCha20-Poly1305 and domain-separated AAD `xops-vault-v2:item:<store>/<item>`, preventing ciphertext substitution across refs.
- **Constant-Time Readback Verification (`PutAndVerify`)**: Every write is immediately re-read from disk, decrypted, and compared against the borrowed `SecretBox` using constant-time `crypto/subtle` equality; any mismatch rolls back the previous ciphertext or deletes the failed file.

## 2. Directory Layout and Cross-Platform Portability

Default path: `~/.xops/vault/` (configurable per store via `vault.stores.<name>.path`, directory mode `0700`, file mode `0600`, protected Owner-Only DACL on Windows):

```text
~/.xops/vault/
├── vault.meta.json         # Metadata: format_version=2, Argon2id params, salt, wrapped_dek, stores
├── vault.meta.json.lock    # Sidecar lock (Windows-safe; data files are never locked before Rename)
└── items/
    ├── <sha256>.enc        # Encrypted item JSON: format_version=2, ref, nonce_b64, ciphertext_b64
    └── <sha256>.enc.lock   # Reusable per-item sidecar lock (preserved on Delete for Unix flock safety)
```

> Filenames use `hex(SHA-256(store + "\x00" + item)) + ".enc"` to eliminate case-insensitive collisions on Windows NTFS / macOS APFS and prevent path-length issues, while the wire payload and AEAD AAD remain strictly bound to the exact case-sensitive `store/item` reference.

## 3. Initialization, Status, and Daily Use

```bash
# 1. Initialize the offline vault (prompts for and confirms the master passphrase; fails if already initialized)
xops creds init

# 2. Check lifecycle state (Uninitialized / Locked / Unlocked)
xops creds status

# 3. Interactively unlock or lock
xops creds unlock
xops creds lock

# 4. Run read-only diagnostics
xops creds doctor
xops doctor --scope vault --json
```

> **Process-Scoped Unlock Boundary**: The decrypted DEK exists only in process memory and is **never written unencrypted to disk**.
> - Long-lived hosts (such as TUI or embedded engines) keep the vault unlocked for the session lifetime until `lock` or exit.
> - For unattended short-lived CLI batch runs or MCP servers, prefer **`os_keychain`**, **`external_helper`**, or **`ssh-agent`** for SSH keys.

## 4. Backup and Recovery

- **Back up atomically**: Copy both `~/.xops/vault/` (preserving `vault.meta.json` and all `items/*.enc`) and `~/.xops/config.yaml` while no writes are in progress.
- **Never re-initialize over existing items**: Deleting `vault.meta.json` and re-running `xops creds init` generates a brand-new DEK that cannot decrypt existing `items/*.enc` files.
- **Lost passphrases are unrecoverable**: There is no backdoor; rotate credentials on target hosts and re-enroll if the master passphrase is lost.

## 5. Honest Security Boundary

- **Guaranteed**: Secret plaintext never leaks into YAML config, audit logs, events, CLI errors, playbook digests, or stdout. XOps-owned buffers (`SecretBox`, derived keys, KDF frames) are explicitly zeroized via `clear()` on scope exit (with `goexperiment.runtimesecret` hooks isolated in `core/domain/secret`).
- **Explicit Limits**: Memory inspection by a privileged attacker on the same host and internal buffers inside upstream third-party libraries (such as `golang.org/x/crypto/ssh`) are outside in-process zeroization guarantees; combine with OS user isolation, disk encryption, and least-privilege access.
