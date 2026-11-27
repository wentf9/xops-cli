# Inventory, Imports, and Vault (XOps v2)

XOps v2 models inventory as a 3-entity graph (**Host**, **Identity**, **Node**) stored in strict `version: 2` YAML at `~/.xops/config.yaml` (override root directory with `XOPS_HOME`).

## Inspect, Resolve, and Diagnose

```bash
xops hosts list --json
xops hosts list --tag web --json
xops hosts list --kind hosts --json        # nodes (default) | hosts | identities | all
xops hosts get web-01 --json               # --kind node (default) | host | identity
xops hosts resolve web-01 --json           # resolves 4-layer OpenSSH policy + hop count + PlanDigest
xops hosts validate-dag --json             # Tarjan jump-DAG cycle check
xops hosts check-secret-refs --store offline --json
xops doctor --json                         # combined read-only inventory + vault health check
xops doctor --scope inventory --check-vault --check-keys --json
```

All `hosts` queries support aliases `host` and `inventory`, plus `--lang <en|zh>` (before or after the subcommand, before `--`). Listing and resolving do not open remote SSH connections. Diagnostic fields in `xops doctor --json` (`findings[].message`, `vault_note`) and `xops config import --json` (`report.warnings[].message`) always remain canonical English regardless of `--lang` or `XOPS_LANG`.

## Declarative CAS CRUD (`xops hosts`)

Always pass `--expected-revision <rev>` from a prior `list`/`get` when avoiding concurrent overwrite races (`revision_conflict` on mismatch):

```bash
# Host
xops hosts create-host --id h-web1 --address 192.0.2.10:22 --alias web1-ep --tag prod,web --json
xops hosts update-host --id h-web1 --address 192.0.2.11:22 --expected-revision <rev> --json
xops hosts delete-host h-web1 --expected-revision <rev> --json

# Identity (--auth-kind: agent | password | private_key)
xops hosts create-identity --id id-agent --user deploy --auth-kind agent --json
xops hosts create-identity --id id-key --user deploy --auth-kind private_key \
  --key-path ~/.ssh/id_ed25519 --cert-path ~/.ssh/id_ed25519-cert.pub --json
xops hosts create-identity --id id-pass --user app --auth-kind password --password-ref offline/app-pass --json
xops hosts update-identity --id id-key --user deploy --auth-kind private_key \
  --key-path ~/.ssh/id_ed25519 --passphrase-ref offline/kp --key-fingerprint SHA256:... --gc-old-secrets --json
xops hosts delete-identity id-key --delete-unused-secrets --require-unreferenced --json

# Node
xops hosts create-node --id web-01 --host h-web1 --identity id-key \
  --alias prod-web --tag prod,web --jump bastion \
  --dialect posix --interpreter bash --login disabled --json
xops hosts update-node --id web-01 --host h-web1 --identity id-key --gc-old-secrets --json
xops hosts delete-node web-01 --delete-unused-secrets --json
```

- Encrypted private keys require **paired** `--passphrase-ref` and `--key-fingerprint` (INV-F1). Prefer `xops creds enroll-key` so XOps verifies decryption and computes the fingerprint automatically.
- Deletions enforce referential integrity and fail closed with `still_referenced` (including `reference_conflict` details in JSON) if another entity still depends on the target.

## Unified Config Import (`xops config import`)

XOps v2 supports `openssh` and `csv` importers (zero v1 config reading):

```bash
xops config formats --json

# Preview conflicts, DAG validity, and warnings without writing
xops config import --format openssh --file ~/.ssh/config --plan --json
xops config import --format openssh --file ~/.ssh/config --json

# Dry-run or apply CSV import (headerless: alias,address,port,user; or header-driven)
xops config import --format csv --file ./hosts.csv --dry-run --json
cat ./hosts.csv | xops config import --format csv --stdin --json
```

- **OpenSSH**: Pure in-memory parse; does not open remote connections or follow `Include` files on disk (emits structured `ImportWarning`s); produces `openssh_derived` nodes.
- **CSV**: Allowed headers: `name`/`alias`/`id`/`node`/`node_id`, `host`/`address`/`hostname`, `port`, `user`/`username`, `key_path`/`key_paths`/`identity_file`, `cert_path`/`cert_paths`/`certificate_file`, `proxy_jump`/`jump`, `aliases`, `tags`, `description`/`desc` (`;` separates multi-value cells). **Any plaintext secret column** (`password`, `passwd`, `pass`, `passphrase`, `secret`, `token`, `private_key`, `key_content`, `totp_secret`, `sudo_password`, `privilege_password`) fails closed immediately.

## Four-Layer OpenSSH Option Precedence

`Tier-1 (CLI flags)` > `Tier-2 (Node options)` > `Tier-3 (config.yaml top-level options)` > `Tier-4 (~/.ssh/config or -F <file>)` > built-in defaults.
- `managed` and `ad_hoc` nodes inherit only transport & mux options from Tier-4 (INV-D2); `openssh_virtual` and `openssh_derived` nodes inherit full Tier-4 options. Pass `-F none` to disable Tier-4.

## Vault Lifecycle & Zero-Plaintext Rules (`xops creds` / `xops vault`)

Supported `vault.stores.<name>.kind` backends: `offline_aead` (Argon2id + XChaCha20-Poly1305 AEAD, default at `~/.xops/vault`), `os_keychain` (Windows Credential Manager / macOS `Security.framework` / Linux D-Bus Secret Service), `external_helper` (stdin/stdout JSON v2 protocol), and `none`.

```bash
xops creds status --json
xops creds doctor --json                   # add --skip-probe to skip per-secret reads
xops creds refs offline/web-pass --json
xops creds delete offline/unused --json
xops creds gc offline/cand1 offline/cand2 --json
```

Interactive commands (require a TTY / interaction port; zero plaintext CLI flags exist):

```bash
xops creds init
xops creds unlock
xops creds lock
xops creds enroll-password --id id-app --user app --store offline
xops creds enroll-key --id id-key --user deploy --key-path ~/.ssh/id_ed25519 --store offline
xops creds set-node-privilege --node web-01 --store offline
xops creds rotate offline/old-item --store offline
```

- **Process-scoped offline unlock**: `offline_aead` keeps the unwrapped DEK only in process memory. Unattended batch jobs and MCP servers should use `os_keychain`, `external_helper`, or `ssh-agent`.
- **Uncertain durability rule**: If `enroll-*`, `set-node-privilege`, or `rotate` returns `"uncertain_durability": true` (`do_not_retry: true`), **do not retry and do not delete credentials**; inspect disk state with `xops creds doctor --json` and `xops hosts list --json` first.

## MCP Equivalent (`nodes` tool)

In MCP mode, use `nodes` with `action`: `list_hosts`, `get_host`, `create_host`, `update_host`, `delete_host`, `list_identities`, `get_identity`, `create_identity`, `update_identity`, `delete_identity`, `list_nodes`, `get_node`, `create_node`, `update_node`, `delete_node`, `resolve`, `validate_dag`, `doctor`, `list_import_formats`, `plan_import`, `apply_import` (import uses inline `content` or `bundle`, never host file paths). Tool descriptions, schemas, and responses remain invariant canonical English regardless of `--lang` or `XOPS_LANG`.
