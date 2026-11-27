# Hosts, Inventory, and Imports

XOps v2 models SSH infrastructure as an immutable, strongly-typed 3-entity graph (**Host / Identity / Node**) persisted in `~/.xops/config.yaml` (`version: 2`) with optimistic CAS (`--expected-revision`), sidecar locking (`config.yaml.lock`), and Tarjan jump-DAG cycle validation.

## 1. Three-Entity Inventory Graph

| Entity | Responsibility | Key Fields |
| --- | --- | --- |
| **Host** | Network endpoint and tags | `address`, `port` (default `22`), `alias`, `tags`, `description` |
| **Identity** | Login user and closed-sum authentication method | `user`, `auth` (`agent` / `password` / `private_key` / `keyboard_interactive` / `composite`), `tags`, `description` |
| **Node** | Connection target binding one Host and one Identity | `host`, `identity`, `aliases`, `tags`, `proxy` (`jump` / `command` / `disabled`), `execution`, `options`, `privilege_password_ref`, `origin` |

Decoupling these entities allows one server address (Host) to serve multiple accounts (such as `deploy` and `audit`) with isolated credentials, privilege settings, and OpenSSH option layers.

### Node Origins (`NodeOrigin`)

XOps v2 distinguishes 4 node origins to govern how Tier-4 OpenSSH config options are folded:

1. `managed`: Native XOps-managed nodes persisted in `config.yaml`.
2. `openssh_virtual`: Read-only virtual hosts resolved directly from `~/.ssh/config` at runtime.
3. `openssh_derived`: Persistent nodes imported via `xops config import --format openssh`.
4. `ad_hoc`: Ephemeral CLI `user@host[:port]` destinations not saved in inventory.

## 2. Inspect, Resolve, and Validate

The primary command is `xops hosts` (aliases: `host`, `inventory`):

```bash
# List nodes (default), hosts, identities, or the full graph snapshot
xops hosts list
xops hosts list --tag web
xops hosts list --kind hosts
xops hosts list --kind identities
xops hosts list --kind all --json

# Inspect an individual entity and current CAS revision
xops hosts get web-01
xops hosts get --kind host h-web1 --json
xops hosts get --kind identity id-deploy

# Resolve effective connection plan (origin, final endpoint, hop count, PlanDigest)
xops hosts resolve web-01
xops hosts resolve -J bastion -p 2222 deploy@192.0.2.10 --json

# Run Tarjan strongly-connected-components DAG validation across all jump routes
xops hosts validate-dag

# Find all asset locations referencing a secret or vault store
xops hosts check-secret-refs --ref offline/web-pass
xops hosts check-secret-refs --store offline
```

## 3. Declarative CRUD with Optimistic CAS

All write commands accept `--expected-revision <rev>` for optimistic concurrency control (if `config.yaml` changed concurrently or was edited externally, the commit fails closed with `revision_conflict`):

```bash
# Create and update a Host
xops hosts create-host --id h-web1 --address 192.0.2.10:22 --alias web1-ep --tag prod,web --desc "Primary web"
xops hosts update-host --id h-web1 --address 192.0.2.11:22 --expected-revision <rev>

# Create and update an Identity (--auth-kind: agent | password | private_key)
xops hosts create-identity --id id-agent --user deploy --auth-kind agent
xops hosts create-identity --id id-key --user deploy --auth-kind private_key \
  --key-path ~/.ssh/id_ed25519 --cert-path ~/.ssh/id_ed25519-cert.pub
xops hosts create-identity --id id-pass --user app --auth-kind password --password-ref offline/app-login

# Encrypted keys require paired --passphrase-ref and --key-fingerprint (or use 'xops creds enroll-key')
xops hosts update-identity --id id-key --user deploy --auth-kind private_key \
  --key-path ~/.ssh/id_ed25519 --passphrase-ref offline/key-pass --key-fingerprint SHA256:... --gc-old-secrets

# Create and update a Node (--jump / --proxy-command, --dialect / --interpreter / --login, --priv-password-ref)
xops hosts create-node --id web-01 --host h-web1 --identity id-key \
  --alias prod-web --tag prod,web --jump bastion \
  --dialect posix --interpreter bash --login disabled
xops hosts update-node --id web-01 --host h-web1 --identity id-key --gc-old-secrets

# Delete assets (referential integrity is enforced automatically)
xops hosts delete-node web-01 --delete-unused-secrets
xops hosts delete-identity id-key --require-unreferenced
xops hosts delete-host h-web1
```

> **Tip**: For password-based identities or encrypted private keys, prefer the interactive [`xops creds enroll-password`](./credentials) and [`xops creds enroll-key`](./credentials) commands, which atomically prompt for secrets, write to the vault, compute/verify fingerprints, and commit the graph in one saga.

## 4. Unified Config Import (`xops config import`)

XOps v2 imports external inventory definitions through `ports.FormatImporter` (100% zero v1 compatibility code), shipping built-in **`openssh`** and **`csv`** importers:

```bash
# List registered formats
xops config formats

# OpenSSH import: preview plan and warnings before writing
xops config import --format openssh --file ~/.ssh/config --plan
xops config import --format openssh --file ~/.ssh/config

# Import from stdin or run in dry-run mode
cat ./hosts.csv | xops config import --format csv --stdin --dry-run --json
```

### OpenSSH Importer (`--format openssh`)

- Pure in-memory stream parsing with zero remote SSH connections and zero disk traversal for `Include` directives (any `Include` emits a structured `ImportWarning`).
- Produces `openssh_derived` nodes preserving `ProxyJump` / `ProxyCommand` and OpenSSH `options` layers; wildcard patterns or non-literal key templates produce warnings instead of silent drops.

### CSV Importer (`--format csv`)

- Supports **headerless 4-column rows**: `alias,address,port,user` (defaults to `agent` authentication).
- Supports **header-driven CSV** (case-insensitive headers, `#` comments, `;`-delimited multi-value cells):
  - Required columns: `name`/`alias`/`id`/`node`/`node_id`, `host`/`address`/`hostname`, `user`/`username`
  - Optional columns: `port` (default `22`), `key_path`/`key_paths`/`identity_file`, `cert_path`/`cert_paths`/`certificate_file`, `proxy_jump`/`jump`, `aliases`, `tags`, `description`/`desc`
- **Zero-Plaintext Enforcement**: Any header containing `password`, `passwd`, `pass`, `passphrase`, `secret`, `token`, `private_key`, `key_content`, `totp_secret`, `sudo_password`, or `privilege_password` fails closed immediately.

```csv
name,address,port,user,key_path,proxy_jump,tags,description
bastion,bastion.example.com,22,deploy,~/.ssh/id_ed25519,,infra,Jump bastion
web-01,192.0.2.10,22,deploy,~/.ssh/id_ed25519,bastion,prod;web,Web server 1
web-02,192.0.2.11,22,deploy,~/.ssh/id_ed25519,bastion,prod;web,Web server 2
```

## 5. 4-Layer OpenSSH Option Precedence

Across `ssh`, `exec`, `scp`, `sftp`, `tunnel`, `mux`, and `hosts resolve`, XOps v2 solves effective SSH options through a single pure monoid solver (FirstWins semantics):

```text
Tier-1: CLI flags (-p / -l / -i / -J / -o / -M / -S)
   > Tier-2: Managed node options (inventory.nodes.<id>.options)
      > Tier-3: XOps global options (top-level options in config.yaml)
         > Tier-4: OpenSSH config (~/.ssh/config or -F <file>)
            > Built-in secure defaults (ControlMaster=no, StrictHostKeyChecking=ask, ForwardAgent=no, PermitLocalCommand=no)
```

### Origin-Scoped Tier-4 Filtering (INV-D2)

- `openssh_virtual` and `openssh_derived` nodes inherit the full Tier-4 (`~/.ssh/config`) option layer.
- `managed` and `ad_hoc` nodes inherit only **multiplexing and transport options** from Tier-4 (`ControlMaster`/`ControlPath`/`ControlPersist`, timeouts, keepalives, crypto algorithms), preventing broad `Host *` stanzas from silently overriding managed identities or jump routes.
- Pass `-F none` (or `--ssh-config none`) to disable Tier-4 OpenSSH config loading entirely.
