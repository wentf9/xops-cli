# Config Schema v2 Reference (`~/.xops/config.yaml`)

XOps v2 persists configuration in strict discriminated **YAML vNext (`version: 2`)** at `~/.xops/config.yaml` (override the root state directory via `XOPS_HOME`).

- **Zero v1 Compatibility**: Only `version: 2` is accepted. Missing version, v1 keys, trailing YAML documents, or unknown fields (`KnownFields(true)`) fail closed.
- **Zero Plaintext Secrets**: Credentials are referenced solely via `{ store, item }` tuples.
- **Typed Durations**: All duration fields (`timeout`, `approval_ttl`, `connect_timeout`, `server_alive_interval`) use Go duration strings (e.g. `10s`, `5m`, `1h`).

## 1. Complete Configuration Example

```yaml
version: 2
revision: 1

vault:
  default_store: offline
  remember_prompted: ask # always | ask | never
  stores:
    offline:
      kind: offline_aead
      path: ~/.xops/vault
    os_keychain:
      kind: os_keychain
    corp_helper:
      kind: external_helper
      command: /usr/local/bin/xops-secret-helper
      args: ["--env", "prod"]
      timeout: 15s

policy:
  cli_default: direct_operator    # direct_operator | strict | strict_operator | strict_agent
  mcp_default: strict_agent
  guardrail:
    approval_threshold: moderate  # safe | moderate | dangerous | critical
    no_elicit_fallback: challenge # deny | challenge
    audit_log: ~/.xops/audit.jsonl
    approval_ttl: 5m              # (0, 24h]
    protected_paths:
      - "/etc/**"
      - "/root/**"
      - "C:/Windows/**"
    node_overrides:
      "prod-*":
        approval_threshold: safe
        decision_floor: require_approval # allow | require_approval | deny
      "staging-*": moderate

# Tier-3 XOps Global OpenSSH option layer
options:
  connect_timeout: 15s
  server_alive_interval: 30s
  server_alive_count_max: 3
  strict_host_key_checking: ask   # yes | ask | accept-new | no
  identities_only: false
  forward_agent: false
  control:
    master: auto                  # no | yes | auto | ask | autoask
    path: "~/.xops/mux-%C"
    persist: "10m"

inventory:
  known_stores:
    - offline
    - os_keychain
  hosts:
    h-bastion:
      address: bastion.example.com
      port: 22
      tags: [infra]
    h-web1:
      address: 192.0.2.10
      port: 22
      alias: web1-ip
      description: "Production web 1"
      tags: [prod, web]
  identities:
    id-agent:
      user: deploy
      auth:
        kind: agent
    id-key:
      user: deploy
      auth:
        kind: private_key
        key_paths: ["~/.ssh/id_ed25519"]
        cert_paths: ["~/.ssh/id_ed25519-cert.pub"]
        passphrase_ref:
          store: offline
          item: deploy-key-pass
        key_fingerprint: "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    id-pass:
      user: app
      auth:
        kind: password
        password_ref:
          store: offline
          item: app-login-pass
    id-mfa:
      user: ops
      auth:
        kind: composite
        methods:
          - kind: agent
          - kind: keyboard_interactive
            rules:
              - kind: totp
                name: "Authenticator OTP"
                prompt_pattern: "(?i)verification code|otp"
                totp_secret_ref:
                  store: offline
                  item: ops-totp
  nodes:
    bastion:
      host: h-bastion
      identity: id-agent
      tags: [infra]
    web-01:
      host: h-web1
      identity: id-key
      aliases: [prod-web-1]
      tags: [prod, web]
      proxy:
        kind: jump
        hops: [bastion]
      execution:
        launch_dialect: posix     # posix | powershell | cmd | raw
        interpreter: bash         # server | sh | bash | zsh | powershell | pwsh | cmd
        login: disabled           # disabled | login | inherit
      privilege_password_ref:
        store: offline
        item: web01-sudo
      description: "Primary web server"
```

## 2. Top-Level Sections

### `vault`

| Field | Type / Values | Description |
| --- | --- | --- |
| `default_store` | `string` | Default store name (must exist in `stores` if `stores` is non-empty) |
| `remember_prompted` | `always` \| `ask` \| `never` | Default policy for remembering interactively entered secrets |
| `stores.<name>.kind` | `offline_aead` \| `os_keychain` \| `external_helper` \| `none` | Vault backend kind |
| `stores.<name>.path` | `string` | Directory for `offline_aead` (defaults to `~/.xops/vault`) |
| `stores.<name>.command` / `args` / `timeout` | `string` / `[]string` / `Duration` | Executable, args, and positive timeout for `external_helper` |

### `policy`

| Field | Type / Values | Description |
| --- | --- | --- |
| `cli_default` / `mcp_default` | `direct_operator` \| `strict` \| `strict_operator` \| `strict_agent` | Default profiles for CLI and MCP modes |
| `guardrail.approval_threshold` | `safe` \| `moderate` \| `dangerous` \| `critical` | Global approval threshold (default `moderate`) |
| `guardrail.no_elicit_fallback` | `deny` \| `challenge` | Non-interactive fallback policy (default `deny`) |
| `guardrail.audit_log` | `string` | Audit log path (cannot reside directly in bare `$HOME`; use `$XOPS_HOME` or a dedicated private directory) |
| `guardrail.approval_ttl` | `Duration` | Two-step approval envelope TTL (default `5m`, range `(0, 24h]`) |
| `guardrail.protected_paths` | `[]string` | Protected path patterns (defaults: `/etc/**`, `/root/**`, `C:/Windows/**`) |
| `guardrail.node_overrides` | `map[pattern]NodeOverride` | Wildcard node overrides (scalar threshold shorthand or `{approval_threshold, decision_floor}`) |

### `options` (OpenSSH `OptionLayerDTO` — Tier-3 global and Tier-2 per-node)

- Connection: `hostname`, `port`, `user`, `connect_timeout`, `server_alive_interval`, `server_alive_count_max`
- Proxy & mux: `proxy` (`kind: unset|disabled|jump|command`), `control` (`master`, `path`, `literal_path`, `persist`)
- Algorithms: `ciphers`, `macs`, `kex_algorithms`, `host_key_algorithms` (`{ op: exact|append|remove|prepend|unset, tokens: [...] }`)
- Auth & trust: `identity_files` / `certificate_files` (`{ state: set|disabled|unset, items: [...], terminated?: bool }`), `identities_only`, `batch_mode`, `strict_host_key_checking`, `user_known_hosts_files` (`{ state, items }`), `forward_agent`
- Env & local command: `send_env` (`{ clear: [...], added: [...] }`), `permit_local_command`, `local_command`

### `inventory.identities.<id>.auth` (Sealed Auth Sum Type)

| `kind` | Variant Fields | Invariants |
| --- | --- | --- |
| `agent` | Optional `agent_spec` | Must not include fields from other auth kinds |
| `password` | Required `password_ref: {store, item}` | Must not include fields from other auth kinds |
| `private_key` | Required non-empty `key_paths`; optional `cert_paths`, paired `passphrase_ref` + `key_fingerprint` | `passphrase_ref` and `key_fingerprint` must appear together or both be omitted (INV-F1) |
| `keyboard_interactive` | Required non-empty `rules` | Rule `kind`: `totp` (`totp_secret_ref`), `secret_ref`, `command` (`command`/`args`/`timeout`), `login_password` |
| `composite` | Required non-empty `methods` | Evaluates ordered sub-methods in sequence |
