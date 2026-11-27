# 配置 Schema v2 参考（`~/.xops/config.yaml`）

XOps v2 采用严格判别式 **YAML vNext（`version: 2`）** 配置文件，默认路径为 `~/.xops/config.yaml`（可通过环境变量 `XOPS_HOME` 覆写根目录）。

- **零 v1 兼容**：仅接受 `version: 2`，任何缺失版本、非 2 版本、多份 YAML 文档或未知字段（`KnownFields(true)`）均失败关闭。
- **零明文机密**：认证凭据仅通过 `{ store, item }` 引用，严禁出现明文密码。
- **强时长语法**：所有时长字段（`timeout`、`approval_ttl`、`connect_timeout`、`server_alive_interval`）遵循 Go 标准时长串（如 `10s`、`5m`、`1h`）。

## 1. 完整配置示例

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
        decision_floor: need_approval # allow | need_approval | deny
      "staging-*": moderate

# Tier-3 XOps 全局 OpenSSH 选项层
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
        key_fingerprint: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
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
                name: "authenticator-otp"
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

## 2. 顶层段字段说明

### `vault`

| 字段 | 类型 / 允许值 | 说明 |
| --- | --- | --- |
| `default_store` | `string` | 默认存储名称（若配置了 `stores`，必须为其键之一） |
| `remember_prompted` | `always` \| `ask` \| `never` | 交互输入凭据后的默认记忆策略 |
| `stores.<name>.kind` | `offline_aead` \| `os_keychain` \| `external_helper` \| `none` | 凭据后端类型 |
| `stores.<name>.path` | `string` | `offline_aead` 目录路径（默认 `~/.xops/vault`） |
| `stores.<name>.command` / `args` / `timeout` | `string` / `[]string` / `Duration` | `external_helper` 可执行路径、参数与正时长超时 |

### `policy`

| 字段 | 类型 / 允许值 | 说明 |
| --- | --- | --- |
| `cli_default` / `mcp_default` | `direct_operator` \| `strict` \| `strict_operator` \| `strict_agent` | CLI 与 MCP 的默认策略配置档 |
| `guardrail.approval_threshold` | `safe` \| `moderate` \| `dangerous` \| `critical` | 全局审批风险阈值（默认 `moderate`） |
| `guardrail.no_elicit_fallback` | `deny` \| `challenge` | 非交互环境回退策略（默认 `deny`） |
| `guardrail.audit_log` | `string` | 审计日志路径（禁止直接放在裸 `$HOME` 根目录，建议放在 `$XOPS_HOME` 或独立私有目录） |
| `guardrail.approval_ttl` | `Duration` | 两步审批信封有效期（默认 `5m`，范围 `(0, 24h]`） |
| `guardrail.protected_paths` | `[]string` | 受保护路径模式列表（默认 `/etc/**`、`/root/**`、`C:/Windows/**`） |
| `guardrail.node_overrides` | `map[pattern]NodeOverride` | 节点通配符护栏覆写（支持标量简写或 `{approval_threshold, decision_floor}`） |

### `options`（OpenSSH `OptionLayerDTO`，适用于顶层 Tier-3 与节点 Tier-2）

- 端点与连接：`hostname`、`port`、`user`、`connect_timeout`、`server_alive_interval`、`server_alive_count_max`
- 代理与复用：`proxy`（`kind: unset|disabled|jump|command`）、`control`（`master`、`path`、`literal_path`、`persist`）
- 加密算法策略：`ciphers`、`macs`、`kex_algorithms`、`host_key_algorithms`（格式 `{ op: exact|append|remove|prepend|unset, tokens: [...] }`）
- 认证与信任：`identity_files` / `certificate_files`（`{ state: set|disabled|unset, items: [...], terminated?: bool }`）、`identities_only`、`batch_mode`、`strict_host_key_checking`、`user_known_hosts_files`（`{ state, items }`）、`forward_agent`
- 环境与本地命令：`send_env`（`{ clear: [...], added: [...] }`）、`permit_local_command`、`local_command`

### `inventory.identities.<id>.auth`（封闭认证和类型）

| `kind` | 专属字段 | 约束 |
| --- | --- | --- |
| `agent` | 可选 `agent_spec` | 禁止携带其他认证字段 |
| `password` | 必填 `password_ref: {store, item}` | 禁止携带其他认证字段 |
| `private_key` | 必填非空 `key_paths`；可选 `cert_paths`、成对 `passphrase_ref` + `key_fingerprint` | `passphrase_ref` 与 `key_fingerprint` 必须同时提供或同时省略（INV-F1） |
| `keyboard_interactive` | 必填非空 `rules` | 规则 `kind` 支持 `totp`（`totp_secret_ref`）、`secret_ref`、`command`（`command`/`args`/`timeout`）、`login_password` |
| `composite` | 必填非空 `methods` | 组合多段子认证方法按序尝试 |
