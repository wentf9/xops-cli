# 凭据路由与密钥管理

XOps v2 在全链路贯彻**零明文配置与零明文 CLI 参数**原则：`~/.xops/config.yaml` 与导入文件只能存放 `<store>/<item>` 格式的凭据引用（`SecretRef`），真实机密全部由多后端 `RouterVault` 加密托管，并在单协程借用闭包（`SecretBox`）退出时自动 `clear()` 零化内存。

## 1. 支持的 4 类凭据后端

在 `~/.xops/config.yaml` 的 `vault.stores` 中可按需声明多个命名存储槽位，并在 `vault.default_store` 中指定默认存储。若未显式配置 `vault.stores`，XOps 会自动装配默认的 `offline`（`offline_aead`）与 `os_keychain`（平台原生钥匙串），默认使用 `offline`。

| `kind` | 实现说明 | 适用场景 |
| --- | --- | --- |
| `offline_aead` | 内置离线加密 dirfd 凭据库（Argon2id + XChaCha20-Poly1305 AEAD，详见[离线加密凭据库](./offline-store)） | 全平台零外部依赖、无桌面会话的服务器或容器环境 |
| `os_keychain` | 平台原生系统钥匙串（纯 Go `CGO_ENABLED=0`）：<br>- **Windows**：Windows Credential Manager（`CREDENTIALW`）<br>- **macOS**：`Security.framework` Keychain（`purego`）<br>- **Linux**：FreeDesktop Secret Service D-Bus（`godbus`，支持 DH AES-128-CBC 与 `plain` 回退）<br>- 其他平台（如 FreeBSD）返回 `unsupported` | 桌面环境免重复输入主口令、交互与无人值守会话 |
| `external_helper` | 通过 `stdin`/`stdout` JSON v2 协议对接外部凭据管理工具（如 `pass`、1Password CLI、Bitwarden 或企业 KMS 包装脚本） | 团队集中密钥库与自定义硬件/KMS 集成 |
| `none` | 显式禁用槽位，所有读写均严格失败关闭返回 `unsupported` | 纯 `ssh-agent` / 无密码存储合规环境 |

### 多后端配置示例（`~/.xops/config.yaml`）

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

## 2. `xops creds` / `xops vault` 全生命周期命令

命令主名为 `xops creds`（别名 `cred`、`vault`），全部支持 `--json` 与 `--policy`：

```bash
# 查看凭据库生命周期状态（Uninitialized / Locked / Unlocked）与已知存储列表
xops creds status --json

# 交互式初始化、解锁与锁定离线凭据库
xops creds init
xops creds unlock
xops creds lock

# 只读健康诊断（校验资产图中全部引用；加 --skip-probe 仅检查元数据不逐条探活）
xops creds doctor
xops creds doctor --skip-probe --json

# 查询某条凭据在资产图中的全部引用位置（5 类位置：密码/私钥口令/提权密码/TOTP/质询规则）
xops creds refs offline/web01-pass

# 安全删除单条未被任何资产引用的凭据（仍被引用时拒绝删除并返回 still_referenced）
xops creds delete offline/unused-item

# 批量安全垃圾回收候选凭据（自动保留仍有引用的条目，报告 deleted / retained / missing）
xops creds gc offline/cand-1 offline/cand-2 --json
```

### 交互式录入与原子轮换（零明文 CLI 标志）

XOps v2 彻底禁止在命令行参数中传递密码。录入与轮换全部通过交互式密码提示结合 `VaultSagaFSM` 状态机原子完成：

```bash
# 1. 录入登录密码并原子创建/替换密码认证 Identity
xops creds enroll-password --id id-app --user app --store offline --desc "App login" --tag prod
# 或指定精确引用名并覆盖既有 Identity：
xops creds enroll-password --id id-app --user app --ref offline/app-login --replace

# 2. 录入加密私钥口令：读取本地私钥校验解密、自动计算并绑定 key_fingerprint（INV-F1）
xops creds enroll-key --id id-deploy --user deploy --key-path ~/.ssh/id_ed25519 --store offline
# 可选附加 SSH 证书与期望指纹校验：
xops creds enroll-key --id id-deploy --user deploy \
  --key-path ~/.ssh/id_ed25519 --cert-path ~/.ssh/id_ed25519-cert.pub \
  --fingerprint SHA256:... --store offline --replace

# 3. 为指定节点绑定 sudo/su/doas 提权密码引用
xops creds set-node-privilege --node web-01 --store offline

# 4. 原子轮换旧凭据：写入新凭据并校验 -> 全图替换全部 5 类引用位置 -> 删除旧凭据
xops creds rotate offline/old-pass --store offline
xops creds rotate offline/old-pass --new-ref keychain/new-pass --expected-revision <rev>
```

## 3. VaultSagaFSM 与 `UncertainDurability` 安全准则

凭据录入与轮换是典型的跨存储多步事务（先写 Vault 并回读校验，再 CAS 提交 `config.yaml`，最后清理旧凭据）。XOps v2 使用纯函数 `VaultSagaFSM` 严格分类异常状态：

- **可确认未落盘（`NotApplied`）**：自动触发补偿清理新建的未引用密文（`compensated: true`），保持原配置完好。
- **已生效但持久性不确定（`Applied && !Durable` → `uncertain_durability: true`、`do_not_retry: true`）**：例如磁盘 `Rename` 成功但目录 `Sync` 报错。此时系统**严禁重试也严禁删除旧凭据或新凭据**，并在输出中明确提示人工核对磁盘状态与运行 `xops creds doctor`。

## 4. 外部凭据助手协议（`external_helper`）

当配置 `kind: external_helper` 时，XOps 通过子进程 `stdin`/`stdout` 与外部助手交换精简 JSON v2 报文（明文仅经 `stdin` 管道传递，绝不出现在进程命令行或环境变量中，响应大小与超时均受硬上限保护）：

**请求（XOps → 助手 `stdin`）**：

```json
{"protocol_version":2,"non_interactive":true,"action":"get","store":"corp_kms","item":"web-pass"}
```

```json
{"protocol_version":2,"non_interactive":true,"action":"store","store":"corp_kms","item":"web-pass","secret_b64":"<base64>"}
```

```json
{"protocol_version":2,"non_interactive":true,"action":"erase","store":"corp_kms","item":"web-pass"}
```

**响应（助手 `stdout` → XOps，严格拒绝未知字段）**：

- `get` 成功：`{"secret_b64":"<base64>"}`
- `store` / `erase` 成功：`{"code":"ok"}`（或退出码 0 且空输出）
- 错误码映射：`not_found`、`locked`、`denied`、`unavailable`、`invalid`（XOps 仅映射受控错误码，**绝不回显助手原始非受控诊断文本**，防止凭据反射泄露）。
- 每次 `store` 后，XOps 会自动执行 `get` 回读并以常量时间 `SecretBox.Equal` 校验写入完整性。
