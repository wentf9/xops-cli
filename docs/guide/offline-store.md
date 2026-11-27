# 离线加密凭据库（`offline_aead`）

XOps v2 内置的离线加密凭据库（`kind: offline_aead`）专为无桌面密钥环、容器、跨平台便携与严格安全审计环境设计。它采用全新版本化 **v2 存储格式（`format_version: 2`）**，100% 经由 `*os.Root` 沙箱与旁路文件锁执行原子持久化。

## 1. 加密算法栈与安全模型

- **主口令密钥派生（KEK）**：采用 **Argon2id**（默认生产参数：`time = 3`、`memory = 64 MiB`、`threads = 1`、16 字节加密安全随机盐值、派生 32 字节 KEK）；架构上支持隔离 KDF 子进程派生以防止大内存 KDF 驻留主进程堆。
- **信封加密（DEK 包装）**：初始化时生成 32 字节随机数据加密密钥（DEK），使用 KEK 经 **XChaCha20-Poly1305 AEAD**（24 字节随机 Nonce + 域分离 AAD `xops-vault-v2:dek`）加密包装后存入 `vault.meta.json`。
- **条目级 AEAD 加密**：每条机密单独生成 24 字节随机 Nonce，使用 DEK 经 XChaCha20-Poly1305 加密，附加域分离 AAD `xops-vault-v2:item:<store>/<item>`，杜绝跨条目密文移花接木。
- **写后常量时间回读校验（`PutAndVerify`）**：每次写入条目后立即重新读取磁盘密文、解密并与内存借用 `SecretBox` 执行 `crypto/subtle` 常量时间比对；若校验失败自动回滚旧密文或删除新建文件。

## 2. 目录结构与跨平台设计

默认位于 `~/.xops/vault/`（可在 `vault.stores.<name>.path` 自定义目录，目录权限 `0700`，文件权限 `0600`，Windows 自动应用受保护 Owner-Only DACL）：

```text
~/.xops/vault/
├── vault.meta.json         # 元数据：format_version=2、Argon2id 参数、salt、wrapped_dek、stores
├── vault.meta.json.lock    # 旁路文件锁（兼容 Windows 共享语义，绝不对数据文件本身加锁后 Rename）
└── items/
    ├── <sha256>.enc        # 单条密文 JSON：format_version=2、ref、nonce_b64、ciphertext_b64
    └── <sha256>.enc.lock   # 条目级可复用旁路锁（Delete 时保留以维持 Unix flock inode 互斥）
```

> 条目文件名采用 `hex(SHA-256(store + "\x00" + item)) + ".enc"`，彻底消除 Windows NTFS / macOS APFS 大小写不敏感碰撞与长路径膨胀风险，同时密文内部与 AEAD AAD 仍严格绑定原始大小写敏感引用 `store/item`。

## 3. 初始化、状态与日常操作

```bash
# 1. 初始化离线凭据库（交互提示输入并确认主口令；若已存在将失败关闭返回 already_exists）
xops creds init

# 2. 查看生命周期状态（Uninitialized / Locked / Unlocked）
xops creds status

# 3. 交互式解锁或锁定
xops creds unlock
xops creds lock

# 4. 运行只读健康诊断
xops creds doctor
xops doctor --scope vault --json
```

> **重要说明（进程级解锁边界）**：离线凭据库的解锁态（解密后的 DEK）仅保存在当前进程内存中，**绝不将未加密 DEK 写盘**。因此：
> - 在长驻进程（如 TUI 或常驻引擎宿主）内解锁一次即可持续使用；
> - 对于短生命周期无人值守 CLI 批处理或 MCP 服务，如果不想每次交互输入主口令，建议使用 **`os_keychain`**、**`external_helper`**，或对于 SSH 私钥认证直接使用 **`ssh-agent`**。

## 4. 备份与恢复

- **完整备份**：在无写操作并发期间备份整个 `~/.xops/vault/` 目录（必须同时包含 `vault.meta.json` 与 `items/*.enc`）以及 `~/.xops/config.yaml`。
- **严禁覆盖重新初始化**：切勿在已有密文的目录上删除 `vault.meta.json` 后重新 `xops creds init`——新生成的随机 DEK 将无法解密任何旧条目密文。
- **主口令遗失不可恢复**：`offline_aead` 零后门设计，主口令遗失后无法找回密文，只能重新录入新凭据并轮换远端主机密码。

## 5. 诚实安全边界

XOps v2 对内存机密保护坚持诚实边界声明：

- **有效防护**：阻断凭据明文泄露至配置文件、审计日志、结构化事件、CLI 错误输出、Playbook 摘要与标准输出；自有内存缓冲（`SecretBox`、派生密钥、KDF 帧）在作用域结束时显式 `clear()` 零化（并在 Go 1.27 `goexperiment.runtimesecret` 下预留寄存器/栈清理钩子）。
- **边界声明**：本机内存转储（如拥有同用户 root/debug 权限读取进程内存）与第三方底层库（如 `golang.org/x/crypto/ssh` 内部状态）不在进程内完全零化承诺范围内，请结合操作系统用户隔离、全盘加密与最小权限原则部署。
