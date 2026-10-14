# 离线凭据库

内置离线凭据库（`encrypted-file`）将凭据加密保存在本机，支持 Linux、Windows 和 macOS 的 amd64/arm64 平台。新安装默认使用名为 `file` 的离线库，并通过独立密钥文件（`credentials.key`）解锁。默认保存策略见[凭据存储](./credentials)。

## 初始化与日常检查

默认 `key-file` 模式在首次保存凭据时自动初始化。你也可以对已配置但尚未创建的离线库手动执行探测与初始化：

```bash
# 检查目标目录是否支持文件锁、原子替换与同步（不读写凭据）
xops credential store probe file

# 手动初始化离线库（父目录须已存在）
xops credential store init file

# 查看离线库元数据，或使用密钥/主口令验证元数据完整性
xops credential store inspect file
xops credential store inspect file --verify
```

- **`probe` 说明**：使用临时目录检验文件系统能力，不读写任何凭据；通过探测不代表发生物理断电时一定不丢数据，请使用可靠存储介质并定期备份。
- **密钥文件规则**：`init` 在密钥文件不存在时会生成 32 字节随机密钥（权限 `0600`），若已有合规密钥文件则直接复用。密钥文件必须位于离线库目录之外，不能使用符号链接；Unix 下须归属当前用户或 `root`，权限为 `0400` 或 `0600`。
- **只读安全保证**：`inspect`（含 `--verify`）、普通读取和解锁均不会初始化新库，也不会为已有库生成替代密钥。

## 使用主口令模式（`unlock: prompt`）

如果希望每次使用前手动输入主口令解锁，可在 `credential.stores` 中配置 `unlock: prompt`：

```yaml
credential:
  default_store: offline
  stores:
    offline:
      type: encrypted-file
      path: credentials-offline
      unlock: prompt
      unlock_idle_ttl: 5m
```

然后初始化该库并按隐藏提示输入两次主口令（至少 12 个字符，切勿将主口令写入命令行参数或环境变量）：

```bash
xops credential store init offline
```

- 仅执行 `init` 不会搬迁已有凭据；如需将现有 `file` 库中的凭据迁入 `offline` 库，请按[凭据迁移](./migration)操作。
- **解锁范围**：在 TUI 中可按 `Ctrl+U` 解锁默认离线库、按 `Ctrl+L` 锁定当前进程已打开的离线库（解锁状态仅限当前进程，不跨进程共享）。MCP、Playbook 和非交互批处理不会提示输入主口令，无人值守任务请使用 `key-file` 模式。

## 密钥轮换与旧版本清理

```bash
# 更换解锁方式或生成新密钥文件（目标密钥的父目录须已存在）
xops credential store rewrap file --unlock key-file --key-file /secure/xops-new.key

# 使用新的数据加密密钥重新加密库内所有凭据
xops credential store reencrypt file

# 预览可清理的历史版本，确认后加 --apply 执行清理
xops credential store prune file
xops credential store prune file --apply
```

- **`rewrap` 与 `reencrypt`**：`rewrap` 仅更换外层解锁材料；`reencrypt` 重新生成内部数据加密密钥并重加密全部条目。更换解锁方式或密钥路径后，请按命令输出提示更新 `xops_config.yaml`，并在确认新材料可用前保留原密钥与备份。
- **超时与中断恢复**：维护命令默认超时为 30 分钟（可用 `--maintenance-timeout 45m` 调整）。若维护中途中断，请勿手动删除库内临时文件，直接运行 `xops credential store resume file` 继续（若已切换解锁材料但尚未更新配置文件，可显式加上 `--unlock` 与 `--key-file`）。

## 备份与恢复

- **备份要求**：备份前先停止对源库的写入，同时备份**配置文件**、**整个离线库目录**和**解锁密钥文件**，并将密钥备份与库目录备份分开存放。
- **从备份恢复**：恢复前先把备份复制到一个可写工作目录，保留原始备份不动。当前配置中的目标库（如 `file`）应指向一个新的、尚未初始化的目录，并配好目标解锁材料（源目录与目标目录不能相同或互相包含）：

```bash
xops credential store restore file --from /backup/work/credentials \
  --source-unlock key-file --source-key-file /backup/work/credentials.key \
  --backup-config /backup/work/xops_config.yaml
```

- `--backup-config` 必须是可信的 Schema v2 备份配置文件，用于校验待恢复的凭据引用（`restore` 不会自动替换你当前的节点配置）。若源库使用主口令，将源参数改为 `--source-unlock prompt` 并去掉 `--source-key-file`。
- 若跨目录恢复中途中断，使用相同的源参数继续恢复：

```bash
xops credential store resume file --from /backup/work/credentials \
  --source-unlock key-file --source-key-file /backup/work/credentials.key
```

若原密钥丢失且没有任何备份，新生成的密钥无法解密旧库——此时请勿覆盖原库；若确实无法找回解锁材料，只能重新录入凭据。完整命令参数与 `clone` 操作见[离线库命令参考](../reference/commands/xops-credential-store)。
