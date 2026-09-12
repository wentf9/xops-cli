# 离线凭据库

离线库将凭据加密保存在本机，支持 Linux、Windows 和 macOS 的 amd64/arm64 平台。新安装默认使用名为 `file` 的库，通过独立密钥文件解锁。默认配置和保存策略见[凭据存储](./credentials)。

## 初始化与检查

默认 key-file 模式在首次保存时自动初始化。也可手动初始化已配置、尚未创建的库：

```bash
xops credential store probe file
xops credential store init file
xops credential store inspect file
xops credential store inspect file --verify
```

`probe` 使用临时数据检查目录是否支持文件锁、原子替换和同步，不读取或写入凭据，也不能保证断电时的数据安全。请使用可靠的存储，并保留备份。

`init` 要求库的父目录已存在。配置的密钥文件不存在时会生成 32 字节随机密钥；已有合规文件直接复用。密钥文件须位于库目录之外。Unix 上密钥文件应属于当前用户或 root，权限为 `0400` 或 `0600`；新生成的文件权限为 `0600`。不要用链接替代密钥文件。

`inspect` 默认只显示元数据；`--verify` 使用密钥或主口令验证元数据，不等于逐条验证所有凭据。读取、检查及解锁都不会初始化新库，也不会为已有库生成替代密钥。

## 使用主口令

需要每次运行时手动解锁时，可在 `credential.stores` 中添加主口令库：

```yaml
offline:
  type: encrypted-file
  path: credentials-offline
  unlock: prompt
  unlock_idle_ttl: 5m
```

然后初始化：

```bash
xops credential store init offline
```

主口令通过隐藏输入提示设置，至少十二个字符，需输入两次确认。不要将主口令放入命令参数或环境变量。初始化不会自动更换默认存储；已有凭据迁入该库的方法见[迁移指南](./migration)。

在 TUI 中，`Ctrl+U` 解锁默认离线库，`Ctrl+L` 锁定当前进程已打开的库。解锁状态不跨进程共享。MCP、Playbook 和批处理不会提示输入主口令；无人值守任务应使用可非交互访问的存储，如 key-file 模式。

## 轮换密钥与清理旧版本

```bash
# 更换解锁密钥，目标路径的父目录须已存在
xops credential store rewrap file --unlock key-file --key-file /secure/xops-new.key

# 使用新的数据加密密钥重新加密凭据
xops credential store reencrypt file

# 查看可清理的旧版本，再执行清理
xops credential store prune file
xops credential store prune file --apply
```

`rewrap` 更换解锁材料，`reencrypt` 重新加密库内数据。更改解锁方式或密钥路径后，按命令提示更新配置。确认新材料可用前，请保留原密钥和备份。

维护命令默认超时为 30 分钟，可通过 `--maintenance-timeout 45m` 调整。维护中断后使用 `xops credential store resume file`；若已切换解锁材料但尚未更新配置，可用 `--unlock` 和 `--key-file` 指定目标材料。不要手动删除中断操作留下的文件。

## 备份与恢复

备份前停止对源库的写入，保存配置文件、整个库目录和解锁材料。密钥备份与库文件备份应分开保管。恢复时先把备份复制到可写工作目录，保留原始备份。

以下示例恢复名为 `file` 的库。当前配置中的 `file` 应指向新的、尚未初始化的目标目录，并配置目标解锁材料；源和目标目录不能相同，也不能互相包含：

```bash
xops credential store restore file --from /backup/work/credentials \
  --source-unlock key-file --source-key-file /backup/work/credentials.key \
  --backup-config /backup/work/xops_config.yaml
```

`--backup-config` 必须是可信的 Schema v2 备份配置，用来验证待恢复的凭据引用。恢复命令不会自动导入或替换当前主机配置。源库使用主口令时，改用 `--source-unlock prompt` 并去掉 `--source-key-file`。

跨库恢复中断后，继续显式指定源目录及源解锁材料：

```bash
xops credential store resume file --from /backup/work/credentials \
  --source-unlock key-file --source-key-file /backup/work/credentials.key
```

丢失原密钥且没有可用备份时，新生成的密钥无法解密旧库。请勿覆盖原库；如无法找回解锁材料，需要重新录入凭据。

完整参数及克隆操作见[离线库命令参考](../reference/commands/xops-credential-store)。
