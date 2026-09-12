# 凭据迁移

本指南描述当前源码中的迁移功能；已安装版本支持的选项以 `xops credential migrate --help` 为准。

## 自动升级旧配置

正常连接、TUI、MCP、Playbook 等 CLI 使用入口会自动把符合条件的 Schema v1 配置升级为引用式 Schema v2。没有后端配置时使用默认离线库；显式 `none`、`remember_prompted: never` 或单次 `--remember never` 禁止自动迁移，仍允许显式迁移。成功后保留旧配置和 `secret.key`；失败保留现有配置和恢复材料。只读命令不触发升级。

启动阶段的自动迁移始终禁止凭据交互，包括 MCP、Playbook、批量命令和 TUI 初始化。需要解锁或不能保证非交互的后端会产生迁移警告，不弹出终端、pinentry 或系统密钥库对话框；保留现有配置和恢复材料。解锁后可重试，或显式执行迁移。

也可手动迁移旧配置，目标必须已配置且可写：

```bash
xops credential migrate --dry-run --to file
xops credential migrate --to file
```

验证 SSH、SFTP、exec、提权及自动化入口后，显式清理 v1 旧配置备份和旧密钥：

```bash
xops credential finalize-migration
```

该清理命令只处理 v1 旧材料，不删除任何后端中的凭据，也不清理 v2 后端迁移备份。

## 从离线库迁往其他后端

在现有配置的 `credential.stores` 中添加目标，保留所有已有字段、库和引用。例如添加 `system` 后，相关配置可以是：

```yaml
credential:
  default_store: file
  remember_prompted: always
  stores:
    file:
      type: encrypted-file
      path: credentials
      unlock: key-file
      key_file: credentials.key
    system:
      type: system
```

`system` 需要可访问且已解锁的系统密钥库。Linux 还需要 `secret-tool`、用户 D-Bus 会话和 Secret Service；仅安装命令不代表服务可用。`pass` 或 `helper` 也可作为目标，配置与依赖见[凭据存储](./credentials)及[配置示例](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml)。

```bash
xops credential doctor
xops credential migrate --dry-run --to system
xops credential migrate --to system
```

迁移覆盖当前配置中所有不在目标库的登录密码、私钥解锁口令和提权密码引用。共享引用只复制一次；已在目标库的引用保持不变。写入、读回验证成功后，使用配置冲突检查一次性切换引用，并将 `default_store` 改为目标库。`remember_prompted` 保持原值。只修改 `default_store` 不会搬迁已有凭据；配置未引用的历史凭据也不会搬迁。

`--dry-run` 不写入文件、凭据或密钥，只检查计划及读取路径，不证明目标库可写。尚未创建的离线目标可通过计划检查，实际初始化在迁移写入时进行。目标若无法保留源凭据的到期信息，读回校验会拒绝切换。

## 迁回离线库

保留原 `file` 配置及库、密钥，执行：

```bash
xops credential migrate --dry-run --to file
xops credential migrate --to file
```

原 key-file 存在时直接使用。只有确认是新库时才允许生成密钥；已有库丢失密钥或存在未完成的库事务时，应先按[离线库恢复指南](./offline-store#备份与恢复)恢复。

## 中断、冲突与保留材料

迁移中断后先修复后端访问问题，再重跑同一命令。迁移会复用记录中的目标引用，校验已写入内容；写入或持久化结果不确定时不删除任何源凭据。配置已经切换但验证尚未完成时，重跑会重新验证并确认配置持久化。

并发配置修改会导致冲突并保留当前配置。确认当前配置是希望保留的版本后，可显式重新规划：

```bash
xops credential migrate --to system --restart
```

`--restart` 仅适用于 v2 实际迁移，不能与 `--dry-run` 合用。它归档旧计划，从当前配置重新分配目标引用；不回滚配置，也不删除此前写入的凭据。配置未改变的普通中断应重跑原命令，无需 `--restart`。

v2 迁移在配置文件旁保存 `<配置文件>.backend-migration.json` 和 `<配置文件>.v2.<源配置摘要>.bak`；后续迁移或重新规划会把旧记录归档为 `.backend-migration.json.<记录摘要>.bak`。这些文件只有配置元数据和引用，不包含凭据值。v1 的 `.migration.json`、`.v1.bak` 和 `.v1.key.bak` 独立保留，不会被后端迁移覆盖。尚未验证完的 v1 迁移须先重跑原命令完成验证，无须提前删除旧材料。

验证实际连接后仍保留源库与备份，本命令没有自动源库清理。恢复旧配置需要对应源库和密钥仍可用；不要只备份引用配置。手动删除历史凭据前，应检查其他配置和备份是否仍引用它们，并使用对应后端的管理工具。`finalize-migration` 不能用作跨后端通用清理命令。
