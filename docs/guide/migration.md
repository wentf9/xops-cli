# 凭据迁移

旧 Schema v1 配置通过显式迁移转换为引用式 Schema v2。迁移前保留旧配置、`secret.key` 和可用备份，并确认目标后端已配置。

```bash
xops credential doctor
xops credential migrate --dry-run --to system
```

dry-run 不写入凭据或迁移文件，只生成迁移计划并检查读取路径；不保证写入权限。

确认目标后端正确后执行：

```bash
xops credential migrate --to system
```

迁移过程会做备份、写入和读回检查。中断后应按迁移状态恢复，不要手动删除备份或状态文件。验证 SSH、SFTP、批处理等实际使用入口均正常后，才显式完成清理：

```bash
xops credential finalize-migration
```

`--to` 也可指定已配置的其他目标存储。完整恢复与边界说明见[迁移设计和操作记录](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/credential-migration.md)。
