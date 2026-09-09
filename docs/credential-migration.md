# 凭据显式迁移（阶段 7）

迁移将 Schema v1 的登录密码、私钥 passphrase 和 sudo/su 密码移入已配置的 Store，
配置文件改为 Schema v2，只保存引用。迁移命令直接读取旧文件，不通过普通配置加载器，
不会把解密结果发布到 Provider，也不会自动生成或替换旧 key。

## 使用步骤

先在旧配置的 `credential.stores` 中配置目标后端。例如：

```yaml
credential:
  default_store: ops-pass
  remember_prompted: ask
  stores:
    ops-pass:
      type: pass
      timeout: 15s
```

然后执行：

```bash
xops credential migrate --dry-run --to ops-pass
xops credential migrate --to ops-pass
# 验证 SSH、SFTP 和提权等实际使用场景后，再执行：
xops credential finalize-migration
```

- dry-run 校验源配置、旧 key、passphrase 对应私钥和目标读取链路，展示迁移数量；
  不创建锁文件、备份或迁移状态，不写入后端。读取成功不代表已验证写权限。
- 有旧秘密时，目标必须可写；`none` 和只读 Store 会被拒绝。
  没有旧秘密、只需要转换配置格式时，可以使用已配置的 `none`。
- 已存在的有效引用保持原样，不复制到目标 Store；若 v1 的 passphrase 引用缺少
  指纹，会读取现有引用并校验私钥，仅补齐元数据。迁移后验证全部引用。
  `default_store` 和 `remember_prompted` 等非秘密设置不因 `--to` 自动改变。
- 迁移 passphrase 时需能读取对应私钥，并用旧 passphrase 解锁取得公钥指纹。
  私钥文件本身不写入 Store。无法解锁时失败，原配置和旧材料保留。
- 源配置只接受受支持字段和单个 YAML 文档，避免迁移时静默丢弃未知配置。
  配置、旧 AES key 和备份必须是普通文件且不能是符号链接；单个迁移输入限制为 16 MiB。
  SSH 私钥路径允许符号链接（包括链接链），但最终目标必须是普通文件且不超过 16 MiB。

## 备份与恢复状态

假设配置为 `~/.xops/xops_config.yaml`：

| 文件 | 内容与用途 |
| --- | --- |
| `xops_config.yaml.v1.bak` | 旧配置的逐字节备份，权限 0600 |
| `xops_config.yaml.v1.key.bak` | 旧 key 的备份，权限 0600；原本无 key 时不创建 |
| `xops_config.yaml.migration.json` | 引用、配置版本摘要和迁移阶段，不含秘密值 |
| `xops_config.yaml.migration.lock` | 防止同一配置的迁移与 finalize 并发执行 |

原 `secret.key` 和备份一直保留到显式 finalize。既有备份内容不同或权限不符合要求时，
迁移不会覆盖它。Windows 的实际文件访问控制仍由当前目录的 ACL 决定。

每个秘密先分配随机不可变引用并写入状态文件，再写后端并读回比较。进程中断或后端
返回不确定结果时，重跑同一 `migrate --to ...` 命令会复用已记录引用：已写入且内容一致
的条目不会重复覆盖。任何失败都不会自动删除旧配置、旧 key 或迁移备份。

后端 I/O 不持有配置锁。最后提交 v2 时重新比较源文件和旧 key 的版本；发生 CAS 冲突，
不会覆盖其他进程的修改，并保留备份与待迁移引用。需先处理并发修改，再恢复到本次
迁移记录的源文件/key 版本后重跑；程序不会擅自回滚或合并这些修改。

提交后会重新读取 v2、检查 metadata-only 快照、引用可读性和迁移值一致性。目录同步
失败或验证中断时，保留新旧材料，重跑迁移完成确认，不对已应用的配置做补偿回滚。

需要手动回滚时，应先保存当前 v2 和迁移状态，停止该配置的并发写入，再将旧配置备份
和旧 key 备份恢复到原路径。不要把 v2 直接交给不支持引用模型的旧版本。保留迁移状态
可让后续重跑复用原引用；不要删除后端中的新条目作为自动回滚步骤。

## finalize 的含义

`finalize-migration` 本身就是用户完成实际连接验证后的显式确认，不会被迁移命令自动
调用。它会：

1. 重新读取当前有效的 v2 配置，不要求非秘密配置仍与迁移当天完全相同；
2. 不使用缓存地读取全部当前引用；仍沿用迁移引用的秘密，还会与旧副本比较；
3. 再次检查配置版本并同步当前文件和目录；
4. 记录 finalizing 状态，删除原 key、旧配置备份、旧 key 备份；
5. 保存 complete 状态，使重复调用不会再次删除后来创建的文件。

后端锁定、缺失、值不一致、旧材料被替换或并发配置修改都会阻止首次删除。
删除到一半失败时，可重跑 finalize；已完成迁移的后端秘密不会被删除。
旧材料被删除后不再保留自动回滚副本，complete 状态文件可以保留用于审计。

已迁移的 v2 通过独立的严格读取/保存路径运行，不再读取或创建 `secret.key`，也不允许
重新写入密码字段。CLI、TUI 和认证成功后的 passphrase 写回会在配置事务外校验私钥，
将公钥指纹与新引用一起提交并记录到恢复日志，满足 v2 对 passphrase 的绑定要求。
新安装的默认格式和普通 v1 的兼容周期仍属于阶段 8，本阶段未切换。

## 验证覆盖

测试覆盖目标校验、intent、备份、key 备份、解密、每个 Put/Get、配置提交、验证和
finalize 删除边界；包含实际子进程退出后由新进程恢复的测试。另有后端写入失败/
结果不确定/读回不一致、CAS 冲突、Applied 非 Durable、备份冲突、缺失 key、
未知字段、keyless plaintext、agent-only 及 finalize 失败的回归测试。
测试均使用隔离文件和 fake 后端，不操作用户的真实凭据库。
