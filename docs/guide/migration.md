# 凭据迁移

`xops credential migrate` 用于将旧版 Schema v1 配置升级为 Schema v2，或在不同的 Schema v2 凭据后端之间搬迁凭据。支持的具体参数可通过 `xops credential migrate --help` 查看。

## 场景一：从旧版（Schema v1）配置升级

v0.12.0 与 v0.13.0 的 Schema v1 自动兼容期已结束。当前版本的 CLI、TUI、MCP 和 Playbook 仅接受 Schema v2 配置（缺少 `schema_version` 的旧文件同样按 v1 拒绝，并提示执行迁移）：
- **切勿手动改版本号**：不要直接把 YAML 中的 `schema_version` 手工改为 `2`——Schema v2 不接受明文或 `ENC:` 加密字段，必须通过 `credential migrate` 将密码写入凭据库并转换为引用。
- **先备份再迁移**：迁移前请先备份旧配置文件和 `secret.key`（若旧配置含有 `ENC:` 字段且丢失了原 `secret.key`，需先从备份找回，迁移器不会生成替代旧密钥）。

```bash
# 1. 预检迁移计划（只读，不修改任何文件或密钥）
xops credential migrate --dry-run --to file

# 2. 执行迁移（若配置中尚未声明后端，会自动补齐默认离线 file 库配置）
xops credential migrate --to file

# 3. 验证日常 SSH、SFTP、exec、提权与 Playbook 正常可用后，清理 v1 遗留备份和 secret.key
xops credential finalize-migration
```

`finalize-migration` **仅清理 v1 升级留下的旧配置备份与 `secret.key`**，不会删除任何凭据库中的凭据，也不会清理 v2 跨后端迁移备份。

## 场景二：在 Schema v2 不同后端之间迁移

### 1. 从默认离线库迁往系统密钥库或其他后端

只修改配置中的 `default_store` 不会搬迁已有凭据。如需将离线库（`file`）中的凭据迁入系统密钥库（`system`）、`pass` 或 `helper`：

**第一步**：在 `~/.xops/xops_config.yaml` 的 `credential.stores` 中添加目标后端（保留原有的 `file` 库和所有现有引用）：

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

> 使用 `system` 时，系统密钥库必须可访问且已解锁（Linux 还需安装 `secret-tool` 并具备活动的 D-Bus 会话与 Secret Service）。其他后端配置见[凭据存储](./credentials)及 [`xops_config.example.yaml`](https://github.com/wentf9/xops-cli/blob/master/xops_config.example.yaml)。

**第二步**：检查存储状态并执行迁移：

```bash
xops credential doctor
xops credential migrate --dry-run --to system
xops credential migrate --to system
```

- **迁移范围与原子切换**：迁移器会复制当前配置引用的所有登录密码、私钥口令和提权密码（多个节点共享的同一引用只复制一次；已在目标库的引用和未被当前配置引用的历史孤儿条目不会搬迁）。全部写入并读回校验通过后，一次性将配置引用和 `default_store` 切换为 `system`（`remember_prompted` 保持不变）。
- **`--dry-run` 边界**：仅检查迁移计划和源读取路径，不写入任何文件或凭据，也不测试目标库写权限；若目标后端不支持保留源凭据的到期时间元数据，正式迁移的读回校验会拒绝切换。

### 2. 迁回离线凭据库

保留原 `file` 库配置与密钥设置，执行：

```bash
xops credential migrate --dry-run --to file
xops credential migrate --to file
```

若原 `credentials.key` 存在会直接复用；仅当确认目标是全新离线库时才会生成新密钥。若已有离线库丢失密钥或存在未完成的事务，请先按[离线库恢复指南](./offline-store#备份与恢复)恢复。

## 中断恢复、并发冲突与备份保留

- **普通中断直接重跑**：若迁移中途因后端锁定或超时中断，修复访问问题后**直接重跑原命令**即可。迁移器会复用已记录的目标引用并校验已写入内容；在写入或配置持久化未完全确认前，绝不会删除源凭据。
- **配置冲突时使用 `--restart`**：若迁移期间其他终端修改了配置文件导致冲突，确认当前配置无误后，可用 `--restart` 归档旧迁移计划并基于最新配置重新分配目标引用（仅用于正式 v2 迁移，不可与 `--dry-run` 同用，也不会回滚配置或删除已写入凭据）：

```bash
xops credential migrate --to system --restart
```

- **备份与记录文件说明**：
  - v2 跨后端迁移会在配置文件旁生成 `<配置文件>.backend-migration.json` 和 `<配置文件>.v2.<源配置摘要>.bak`（重规划时归档为 `.backend-migration.json.<摘要>.bak`），其中仅含引用与元数据，不含明文密码。
  - v1 升级生成的 `.migration.json`、`.v1.bak` 和 `.v1.key.bak` 与 v2 迁移互不覆盖。
  - **源库保留**：v2 跨后端迁移完成后，源凭据库中的数据和备份文件会继续保留（不会自动清空源库）。手动清理旧后端凭据前，请确认没有其他配置文件或备份仍在引用它们。
