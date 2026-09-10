# 离线加密凭据库

`encrypted-file` 已接入配置、命令和凭据引用调用链。当前实现开放 Linux amd64，
不按文件系统类型限制访问；由用户选择能可靠提供锁、原子替换和文件/目录同步的存储。
ext4、XFS、Btrfs 是主流本地文件系统的验证范围，不是准入白名单。
Windows/macOS 等未实现平台仍返回 unsupported；实际文件操作不受支持或同步失败时
明确报错，不省略必要操作。阶段 F 本地、原生部署及隔离 KVM
断电验收已完成；[格式与接口 v1 已冻结](design/offline-encrypted-credential-store-v1-freeze.md)，发布状态为未发布。默认后端仍为 none，启用必须显式配置，不会自动降级到其他后端。

## 配置

在现有配置的 credential.stores 中添加离线库，例如：

```yaml
credential:
  default_store: offline
  remember_prompted: ask
  stores:
    offline:
      type: encrypted-file
      path: ./credentials/offline
      unlock: prompt
      unlock_idle_ttl: 5m
      prompt_timeout: 2m
      unlock_timeout: 30s
      timeout: 10s
      cache_ttl: 0s
      read_only: false
```

相对 path 和 key_file 以实际配置文件目录为基准。内存配置未提供基准时只能使用
绝对路径。超时字段省略使用上述默认值；显式零值、负值无效，idle TTL 最长 30m。
cache_ttl 可以为零，表示禁用条目缓存。command、args、prefix 不能用于该后端。

无人值守配置使用 `unlock: key-file` 和 `key_file: /run/credentials/xops.key`，
并可设置 `non_interactive: true`。密钥文件必须为 32 字节，属于当前用户或 root，权限
为 0400 或 0600；库目录必须私有，不能用符号链接或硬链接替代受保护文件。管理员负责通过
受控方式准备、交付及备份密钥文件，XOps 不生成或删除密钥文件。

主口令仅通过隐藏终端输入，不支持口令 argv 或环境变量。新口令至少十二个 Unicode
字符，初始化与重包裹会二次确认。key-file 与 prompt 不能同时配置。

## 初始化、检查与轮换

```sh
xops credential store init offline
xops credential store inspect offline
xops credential store inspect offline --verify --json
xops credential store rewrap offline
xops credential store rewrap offline --unlock key-file --key-file /run/credentials/new.key
xops credential store reencrypt offline --maintenance-timeout 30m
xops credential store resume offline
xops credential store prune offline
xops credential store prune offline --apply
```

init 要求已配置、未初始化的目标，不更改 default_store。父目录须已存在且通过
安全检查。inspect 默认只读未认证元数据；--verify 使用允许的解锁材料认证元数据
和预算，并不代表对所有秘密做完整备份验证。doctor 不解锁、不初始化、不写测试秘密。

rewrap 保留 DEK，复制密文并共享预算；reencrypt 使用新 DEK。模式转换后按命令
提示显式更新配置；发布后配置尚未更新时，可用 resume 的 --unlock/--key-file 提供
目标材料。所有维护命令接受正值 --maintenance-timeout，默认总期限 30m。

resume 的 --operation 可限定事务 ID。恢复不推测最新目录，不支持 --force。
预算或状态异常可能要求重新构建目标，不能手工重置预算以继续使用旧 DEK。
prune 默认只展示计划，--apply 才删除经认证提交关系授权的旧修订；未知孤立目录保留。
GC 仍只清理配置已解除引用的条目，prune 负责库的旧修订，二者职责不同。

--json 的 code/op/outcome 为机器可读结果，仅包含元数据；Applied 与 Durable
分别报告发布和耐久确认。命令失败返回非零退出状态，不能仅凭文件存在或阶段编号
判断提交成功。

## 克隆与备份恢复

先在配置中声明新目标库，再执行：

```sh
xops credential store clone offline --to independent
xops credential store restore offline --from /backup/work/vault \
  --source-unlock key-file --source-key-file /backup/work/vault.key \
  --backup-config /backup/work/config.yaml
```

克隆产生新 VaultID、目标 StoreID 和 DEK，保留 ItemID。恢复保持原 StoreID/VaultID，
使用新 DEK 和更高修订；目标必须未初始化。restore 额外要求显式选择可信 schema-v2
备份配置，从中提取该 StoreID 的引用并逐个验证，不隐式导入或替换当前配置。
备份配置只含引用；v1 先使用已有 migrate 流程转换。

源库必须停写。由于跨库事务会在源工作目录写入维护镜像，应先把归档复制到隔离、
可写工作目录，不直接操作只读挂载或唯一备份。新目标不能与源相同或互为祖先目录。
源主口令模式使用 --source-unlock prompt；不能同时提供 --source-key-file。

跨库恢复继续显式指定源，例如：

```sh
xops credential store resume independent --from /backup/work/vault \
  --source-store offline --source-unlock key-file \
  --source-key-file /backup/work/vault.key
```

source-store 默认为目标 StoreID，clone 恢复必须填写原源 StoreID。不从事务日志
加载任意源路径。源材料与目标材料分开处理；目标模式改变时用 --unlock/--key-file
明确目标。

## 调用方与生命周期

CLI 进程中的 SSH/SFTP/SCP/exec、配置编辑、导入和凭据 Service 借用同一 Runtime，
退出时等待清零与文件、KDF 子进程回收。TUI 列表中 Ctrl+L 锁定当前进程已打开的库，
Ctrl+U 解锁默认离线库，退出等待回收。TUI 普通后台操作不发起主口令提示，需先
显式解锁；已解锁会话可供非交互请求使用。TUI 启动的独立 SSH CLI 子进程拥有自己的
Runtime，不能通过其他进程控制 TUI 会话。

MCP、Playbook 和批处理不得发起或加入主口令输入，可自动解锁 key-file。配置引用
不可用时返回错误，不把失败转为服务器密码提示，也不回填明文到配置。

v1 migrate/finalize 使用同一工厂；迁移前先初始化目标库。finalize 只删除旧 v1
材料，不删除离线库或独立密钥文件。若 key_file 与旧 secret.key 或迁移备份文件
重叠，迁移或 finalize 会拒绝执行；应先把库重包裹到独立、安全的密钥文件并更新配置。条目缓存由库会话管理，每次命中仍核对 CURRENT
和条目内容，不叠加通用 CachedStore。配置后端策略变更需要关闭旧 Runtime 并重新
构造，当前命令不提供跨 Runtime 热替换或 IPC。

嵌入调用方使用 `config.NewEncryptedRuntime(ctx, configPath, prompt)`，通过其
Registry/Store 注入服务，最后必须调用 Close 并处理错误。独立 BuildStore 工厂
缺少所有者时不会偷偷创建离线 Runtime。密码输入 Provider 为 nil 时失败关闭。
