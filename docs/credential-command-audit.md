# 阶段 8 命令凭据接入核对（2026-09-09）

范围：根命令注册表及其子命令，检查引用解析、交互边界、秘密写入和资产删除。
自动化验证使用隔离配置、fake helper 和 loopback。

| 入口 | 读取与写入路径 | 核对结果 |
| --- | --- | --- |
| ssh（含隧道）、sftp | 共用 SSH options、Registry、CredentialService | 已接入，保存确认延后到认证成功 |
| scp | Registry；批量 non-interactive；覆盖值 session-only | 已接入 |
| exec | Registry；批量 non-interactive；交互模式可保存 | 已接入 |
| firewall | 复用 SSH 组装；文件/标签/多目标 non-interactive | 已修复遗漏解析器 |
| play | Registry + non-interactive | 已接入 |
| mcp / mcp serve | Registry 注入 server，非交互解析 | 已接入 |
| tui | Registry、CredentialService、异步编辑与确认器 | 已接入，资产删除含恢复日志与后端清理 |
| sudo、本地 firewall | 本地身份引用按需读取；sudo 遵循 remember | 已接入 |
| host add/edit、identity add/edit | 凭据服务和版本化编辑 | 已接入；新增失败可保留无秘密元数据，遵循阶段 6 约定 |
| host import/load、loadHost | 非交互 Registry；v2 CSV 秘密经凭据服务 | 缺陷修复；逐行原子创建/编辑，验证连接失败保留已提交资产 |
| host list/tags/tag、identity list | 配置元数据 | 不读取后端秘密 |
| host delete、identity delete、TUI 资产删除 | 版本化配置删除 + asset_delete journal | 已修复后端清理缺口，见下文 |
| identity credential set/delete | 凭据服务显式写入/解除引用/清理 | 已接入 |
| credential store list/doctor/gc | 列配置、受限探测、恢复日志 GC | 已接入；GC 不枚举后端所有条目 |
| credential migrate/finalize-migration | 独立迁移器 | 不走普通 v1 加载器；finalize 不影响 v2 引用生效 |
| init | 配置初始化及 OpenSSH 元数据导入 | v2 + none；不访问凭据库 |
| version/help、nc/dns/ping/encode/forward | 版本信息或网络/编码工具 | 无 SSH 凭据消费；forward 是普通 TCP/UDP 转发 |

## 缺陷修复

CSV 导入曾使用未注入 Registry 的验证连接器，且将密码/passphrase 写入配置字段。
v2 导入先写入并读回后端秘密，再一次提交节点/身份和引用；编辑使用完整节点版本
CAS。未配置可写默认 Store 时拒绝导入秘密，不留下该操作创建的元数据。全部后端访问
传递非交互策略，不启动解锁提示。v1 的 AES 导入仅在既定兼容周期内保留。

## 资产删除清理（已修复）

CLI 和 TUI 删除资产前，为所有可能移除的登录密码、私钥口令与提权密码引用写入
asset_delete journal，并持有日志条目的进程锁。随后以原实体版本执行一次配置删除，
后台 I/O 不进入配置锁。意图记录失败或 CAS 失败时不删除资产或后端秘密。

Applied 非 Durable 时保留秘密和日志；配置 durable 后再检查全局引用与磁盘耐久性，
仅删除已无引用的条目。共享身份/共享凭据仍被其他资产引用时保留秘密。后端锁定、
不可用或清理失败时配置删除已经生效，命令返回 CleanupError，TUI 刷新列表并提示
运行 credential gc。GC 有未完成条目时返回非零结果；重复调用可重试。

恢复根据当前持久化引用是否存在做决定，不要求已经删除的节点或身份仍存在。
测试覆盖各类失败、进程提交前后退出、fresh service 恢复、共享引用和 TUI 异步删除。

修复前已经删除资产且未记录 journal 的历史孤立条目无法由当前 GC 自动发现；
修复不会猜测或删除真实后端中的这些条目。需要根据旧备份或后端管理工具人工核对。
