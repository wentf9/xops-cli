# 凭据持久化实施计划

## 1. 实施原则

- 开始实现前将 ADR-0001 从“提议”更新为“接受”；
- 结构重构和行为变化分别提交；
- 每个阶段从干净、已提交且测试通过的基线开始；
- 新增功能或修复必须在同一阶段补充测试；
- 不在配置 Repository 的锁内执行 keyring、GPG、子进程或其他 I/O；
- 不以通过现有测试代替取消、资源释放和故障恢复验证。

## 2. 影响面

| 区域 | 主要变化 |
| --- | --- |
| `pkg/models` | 秘密值替换为 CredentialRef |
| `pkg/config` | Schema v2、ref 版本计算、迁移兼容 |
| `pkg/credential` | Registry、Service、Cache、Journal |
| `internal/credentialhelper` | helper 协议及进程生命周期 |
| `pkg/ssh` | 拆分配置、解析和记录接口；收紧明文生命周期 |
| `pkg/adapter` | 配置和凭据系统的组合适配 |
| `cmd` | stdin、remember、credential 管理命令、旧 flag 弃用 |
| `pkg/tui` | stored 状态与 keep/replace/delete |
| `pkg/mcpserver` | 非交互 Store 注入和错误映射 |
| 文档/示例 | Schema、命令帮助、迁移和安全模型 |

## 3. 阶段 0：决策与安全网

目标：不改变生产行为，记录现状并补足特征测试。

工作项：

- 确认 ADR 三个决策门并更新状态；
- 为 `Store.Load/Save`、`Provider.Snapshot`、`SSHAdapter.GetConfig` 建立特征测试；
- 覆盖 `auth_type:auto` 成功后写回；
- 覆盖共享 Identity 创建节点私有覆盖；
- 覆盖 MCP 非交互失败；
- 建立秘密泄露断言辅助函数，检查 YAML、日志、错误和命令输出。

退出条件：现有行为被测试固定，尚无生产代码结构变化。

建议提交：

```text
test: characterize credential persistence behavior
docs: accept credential persistence architecture
```

## 4. 阶段 1：拆分 SSH 端口

目标：行为保持不变，将当前 `ssh.ConfigStore` 拆成：

- `ConnectionProvider`；
- `SecretResolver`；
- `CredentialRecorder`。

旧适配器仍从当前明文配置返回秘密，确保此阶段只是结构重构。使用编译期接口检查，更新
所有 CLI、TUI、MCP、SFTP、Playbook 和测试构造点。

测试：

- 所有既有 SSH 认证测试；
- nil/default resolver 的 fail-closed 行为；
- context 透传；
- `go test -race` 重复运行连接与关闭测试。

建议提交：

```text
refactor: split ssh credential provider contracts
```

## 5. 阶段 2：收紧明文生命周期

目标：拆分 `ConnectionConfig`、`AuthMaterial`、`PrivilegeMaterial`，但仍以旧 Store 作为秘密
来源。

工作项：

- 登录密码不再保存在池化 Client；
- passphrase 在生成 signer 后释放；
- sudo/su 执行按命令解析秘密；
- 清理所有返回路径上的临时字节；
- 保持 Prompt Gate、握手协调和 HostKey 行为不变。

测试：

- 使用探针 resolver 证明读取发生在需要点；
- 登录成功后 Client 不保留 AuthMaterial；
- sudo 并发执行无竞态；
- 取消时 resolver 和执行立即退出；
- goroutine leak 测试。

建议提交：

```text
refactor: limit ssh credential plaintext lifetime
```

## 6. 阶段 3：Credential 核心与 Schema v2

目标：引入新模型，但不切换默认运行路径。

工作项：

- `CredentialRef`、Kind、验证和 sentinel errors；
- Store Registry；
- 有界 lazy cache；
- 非敏感恢复 journal；
- Schema v2 DTO 和严格验证；
- ref 参与认证和提权版本哈希；
- v1/v2 格式探测。

测试：

- 引用验证和 YAML round-trip；
- 配置快照不存在秘密字段；
- 缓存 TTL、容量、复制和失效；
- journal 原子写入与崩溃阶段恢复；
- 并发 Registry/Cache race 测试。

建议提交：

```text
feat: add credential reference model and registry
feat: add credential recovery journal
```

## 7. 阶段 4：Helper 协议和后端

目标：实现协议 v1 和首批 Store。

顺序：

1. fake helper：覆盖协议和故障注入；
2. `none`：固定 fail-closed 语义；
3. `system`：Windows、macOS、Linux 适配；
4. `pass`：headless Linux；
5. `external`：任意只读/读写 helper。

测试：

- 协议版本、未知字段、非法 Base64、输出超限；
- not-found/locked/unavailable/denied/read-only 映射；
- context 超时、父进程取消、helper 崩溃；
- Unix 进程组和 Windows Job Object 清理；
- pipe close、Wait 错误和 stderr 截断；
- 确认秘密不在 argv、日志和错误中；
- Linux/Windows/macOS 原生集成测试。

系统后端库必须先做独立 spike，验证真实系统上的解锁、超时、签名变化和错误映射，再
决定依赖；不得只依赖 mock 测试选型。

建议提交：

```text
feat: add credential helper protocol
feat: add system credential helper
feat: add pass and external credential helpers
```

## 8. 阶段 5：双存储写入服务

目标：实现 copy-on-write、CAS、补偿和恢复。

工作项：

- 新增、轮换、删除服务；
- journal 状态机；
- Repository 新增只写 ref 的版本化 API；
- 共享 Identity 的节点私有覆盖；
- cleanup/GC；
- Applied/Durable 与 Store 清理组合错误。

故障注入矩阵至少覆盖：

- intent 写入失败；
- Put 失败或不确定；
- 读回不一致；
- 配置 CAS 冲突；
- 配置未 Applied；
- Applied 但目录 sync 失败；
- 旧 ref 删除失败；
- 每个阶段进程崩溃后重新运行恢复。

建议提交：

```text
feat: coordinate credential and configuration updates
```

## 9. 阶段 6：调用方接入

### CLI

- 新增 `credential store list`、`doctor`、`gc`；
- 新增 `identity credential set/delete`；
- 增加 `--password-stdin`、`--passphrase-stdin`；
- 增加 `--remember=ask|always|never`；
- 旧秘密值 flag 输出弃用警告，下一正式版本删除。

### TUI

- 删除秘密回填；
- 显示 Store 状态；
- 使用 keep/replace/delete；
- 持久化放入现有异步状态机，禁止阻塞 Update。

### MCP/Playbook/批处理

- 注入非交互 SecretResolver；
- 禁止解锁提示；
- 统一错误映射；
- 默认禁止记录自动发现的秘密。

建议按文件冲突关系顺序实施，CLI 与 TUI 可在核心接口稳定后并行，MCP 和 SSH Adapter
应顺序实施。

建议提交：

```text
feat: add credential management commands
feat: use credential references in tui
feat: enforce non-interactive credential access in mcp
```

## 10. 阶段 7：显式迁移

目标：安全完成 v1 到 v2 转换。

命令：

```text
xops credential migrate --dry-run --to <store>
xops credential migrate --to <store>
xops credential finalize-migration
```

步骤：

1. 校验目标 Store；
2. 创建权限为 `0600` 的旧配置备份；
3. 使用旧 key 解密，但不发布到 Provider；
4. 创建 refs 并全部写入、读回；
5. 原子提交 Schema v2；
6. 重新加载并检查 YAML、Snapshot 和引用完整性；
7. 保留旧备份和 key 以供回滚；
8. 用户验证后显式 finalize，删除旧材料。

测试必须在每一步注入失败和崩溃，并验证至少存在一个可恢复的秘密副本。

建议提交：

```text
feat: migrate encrypted credentials to configured stores
```

## 11. 阶段 8：默认切换和兼容清理

- 新安装写 Schema v2；
- 桌面仅在 doctor 通过后建议 system；
- headless 保持 none，提示 pass/external；
- v1 普通运行按 ADR 确认的发布周期告警；
- 兼容期结束后普通命令拒绝 v1，迁移器继续可用；
- 最后移除 AES 写入和自动创建 `secret.key` 的路径。

建议提交：

```text
feat: default new configurations to credential references
chore: remove legacy credential encryption writes
```

## 12. CI 与本地门禁

每个代码阶段必须运行：

```bash
go build ./...
go test ./...
go test -race ./...
golangci-lint run ./...
```

修改 `.golangci.yml` 时额外运行：

```bash
golangci-lint config verify
```

平台验证：

- Linux：fake helper、`pass` 集成、可选 Secret Service 集成；
- Windows：Credential Manager 与 Job Object 取消；
- macOS：Keychain、签名/重编译访问和取消；
- headless：无 D-Bus、无 TTY、Store 锁定和 agent-only 场景。

## 13. 风险登记

| 风险 | 缓解措施 |
| --- | --- |
| 双存储非原子 | 不可变 ref、CAS、journal、GC |
| helper 不响应取消 | 独立进程树、超时、Wait |
| headless Secret Service 不可用 | 默认 none，显式 pass/external |
| 同用户进程可读系统密钥库 | 文档明确威胁模型，推荐 agent/远程动态凭据 |
| TUI 意外清空密码 | 显式 keep/replace/delete |
| 旧版本无法读取 v2 | 备份、兼容周期、显式 finalize |
| secret 出现在 argv/log | stdin 协议、泄露测试、稳定错误分类 |
| 缓存扩大暴露面 | 有界 TTL、容量、清零、可禁用 |

## 14. 完成定义

只有同时满足以下条件才算完成：

- ADR 决策已接受并与实现一致；
- Schema v2 成为新安装默认；
- 所有配置和展示路径不含秘密；
- system、pass、external、none 有契约测试；
- Windows/macOS/Linux 的关键原生行为有验证记录；
- 迁移故障矩阵全部通过；
- 文档、示例配置、CLI 帮助和中英文 README 同步；
- 完整 build/test/race/lint 门禁通过。
