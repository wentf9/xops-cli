# pkg/config/ — 配置读取、版本、事务与连接目标

- `Repository`（`repository.go`）是持久化变更边界；`Provider`（`provider.go`）负责一致的内存读快照，应用侧写入不要绕过仓库层。
- `Store`/`TransactionStore`（`store.go`）区分已应用与已持久化，`Applied=true, Durable=false` 不是“失败即可安全重试”。禁止掩盖这种部分成功。
- 重要变更必须检查 revision、NodeRef/IdentityRef、并发 CAS 冲突、配置克隆/解析/索引、节点/身份/跳板引用。
- `schema_v2.go`、`target.go`、`repository_execution.go` 等属于对外配置行为，变更要维护旧配置兼容性与 round-trip 测试；探测配置保存要受 NodeRef 约束，不能覆盖并发编辑。
- 凭据只保存引用，不恢复向遗留明文字段写值；加密凭据生命周期由 `EncryptedRuntime` 与服务层管理。
- 默认验证：`go test ./pkg/config ./pkg/adapter ./cmd/host`；涉及配置序列化需补 `go test ./internal/clicontract`；涉及持久化/跨进程锁需增加集成或故障注入测试。
