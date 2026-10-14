# pkg/credential/ — 凭据事务与机密边界

- `pkg/credential/service.go` 定义凭据服务与 `ConfigUpdater` 的版本化接口；`pkg/config.Repository` 负责配置引用提交；`internal/credentialfile` 实现加密离线凭据与文件系统事务。
- 修改任何凭据引用、清理、恢复逻辑，先画出“新凭据创建 -> 配置 CAS 提交 -> 提交状态确认 -> 旧凭据清理/后续 GC”的实际路径。
- 明确区分 `Applied`/`Durable`/`CleanupError`/未知结果：提交生效后清理失败不可回滚已生效配置；绝不能把部分成功作为完全失败重试。
- 禁止日志/错误/测试快照包含明文口令、解密缓冲或 bearer token；确认 secret 释放、缓存 TTL、解锁超时及子进程生命周期。
- 更新凭据格式/平台持久化时，检查 `docs/development/compatibility.md`、`internal/credentialfile/format`、离线平台验证工作流；需证据区别真实断电与 CI 崩溃测试。
- 最小验证：`go test ./pkg/credential ./pkg/config ./internal/credentialfile/...`；必要时结合 integration tags 和平台任务。
