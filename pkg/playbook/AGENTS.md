# pkg/playbook/ — 批量/声明式编排

- `engine.go` 负责目标与执行配置快照及任务调度，`runner.go` 负责 step 分发、运行与重试，`loader.go` 负责读取和解析；远程执行必须复用 `core/ssh` 与 `core/sftp`。
- 变更先明确 shell/script/copy/ensure/template 各自语义；关注 `settings.on_error`、并发、取消和结果报告。
- `ExecutionConfig` 由全局、节点、步骤层组合；保持计划与脚本源快照一致，不允许批量运行中随配置漂移。
- 远端结果为 unknown、存在清理或 IO 错误时，不能盲目重试可能已有副作用的操作；重试策略必须与 `StepResult` 保持一致。
- 先跑 `go test ./pkg/playbook ./core/ssh`，修改 CLI 命令入口后跑 `go test ./cmd`，再选择 race/平台验证。
