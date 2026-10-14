# core/ — 公共模块边界

必须先参考 `core/README.md` 和 `docs/development/shared-core-decoupling.md`。

- `core/` 是可被独立消费者提取的共享代码子树，当前仍与 CLI 共用根模块；**不能 import 根 `cmd/`、`pkg/`、`internal/`，不能引入消费者 `xops-mcp` 的依赖**。
- core 接收显式环境、凭据来源、信任验证器、状态源、Gate/Permit、执行后端及日志接口；应用默认路径/个人目录/OS 环境/CLI 输出应在宿主注入。
- 不创建 `pkg/ssh`、`pkg/sftp`、`pkg/mcpserver` 等已迁移的平行旧 API。
- 分辨不可变 plan 与实际授权：plan/digest 并非许可；`RetirePlan` 并非撤销授权。
- 核心公共接口与 `internal/clicontract` fixture 变更要求兼容性审查，不能“更新快照让测试过”。
- 改动验证：`python3 -m unittest discover -s scripts -p test_check_core.py`、`python3 scripts/check_core.py --race`；必要时测试消费者兼容性。
