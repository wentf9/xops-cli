# core/ssh/ — SSH 连接和远程执行（高风险）

先读 `core/README.md` 中连接租约与命令计划说明、`docs/development/ssh-execution-compatibility.md`、`docs/development/ssh-execution-implementation.md` 与最新 probe 文档。

- `Connector`（`connector.go`）负责连接/缓存/生命周期；连接计划 `ConnectPlan` 返回 `PlanConnection` 租约，释放租约不应关闭其他借用者的共享连接；核对 `RetirePlan` 语义。
- 命令计划位于 `command_plan.go`，执行位于 `command_execution.go` 等。计划冻结解释器、启动方言、登录方式、输入、限额；**默认 `server` 直通，不应擅自包装 Bash/POSIX**。
- 执行结果要保留 `not_started/completed/unknown` 与执行、IO、cleanup 错误分类；结果未知时禁止自动重放。
- 会话请求、远程命令、PTY、流式输入输出、取消、shutdown、jump、keepalive 必须做生命周期和所有权审查。不能仅在一个 select 中添加 context 就宣称可取消。
- 主机密钥验证严格 fail-closed；不得静默信任新密钥、降低算法安全要求或打印密钥/密码。
- 改动测试先跑相关 test：`go test ./core/ssh -count=1`，并发/取消路径加 `go test -race ./core/ssh -shuffle=on -count=1`；新 shell/OS 行为需要对应真实平台证据，不得仅靠编译推断通过。
