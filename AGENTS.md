# AI 助手开发协作指南 (AGENTS.md)

## 0. 优先级与工作模式

- 接受任何开发任务前，先说明：用户目标、相关模块、已定位的源文件、预计更改范围、验证方法、仍需确认的事实。
- **调查 / 文档生成**：默认只读，不修改源码/配置，不运行可能创建凭据、执行远程命令或修改主机的操作。
- **开发**：先提交简短影响分析；跨越两个以上子系统（`core/ssh`, `core/mcp`, `pkg/config`, `pkg/credential`, `internal/mcphost`, `pkg/playbook`, `cmd`）或触及持久化/授权/协议/兼容性时，先给方案并明确验收门槛。
- 禁止凭名称猜测模块职责、编造函数、编造测试结果；重要事实附 `路径:符号`，必要时附准确行号。无法确认时写「待验证」。
- 先阅读 `docs/development/governance/architecture-map.md` 的导航与与任务有关的已有设计，再精确阅读被修改代码；不强制每次通读全部文档。

## 1. 不可破坏的包边界

- `cmd/`：Cobra 命令注册、参数解析、表现层与 CLI 组合根；不在此创建第二套 SSH/SFTP、配置持久化或 MCP 策略引擎。
- `pkg/config/`：配置 `Repository` 是持久变更边界，`Provider` 提供版本一致的读取视图；已有事务/冲突/持久性语义不可绕过。
- `pkg/credential/` 与 `internal/credentialfile/`：凭据服务、引用和离线凭据持久化；禁止将明文写回遗留字段、日志或错误。
- `pkg/adapter/`、`internal/sshenv/`、`internal/mcphost/`：将应用配置、认证、运行环境和策略装配到 `core/`；不得在 core 中重新引入 CLI 依赖。
- `core/ssh/`、`core/sftp/`：唯一共享 SSH/SFTP 执行与传输能力；新能力优先在现有入口中扩展。
- `core/mcp/{ports,sshexec,state,guardrail,runtime,transfer,tunnel}`：协议契约、执行后端、状态准入、护栏、运行时与任务生命周期各有边界；不可因为“调用更简单”绕开 permit、binding、policy 或 snapshot。
- `pkg/playbook/`：编排、步骤结果、重试政策；不能自行再实现一套 SSH 远程执行器。
- `core/**` 的所有代码、测试与 fixture 不得 import `cmd/**`、`pkg/**` 或根 `internal/**`；不得依赖外部 `xops-mcp` 消费者。参见 `core/README.md` 和 `docs/development/shared-core-decoupling.md`。

## 2. 开发底线

- Go 1.26+；保留 Go 缩写规范（ID、URL、SSH、CLI、SFTP、TCP）；遵守 gofmt 与仓库 golangci-lint v2。
- 任何连接、文件、租约、会话、goroutine 和取消函数必须标明**谁拥有、何时释放**；优先用 `defer`，但借用资源不应随意 `Close`。不要关闭调用方持有的输入输出流。
- 网络与并发操作必须有有界生命周期；取消需要使等待/子协程最终终止。需要同步的共享状态明确采用何种锁/通道/不可变快照策略，禁止数据竞争和锁反转。
- 错误用 `%w` / `errors.Is` / `errors.As` 保留语义；远程命令执行区分 `not_started`、`completed`、`unknown`；未知结果不自动重试。
- 禁止隐式放宽 SSH 主机信任、鉴权、MCP 风险分级、HTTP Token/Origin/Host 校验、路径保护、审批、审计或传输任务授权绑定。
- 不为解决局部问题新增与既有实现平行的管理器、wrapper 或类型别名。确需新抽象时，说明替代什么、消除什么复杂性、何处调用、如何验证。
- 不顺带做无关格式化/重命名/大范围移动。历史文档与协议 fixture 不得因“看起来旧”而直接覆盖。

## 3. 每次变更的固定交付

- **变更前**：目标与非目标；具体源码/符号；拥有职责的包；受影响调用方；兼容与安全风险；拟执行的测试。
- **变更后**：修改摘要；行为对照；实际运行的测试及结果；未运行项目及理由；剩余风险。只有当变更影响 CLI/MCP 对外契约或实际设计时更新相关文档（中英文公开文档均需同步）。
- 修复 bug 原则上添加能复现旧问题的回归测试；修改高风险路径需要边界情况与取消/错误路径测试。若确不能测，明确记录原因及替代证据。
- 不将 `go build ./...`、`go test ./...`、lint、交叉编译、native 平台执行等同。构建≠原生平台测试，lint≠回归测试。不要宣称未执行的步骤通过。

## 4. 仓库现有验证入口

```sh
go build ./...
go test ./...
golangci-lint run ./...
# 修改 core 架构/依赖/公共接口：
python3 -m unittest discover -s scripts -p test_check_core.py
python3 scripts/check_core.py --race
# 修改 MCP schema/协议：
go test ./internal/clicontract ./internal/mcphost
# 修改跨平台文档：
npm run docs:check
```

修改并发相关模块应执行受影响包的 `go test -race -shuffle=on -count=1`；跨平台相关变更由 CI 原生 Linux/Windows/macOS 作最终验证。按 `docs/development/governance/validation-matrix.md` 选择增量测试，提交/PR 前遵守仓库现有完整 build/test/lint 要求。不要用 `make ci` 在只读调查中运行：其中的 `go mod tidy` 会修改文件。

## 5. Git、操作安全和人类控制

- 提交信息遵循现有 `feat:`, `fix:`, `chore:`, `ci:`, `docs:`, `test:` 惯例。
- 禁止擅自直接推送、合并、强推、修改 CI 权限、使用管理员 bypass；除非用户明确授权。
- **架构调查或代码维护任务，不代表授权连接或操作用户机器/服务器。** 禁止未经授权调用项目本身的 SSH/SCP/Playbook/MCP 工具执行真实远端操作；安全护栏测试应使用 fake backend、fixture、沙盒环境。
- 目录限定指令位于多个子目录的 `AGENTS.md`；工作时同时遵守根目录与作用域内规范。