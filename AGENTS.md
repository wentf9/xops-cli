# AI 助手开发协作指南 (AGENTS.md)

## 🎨 1. 编码规范 (Coding Standards)

1. **语言版本**：Go 1.26+ (严禁降级)。
2. **命名规范**：遵循 Go 社区的缩写命名惯例，**ID, URL, SSH, CLI, SFTP, TCP** 必须全大写（例如：使用 `nodeID`，禁止使用 `nodeId`）。
3. **绝对禁止资源泄漏**：
  - 所有的 `net.Conn`、`os.File` 等资源必须有确定的 `Close()` 路径，无论正常结束还是 error 返回，必须使用 `defer` 确保关闭。
  - 启动任何 Goroutine 时，必须明确它何时、何种情况下会退出（防止 Goroutine Leak）。必须通过 `context.Context` 传递取消信号。
4. **严格的超时控制**：
  - 所有网络操作（Dial, Read, Write）必须设置超时时间（Deadline）。
  - 禁止无限阻塞的 I/O 调用。
5. **错误处理**：
  - 严禁吞咽错误（`_ = err`）或直接 `panic`。
  - 错误必须包含上下文（使用 `fmt.Errorf("do xyz failed: %w", err)` 包装）。
  - 错误字符串不应以标点符号（如 `!` 或 `.`）或换行符结尾。
6. **并发安全**：共享状态必须使用 `sync.RWMutex` 或并发安全结构保护，粒度要尽量小，严防死锁。
7. **变量赋值**：避免无效赋值，若变量赋值后不再使用，必须删除或使用下划线忽略。
8. **文档同步**：更新代码的同时，**必须**同步更新相关的文档（如 `README.md`、CLI 帮助信息、代码注释等）。

## 📦 2. Git 规范 (Git Standards)

- **Commit 规范**：提交信息必须遵循以下格式：
  - `feat: ...` (新功能)
  - `fix: ...` (修复)
  - `chore: ...` (配置/维护)
  - `ci: ...` (流水线修改)
  - `docs: ...` (文档更新)
  - `test: ...` (测试用例)
- **分支与合并**：仓库设置了强制 PR 规则，紧急修复 Lint 或 CI 配置文件时，可利用管理员 Bypass 权限直接推送到 `master`。

## 🛠️ 3. 测试、构建与 CI (Testing, Building & CI)

- **强制要求测试 (核心红线)**：**必须**为所有新增功能、核心逻辑或修复的 Bug 编写对应的测试用例（Unit Test 或 Integration Test）。拒绝任何无测试覆盖的代码修改。
- **强制校验规范**：在任何 `git push` 或提交 PR 之前，必须在本地终端执行并成功通过：
  1. `go build ./...` (确保编译通过)
  2. `go test ./...` (确保逻辑正确且测试通过)
  3. `golangci-lint run ./...` (确保代码质量 0 Issues)
- **Linter 配置**：使用 golangci-lint v2.x。修改 `.golangci.yml` 后，必须运行 `golangci-lint config verify` 进行格式检查。
- **常用命令**：
  - `make build`：本地编译二进制文件
  - `make test`：运行所有测试
  - `golangci-lint run ./...`：运行全量代码扫描
  - `golangci-lint run --fix ./...`：自动修复可修正的 Lint 问题
- **CI/CD**：依赖 GitHub Actions 进行 CI/CD，启用 Dependabot 进行依赖自动更新。处理 Dependabot PR 时优先本地 `go build` 验证。

---

**提示**：在任何时候，代码的“干净程度”优于实现的“速度”。
