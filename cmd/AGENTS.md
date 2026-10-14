# cmd/ — CLI 入口和命令组合

- `cmd/cli/main.go` 负责进程入口与语言初始化；`cmd/root.go` 创建 Cobra root、构造 `EncryptedRuntime`、注入 credential runtime、注册命令。
- `cmd/ssh.go`、`cmd/exec.go`、`cmd/scp.go`、`cmd/sftp.go`、`cmd/play.go`、`cmd/mcp.go` 主要负责 CLI 入口、参数语义和编排；底层功能按既有分层调用 `core/`、`pkg/`、`internal/`。
- 新 flag 必须明确：缺省行为、显式传值、互斥/组合限制、帮助文案和中英文 docs；绝不能因新 flag 默默更改已有行为。
- 命令行资源归属应清楚：config runtime/credential registry、SSH connector、stdio/PTY、子进程；出错也必须回收。
- 不能直接把配置写进 YAML 而绕开 `pkg/config.Repository`，也不能把明文密码写入配置字段。
- 不要为了复用把 Cobra 参数或 UI 类型放入 core；抽取适当的核心契约并由 CLI 适配。
- 需检查 `cmd/*_test.go`、`cmd/host/*_test.go` 与跨 OS 终端 fixture。验证 `go test ./cmd/...`，改变 SSH/凭据/MCP 需额外跑相应底层包测试。
