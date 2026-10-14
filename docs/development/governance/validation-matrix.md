# XOps 改动验证矩阵

原则：先跑**相关包**快速测试，再按风险扩大验证；PR 前保留仓库已有 build/test/lint 要求。命令是建议运行项而不是“已验证通过”的声明。

| 修改范围 | 首先运行 | 高风险补充 |
|---|---|---|
| CLI 参数/帮助 | `go test ./cmd/...` | SSH/core 回归；`npm run docs:check` |
| SSH 连接、执行、探测 | `go test ./core/ssh ./cmd -count=1` | `go test -race -shuffle=on -count=1 ./core/ssh ./cmd`，原生 shell/PTY |
| SFTP/SCP | `go test ./core/sftp ./cmd/sftpshell ./cmd -count=1` | 权限、symlink、部分上传、Windows ConPTY |
| Playbook | `go test ./pkg/playbook ./core/ssh -count=1` | `go test -race ./pkg/playbook ./core/ssh`；不同 shell 与 ensure |
| 配置/身份 | `go test ./pkg/config ./pkg/adapter ./cmd/host` | 冲突/transaction、导入导出、MCP host |
| 凭据与离线文件 | `go test ./pkg/credential ./pkg/config ./internal/credentialfile/...` | CI integration tag、离线兼容验证、原生权限/崩溃 |
| MCP 工具或策略 | `go test ./core/mcp/... ./internal/mcphost ./internal/clicontract` | -race、审批拒绝、HTTP admission、恢复、schema 兼容 |
| Core 依赖/接口 | `python3 -m unittest discover -s scripts -p test_check_core.py` | `python3 scripts/check_core.py --race`，下游 xops-mcp consumer |
| 双语文档 | `npm run docs:check` | `npm run docs:build`（会更新生成物，应在可写开发阶段运行） |

合并前主线验证：

```sh
go build ./...
go test ./...
golangci-lint run ./...
```

GitHub CI 还覆盖：Linux race+shuffle+coverage、fish/zsh、原生 sudo、离线凭据 integration，Windows 构建/测试+ConPTY，macOS 原生测试，core isolation。详见 `.github/workflows/ci.yml` 与 `.github/workflows/offline-compatibility.yml`。

**只读调查时不执行** `make ci` / `go mod tidy` / `npm run docs:build` / 涉及真实网络、SSH、凭据创建和用户配置写入的命令。

## 验收证据格式

```
Commit / branch:
OS / GOOS/GOARCH / Go version:
执行命令:
通过 / 失败 / 跳过:
是否有外部依赖（SSH fixture、tty、sudo、keychain、网络）:
已验证平台 vs 尚未验证平台:
```
