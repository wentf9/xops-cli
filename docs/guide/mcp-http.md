# MCP 服务与 HTTP 流式传输

XOps v2 内置符合 MCP 规范（优先协商 **`2025-03-26`**，向下兼容 **`2024-11-05`**）的协议运行时，暴露 **7 个强类型判别式工具**，支持 **`stdio`** 与 **Streamable HTTP** 两种传输，并内置最高 **10 GiB** 双代 WAL 可恢复流式文件传输端点。

## 1. 启动 MCP 服务（`xops mcp`）

```bash
# 1. 本地 stdio 模式（默认，适合 Claude Desktop / Cursor / Codex / Antigravity）
xops mcp serve --transfer-root ~/.xops/transfers --artifact-root ~/.xops/artifacts

# 2. 本地回环 Streamable HTTP 模式（默认监听 127.0.0.1:8080）
xops mcp serve --transport http --listen 127.0.0.1:8080 \
  --transfer-root ~/.xops/transfers --artifact-root ~/.xops/artifacts

# 3. 如确需绑定非回环地址（需显式开启并配置 Host/Origin 白名单；建议前置反向代理 TLS 与鉴权）
xops mcp serve --transport http --listen 0.0.0.0:8080 \
  --allow-non-loopback \
  --allowed-host 192.168.1.10:8080 \
  --allowed-origin https://agent.internal.example \
  --transfer-root ~/.xops/transfers
```

### 客户端配置示例（`stdio`）

```json
{
  "mcpServers": {
    "xops": {
      "command": "/usr/local/bin/xops",
      "args": [
        "mcp", "serve",
        "--transfer-root", "/home/alice/.xops/transfers",
        "--artifact-root", "/home/alice/.xops/artifacts"
      ]
    }
  }
}
```

### `xops mcp` 启动标志

| 标志 | 说明 |
| --- | --- |
| `--transport <mode>` | 传输协议：`stdio`（默认）\| `http` |
| `--listen <addr>` | `--transport=http` 时的监听地址（默认 `127.0.0.1:8080`） |
| `--transfer-root <dir>` | MCP 流式传输专用 `ScopedRootFS` 沙箱根目录 |
| `--artifact-root <dir>` | MCP GUI 截图与产物专用 `ScopedRootFS` 沙箱根目录（未设置时回退 `--transfer-root`） |
| `--allow-non-loopback` | 显式允许绑定非回环网卡（默认物理拒绝非回环地址） |
| `--allowed-origin <origin>` | 允许的非回环 HTTP `Origin` 白名单（可重复，支持逗号分隔） |
| `--allowed-host <host>` | 允许的非回环 HTTP `Host` 白名单（可重复，支持逗号分隔） |
| `-F <configfile>` | 替代 OpenSSH 配置文件（显式传入时严格检查存在性；`none` 禁用） |
| `--policy <profile>` | 策略配置档（MCP 默认 **`strict_agent`**） |

## 2. 强制安全边界与 `ssh-agent` 认证说明

XOps v2 在组合根（`cmd/xops`）与核心引擎两层为 MCP 模式实施了**物理级安全隔离**：

1. **物理零 `OperatorReadFS`（仅 `ScopedRootFS`）**：MCP 运行时绝不注入 `OperatorReadFS`、`InteractionPort` 与本地 `TerminalPort`，因此 MCP 工具**无法读取宿主机任意文件路径**，本地文件 I/O 严格锁定在 `--transfer-root` / `--artifact-root` 的 `os.Root` 沙箱之内。
2. **重要：`AuthPrivateKey` 与 `ssh-agent` 说明**：
   - 正因为 MCP 模式下 `OperatorReadFS == nil`，配置为直接读取本机磁盘私钥文件的 `kind: private_key`（`AuthPrivateKey`）身份在 MCP 中**无法从宿主机磁盘读取私钥文件**（会安全失败关闭返回 `ErrSignerUnavailable`）。
   - 在 MCP 中使用密钥认证的推荐做法：提前将私钥添加到本机 **`ssh-agent`**（Unix 通过 `SSH_AUTH_SOCK`，Windows 通过受安全 DACL 校验的 `\\.\pipe\openssh-ssh-agent` 命名管道），并为节点使用 `kind: agent` 身份（或在 `composite` 认证链中包含 `agent`）。
   - 若使用密码、TOTP 或键盘交互认证，请配合在无交互环境下可读取的 Vault 后端（如 `os_keychain` 或 `external_helper`）。
3. **默认 `strict_agent` 熔断**：任何 `AuditPostWriteError` 立即触发不可逆 `Halted` 熔断态，清空受管句柄并拒绝所有后续请求（HTTP 端点返回 `503 Service Unavailable`，`code: "gate_halted"`）。
4. **启动期自动 `Prepare` 对账**：服务在开始接收请求前自动执行 O(1) 跨进程审计崩溃对账与双代 WAL 传输日志恢复（遇 `TransferUncertainCommit` 零副作用隔离并报告，严禁自动覆盖或删除）。

## 3. Streamable HTTP 端点与安全机制

在 `--transport http` 模式下，服务端暴露三个受 Host/Origin（DNS Rebinding 与 CSRF 防护）及 `Halted` 门禁保护的端点：

| 端点 | 方法 | 用途 |
| --- | --- | --- |
| `/mcp` | `POST` / `GET` / `DELETE` | Streamable HTTP JSON-RPC 2.0 端点：`POST initialize` 签发 `Mcp-Session-Id`（默认最多 64 并发会话、单报文上限 4 MiB）；后续请求必须携带 `Mcp-Session-Id`；`GET` 附带 `Accept: text/event-stream` 建立 SSE；`DELETE` 销毁会话 |
| `/transfers/{transfer_id}/stream` | `PUT` / `POST` / `GET` | 最高 **10 GiB** 零整包缓冲（默认 1 MiB 定长分片）流式上传与下载端点，要求有效 `Mcp-Session-Id` |
| `/healthz` | `GET` | 健康探针，返回 `{"ready":true,"halted":false}`；未就绪、已关闭或熔断时返回 HTTP `503` |

> **网络暴露建议**：Streamable HTTP 内置回环绑定限制与 Host/Origin 校验，但**不内置应用层 Bearer Token 或 TLS**。如需跨主机或局域网访问，请在前方部署带 TLS + 强认证（如 mTLS / OAuth / Bearer Token）的反向代理，并严格限制 `--allowed-host` 与 `--allowed-origin`。

## 4. 10 GiB 流式传输流程与两步审批

### 流式上传（`transfer` 工具 + `PUT /transfers/{id}/stream`）

1. 通过 `/mcp` 调用 `transfer` 工具（`action: "start"`, `direction: "upload"`, `target`, `remote_path`, `total_bytes`, 可选 `expected_digest`），获得 `transfer_id` 与句柄绑定。
2. 向 `PUT /transfers/{transfer_id}/stream?commit=true` 发送原始二进制流（携带 `Mcp-Session-Id`；断点续传可附 `X-Xops-Start-Offset: <bytes>`）。
3. 服务端按定长分片流式直写远端并记录双代 CRC32 WAL；若启用 `?commit=true` 且已达 `total_bytes`，自动完成校验与原子提交并返回实际 SHA-256 摘要。

### 流式下载（`transfer` 工具 + `GET /transfers/{id}/stream`）

1. 通过 `/mcp` 调用 `transfer` 工具（`action: "start"`, `direction: "download"`, `target`, `remote_path`, `local_dest`）。
2. 向 `GET /transfers/{transfer_id}/stream` 发起请求（携带 `Mcp-Session-Id`），服务端拉取分片、提交至 `--transfer-root` 沙箱，再以 `application/octet-stream` 流式回传，并在响应头附带 `X-Xops-Transfer-Id`、`X-Xops-Transfer-State` 与 `X-Xops-Transfer-Digest`。

### 两步审批闭环（`no_elicit_fallback: challenge`）

当配置 `policy.guardrail.no_elicit_fallback: challenge` 且操作命中护栏审批阈值时：

- `/mcp` 工具返回 `code: "approval_required"` 及 `approval_challenge`（含 `envelope`、`envelope_digest`、`escalated`、`reason`、`instructions`）；HTTP 流端点返回 HTTP `428 Precondition Required`。
- 客户端将 `envelope` 展示给人工确认后，在同一调用中附带 `approval` 对象（或 HTTP 流请求头 `X-Xops-Approval: {"verdict":"allow","envelope_digest":"..."}`）重新提交即可通过校验；单次审批信封防重放且受 `approval_ttl` 约束。

## 相关参考

- [MCP 7 工具协议参考](../reference/mcp) — 查阅全部 7 个工具的 `action` 枚举与参数表
- [MCP 隧道与多路复用工具](./mcp-tunnels) — 深入使用 `tunnel` 工具管理转发与 ControlMaster
