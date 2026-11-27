# MCP 隧道与多路复用工具

在 XOps v2 中，`tunnel` 是内置 MCP 服务端的 7 大标准判别式工具之一，在 **`stdio`** 与 **Streamable HTTP** 两种传输模式下均完整可用。通过 `tunnel` 工具，AI 助手可以在安全护栏和审计约束下创建、检查与关闭 SSH 端口转发、动态 SOCKS5、StreamLocal Unix 套接字、TUN 隧道以及 ControlMaster 多路复用会话。

## 1. 支持的 8 个操作（`action`）

| 类别 | `action` | 功能 |
| --- | --- | --- |
| **转发管理** | `start_forward` | 建立受管转发并返回带世代校验的 `handle` / `handle_token` |
| | `inspect_forward` | 查询受管转发的实时绑定地址与状态 |
| | `stop_forward` | 停止并释放指定受管转发句柄 |
| **ControlMaster 复用** | `start_mux` | 启动并托管 ControlMaster 多路复用主控会话 |
| | `inspect_mux` | 查询受管 ControlMaster 主控会话状态 |
| | `stop_mux` | 停止并释放受管 ControlMaster 主控会话 |
| | `probe_mux` | 探测指定 `socket_path` / 目标的外部或既有 ControlMaster 存活状态 |
| | `control_mux` | 向活跃 ControlMaster 发送控制命令（`mux_action`: `check` \| `forward` \| `cancel` \| `exit` \| `stop`） |

## 2. 转发类型与调用示例

`start_forward` 支持全部 4 类 `direction`（`local` / `remote` / `dynamic` / `tun`）及 `tcp` / `unix` 两种端点类型：

### 本地端口转发（`-L`）

```json
{
  "action": "start_forward",
  "target": "web-01",
  "direction": "local",
  "bind_kind": "tcp",
  "bind_addr": "127.0.0.1:18080",
  "target_kind": "tcp",
  "target_addr": "127.0.0.1:80"
}
```

### 远端端口转发（`-R`）

```json
{
  "action": "start_forward",
  "target": "worker-01",
  "direction": "remote",
  "bind_kind": "tcp",
  "bind_addr": "127.0.0.1:9000",
  "target_kind": "tcp",
  "target_addr": "127.0.0.1:3000"
}
```

### 动态 SOCKS5 代理（`-D`）与 StreamLocal（`unix`）

```json
{
  "action": "start_forward",
  "target": "web-01",
  "direction": "dynamic",
  "bind_kind": "tcp",
  "bind_addr": "127.0.0.1:1080"
}
```

```json
{
  "action": "start_forward",
  "target": "web-01",
  "direction": "local",
  "bind_kind": "unix",
  "bind_addr": "/tmp/xops-local.sock",
  "target_kind": "unix",
  "target_addr": "/var/run/docker.sock"
}
```

### 检查与关闭转发

使用 `start_forward` 返回的 `handle` 或 `handle_token` 精确操作该世代会话：

```json
{
  "action": "inspect_forward",
  "handle_token": "<token-from-start_forward>"
}
```

```json
{
  "action": "stop_forward",
  "handle_token": "<token-from-start_forward>"
}
```

## 3. ControlMaster 多路复用示例

```json
{
  "action": "start_mux",
  "target": "web-01",
  "socket_path": "~/.xops/mcp-mux-%C",
  "control_master": "yes",
  "control_persist": "10m"
}
```

```json
{
  "action": "control_mux",
  "target": "web-01",
  "socket_path": "~/.xops/mcp-mux-%C",
  "mux_action": "check"
}
```

## 4. 受管句柄生命周期与安全边界

- **世代防串扰**：所有活跃转发与 Mux 会话均以不可伪造的世代句柄（`ManagedHandle`）追踪，防止句柄复用误关其他会话。
- **自动停机与熔断吊销**：
  - MCP 服务端正常关闭（`Close`）时会自动清理全部非持久化受管句柄（PTY、Forward、Mux、GUI），不会遗留孤儿监听端口。
  - 若在 `strict_agent` 下发生审计写失败进入 `Halted` 熔断态，引擎会立即吊销全部活跃受管句柄并拒绝后续调用。
- **网络位置认知**：`bind_addr` 中的“本地”指运行 `xops mcp serve` 进程的宿主机或容器环境。建议默认绑定 `127.0.0.1`，开放非回环地址或高风险转发会触发护栏审批。
- **认证前置提醒**：与所有 MCP 工具一致，`tunnel` 在 `OperatorReadFS == nil` 沙箱下运行，使用密钥认证的节点请通过 **`ssh-agent`** 提供签名（参见 [MCP 服务安全边界](./mcp-http)）。
