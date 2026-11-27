# MCP 7 工具协议参考

XOps v2 MCP 运行时优先协商协议版本 **`2025-03-26`**（兼容 **`2024-11-05`**），所有工具 Schema 均开启 `"additionalProperties": false`，返回同时包含文本块与规范 JSON `structuredContent`，且全部工具支持统一的 `risk` 声明与两步审批回执 `approval`。

> **安全边界提示**：MCP 模式下 `OperatorReadFS == nil`（仅暴露基于 `os.Root` 的 `ScopedRootFS`），且默认启用 `strict_agent` 熔断档。私钥认证请通过 **`ssh-agent`** 提供（详见 [MCP 服务指南](../guide/mcp-http)）。

## 1. 7 大判别式工具一览

| 工具名 | 职责 | 支持的 `action` 枚举 |
| --- | --- | --- |
| `nodes` | 资产查询、CAS CRUD、Tarjan DAG 校验、只读诊断、目标解析与统一导入 | `list_hosts`, `get_host`, `create_host`, `update_host`, `delete_host`, `list_identities`, `get_identity`, `create_identity`, `update_identity`, `delete_identity`, `list_nodes`, `get_node`, `create_node`, `update_node`, `delete_node`, `resolve`, `validate_dag`, `doctor`, `list_import_formats`, `plan_import`, `apply_import` |
| `terminal_exec` | 单次执行、提权执行、两阶段 Shell 探测、并发批量执行与 Playbook v2 运行 | `exec`, `exec_privileged`, `probe_shell`, `batch_exec`, `run_playbook` |
| `terminal_session` | 跨请求持久 PTY 受管会话生命周期管理 | `open`, `read`, `write`, `resize`, `signal`, `inspect`, `close` |
| `file` | 远端 SFTP 原子读写、FSTAT 锚定补丁、重命名与目录变更（0 `OperatorReadFS`） | `read`, `write`, `patch`, `stat`, `rename`, `list`, `mkdir`, `remove`, `removedir` |
| `transfer` | 最高 10 GiB 可恢复流式传输控制面（与 HTTP `/transfers/{id}/stream` 绑定） | `start`, `chunk`, `pull`, `commit`, `abort`, `resume`, `recover`, `inspect` |
| `tunnel` | SSH 端口转发（`-L`/`-R`/`-D`/StreamLocal/TUN）与 ControlMaster 复用管理 | `start_forward`, `inspect_forward`, `stop_forward`, `start_mux`, `inspect_mux`, `stop_mux`, `probe_mux`, `control_mux` |
| `gui` | POSIX 强校验远端 GUI 动作、纯 Go 防炸弹截图压缩与受管 X11/VNC 隧道（0 `OperatorReadFS`） | `exec`, `open_session`, `inspect_session`, `close_session` |

## 2. 各工具核心参数摘要

### `nodes`

- 标识与载荷：`id`、`target`、`host`、`identity`、`node`、`expected_revision`
- 清理与诊断：`gc_unreferenced_old_secrets`、`delete_unused_secrets`、`require_secrets_unreferenced`、`check_vault_secrets`、`check_private_keys`
- 导入：`format`（`openssh` / `csv`）、`source_name`、`content`（内联文本，不读取宿主机路径）、`bundle`、`dry_run`

### `terminal_exec`

- 目标与选择：`target`、`targets`、`selector`、`exclude_nodes`、`exclude_tags`
- 命令与控制：`command`、`work_dir`、`env`、`stdin`、`timeout`、`max_output_bytes`、`pty`、`term`
- 提权：`privilege_method`（`sudo` \| `su` \| `doas`）、`target_user`、`non_interactive`、`password_ref`
- 批处理与 Playbook：`concurrency`、`fail_fast`、`playbook`（Playbook v2 JSON 对象）、`extra_vars`、`paths`、`recursive_paths`

### `terminal_session`

- 会话参数：`target`、`handle` / `handle_token`、`term`、`cols`（1..65535）、`rows`（1..65535）、`max_buffer_bytes`
- 交互操作：`max_bytes`、`wait`、`data` / `data_b64`、`signal`

### `file`

- 路径与内容：`target`（必填）、`path`、`old_path`、`new_path`、`content` / `content_b64`
- 原子补丁与锚定：`edits`（`[{ old_text, new_text, replace_all? }]`）、`expected_anchor`、`expected_digest`
- 权限与控制：`perm`（1..511）、`no_clobber`、`create_parents`、`follow_symlinks`、`max_bytes`

### `transfer`

- 启动与元数据：`target`、`direction`（`upload` \| `download`）、`transfer_id`、`handle` / `handle_token`、`remote_path`、`local_dest`（`--transfer-root` 内相对路径）、`total_bytes`、`expected_digest`
- 分片与提交：`offset`、`data_b64`、`max_chunk_bytes`、`no_clobber`、`preserve_times`、`perm`、`expected_anchor`
- 恢复与中止：`reason`、`start_next_gen`、`prune_superseded`、`all`

### `tunnel`

- 转发参数：`target`、`handle` / `handle_token`、`direction`（`local` \| `remote` \| `dynamic` \| `tun`）、`bind_kind` / `target_kind`（`tcp` \| `unix`）、`bind_addr`、`target_addr`、`tun_mode`（`point_to_point` \| `ethernet`）、`tun_local_unit`、`tun_remote_unit`
- 多路复用参数：`socket_path`、`control_master`、`control_persist`、`mux_action`（`check` \| `forward` \| `cancel` \| `exit` \| `stop`）

### `gui`

- 动作参数：`target`、`handle` / `handle_token`、`gui_action`（`screenshot` \| `click` \| `double_click` \| `right_click` \| `move` \| `drag` \| `scroll` \| `type` \| `key`）、`display`、`wayland_display`
- 归一化坐标与输入：`x`/`y`/`start_x`/`start_y`/`end_x`/`end_y`（`0..1000`）、`clicks`（`1..100`）、`direction`（`up` \| `down` \| `left` \| `right`）、`text`、`key`、`include_shot`、`artifact_file`（写入 `--artifact-root` 沙箱）、`timeout`
- 隧道会话：`session_kind`（`x11` \| `vnc`）、`display_num`（`0..99`）、`use_unix_socket`、`allow_non_loopback_bind`、`local_bind_host`、`local_bind_port`

## 3. 统一审批回执与脱敏错误载荷

### 两步审批提交对象（所有 7 个工具共享 `approval` 字段）

```json
{
  "verdict": "allow",
  "envelope_digest": "sha256:...",
  "envelope": { "...可选原始审批信封..." },
  "comment": "Operator approved for maintenance window"
}
```

### 统一工具错误载荷（`ToolErrorPayload`）

```json
{
  "code": "approval_required",
  "message": "sanitized human-readable message",
  "retryable": false,
  "uncertain": false,
  "halted": false,
  "approval_challenge": {
    "envelope": {},
    "envelope_digest": "sha256:...",
    "escalated": false,
    "reason": "...",
    "instructions": "..."
  }
}
```

- 当 `uncertain: true` 时严禁自动重试。
- 当 `halted: true` 时表示引擎已触发不可逆熔断（`gate_halted`），需停止操作并排查本地审计存储后再重启服务。
