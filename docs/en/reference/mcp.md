# MCP 7-Tool Protocol Reference

The XOps v2 MCP runtime negotiates protocol version **`2025-03-26`** (with **`2024-11-05`** fallback). Every tool schema enforces `"additionalProperties": false`, returns both text blocks and canonical JSON `structuredContent`, and supports uniform `risk` hints and two-step `approval` submissions.

> **Security Boundary Reminder**: MCP mode physically enforces `OperatorReadFS == nil` (`ScopedRootFS` only) and defaults to the `strict_agent` circuit-breaking profile. Use **`ssh-agent`** for private-key authentication (see [MCP Server Guide](../guide/mcp-http)).

## 1. Seven Discriminated Tools

| Tool Name | Responsibility | Supported `action` Values |
| --- | --- | --- |
| `nodes` | Inventory queries, CAS CRUD, Tarjan DAG check, read-only doctor, target resolution, and unified import | `list_hosts`, `get_host`, `create_host`, `update_host`, `delete_host`, `list_identities`, `get_identity`, `create_identity`, `update_identity`, `delete_identity`, `list_nodes`, `get_node`, `create_node`, `update_node`, `delete_node`, `resolve`, `validate_dag`, `doctor`, `list_import_formats`, `plan_import`, `apply_import` |
| `terminal_exec` | Single exec, privileged exec, two-stage shell probe, concurrent batch exec, and Playbook v2 runs | `exec`, `exec_privileged`, `probe_shell`, `batch_exec`, `run_playbook` |
| `terminal_session` | Cross-request persistent PTY managed session lifecycle | `open`, `read`, `write`, `resize`, `signal`, `inspect`, `close` |
| `file` | Remote SFTP atomic read/write, FSTAT-anchored patch, rename, and directory mutations (0 `OperatorReadFS`) | `read`, `write`, `patch`, `stat`, `rename`, `list`, `mkdir`, `remove`, `removedir` |
| `transfer` | Resumable streaming transfer control plane up to 10 GiB (paired with `/transfers/{id}/stream`) | `start`, `chunk`, `pull`, `commit`, `abort`, `resume`, `recover`, `inspect` |
| `tunnel` | SSH port/StreamLocal/TUN forwarding and ControlMaster multiplexer management | `start_forward`, `inspect_forward`, `stop_forward`, `start_mux`, `inspect_mux`, `stop_mux`, `probe_mux`, `control_mux` |
| `gui` | POSIX-validated remote GUI actions, pure-Go decompression-bomb-safe screenshots, and managed X11/VNC tunnels (0 `OperatorReadFS`) | `exec`, `open_session`, `inspect_session`, `close_session` |

## 2. Parameter Summary by Tool

### `nodes`

- Lookup & mutation: `id`, `target`, `host`, `identity`, `node`, `expected_revision`
- Cleanup & diagnostics: `gc_unreferenced_old_secrets`, `delete_unused_secrets`, `require_secrets_unreferenced`, `check_vault_secrets`, `check_private_keys`
- Import: `format` (`openssh` / `csv`), `source_name`, `content` (inline payload—never reads arbitrary host paths), `bundle`, `dry_run`

### `terminal_exec`

- Targets: `target`, `targets`, `selector`, `exclude_nodes`, `exclude_tags`
- Execution: `command`, `work_dir`, `env`, `stdin`, `timeout`, `max_output_bytes`, `pty`, `term`
- Escalation: `privilege_method` (`sudo` \| `su` \| `doas`), `target_user`, `non_interactive`, `password_ref`
- Batch & Playbook: `concurrency`, `fail_fast`, `playbook` (Playbook v2 JSON object), `extra_vars`, `paths`, `recursive_paths`

### `terminal_session`

- Session: `target`, `handle` / `handle_token`, `term`, `cols` (`1..65535`), `rows` (`1..65535`), `max_buffer_bytes`
- I/O & signals: `max_bytes`, `wait`, `data` / `data_b64`, `signal`

### `file`

- Paths & content: `target` (required), `path`, `old_path`, `new_path`, `content` / `content_b64`
- Anchored patching: `edits` (`[{ old_text, new_text, replace_all? }]`), `expected_anchor`, `expected_digest`
- Flags: `perm` (`1..511`), `no_clobber`, `create_parents`, `follow_symlinks`, `max_bytes`

### `transfer`

- Setup: `target`, `direction` (`upload` \| `download`), `transfer_id`, `handle` / `handle_token`, `remote_path`, `local_dest` (relative inside `--transfer-root`), `total_bytes`, `expected_digest`
- Chunks & commit: `offset`, `data_b64`, `max_chunk_bytes`, `no_clobber`, `preserve_times`, `perm`, `expected_anchor`
- Recovery & abort: `reason`, `start_next_gen`, `prune_superseded`, `all`

### `tunnel`

- Forwards: `target`, `handle` / `handle_token`, `direction` (`local` \| `remote` \| `dynamic` \| `tun`), `bind_kind` / `target_kind` (`tcp` \| `unix`), `bind_addr`, `target_addr`, `tun_mode` (`point_to_point` \| `ethernet`), `tun_local_unit`, `tun_remote_unit`
- Multiplexing: `socket_path`, `control_master`, `control_persist`, `mux_action` (`check` \| `forward` \| `cancel` \| `exit` \| `stop`)

### `gui`

- Actions: `target`, `handle` / `handle_token`, `gui_action` (`screenshot` \| `click` \| `double_click` \| `right_click` \| `move` \| `drag` \| `scroll` \| `type` \| `key`), `display`, `wayland_display`
- Coordinates & input: `x`/`y`/`start_x`/`start_y`/`end_x`/`end_y` (`0..1000`), `clicks` (`1..100`), `direction` (`up` \| `down` \| `left` \| `right`), `text`, `key`, `include_shot`, `artifact_file` (written inside `--artifact-root`), `timeout`
- Tunnels: `session_kind` (`x11` \| `vnc`), `display_num` (`0..99`), `use_unix_socket`, `allow_non_loopback_bind`, `local_bind_host`, `local_bind_port`

## 3. Shared Approval Submission & Sanitized Error Payload

### Two-Step Approval Object (`approval`, supported by all 7 tools)

```json
{
  "verdict": "allow",
  "envelope_digest": "sha256:...",
  "envelope": { "...optional original approval envelope..." },
  "comment": "Operator approved for maintenance window"
}
```

### Standard Error Payload (`ToolErrorPayload`)

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

- Never automatically retry when `uncertain: true`.
- When `halted: true` (`gate_halted`), stop all operations, inspect local audit storage/permissions, and restart the MCP server only after fixing the root cause.
