# MCP Tunnel and Mux Tools

In XOps v2, `tunnel` is one of the 7 first-class discriminated MCP tools and works identically over both **`stdio`** and **Streamable HTTP** transports. It enables AI assistants to create, inspect, and close local/remote/dynamic SOCKS5/StreamLocal/TUN forwards and ControlMaster multiplexers under full guardrail and audit enforcement.

## 1. Eight Supported Actions (`action`)

| Category | `action` | Purpose |
| --- | --- | --- |
| **Port & TUN Forwarding** | `start_forward` | Open a managed forward and return a generation-bound `handle` / `handle_token` |
| | `inspect_forward` | Inspect bound address and live state of a managed forward |
| | `stop_forward` | Stop and release a managed forward handle |
| **ControlMaster Mux** | `start_mux` | Start a managed ControlMaster multiplexer session |
| | `inspect_mux` | Inspect a managed ControlMaster session |
| | `stop_mux` | Stop and release a managed ControlMaster session |
| | `probe_mux` | Probe liveness of an existing ControlMaster socket |
| | `control_mux` | Send a control command (`mux_action`: `check` \| `forward` \| `cancel` \| `exit` \| `stop`) |

## 2. Forwarding Modes and Examples

`start_forward` supports all 4 `direction` values (`local`, `remote`, `dynamic`, `tun`) and both `tcp` and `unix` (StreamLocal) endpoint kinds:

### Local Port Forward (`-L`)

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

### Remote Port Forward (`-R`)

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

### Dynamic SOCKS5 (`-D`) and StreamLocal (`unix`)

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

### Inspect and Stop

Pass the `handle` or `handle_token` returned by `start_forward`:

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

## 3. ControlMaster Multiplexing Example

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

## 4. Handle Lifecycle and Security Boundaries

- **Generation-Bound Handles**: Active forwards and mux masters are tracked by `ManagedHandle` with generation tokens to prevent ABA handle confusion.
- **Deterministic Cleanup & Circuit-Break Revocation**:
  - When the MCP server shuts down (`Close`), all ephemeral managed handles (PTY, Forward, Mux, GUI) are cleanly closed so no orphan listeners remain.
  - If the Engine enters `Halted` under `strict_agent`, all active handles are revoked immediately.
- **Network Scope**: "Local" refers to the machine or container running `xops mcp serve`. Prefer `127.0.0.1` binds unless broader exposure is explicitly authorized and approved.
- **Auth Prerequisite**: Like all MCP tools, `tunnel` operates with `OperatorReadFS == nil`; preload private keys into **`ssh-agent`** (see [MCP Server Security Boundary](./mcp-http)).
