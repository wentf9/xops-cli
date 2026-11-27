# MCP Server and HTTP Streaming

XOps v2 includes a standards-compliant MCP runtime (negotiating **`2025-03-26`** with **`2024-11-05`** fallback) that exposes **7 strongly-typed discriminated tools** over **`stdio`** and **Streamable HTTP**, plus a dedicated **10 GiB** dual-generation WAL streaming transfer endpoint.

## 1. Starting the MCP Server (`xops mcp`)

```bash
# 1. Local stdio transport (default; for Claude Desktop, Cursor, Codex, Antigravity)
xops mcp serve --transfer-root ~/.xops/transfers --artifact-root ~/.xops/artifacts

# 2. Loopback Streamable HTTP transport (defaults to 127.0.0.1:8080)
xops mcp serve --transport http --listen 127.0.0.1:8080 \
  --transfer-root ~/.xops/transfers --artifact-root ~/.xops/artifacts

# 3. Non-loopback bind (requires explicit opt-in + Host/Origin allowlists; front with TLS + auth proxy)
xops mcp serve --transport http --listen 0.0.0.0:8080 \
  --allow-non-loopback \
  --allowed-host 192.168.1.10:8080 \
  --allowed-origin https://agent.internal.example \
  --transfer-root ~/.xops/transfers
```

### Example Client Configuration (`stdio`)

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

### `xops mcp` Flags

| Flag | Description |
| --- | --- |
| `--transport <mode>` | Transport mode: `stdio` (default) \| `http` |
| `--listen <addr>` | Listen address for `--transport=http` (default `127.0.0.1:8080`) |
| `--transfer-root <dir>` | `ScopedRootFS` sandbox directory for MCP file transfers |
| `--artifact-root <dir>` | `ScopedRootFS` sandbox directory for GUI/output artifacts (defaults to `--transfer-root`) |
| `--allow-non-loopback` | Explicitly allow binding HTTP listener to non-loopback addresses (denied by default) |
| `--allowed-origin <origin>` | Allowed non-loopback HTTP `Origin` header (repeatable, CSV supported) |
| `--allowed-host <host>` | Allowed non-loopback HTTP `Host` header (repeatable, CSV supported) |
| `-F <configfile>` | Alternate OpenSSH config file (validated fail-closed if specified; `none` disables) |
| `--policy <profile>` | Policy profile (MCP defaults to **`strict_agent`**) |
| `--lang <en\|zh>` | Applies only to `xops mcp` CLI help and startup errors; **never affects** MCP wire tool schemas or responses (always canonical English) |

## 2. Security Boundary and `ssh-agent` Note

In MCP mode, `cmd/xops` and `core/engine` physically enforce strict least-privilege isolation:

1. **Zero `OperatorReadFS` (`ScopedRootFS` Only)**: MCP mode sets `OperatorReadFS == nil`, `Interaction == nil`, and `Terminal == nil`. MCP tools **cannot read arbitrary host files**—all local I/O is confined inside the `os.Root` sandboxes given by `--transfer-root` / `--artifact-root`.
2. **Important Note for `AuthPrivateKey` & `ssh-agent`**:
   - Because `OperatorReadFS == nil`, identities configured with `kind: private_key` (`AuthPrivateKey`) **cannot load private key files directly from host disk** in MCP mode (they fail closed with `ErrSignerUnavailable`).
   - For key-based SSH authentication under MCP, load your keys into **`ssh-agent`** (`SSH_AUTH_SOCK` on Unix or the ACL-verified `\\.\pipe\openssh-ssh-agent` named pipe on Windows) and configure `kind: agent` (or include `agent` in a `composite` identity).
   - For password, TOTP, or keyboard-interactive credentials, use a non-interactively accessible Vault backend such as `os_keychain` or `external_helper`.
3. **Default `strict_agent` Circuit Breaking**: Any `AuditPostWriteError` immediately transitions the Engine into the irreversible `Halted` state, revoking active managed handles and rejecting subsequent requests (`503 Service Unavailable`, `code: "gate_halted"`).
4. **Automatic Startup `Prepare`**: Before serving requests, the server runs O(1) crash-audit reconciliation and dual-generation WAL transfer recovery (`TransferUncertainCommit` entries are quarantined with zero side effects).
5. **Canonical English Machine Contract (Unaffected by `--lang` / `XOPS_LANG`)**: All **7 MCP tool** names, `tools/list` descriptions, and JSON Schemas (`nodes`, `terminal_exec`, `terminal_session`, `file`, `transfer`, `tunnel`, `gui`), all JSON-RPC 2.0 error responses and `ToolErrorPayload` fields (`code`, `message`, `uncertain`, `halted`), `approval_challenge` payloads (`reason`, `instructions`, `envelope`, `envelope_digest`), and `OutcomeUnknown` responses (`code: "uncertain_outcome"` / `"transfer_uncertain_commit"`, `"uncertain": true`, preserving the automatic-retry-forbidden warning) always remain invariant canonical English for deterministic client parsing.

## 3. Streamable HTTP Endpoints and Protections

When running with `--transport http`, three endpoints are served behind Host/Origin (DNS Rebinding & CSRF) and `Halted` checks:

| Endpoint | Methods | Behavior |
| --- | --- | --- |
| `/mcp` | `POST` / `GET` / `DELETE` | Streamable HTTP JSON-RPC 2.0 endpoint: `POST initialize` mints `Mcp-Session-Id` (default max 64 sessions, 4 MiB body limit); subsequent calls require `Mcp-Session-Id`; `GET` with `Accept: text/event-stream` opens SSE; `DELETE` closes the session |
| `/transfers/{transfer_id}/stream` | `PUT` / `POST` / `GET` | Constant-memory (default 1 MiB chunk) streaming upload/download endpoint up to **10 GiB**, requiring a valid `Mcp-Session-Id` |
| `/healthz` | `GET` | Health check returning `{"ready":true,"halted":false}` (or HTTP `503` when unprepared, closed, or `Halted`) |

> **Exposure Guidance**: Streamable HTTP enforces loopback-only binding and Host/Origin checks by default, and intentionally does not embed application-layer Bearer tokens or TLS. If exposing beyond loopback, terminate TLS and strong authentication (mTLS / OAuth / Bearer token) in a reverse proxy and lock down `--allowed-host` and `--allowed-origin`.

## 4. 10 GiB Streaming Transfers and Two-Step Approval

### Streaming Upload (`transfer` tool + `PUT /transfers/{id}/stream`)

1. Call `transfer` over `/mcp` (`action: "start"`, `direction: "upload"`, `target`, `remote_path`, `total_bytes`, optional `expected_digest`) to obtain `transfer_id` and its managed handle binding.
2. Stream raw bytes to `PUT /transfers/{transfer_id}/stream?commit=true` with `Mcp-Session-Id` (resume with `X-Xops-Start-Offset: <bytes>`).
3. Chunks stream straight to the remote host with dual-generation CRC32 WAL persistence; when `?commit=true` reaches `total_bytes`, XOps verifies and commits atomically, returning the actual SHA-256 digest.

### Streaming Download (`transfer` tool + `GET /transfers/{id}/stream`)

1. Call `transfer` over `/mcp` (`action: "start"`, `direction: "download"`, `target`, `remote_path`, `local_dest`).
2. Issue `GET /transfers/{transfer_id}/stream` with `Mcp-Session-Id`; XOps pulls chunks, commits atomically inside `--transfer-root`, and streams back `application/octet-stream` with `X-Xops-Transfer-Id`, `X-Xops-Transfer-State`, and `X-Xops-Transfer-Digest` headers.

### Two-Step Approval (`no_elicit_fallback: challenge`)

When `policy.guardrail.no_elicit_fallback: challenge` is configured and an action hits the approval threshold:

- `/mcp` returns `code: "approval_required"` with `approval_challenge` (`envelope`, `envelope_digest`, `escalated`, `reason`, `instructions`); HTTP transfer streams return HTTP `428 Precondition Required`.
- Present `envelope` to the human operator and resubmit with the `approval` object (or `X-Xops-Approval: {"verdict":"allow","envelope_digest":"..."}` on `/transfers/{id}/stream`). Approvals are single-use, replay-protected, and bounded by `approval_ttl`.

## Related Documentation

- [MCP 7-Tool Protocol Reference](../reference/mcp) — Complete action enums and parameter schemas for all 7 tools
- [MCP Tunnel and Mux Tools](./mcp-tunnels) — Managing forwards and ControlMaster handles via MCP
