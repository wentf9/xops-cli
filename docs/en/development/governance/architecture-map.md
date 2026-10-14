# XOps CLI Architecture Map (for Developers and Coding Agents)

Baseline: `master` @ `a12d52f` (2026-10-13). This map summarizes the architecture verified from source code and design documents; it is a navigation aid rather than an exhaustive function-level call graph.

## System Capabilities

XOps is an operations CLI written in Go covering host/identity management, SSH/SFTP/SCP, batch command execution and Playbooks, TUI, port forwarding, and stdio/HTTP MCP servers across Linux, Windows, and macOS. See `README.md` and `README_en.md`.

## Architecture Entry Points

```mermaid
flowchart TD
  E[cmd/cli/main.go] --> R[cmd/root.go / Cobra]
  R --> C[cmd/* SSH/exec/SCP/play/host/MCP]
  C --> A[pkg/adapter]
  C --> P[pkg/playbook + pkg/tui]
  C --> CFG[pkg/config Repository + Provider]
  C --> CM[cmd/mcp.go]
  CM --> MH[internal/mcphost]
  MH --> PORTS[core/mcp/ports]
  MH --> MR[core/mcp/runtime]
  MH --> B[core/mcp/sshexec]
  MR --> PORTS
  MR --> G[core/mcp/guardrail + state + transfer + tunnel]
  G --> PORTS
  B --> PORTS
  B --> SSH[core/ssh]
  B --> SFTP[core/sftp]
  A --> SSH
  P --> SSH
  CFG --> CR[pkg/credential + internal/credentialfile]
  SFTP --> SSH
```

**Note**: The diagram shows both composition and Go dependency directions (for example, `core/mcp/runtime`, `core/mcp/sshexec`, and `internal/mcphost` all depend one-way on `core/mcp/ports`; `core/sftp` depends on `core/ssh`). Use `go list -json ./...` to inspect the exact Go import graph.

## Recommended Reading Order

1. **Process startup / composition root**: `cmd/cli/main.go:main` -> `cmd/root.go:Execute` -> `cmd/{ssh,exec,mcp,play,credential}.go`.
2. **Configuration and credential state**: `pkg/config/{provider,repository,store,target,encrypted_runtime}.go`; `pkg/credential/service.go`; `internal/credentialfile`.
3. **Connection / execution semantics**: `pkg/adapter/ssh_adapter.go` -> `core/ssh/{connector,plan,command_plan,command_execution,execution_config,probe}.go`.
4. **MCP layering**: `cmd/mcp.go:runMCPServer` -> `internal/mcphost/{config,host}.go` -> `core/mcp/runtime/{server,invocation}.go` -> `core/mcp/ports/types.go`, `core/mcp/sshexec/backend.go`, `core/mcp/guardrail/*` (Note: in CLI mode, `internal/mcphost.host` directly implements `StateSource` and `ExecutionGate`; dynamic publication hosts use `core/mcp/state.Coordinator`).
5. **Batch orchestration**: `cmd/exec.go`, `cmd/exec_execution.go`, and `pkg/playbook/{engine,runner}.go`.
6. **Interactive UI & terminal**: `pkg/tui/*`, `cmd/sftpshell/*`, `internal/terminal/*`.

## "Read the Index First, Then Inspect Source"

- Authoritative boundary specs: `core/README.md`, `docs/en/development/shared-core-decoupling.md`.
- SSH interpreter evolution: `docs/en/development/ssh-execution-compatibility.md`, `ssh-execution-implementation.md`, `ssh-execution-probe-{design,implementation}.md`.
- MCP HTTP transfers: `docs/en/development/mcp-http-transfer-design.md`, `docs/en/guide/mcp-http.md`.
- Offline store compatibility: `docs/en/development/compatibility.md`, `docs/en/development/credential-experience-design.md`.
- Testing & automation: `.github/workflows/ci.yml`, `offline-compatibility.yml`, `Makefile`, `scripts/check_core.py`, `package.json`.

## Anti-Rot Conventions

For any module, record only: responsibility, non-responsibilities, source entry points, dependencies, resource/state ownership, critical invariants, representative tests, open questions, and verified baseline. Do not translate comments file-by-file.

Plans or historical baselines in older design records must not be confused with current implementation; when discrepancies arise, current source code and passing tests take precedence.
