# XOps Change Validation Matrix

Principle: run **affected package** fast tests first, then expand by risk; run the repository's full build/test/lint suite before opening or merging a PR. Commands below are required validation steps, not claims of prior execution.

| Scope of Change | Primary Validation | High-Risk Additions |
|---|---|---|
| CLI flags / help | `go test ./cmd/...` | SSH/core regressions; `npm run docs:check` |
| SSH connectivity, execution, probing | `go test ./core/ssh ./cmd -count=1` | `go test -race -shuffle=on -count=1 ./core/ssh ./cmd`, native shell/PTY |
| SFTP / SCP | `go test ./core/sftp ./cmd/sftpshell ./cmd -count=1` | Permissions, symlinks, partial uploads, Windows ConPTY |
| Playbook | `go test ./pkg/playbook ./core/ssh -count=1` | `go test -race ./pkg/playbook ./core/ssh`; multi-shell and `ensure` |
| Configuration / Identities | `go test ./pkg/config ./pkg/adapter ./cmd/host` | Conflicts/transactions, import/export, MCP host |
| Credentials & offline store | `go test ./pkg/credential ./pkg/config ./internal/credentialfile/...` | CI integration tag, offline compatibility, native permissions/crash recovery |
| MCP tools or policies | `go test ./core/mcp/... ./internal/mcphost ./internal/clicontract` | `-race`, approval rejection, HTTP admission, recovery, schema compatibility |
| Core dependencies / interfaces | `python3 -m unittest discover -s scripts -p test_check_core.py` | `python3 scripts/check_core.py --race`, downstream `xops-mcp` consumer |
| Bilingual documentation | `npm run docs:check` | `npm run docs:build` (updates generated command docs during writable development) |

Pre-merge baseline validation:

```sh
go build ./...
go test ./...
golangci-lint run ./...
```

GitHub CI additionally covers: Linux race+shuffle+coverage, fish/zsh, native sudo, offline credential integration, Windows build/test+ConPTY, macOS native tests, and core isolation. See `.github/workflows/ci.yml` and `.github/workflows/offline-compatibility.yml`.

**During read-only investigations**, do not run `make ci`, `go mod tidy`, `npm run docs:build`, or commands that connect to real networks/SSH hosts, create credentials, or modify user configuration.

## Acceptance Evidence Template

```
Commit / branch:
OS / GOOS/GOARCH / Go version:
Executed commands:
Passed / failed / skipped:
External dependencies (SSH fixture, tty, sudo, keychain, network):
Validated platforms vs. unvalidated platforms:
```
