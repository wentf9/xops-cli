# Remote execution and automation

Examples use a POSIX local shell. Remote command syntax and utilities depend on the target; POSIX examples require a POSIX server shell, not necessarily Bash. Current source uses the P3 defaults: ordinary `exec`, SSH commands, MCP commands, and Playbook `shell` steps default to `server`, launch dialect `unknown`, and inherited login mode. A server command is sent unchanged in an SSH exec request. Older installed versions can still wrap commands in Bash; check version and available flags before applying these defaults.

## Select the execution environment

Global and node `execution` configuration can change the defaults. For one-off ordinary commands, current `exec` supports:

```bash
# Native cmd.exe server shell; no remote Bash prerequisite
xops exec --host win-01 -c 'ver'

# Explicit interpreter and verified outer server shell
xops exec --host linux-01 --interpreter sh --launch-dialect posix -c 'id -u'
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell -c 'printf "%s\n" "$PATH"'
xops exec --host win-01 --interpreter powershell --launch-dialect cmd -c 'Get-Process | Select-Object -First 5'
xops exec --host win-01 --interpreter cmd --launch-dialect cmd -c 'dir'
```

Select the launch dialect from the **remote SSH default shell**, not the local OS or the requested inner interpreter. Unknown is valid for `server`; explicit adapters need a supported known dialect:

| Interpreter | Launch dialect | Login behavior |
| --- | --- | --- |
| `server` | `unknown` or a known dialect | Inherited only; do not pass `--login-shell`, including `false`. |
| `bash` | `posix` | Explicit adapter defaults to non-login; `--login-shell` enables login. |
| `sh` | `posix` | Non-login only. |
| `powershell` | `cmd` or `powershell` | Inherited; uses `-NoProfile -NonInteractive -EncodedCommand`. |
| `pwsh` | `posix`, `cmd`, or `powershell` | Inherited; uses the encoded PowerShell adapter. |
| `cmd` | `cmd` | Inherited; currently rejects `%`, `!`, newlines, and unbalanced double quotes. |

`--no-login` alone selects non-login Bash for compatibility and assumes POSIX launch when no dialect was supplied. It is not a generic switch for server/sh/PowerShell/cmd. Explicit `--launch-dialect unknown` is not replaced with POSIX, and `--login-shell` conflicts with `--no-login`.

Current CLI boundaries matter:

- `exec` with explicit `--interpreter`, `--launch-dialect`, or `--login-shell` supports buffered commands or single-host PTY commands; it rejects scripts, sudo, `--stream`, and `--out-dir`. Planned buffered execution has a 5-minute default timeout, 64 KiB command/payload bounds, and retains the last 5 MiB of output. Do not assume every legacy/streaming entry point has those same limits.
- Legacy `exec` streaming/file-output paths support server/Bash/sh, not the Windows adapters. For cmd/PowerShell commands, use the explicit buffered CLI flags above; setting a Windows node default does not enable every entry point.
- Explicit `exec -x` uses strict native output support: Linux terminals/pipes, macOS terminals/already nonblocking pipes and Windows pipes, without regular-file redirection or Windows consoles. Ordinary `exec -x` without those explicit flags uses a compatible terminal path and accepts regular-file output; it still uses the resolved server/adapter payload.
- Explicit execution flags on `ssh` (also `--no-login`) check actual local I/O capabilities and reject sudo and `-N`. Windows file stdin uses the host-injected input bridge; only a missing bridge causes rejection before remote requests. Ordinary SSH commands and unconfigured piped server-shell input select strict or compatible output paths by capability. Remote Windows support and native Windows **client** output support are separate concerns.
- One-shot PTY commands report nonzero, signal, and missing-status failures. Unknown outcomes after disconnect or cancellation are not safe to replay automatically.

## One host and bounded inspection

```bash
xops exec web-01 uptime
xops exec --host web-01 -- uname -a
xops exec --host web-01 -c 'df -h'
xops exec --host web-01 -c 'tail -n 100 /var/log/app.log'
xops exec --host web-01 --sudo -c 'id -u'
```

Use `exec` for finite commands. Keep logs bounded; `tail -f`, `top`, and `vim` require a deliberate long-running/interactive workflow. For shell expressions intended for the remote machine, protect expansion locally:

```bash
xops exec --host web-01 -c 'printf "%s\n" "$HOME"'
```

After a target selector (`--host`, `--ifile`, or `--tag`), positional arguments are the remote command, not another host. Use `--` to disambiguate remote options, for example `xops exec --host web-01 -- echo --help`. Put XOps options before the remote command. Do not invent an `exec --timeout` flag; set a suitable bound in the Agent's command runner and cancel its process when needed.

`--sudo` uses the node's configured Unix privilege strategy, including root, sudo, or su modes. It is distinct from `xops sudo`, which elevates on the local CLI machine. Unconfigured escalation retains the legacy Unix Bash compatibility path; explicit server escalation is unsupported. Configured Bash/sh escalation and configured su have narrower support than ordinary execution; do not infer Windows UAC support or silently remove `--sudo`. Login success alone does not prove privilege escalation succeeded.

## Batch commands and local scripts

```bash
xops host list --tag web
xops exec --tag web --exclude web-02 --task 3 -c 'uptime'
xops exec --host web-01,web-02 --task 2 --stream -c 'df -h'
xops exec --ifile ./hosts.txt --out-dir ./results -c 'uname -a'
# Deliberately run this local script as non-login Bash on POSIX targets
xops exec --tag web --no-login --shell ./check.sh --task 3
```

The `--host`, `--ifile`/`-I`, and `--tag` flags are mutually exclusive: choose one, since combining any of them is rejected before execution. `--exclude` narrows the selected set. `--task` limits concurrent hosts, `--stream` prefixes streamed multi-host output, and `--out-dir` retains per-host logs. Protect logs if command output is sensitive.

Write a local script for complex quoting or several dependent commands, then pass it with `--shell`. The script belongs to the CLI machine and is sent to the selected interpreter through stdin. Do not combine script bytes with a separate runtime stdin stream or credential stdin stream. A no-command `exec` with piped stdin is also a script; a no-command nonterminal `ssh HOST` in server mode instead sends an SSH shell request. Piped `ssh --sudo` remains an escalation operation.

Scripts now require a reliable interpreter. Supported `sh`/`bash` shebangs (such as `#!/bin/sh`, `#!/bin/bash`, or `#!/usr/bin/env sh`, without extra arguments) can select it; a shebang does **not** establish the outer launch dialect. Configure `launch_dialect: posix` only after verifying the server shell. Missing shebangs need a configured non-server interpreter or the deliberate Bash `--no-login` compatibility path. An unsupported shebang needs a supported explicit step/settings or CLI interpreter override; a node default alone does not override it. BOMs and explicit server scripts remain rejected. Do not silently strip or rewrite script bytes. The current script adapter supports Bash/sh, not arbitrary Python, cmd, or PowerShell scripts.

For a node that deliberately needs the old login Bash environment, merge this fragment into that node's existing configuration, preserving its connection and identity fields:

```yaml
execution:
  interpreter: bash
  launch_dialect: posix
  login: true
```

Do not automatically apply it to every host. Explicit `--interpreter`, `--launch-dialect`, and `--login-shell` flags are not currently accepted together with `--shell`; use supported node configuration, `--no-login` for a Bash script, or Playbook execution settings. Use explicit failure handling inside scripts; the last successful command must not hide an earlier failure. Check each host's outcome and the process exit code. After an interrupted mutation, inspect the affected hosts before rerunning it.

## Playbooks

Use `play` for repeatable workflows combining `shell`, `script`, `copy`, `ensure`, and `template`. A read-only starting point:

```yaml
name: check-web
targets:
  tags: [web]
settings:
  concurrency: 2
  on_error: stop
  timeout: 2m
steps:
  - name: uptime
    shell: uptime
```

Save as `check-web.yaml`, then:

```bash
xops play check-web.yaml --dry-run
xops play check-web.yaml --limit web-01
```

`--limit` overrides Playbook targets; verify those explicit nodes. `--concurrency` overrides concurrency, `--sudo` forces global elevation, and repeated `--var key=value` overrides/adds variables used by steps and external templates. Empty variable values are valid; missing variables fail and values are not recursively expanded.

| Step | Use |
| --- | --- |
| `shell` | Execute a remote command. |
| `script` | Read a local script and send its bytes to the resolved interpreter. |
| `copy` | Upload a local file. |
| `ensure` | Run a check and execute its action only if the desired state is absent. |
| `template` | Render a local Go template and upload the result. |

`on_error: stop` stops later steps on the failing host; `abort_all` cancels other host tasks; `continue` permits later steps on that same host. `--dry-run` previews the workflow without proving connectivity or credentials. More examples are in the [automation guide](https://wentf9.github.io/xops-cli/guide/automation).

Ordinary step configuration resolves from step → `settings.execution` → node → global configuration. For scripts, explicit step/settings interpreter choices precede a supported shebang, then non-server node/global defaults. `server` is not a script interpreter. When a workflow needs POSIX script or ensure adapters, explicitly configure the known environment, for example:

```yaml
settings:
  execution:
    interpreter: bash
    launch_dialect: posix
    login: false
  timeout: 5m
```

Use this only on compatible hosts. Ensure checks reject explicitly configured server mode; unconfigured checks probe once and require a detected POSIX bash/sh adapter. The same adapter is used for check, action and verification. Playbook scripts without a shebang can use the same bounded connection cache when execution is unspecified. Runtime probing does not persist configuration or change ordinary command defaults. Windows script/ensure remains unsupported; SFTP cwd exec can use a detected Windows adapter. Probe failures stop before user work and are not interpreter retries. Only a confirmed check result can authorize the action and subsequent verification. Timeout, cancellation, signal, I/O, cleanup, or uncertain startup failures must not be treated as an absent desired state. Retry settings apply to confirmed clean command failures; do not assume every failed attempt is retryable. Script sources and execution settings are frozen within a run, so changing local files/configuration during execution is not an update mechanism.

## Interactive and local utilities

```bash
xops ssh -J bastion.example.com -i ~/.ssh/id_ed25519 deploy@web-01
xops ssh --sudo web-01
xops exec -x web-01 top
xops tui
```

Use these when the task needs a terminal. `exec -x` supports one host and no local script; it returns after the requested command and now defaults to the native server payload. Privileged PTY `--no-login` is currently rejected. `ssh` without a command opens a full server shell; that login session is distinct from one-shot command execution. Single-label jump hosts must be configured nodes/aliases; FQDN, IP, and explicit `host:port` can identify direct jumps.

Text conversion is local:

```bash
xops encode base64 'hello'
xops encode base64 --decode 'aGVsbG8='
xops encode url 'https://example.com/a b'
xops encode utf8 '你好'
xops encode unicode '你好'
```

Use `--decode` for the reverse operation and `encode base64 --url` for URL-safe Base64. Available modes are `base64`, `url`, `utf8`, and `unicode`; there is no `encode hex` subcommand. `version`, `help`, and `completion` provide local CLI discovery and shell completion.

The project also has CLI administration commands `xops mcp serve` and `xops mcp recover`. They are for explicitly requested MCP service administration, not prerequisites for this skill's host workflows. Consult `xops mcp --help` and the [HTTP service guide](https://wentf9.github.io/xops-cli/guide/mcp-http) for such a task.
