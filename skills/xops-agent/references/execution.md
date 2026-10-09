# Remote execution and automation

Examples use a POSIX local shell and require Bash plus the referenced utilities on the remote host. By default, `xops exec` wraps ordinary commands in `bash -l -c`; `--no-login` selects `bash -c`, not the target's default shell. Windows targets also need Bash available to the SSH execution environment, even when the inner command invokes `powershell.exe`. Quote for the local shell, Bash, and any explicitly invoked interpreter. For an ordinary buffered command without Bash, current source supports `xops exec --host NODE --interpreter server -c COMMAND`, forwarding the command unchanged to the server; check installed help before using it. This explicit mode rejects scripts, sudo, streaming/file output, and has a 5-minute timeout with a 5 MiB buffer window. It also supports single-host `-x` with a local terminal and cancelable Linux terminal/pipe output; regular-file redirection and native output on other client platforms are rejected. One-shot PTY nonzero/signal/missing exits now report failure. Ordinary PTY --no-login takes effect; privileged PTY --no-login is currently rejected. Command syntax belongs to the server; uncertain execution outcomes must not be replayed automatically. For file tasks on targets without Bash, use the SCP/SFTP workflows in [Files and transfers](files.md).

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

`--sudo` uses the node's configured privilege strategy, including root, sudo, or su modes. It is distinct from `xops sudo`, which elevates on the local CLI machine. Login success alone does not prove privilege escalation succeeded.

## Batch commands and local scripts

```bash
xops host list --tag web
xops exec --tag web --exclude web-02 --task 3 -c 'uptime'
xops exec --host web-01,web-02 --task 2 --stream -c 'df -h'
xops exec --ifile ./hosts.txt --out-dir ./results -c 'uname -a'
xops exec --tag web --shell ./check.sh --task 3
```

The `--host`, `--ifile`/`-I`, and `--tag` flags are mutually exclusive: choose one, since combining any of them is rejected before execution. `--exclude` narrows the selected set. `--task` limits concurrent hosts, `--stream` prefixes streamed multi-host output, and `--out-dir` retains per-host logs. Protect logs if command output is sensitive.

Write a local script for complex quoting or several dependent commands, then pass it with `--shell`. The script belongs to the CLI machine. Use explicit failure handling inside it; the last successful command must not hide an earlier failure. Check each host's outcome and the process exit code. After an interrupted mutation, inspect the affected hosts before rerunning it.

## Playbooks

Use `play` for repeatable workflows combining `shell`, `script`, `copy`, `ensure`, and `template`. A read-only starting point:

```yaml
name: check-web
targets:
  tags: [web]
settings:
  concurrency: 2
  on_error: stop
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
| `script` | Upload and execute a local script. |
| `copy` | Upload a local file. |
| `ensure` | Run a check and execute its action only if the desired state is absent. |
| `template` | Render a local Go template and upload the result. |

`on_error: stop` stops later steps on the failing host; `abort_all` cancels other host tasks; `continue` permits later steps on that same host. `--dry-run` previews the workflow without proving connectivity or credentials. More examples are in the [automation guide](https://wentf9.github.io/xops-cli/guide/automation).

## Interactive and local utilities

```bash
xops ssh -J bastion.example.com -i ~/.ssh/id_ed25519 deploy@web-01
xops ssh --sudo web-01
xops exec -x web-01 top
xops tui
```

Use these when the task needs a terminal. `exec -x` supports one host and no local script; it returns after the requested command and requires Bash on the target in the default compatibility path. `ssh` provides a full shell. Single-label jump hosts must be configured nodes/aliases; FQDN, IP, and explicit `host:port` can identify direct jumps.

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
