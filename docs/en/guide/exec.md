# Command execution

Use `xops exec` to run commands across one or many remote hosts, distribute and run local scripts, or allocate an interactive pseudo-terminal (PTY).

## Quick start

```bash
# Run a command on a single host
xops exec web-01 uptime

# Run a command in parallel across all hosts with the 'web' tag
xops exec --tag web -c 'uptime'

# Run a local script across tagged hosts with a concurrency limit of 5
xops exec --tag web --shell ./check.sh --task 5

# Exclude specific nodes from a batch run
xops exec --tag web --exclude web-maintenance-01 -c 'df -h'
```

**Target selection and argument rules**:
- `--host`, `--ifile`/`-I` (host list file), and `--tag` are mutually exclusive. Once a target selector is set, the first positional argument becomes the remote command (e.g. `xops exec --host web-01 uname -a`), or you can pass the command string explicitly with `-c`.
- Global flags can appear before or after the subcommand (e.g. `xops --color never exec --host web-01 uname -a`). If the remote command itself takes flags starting with `-`, quote it with `-c` or place `--` before the command (e.g. `xops exec --host web-01 -- echo --help`).
- **Batch limits**: Non-interactive batch runs never open desktop keyring unlock dialogs (an already unlocked Linux keyring can still be read; a locked keyring returns `locked`). Raw commands and quoted payloads are each capped at 64 KiB, with a default 5-minute timeout and a 5 MiB rolling output window (excess output is drained and marked as truncated).

## Interpreters and cross-platform execution

### 1. Default mode: Native passthrough (`server`)

When `--interpreter` is omitted and the node has no configured `execution`, XOps defaults to `server` mode:
- The command string is sent unchanged in the SSH `exec` request to the remote default shell without an implicit `bash -l -c` wrapper.
- Works out of the box on targets without Bash, including Alpine Linux (`ash`/`sh`), Windows OpenSSH (CMD or PowerShell), and network appliances.
- `server` mode rejects `--login-shell`.

### 2. Choosing an interpreter and launch dialect

When a command relies on specific shell syntax, login profile variables, or cross-platform quoting, specify `--interpreter` and `--launch-dialect`:

```bash
# Run with login Bash (bash -l -c)
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell -c 'echo $PATH'

# Run with non-login Bash (bash -c) or POSIX sh (sh -c)
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false -c 'echo $VAR'
xops exec --host alpine-01 --interpreter sh --launch-dialect posix -c 'id'

# Nodes with zsh or fish as their default shell
xops exec --host zsh-01 --interpreter zsh --launch-dialect posix -c 'print -r -- $ZSH_VERSION'
xops exec --host fish-01 --interpreter fish --launch-dialect fish -c 'set greeting hello; echo $greeting'

# Windows targets via PowerShell or CMD
xops exec --host win-01 --interpreter powershell -c 'Get-Process | Select-Object -First 5'
xops exec --host win-01 --interpreter cmd -c 'dir'
```

| Interpreter (`--interpreter`) | Supported outer dialects (`--launch-dialect`) | Login and quoting behavior |
| --- | --- | --- |
| `server` (default) | `unknown` (or omitted) | Sent unchanged; rejects `--login-shell`; cannot be used for local scripts without a resolved interpreter |
| `bash` | `posix`, `fish` | Supports `--login-shell` (`bash -l -c`) and `--no-login` / `--login-shell=false` (`bash -c`) |
| `sh` | `posix`, `fish` | Non-login `sh -c` / `sh -s`; rejects login mode |
| `zsh` | `posix`, `fish` | Supports `--login-shell` (`zsh -l -c`), `zsh -s` scripts, and `sudo`/`su` |
| `fish` | `posix`, `fish` | Supports `--login-shell` (`fish -l -c`), scripts, and `sudo`/`su` |
| `powershell` / `pwsh` | `cmd`, `powershell` (`pwsh` also supports `posix`/`fish`) | UTF-16LE Base64 `-EncodedCommand` payload; preserves `$LASTEXITCODE` (capped at 32767 characters) |
| `cmd` | `cmd` | Wrapped in `cmd.exe /d /s /c` with caret escaping; preserves `%ERRORLEVEL%` (capped at 8191 characters; blocks outer `%VAR%`/`!VAR!` expansion) |

To avoid passing interpreter flags on every command, save `execution` on the node in `~/.xops/xops_config.yaml` (`host add`/`import` also probes and saves this automatically)—see [Hosts and identities](./hosts#node-execution-configuration-execution). Explicit `--no-login` (including `--no-login=false`) retains its legacy Bash selection semantics.

## Interactive terminal and PTY (`-x`)

Add `-x` / `--interactive` to allocate a pseudo-terminal (PTY) for a single host when running full-screen terminal apps (`top`, `htop`, `vim`) or interactive elevated commands:

```bash
# Run an interactive terminal program
xops exec -x web-01 top

# Run a single elevated command interactively
xops exec -x --sudo web-01 ls -la /root
```

- **Single-host only**: `-x` targets a single host and cannot be combined with multi-host batches, local scripts (`--shell`), `--stream`, or `--out-dir`.
- **Direct streaming and exit status**: Output streams directly to the local terminal without the 5 MiB memory cap, supports stdout/stderr redirection (e.g. `xops exec -x web-01 uptime 2>error.log`), and propagates nonzero exit codes and signals.
- **Bounded cleanup**: Pressing `Ctrl+C` or losing the connection restores the local terminal, closes the SSH channel, and joins background workers within bounded deadlines.

## Quoting and variable expansion tips

When a command contains spaces, pipelines, or environment variables, pass `-c` with single or double quotes depending on where variables should expand:

```bash
# Single quotes: keep $HOME literal locally so the remote shell expands it
xops exec web-01 -c 'printf "%s\n" "$HOME"'

# Double quotes: expand $USER on the local machine before sending
xops exec web-01 -c "echo Current User is $USER"
```

When running XOps from local Windows PowerShell or CMD, keep local quoting rules in mind; for multi-line or complex logic, put the commands in a script file and run it with `--shell`. See the [`xops exec` command reference](../reference/commands/xops-exec) for all options.
