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
- **Batch credentials**: Batch runs do not display credential-store unlock dialogs. Unlock the required stores before starting a batch.
- **Script input**: `--shell` requires a regular file. Pipe scripts through standard input instead, without also supplying credentials through `--password-stdin` or `--passphrase-stdin`.
- **Explicit interpreter limits**: Ordinary commands are limited to 64 KiB and scripts to 16 MiB, with a default 5-minute timeout for non-interactive execution. Results retain the last 5 MiB of output and report truncation when exceeded; `--stream` displays output live and `--out-dir` saves logs without this retention limit. Some shells impose stricter command-length limits.

## Interpreters and cross-platform execution

### 1. Default mode: Native passthrough (`server`)

When `--interpreter` is omitted and the node has no configured `execution`, XOps defaults to `server` mode:
- Commands run in the remote default shell; XOps does not automatically switch to Bash.
- Works out of the box on targets without Bash, including Alpine Linux (`ash`/`sh`), Windows OpenSSH (CMD or PowerShell), and network appliances.
- `server` mode rejects `--login-shell`.

### 2. Choosing an interpreter and launch dialect

When a command relies on specific shell syntax, login profile variables, or cross-platform quoting, specify `--interpreter` and `--launch-dialect`:

```bash
# Run with Bash and load the login environment
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell -c 'echo $PATH'

# Run with Bash or sh without loading the login environment
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false -c 'echo $VAR'
xops exec --host alpine-01 --interpreter sh --launch-dialect posix -c 'id'

# Nodes with zsh or fish as their default shell
xops exec --host zsh-01 --interpreter zsh --launch-dialect posix -c 'print -r -- $ZSH_VERSION'
xops exec --host fish-01 --interpreter fish --launch-dialect fish -c 'set greeting hello; echo $greeting'

# Windows targets whose SSH default shell is CMD
xops exec --host win-01 --interpreter powershell --launch-dialect cmd -c 'Get-Process | Select-Object -First 5'
xops exec --host win-01 --interpreter cmd --launch-dialect cmd -c 'dir'
```

Set `--launch-dialect` to match the remote SSH default shell; for example, use `powershell` when that shell is PowerShell.

| Interpreter (`--interpreter`) | Supported launch dialects (`--launch-dialect`) | Usage notes |
| --- | --- | --- |
| `server` (default) | `unknown` (or omitted) | Uses the remote default shell and rejects `--login-shell`; choose a specific interpreter for local scripts |
| `bash` | `posix`, `fish` | Load the login environment with `--login-shell`; skip it with `--no-login` or `--login-shell=false` |
| `sh` | `posix`, `fish` | Does not load a login environment or support login mode |
| `zsh` | `posix`, `fish` | Supports login environments, scripts, and `sudo`/`su` |
| `fish` | `posix`, `fish` | Supports login environments, scripts, and `sudo`/`su` |
| `powershell` / `pwsh` | `cmd`, `powershell` (`pwsh` also supports `posix`/`fish`) | Does not load user profiles; preserves command exit status |
| `cmd` | `cmd` | Subject to CMD's 8191-character limit; commands containing `%`, `!`, newlines, or unpaired double quotes are currently unsupported |

Interpreter flags can be combined with `--shell`, `--sudo`, `--stream`, or `--out-dir`:

```bash
# Run a local script with sh, elevate, and save per-host logs in logs
xops exec --tag web --interpreter sh --launch-dialect posix --sudo --shell check.sh --out-dir logs

# Run a Bash command across hosts and display output live
xops exec --tag web --interpreter bash --launch-dialect posix --stream -c 'uptime'

# Use the remote default shell and save output to logs
xops exec --host web-01 --interpreter server --out-dir logs -c 'df -h'
```

Scripts and Unix privilege escalation support `bash`, `sh`, `zsh`, and `fish`, not `server`, `powershell`, `pwsh`, or `cmd`. `--stream` and `--out-dir` remain mutually exclusive; see below for interactive-mode restrictions.

To avoid passing interpreter flags on every command, save `execution` on the node in `~/.xops/xops_config.yaml` (`host add`/`import` also probes and saves this automatically)—see [Hosts and identities](./hosts#node-execution-configuration-execution). Explicit `--no-login` (including `--no-login=false`) retains its legacy Bash selection semantics.

## Interactive terminal and PTY (`-x`)

Add `-x` / `--interactive` to allocate a pseudo-terminal (PTY) for a single host when running full-screen terminal apps (`top`, `htop`, `vim`) or interactive elevated commands:

```bash
# Run an interactive terminal program
xops exec -x web-01 top

# Run a single elevated command interactively
xops exec -x --sudo web-01 ls -la /root

# Select an interpreter and save interactive output (input still comes from the terminal)
xops exec --host web-01 -x --interpreter bash --launch-dialect posix -c 'uptime' >output.log 2>error.log
```

- **Single-host only**: `-x` targets a single host and cannot be combined with multi-host batches, local scripts (`--shell`), `--stream`, or `--out-dir`.
- **Output and exit status**: Output appears in the terminal by default. Save it with `>output.log`, `2>error.log`, or `>output.log 2>&1`, including when selecting an explicit interpreter. The 5 MiB result-retention limit above does not apply, and nonzero exit codes and signals are preserved. Input must still come from a local terminal. Logs from terminal programs may contain color or cursor-control characters, and remote stdout and stderr may not remain separate.
- **Interrupting commands**: Press `Ctrl+C` to interrupt. If the disk or filesystem becomes unresponsive while saving logs, interruption may need to wait; no log writes continue after the command returns. After a disconnection, check what ran remotely before retrying; do not immediately repeat commands that might change data.

## Quoting and variable expansion tips

When a command contains spaces, pipelines, or environment variables, pass `-c` with single or double quotes depending on where variables should expand:

```bash
# Single quotes: keep $HOME literal locally so the remote shell expands it
xops exec web-01 -c 'printf "%s\n" "$HOME"'

# Double quotes: expand $USER on the local machine before sending
xops exec web-01 -c "echo Current User is $USER"
```

When running XOps from local Windows PowerShell or CMD, keep local quoting rules in mind; for multi-line or complex logic, put the commands in a script file and run it with `--shell`. See the [`xops exec` command reference](../reference/commands/xops-exec) for all options.
