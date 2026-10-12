# Command execution

XOps CLI provides robust remote command execution (`xops exec`), supporting single-host interactive terminals, multi-host parallel batching, script distribution, and cross-platform command interpreter adaptations.

Selecting targets via `--host`, `--ifile`/`-I`, or `--tag` treats the first positional argument as the remote command. For example, `xops exec --host web-01 uname -a`. The `--host`, `--ifile`/`-I`, and `--tag` target selectors are mutually exclusive; select one and use `--exclude` to narrow down the target list.

Global flags may appear before or after subcommands, for example `xops --color never exec --host web-01 uname -a`. Positional arguments following the remote command are preserved as-is. Use `--` to avoid flag ambiguity, such as `xops exec --host web-01 -- echo --help`.

## Regular and batch execution

```bash
# Execute command on a single node
xops exec web-01 uptime

# Execute command across a group of hosts matched by tag
xops exec --tag web -c 'uptime'

# Distribute and execute a local script with concurrency of 5
xops exec --tag web --shell ./check.sh --task 5
```

- **Batch execution use cases**: Ideal for routine operations, batch deployments, and automated tasks. Batch execution does not prompt interactively for credential store unlocking; ensure non-interactive credentials (such as passwordless SSH keys or unlocked credential stores) are configured beforehand.
- **Buffering and truncation protection**: Regular execution retains the latest 5 MiB of output in memory, continues draining beyond that limit, and displays a truncation indicator to prevent unbounded memory growth from large logs.
- **Payload and timeout bounds**: The raw command and quoted execution payload are each capped at 64 KiB, with a default single-command execution timeout of 5 minutes.

## Interpreters and execution configuration

XOps supports multiple remote command interpreters to adapt seamlessly across Linux, Alpine, Windows, and specialized systems.

### Default interpreter: Native execution (`server`)

When no interpreter is explicitly specified and no node-level interpreter is configured, XOps defaults to `server` mode:
- **Zero-dependency native execution**: Commands are forwarded directly through the SSH exec subsystem to the remote default shell or command handler without wrapper layers.
- **Broad OS compatibility**: Requires no Bash pre-installed on the target, working out of the box on minimal containers, Alpine Linux (using default `ash`/`sh`), Windows (using PowerShell or CMD), and network appliances.
- **Standard behavior**: `server` mode applies no outer shell wrapping and rejects `--login-shell`.

### Multi-interpreter support

When specific shell environments, login scripts, or variables are required, choose an interpreter using `--interpreter`:

```bash
# Native SSH execution (default)
xops exec --host alpine-01 --interpreter server -c 'uname -a'

# Explicit Bash with login shell environment
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell -c 'echo $PATH'

# Explicit Bash without login shell
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false -c 'echo $VAR'

# Explicit POSIX sh
xops exec --host linux-01 --interpreter sh --launch-dialect posix -c 'id'

# Explicit zsh on a zsh default shell
xops exec --host zsh-01 --interpreter zsh --launch-dialect posix -c 'print -r -- $ZSH_VERSION'

# Fish command on a fish default shell
xops exec --host fish-01 --interpreter fish --launch-dialect fish -c 'set greeting hello; echo $greeting'

# Windows target via PowerShell
xops exec --host win-01 --interpreter powershell -c 'Get-Process | Select-Object -First 5'

# Windows target via CMD
xops exec --host win-01 --interpreter cmd -c 'dir'
```

- **`bash`**: Invokes remote `bash`. Supports `--login-shell` (equivalent to `bash -l -c`) and `--no-login` / `--login-shell=false` (equivalent to `bash -c`). Requires the `posix` or `fish` launch dialect.
- **`sh`**: Invokes standard POSIX `sh -c`. Suited for standard shell scripts independent of Bash features; rejects login shells.
- **`zsh`**: Uses `zsh -c`, or `zsh -l -c` with `--login-shell`. Requires a `posix` or `fish` outer launch dialect. Scripts use `zsh -s`; sudo/su reuse the POSIX authentication handshake while retaining zsh semantics.
- **`fish`**: Uses `fish -c`, or `fish -l -c` with `--login-shell`. Requires `posix` or `fish` as the actual outer launch dialect; `--no-login` remains a Bash compatibility flag.
- **`powershell` / `pwsh`**: Designed for Windows hosts or cross-platform PowerShell environments, handling command argument escaping and exit code forwarding.
- **`cmd`**: Designed for Windows Command Prompt (`cmd /c`), handling quoting and enforcing an 8191-character safety limit.

When using saved zsh/fish execution settings, ordinary and elevated `exec` commands retain the configured login mode. Explicit `--no-login` (including `--no-login=false`) keeps its legacy Bash selection semantics.

### Launch dialects (`--launch-dialect`)

The launch dialect instructs XOps how to validate and escape command payloads:
- `posix`: For Linux/UNIX shells (Bash, sh, Zsh, etc.).
- `fish`: Fish default shell, with separate escaping for quotes and backslashes.
- `powershell`: For Windows PowerShell and cross-platform PowerShell.
- `cmd`: For Windows Command Prompt.

> 💡 **Tip**: Instead of specifying options on every command, you can persist execution configurations in `~/.xops/xops_config.yaml`. See [Hosts and identities](./hosts).

## Interactive terminal and PTY (`-x`)

The `-x` flag allocates a pseudo-terminal (PTY) for a single host, enabling interactive full-screen terminal programs:

```bash
# Live system monitoring
xops exec -x web-01 top

# Interactive system inspection
xops exec -x web-01 htop

# Interactive privileged command execution
xops exec -x --sudo web-01 ls -la /root
```

- **Single-host restriction**: PTY mode is strictly scoped to one host and cannot be combined with multi-host batching or local script files.
- **Streaming terminal output**: Interactive execution streams directly to the local terminal without the 5 MiB buffer limit, returning to the local prompt upon exit.
- **Output redirection and compatibility**: Output and error streams can be redirected normally (e.g. `xops exec -x web-01 uptime 2>error.log`).
- **Cancellation and resource reclamation**: When interrupted by Ctrl+C or a network drop, XOps cleanly releases terminal resources, terminates the SSH channel, and joins background routines within bounded limits.

## Quoting and escaping guidelines

When commands contain whitespace, environment variables, or shell syntax, use `-c` along with single or double quotes:

```bash
# Protect variable expression so it resolves on the remote host
xops exec web-01 -c 'printf "%s\n" "$HOME"'

# Expand variable locally before passing to the remote host
xops exec web-01 -c "echo Current User is $USER"
```

When running commands from Windows PowerShell or CMD locally, keep local quoting differences in mind. Complex multi-step operations are best authored as script files distributed via `--shell`. See the [command reference](../reference/commands/xops-exec) for complete options.
