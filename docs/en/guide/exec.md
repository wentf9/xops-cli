# Command execution

For both `exec` and `scp`, the target selectors `--host`, `--ifile`/`-I`, and `--tag` are mutually exclusive. Combining them fails before execution. Choose one selector and use `--exclude` to narrow its targets.

With targets selected by `--host`, `--ifile`/`-I`, or `--tag`, the first positional argument starts the remote command; do not repeat a positional host. `ssh --host` likewise preserves the complete positional command. Both `xops exec --host web-01 uname -a` and `xops ssh --host web-01 uname -a` execute `uname -a`.

Global flags may appear before or after the subcommand, for example `xops --color never exec --host web-01 uname -a`. SSH/exec preserve arguments after the remote command begins. Use `--` to disambiguate, for example `xops exec --host web-01 -- echo --help`.

## Regular and batch execution

```bash
xops exec web-01 uptime
xops exec --tag web -c 'uptime'
xops exec --tag web --shell ./check.sh --task 5
```

Regular mode suits finite output, scripts, and batch jobs. Batch execution does not display credential-store unlock prompts; prepare credentials that are accessible non-interactively.

The default compatibility mode of `exec` requires Bash in the remote SSH execution environment: ordinary commands use `bash -l -c`, and `--no-login` only changes this to `bash -c`. Windows SSH targets also need Bash; explicitly invoking `powershell.exe` does not remove the outer Bash wrapper. Without Bash, use SCP/SFTP to download, edit locally, upload, and download again for verification. Use SFTP file commands for directory operations; SFTP's `exec` also requires Bash.

## Explicit interpreters

The current source implements P1-A ordinary-command foundations and the first P1-B request/PTY migration. `exec` supports explicit server/Bash selection for buffered commands and PTY commands. Check `xops exec --help` for availability in an installed release; the default compatibility mode has not switched.

```bash
xops exec --host alpine-01 --interpreter server -c 'uname -a'
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell -c 'printf "%s\n" "$PATH"'
```

server sends the `-c` string unchanged in SSH exec without adding Bash, probing, or translating commands. The server may still use its own shell or forced command; Windows and device commands must match that server's syntax. Positional arguments are still joined with spaces; use `-c` to preserve quoting and whitespace.

Explicit Bash requires a known POSIX launch dialect and defaults to non-login mode. `--login-shell` enables login mode, while `--login-shell=false` explicitly disables it. server rejects login options. In P1, overriding only dialect or login retains the stage default of Bash+login and still requires a known POSIX launch dialect; switching to server requires explicit `--interpreter server`. `--no-login` retains its legacy Bash meaning and is mutually exclusive with `--login-shell`.

Explicit mode supports buffered ordinary commands and single-host PTY commands, while still rejecting scripts/piped scripts, `--sudo`, `--stream`, and `--out-dir`. `exec -c` does not forward piped user data. Buffered execution retains the last 5 MiB of output, continues draining beyond that limit, and shows a truncation marker. The original command and quoted exec payload are each limited to 64 KiB; each command has a 5-minute total timeout. Nonzero exits, signals, and uncertain outcomes report failure; `outcome=unknown` means side effects may already have occurred and must not be directly replayed. Closing the connection does not prove remote process termination.

Explicit PTY examples (Linux client terminal):

```bash
xops exec --host linux-01 --interpreter server -x top
xops exec --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false -x top
```

The new PTY path requires local terminal input and streams output without the 5 MiB buffer window. Linux terminal/pipe output uses independent cancelable handles with a 10-second per-write limit and a 1-second output-drain grace period after exit. Original standard streams are not closed and their file flags are not changed. Input-bridge initialization failures, broken output pipes, and write timeouts trigger bounded cleanup immediately rather than waiting for the full command timeout. If the peer does not acknowledge channel closure, interrupt the transport and join output workers. Regular-file redirection and native output bridges on other client platforms remain unvalidated and are rejected before sending a command; core consumers may provide a `ContextWriter` that honors cancellation. Unification of existing `ssh` and legacy output entry points remains in progress.

## Interactive commands

```bash
xops exec -x web-01 top
xops exec -x web-01 ls
xops exec -x --sudo web-01 ls /root
```

`-x` provides an interactive terminal for one host, suitable for programs such as `top` and `vim`. It does not support multiple hosts or local script files and requires Bash in the default compatibility path; explicit server adds no Bash wrapper. When the command finishes, you return to the local terminal without opening an additional remote shell. One-shot commands report nonzero exits, signals, and missing exit status as failures; full login shells retain their existing exit policy. Ordinary PTY --no-login now takes effect; combining it with privileged PTY commands is currently rejected. PTY also rejects script input, --stream, and --out-dir.

Output from the command or login startup scripts is preserved. Use `xops ssh` for a full interactive shell. Commands such as `ls` usually do not need `-x`.

## Quoting

Protect expressions intended for the remote shell using your local shell's quoting rules. For example, in Bash:

```bash
xops exec web-01 -c 'printf "%s\n" "$HOME"'
```

When using PowerShell locally, its quoting rules differ. Prefer script files for complex tasks; the remote host still needs Bash. See the [command reference](../reference/commands/xops-exec) for all options.
