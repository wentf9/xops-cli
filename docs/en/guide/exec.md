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

`exec` requires Bash to be available in the remote SSH execution environment: ordinary commands use `bash -l -c`, and `--no-login` only changes this to `bash -c`. Windows SSH targets also need Bash; explicitly invoking `powershell.exe` does not remove the outer Bash wrapper. Without Bash, use SCP/SFTP to download, edit locally, upload, and download again for verification. Use SFTP file commands for directory operations; SFTP's `exec` also requires Bash.

## Interactive commands

```bash
xops exec -x web-01 top
xops exec -x web-01 ls
xops exec -x --sudo web-01 ls /root
```

`-x` provides an interactive terminal for one host, suitable for programs such as `top` and `vim`. It does not support multiple hosts or local script files and also requires Bash on the remote host. When the command finishes, you return to the local terminal without opening an additional remote shell.

Output from the command or login startup scripts is preserved. Use `xops ssh` for a full interactive shell. Commands such as `ls` usually do not need `-x`.

## Quoting

Protect expressions intended for the remote shell using your local shell's quoting rules. For example, in Bash:

```bash
xops exec web-01 -c 'printf "%s\n" "$HOME"'
```

When using PowerShell locally, its quoting rules differ. Prefer script files for complex tasks; the remote host still needs Bash. See the [command reference](../reference/commands/xops-exec) for all options.
