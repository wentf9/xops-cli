# Command execution

With targets selected by `--host`, `--ifile`/`-I`, or `--tag`, the first positional argument starts the remote command; do not repeat a positional host. `ssh --host` likewise preserves the complete positional command. Both `xops exec --host web-01 uname -a` and `xops ssh --host web-01 uname -a` execute `uname -a`.

Global flags may appear before or after the subcommand, for example `xops --color never exec --host web-01 uname -a`. SSH/exec preserve arguments after the remote command begins. Use `--` to disambiguate, for example `xops exec --host web-01 -- echo --help`.

## Regular and batch execution

```bash
xops exec web-01 uptime
xops exec --tag web -c 'uptime'
xops exec --tag web --shell ./check.sh --task 5
```

Regular mode suits finite output, scripts, and batch jobs. Batch execution does not display credential-store unlock prompts; prepare credentials that are accessible non-interactively.

## Interactive commands

```bash
xops exec -x web-01 top
xops exec -x web-01 ls
xops exec -x --sudo web-01 ls /root
```

`-x` provides an interactive terminal for one host, suitable for programs such as `top` and `vim`. It does not support multiple hosts or local script files. Ordinary interactive commands require Bash on the remote host. When the command finishes, you return to the local terminal without opening an additional remote shell.

Output from the command or login startup scripts is preserved. Use `xops ssh` for a full interactive shell. Commands such as `ls` usually do not need `-x`.

## Quoting

Protect expressions intended for the remote shell using your local shell's quoting rules. For example, in Bash:

```bash
xops exec web-01 -c 'printf "%s\n" "$HOME"'
```

PowerShell uses different quoting rules. Prefer script files for complex tasks. See the [command reference](../reference/commands/xops-exec) for all options.
