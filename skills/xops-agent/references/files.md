# Remote files and transfers through the CLI

Use `exec` with the target's actual command language for text operations, `scp` for transfers, and batch `sftp` file commands for filesystem operations without a remote shell. Ordinary commands default to the server shell and do not require Bash. No MCP connection, HTTP transfer task, or transfer helper is needed. Local paths always refer to the Agent's CLI environment.

## Read and edit text

On a target with a POSIX server shell and the required utilities:

```bash
xops exec --host web-01 -c 'ls -ld /srv/app && ls -l /srv/app'
xops exec --host web-01 -c 'sed -n "1,120p" /srv/app/settings.ini'
xops exec --host web-01 -c 'tail -n 100 /var/log/app.log'
```

Use a bounded range for inspection. If exact bytes, binary data, or a large file are needed, download it and inspect locally. Byte-range reads can use a target-supported utility such as `dd`; its offsets and counts are byte-oriented only with the appropriate block-size settings.

On a Windows target, use syntax for its configured SSH server shell, or select a supported explicit adapter for an ordinary command. For example, from a POSIX local shell when the server launches through cmd.exe:

```bash
xops exec --host win-01 --interpreter powershell --launch-dialect cmd -c 'Get-Content -LiteralPath "C:\app\settings.ini" -TotalCount 120'
```

Verify the launch dialect first; a Windows target can have a PowerShell default shell instead. See [execution selection and current CLI limits](execution.md#select-the-execution-environment). If the command language or tools are unavailable, download with SCP/SFTP, read or edit locally, upload with the intended overwrite policy, and download to a separate local path to verify content.

For a small authorized append on a POSIX target:

```bash
xops exec --host web-01 -c 'printf "%s\n" "feature_enabled=true" >> /srv/app/settings.ini'
```

Do not repeat an append after a timeout until checking whether it was applied. For a complete rewrite, prepare the final file locally and upload it, rather than embedding large content in shell arguments:

```bash
cat > ./settings.ini <<'CONFIG'
port=8080
feature_enabled=true
CONFIG
xops scp ./settings.ini 'web-01:/srv/app/settings.ini' --force
xops exec --host web-01 -c 'cat /srv/app/settings.ini'
```

Use this overwrite example only when replacing that destination is authorized. Read the original first and retain a recovery copy where needed. Validate the resulting content and application syntax before any requested reload. For sensitive files use private local temporary files and remove them after use; do not put secrets into the command transcript.

SCP and SFTP have no remote `--sudo` transfer flag. For a privileged destination, upload to a unique path in a private directory writable by the SSH user, then use `xops exec --sudo` with target-native operations to set the intended owner/mode and publish the file. On Linux, for example, `install -m 0644 STAGING_PATH DESTINATION` sets a mode but does not promise atomic publication. Choose a same-filesystem staged rename workflow when atomic replacement is required. Verify the result and clean up the staging file. Do not assume CLI transfers preserve all ownership, ACLs, or extended attributes.

## Filesystem operations

Batch SFTP handles ordinary paths without needing POSIX tools on the remote host:

```bash
xops sftp --no-clobber web-01 <<'SFTP'
ls /srv/app
mkdir /srv/app/archive
cp /srv/app/settings.ini /srv/app/archive/settings.ini
mv /srv/app/incoming.txt /srv/app/ready.txt
exit
SFTP
```

These are examples of separate requested actions, not a mandatory sequence. SFTP `mkdir` creates one directory and requires an existing parent; an existing destination can fail the batch. `cp` and `rm` support directories recursively. `--no-clobber` skips existing destinations; skipped copies do not prove the desired content was installed. Use `--force` for intended overwrite, or `cp -f` / `mv -f` for a single operation. An authorized deletion can use `rm -f /exact/path` in the batch; review the exact path and wildcard expansion first.

SFTP input is split on whitespace; quoted filenames with spaces are not shell-parsed. For such paths use `scp` with the whole operand quoted, or `exec -c` with correctly quoted target-native commands. Wildcards `*`, `?`, and `[...]` are expanded by SFTP path operations; use exact paths for narrowly scoped changes.

SFTP `exec` is separate from these file commands: it prepends a working-directory operation using the node/global execution adapter. Saved `server/cmd` uses a temporary CMD adapter for cwd without changing configuration; `/C:` becomes absolute `C:/`. Other explicit `server` configurations reject a nonempty SFTP cwd, including `/`; select a compatible adapter before using them. Its strict output path accepts Linux terminals/pipes, Windows pipes and macOS terminals/already nonblocking pipes (batch regular-file output is supported), so prefer pure SFTP commands for portable file operations.

| Need | POSIX target command through `xops exec -c` | Notes |
| --- | --- | --- |
| List metadata | `ls -l /srv/app` | Prefer SFTP `ll` when no remote shell is available. |
| Create parents | `mkdir -p /srv/app/cache` | SFTP `mkdir` creates only one level. |
| Create a file without truncating an existing one | `touch /srv/app/marker` | Changes timestamps if it exists. There is no SFTP `touch` command. |
| Explicitly empty a file | `: > /srv/app/marker` | Truncates contents; only for an intended rewrite. |
| Copy a tree | `cp -r /srv/app/assets /srv/archive/` | Inspect destination/overwrite semantics. |
| Rename/move | `mv /srv/app/old /srv/app/new` | Check existing destination first. |
| Delete | `rm -- /srv/app/obsolete.txt` | Use recursive deletion only for an authorized directory scope. |

File/pipe input automatically selects SFTP batch mode. It stops at the first failed command with nonzero exit status and does not write interactive history. Confirmation-requiring operations fail unless the applicable force/no-clobber behavior is selected. Do not pipe `yes` into the session. `exec` and `lexec` receive EOF stdin in batch mode; `shell` and `lshell` require a terminal. A batch command line is limited to 1 MiB.

## Upload, download, distribute, and relay

```bash
# Local file to one node; download back to a separate local name
xops scp ./report.txt 'web-01:~/uploads/report.txt' --no-clobber
xops scp 'web-01:~/uploads/report.txt' ./downloaded-report.txt --no-clobber

# Directory upload
xops scp -r ./assets 'web-01:~/uploads/' --no-clobber

# Remote-to-remote relay through the CLI machine
xops scp 'web-01:/srv/report.txt' 'archive-01:/srv/report.txt' --no-clobber

# Batch upload to selected nodes
xops host list --tag web
xops scp --tag web --task 3 --no-clobber ./config.conf /srv/app/
```

SCP requires two paths: `xops scp [options] <source> <destination>` (or pass both `--src` and `--dest` without positional paths; never mix the two). Without host selectors, either path accepts `[[user@]host:]file` (node name, alias, or `[user@]host`). Everything after the address delimiter (after `]:` for IPv6) is the file path, including numeric prefixes like `22:file`. Use `-P`/`--port` for an explicit SSH port—never `-p` or `host:port:file`. When `-P` is omitted, a unique matching node supplies its configured port; if multiple ports match, disambiguate with `-P` or a unique alias. With `--host`, `--tag`, or `--ifile`/`-I` (mutually exclusive; filter with `--exclude`), SCP always uploads from local and treats both paths as literal filenames (including `:` and `@`).

Terminals show a progress bar on `stderr` by default (omitted when piped or redirected). `-q`/`--quiet` hides progress and SSH warnings/diagnostics while keeping errors and security prompts. `-v`/`--verbose` prints SSH/SFTP and transfer diagnostics independently of global `--debug` (`-v` connection/auth/SFTP state, `-vv` SFTP extensions and file ops, `-vvv` SFTP packet metadata). Flag order follows OpenSSH: `-qv` hides progress while showing SSH/SFTP diagnostics; `-vq` hides progress and SSH diagnostics while keeping SCP transfer and SFTP init messages. Linux terminals/pipes, Windows pipes and macOS terminals/already nonblocking pipes support native cancelable output. Unsupported sinks, including Windows consoles and macOS blocking anonymous pipes, skip progress, diagnostics and upload status; redirect `stderr` to a regular file to capture diagnostics.

Choose `--no-clobber` (`-n`) to skip existing targets or `--force` (`-f`) to overwrite (even when size and mtime match); do not combine both. `--task` controls parallel host transfers and `--thread` controls per-file concurrency.

Quote remote `~` operands to prevent local shell expansion. XOps expands `~`/`~/...` using the remote SFTP login directory; `~otheruser` is unsupported. Prefer an absolute path when targeting a specific filesystem location. Windows SFTP path syntax depends on the server; inspect its reported working directory before assuming a drive path.

For repeated transfer operations in one session:

```bash
xops sftp --no-clobber web-01 <<'SFTP'
put ./report.txt /srv/uploads/report.txt
get /srv/logs/result.txt ./result.txt
exit
SFTP
```

Check per-host results and exit status, then verify size/hash at the destination when content integrity matters. CLI progress alone is not proof of the final content. An interrupted transfer has no MCP status/cancel tool to query; inspect the process and source/destination before retrying. Stopping the owned process does not roll back files already written.

Local download replacement prefers atomic rename, but can use backup-and-replace when the filesystem rejects overwrite rename; that compatibility fallback is not atomic. Preserve any backup path reported after a failed restore. Do not apply HTTP transfer task states or guarantees to these CLI commands.
