# SFTP and file transfer

XOps provides both an interactive SFTP shell (`xops sftp`) and a command-line file transfer tool (`xops scp`).

## Quick start

### 1. Upload, download, and distribute files with SCP

```bash
# Upload a file or directory relative to the remote login home directory
xops scp ./test.tar 'web-01:~/tmp/' -v

# Download from a remote host to a local directory
xops scp 'web-01:~/tmp/test.tar' ../ -v

# Distribute a file to all hosts matching a tag (quote ~ paths so the local shell does not expand them)
xops scp ./config.conf --tag web --dest '~/tmp/'
xops scp ./config.conf --tag web --dest /etc/app/
```

- **Path rules**: Remote paths support `~` and `~/...` relative to the remote SFTP login directory (normally the user's home) across uploads, downloads, remote-to-remote relays, and batch uploads. `~otheruser` is not supported; use an absolute path instead.
- **Overwrite policy**: Answering `y` at a prompt or passing `--force` overwrites existing files even if size and modification time match; `--no-clobber` skips existing destinations. Always verify target directory permissions before overwriting.
- **Local download replacement**: Downloads first attempt an atomic rename. If the filesystem refuses to rename over an existing regular file, XOps backs up the original file before promoting the download and restores it on failure (this fallback is non-atomic; if restoration fails, the error reports the backup path). A directory of the same name is never replaced with a regular file.

### 2. Interactive SFTP shell

```bash
xops sftp web-01
```

Type `help` at the SFTP prompt to list all commands. Common operations:

```text
pwd
ls
cd /var/tmp
put ./report.txt
get report.txt
exec date
exit
```

- `exec <command>`: Runs a command in the current remote directory (allocating a PTY in interactive mode for terminal programs) and returns to the SFTP prompt.
- `shell` / `lshell`: Opens a remote or local interactive shell; `lexec`: runs a local command. The SFTP prompt resumes when the child program exits.
- If the connection drops, the SFTP shell exits immediately with a nonzero status rather than accepting further commands.

## Interactive input and keyboard shortcuts

The SFTP prompt supports line editing, command history (saved in `~/.xops_sftp_history`), and local/remote path completion:

| Key | Behavior |
| --- | --- |
| `Tab` / `Shift+Tab` | Request path completion and cycle forward/backward through candidates (turning pages automatically) |
| `PageUp` / `PageDown` | Move by a full page in the completion menu (stops at first/last page) |
| `Enter` / `Esc` (completion menu) | `Enter` inserts the selected candidate without running the command; `Esc` closes the menu |
| `↑` / `↓`, `Ctrl+P` / `N` | Browse history; returning to the newest line restores your current draft |
| `Ctrl+R` | Reverse-search history; press again for an earlier match |
| `Enter` / `Esc` / `Ctrl+G` (search) | `Enter`/`Esc` accepts the match and returns to editing; `Ctrl+G` cancels search and restores the draft |
| `Home` / `End`, `Ctrl+A` / `E` | Jump to the start / end of the line |
| `Ctrl+U` / `K` / `W` | Delete before cursor / after cursor / previous word |
| `Delete` / `Ctrl+D` | `Delete` removes the character under the cursor; `Ctrl+D` exits on an empty line or deletes under the cursor |
| `Ctrl+C` | Cancel current input; at an overwrite/delete prompt, abort remaining files in the current command (`n` skips only the current item) |

**Editor and history behavior**:
- **Completion menu**: A single match is inserted immediately; after completing a directory, press `Tab` again to complete inside it. Multiple matches display in a multi-column grid (up to 6 rows with page and total counts) highlighted with `>`. Remote completion queries time out after 2 seconds and cancel automatically if you keep typing.
- **Scrolling and paste**: Long lines scroll horizontally while editing and echo in full on submission. Wide characters, combining marks, emoji, and bracketed pastes split across reads are preserved (newlines and tabs in pasted text become spaces without submitting the command). When `stdin` is a terminal and `stdout` is piped (e.g. to `tee`), prompts and terminal resize handling continue to work via the input terminal.
- **History resilience**: Up to 500 recent non-empty, non-duplicate interactive commands are stored (confirmation answers and batch commands are excluded). If the history or lock file is unavailable at startup, XOps warns and falls back to session-only history. Temporary Windows file-sharing conflicts retry within a 2-second deadline; write failures keep commands in memory and merge them back to disk once writing recovers.

## Batch mode

Piping or redirecting input into `xops sftp` (e.g. `xops sftp web-01 < batch.txt`) automatically enables batch mode:
- The first command failure stops execution immediately with a nonzero exit status, without running later commands or writing interactive history.
- Local `lls`/`lll` and remote `ls`/`ll` fail immediately on missing paths or read errors; a failure on any wildcard match stops the remaining matches and subsequent commands.
- Batch `exec` allocates no PTY, and `exec` / `lexec` receive `EOF` on stdin so they cannot consume subsequent SFTP commands.
- `shell`/`lshell` require an interactive terminal; operations that would prompt for overwrite or removal fail unless resolved with force/no-clobber options. Each command line is capped at 1 MiB.

## Working directory inheritance and probing for `exec`

After changing the remote directory with `cd`, SFTP `exec` binds the current remote working directory (`cwd`) to your command:

- **POSIX and fish (`bash`/`sh`/`zsh`/`fish`)**: A nonempty `cwd` wraps the entire user program in a conditional block (`cd ... && { ...; }` or fish's `cd ...; and begin ... end`). If changing directories fails, semicolon-separated or multiline commands do not run; on success, the user program's exit status is preserved.
- **Windows CMD (`cmd` and saved `server/cmd`)**: Uses `cd /d "directory" || exit /b & user-command`. A failed directory change exits immediately with the failure `ERRORLEVEL` so later `&`, `&&`, `||`, or grouped commands never run; on success, native CMD syntax, `rem` comments, and exit codes are preserved. Saved `server/cmd` nodes derive a temporary CMD adapter for `cwd`-aware `exec` calls without reprobing or modifying node settings.
- **Windows path normalization**: Windows SFTP paths `/C:/...` convert to `C:/...`, and drive roots `/C:` or `/C:/` convert to `C:/` (running `exec dir` at `sftp:/C:>` lists the root of `C:`). Cross-platform `pwsh` selects path formats at runtime via its own `$IsWindows` even on cold connections without a probe cache; POSIX paths remain unchanged.
- **On-demand probing**: When execution settings are unspecified and the launch dialect is unknown, `exec` with a nonempty `cwd` runs a bounded read-only probe once per connection and caches the result in memory (Linux prefers default `bash`/`sh`/`zsh`/`fish`; Windows CMD prefers installed PowerShell for `cwd` handling and falls back to CMD). Empty-`cwd` commands do not probe. Other explicit `server` configurations reject a nonempty `cwd`. A failed probe aborts before running user code and never retries under another interpreter.
