# SFTP and file transfer

XOps provides both an interactive SFTP shell (`xops sftp`) and a command-line file transfer tool (`xops scp`).

## Quick start

### 1. Upload, download, and distribute files with SCP

```bash
# Upload a file or directory relative to the remote login home directory
xops scp ./test.tar 'web-01:~/tmp/'

# Download from a remote host to a local directory
xops scp 'web-01:~/tmp/test.tar' ../

# Relay a file directly between two remote hosts (routed through your machine)
xops scp 'web-01:~/config.conf' 'web-02:~/config.conf'

# Upload to one or more hosts with --host
xops scp --host web-01 ./config.conf ./
xops scp --host web-01,web-02 ./config.conf /etc/app/

# Distribute a file to all hosts matching a tag (quote ~ paths so the local shell does not expand them)
xops scp --tag web ./config.conf '~/tmp/'
```

Basic syntax: `xops scp [options] <source> <destination>`. Both source and destination paths are required:

- **Single-host and relay transfers**: Without `--host`, `--tag`, or `-I/--ifile`, either path can use `[[user@]host:]file` (where the host part is a node name, alias, or host address). Local-to-remote uploads, remote-to-local downloads, and remote-to-remote relays through the local client are all supported (local-to-local is not).
- **Ports and special paths**:
  - Like OpenSSH `scp`, use `-P 122` (or `--port 122`) to set the SSH port; lowercase `-p` is not used for ports.
  - Everything after the host colon is treated as the file path, not a port—for example, `user@host:22:file` refers to a remote file named `22:file`. Enclose IPv6 addresses in brackets, such as `user@[::1]:file`.
  - When `-P` is omitted, XOps uses the matched node's configured port. If a host matches multiple saved ports, XOps reports the ambiguity rather than guessing port 22—specify `-P` or use a unique alias. To relay between two hosts on different ports, assign each host an alias.
  - Windows remote paths accept `vm:C:/Users/example/file.txt`. Prefix local filenames containing colons with `./` (e.g., `./22:file`).
- **Batch or targeted uploads (`--host` / `--tag` / `-I`)**: Passing `--host`, `--tag`, or `-I/--ifile` always uploads from the local machine to the selected hosts (the three flags are mutually exclusive; use `--exclude` to filter out hosts). In this mode, both paths are treated as literal file paths—characters like `:`, `@`, and `[` are treated as ordinary filename characters rather than remote address syntax.
- **`--src` and `--dest` compatibility flags**: You can pass `--src <source> --dest <dest>` instead of two positional paths, but both flags must be used together and cannot be mixed with positional arguments.

```bash
# Connect on port 122 and upload to a remote file named 22:file
xops scp -P 122 ./config.conf user@host:22:file

# With --host, @ and : in paths are treated as literal filename characters
xops scp --host web-01 ./config.conf 'user@name:backup'

# Using --src and --dest compatibility flags
xops scp --src ./config.conf --dest web-01:~/config.conf
xops scp --tag web --src ./config.conf --dest /etc/app/
```

- **Progress bar and connection diagnostics**:
  - A progress bar is shown on `stderr` by default in interactive terminals and hidden automatically when output is piped or redirected.
  - `-q` / `--quiet`: Hides the progress bar and SSH warnings/diagnostics (errors and security prompts are still shown).
  - `-v` / `--verbose`: Prints SSH/SFTP connection and transfer diagnostics (independent of project-level `--debug` logs):
    - `-v`: Shows connection, authentication, and transfer information.
    - `-vv`: Adds more detail about file operations.
    - `-vvv`: Produces the most detailed troubleshooting log.
  - Combining `-q` and `-v` follows OpenSSH flag order: `-qv` hides the progress bar while keeping SSH/SFTP diagnostics; `-vq` hides both the progress bar and SSH diagnostics, keeping only SCP transfer and SFTP init messages.
  - If the output environment does not support progress or diagnostics, these extra messages are omitted while file transfers continue. To save diagnostics, append `2>scp.log` to the command.

```bash
# Quiet mode (no progress bar)
xops scp -q ./file web-01:~/file

# Hide progress bar while showing SSH/SFTP diagnostics
xops scp -qv ./file web-01:~/file

# Get a more detailed troubleshooting log
xops scp -qvv ./file web-01:~/file
```

- **Remote `~` paths**: Remote paths support `~` and `~/...`, resolved relative to the remote SFTP login directory (typically the user's home directory). `~otheruser` is not supported; use an absolute path instead.
- **Overwrite behavior**: Answering `y` at a prompt or passing `-f`/`--force` overwrites existing files (even when size and modification time match); passing `-n`/`--no-clobber` skips existing files.
- **Local download protection**: If an overwrite fails, XOps attempts to restore the original file. If manual recovery is needed, follow the backup path in the error message. An existing directory is never replaced by a regular file.

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
- If the connection drops or command output fails, the session ends with a nonzero status. Reconnect to continue working.
- **Connection diagnostics**: `-v` / `--verbose` prints SSH/SFTP diagnostics to `stderr` (independent of `--debug`). It uses the same `debug1/2/3:` format as `xops ssh -v`:
  - `-v`: Shows connection, host key verification, authentication, negotiated algorithms, and SFTP initialization.
  - `-vv`: Adds SFTP extensions, path requests, and `get`/`put` file operations.
  - `-vvv`: Adds SFTP packet types, request IDs, lengths, and status codes. File contents and credentials are never printed.
  - Unlike `xops scp`, `xops sftp` has no `-q`. Diagnostics from tab completion or a running command may interleave with the line being edited; to keep the prompt clean, save them to a file, for example `xops sftp -vv web-01 2>sftp.log`.

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
- **History**: Up to 500 recent non-empty interactive commands are saved, excluding consecutive duplicates, confirmation answers, and batch commands. If the history file is unavailable, XOps warns and temporarily keeps session-only history. A failed save does not erase old entries; saving resumes when the file becomes available.

## Batch mode

Piping or redirecting input into `xops sftp` (e.g. `xops sftp web-01 < batch.txt`) automatically enables batch mode:
- The first command failure stops execution immediately with a nonzero exit status, without running later commands or writing interactive history.
- Local `lls`/`lll` and remote `ls`/`ll` fail immediately on missing paths or read errors; a failure on any wildcard match stops the remaining matches and subsequent commands.
- Batch `exec` allocates no PTY, and `exec` / `lexec` receive `EOF` on stdin so they cannot consume subsequent SFTP commands.
- `shell`/`lshell` require an interactive terminal; operations that would prompt for overwrite or removal fail unless resolved with force/no-clobber options. Each command line is capped at 1 MiB.

## Working directory inheritance and probing for `exec`

`exec` runs commands in the current remote directory. Use `cd` to change directories first. If the directory cannot be entered, the command will not run.

For Windows hosts, use paths such as `/C:/...`:

```text
cd /C:/Windows
exec dir
```

Use `cd /C:` to enter the root of the C: drive.

When no interpreter is configured, XOps attempts to detect the remote environment. If execution is reported as unsupported, check the node's `execution` settings and select an interpreter installed on that host—see [Hosts and identities](./hosts#node-execution-configuration-execution). A configured `server` interpreter supports the SFTP working directory only with the `cmd` launch dialect; other environments need an explicit interpreter. If detection fails, the command does not run.
