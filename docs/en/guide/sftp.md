# SFTP and SCP File Transfers

XOps v2 explicitly distinguishes **local `os.Root` sandboxed atomic semantics** from **remote SFTP v3 protocol semantics**, offering resumable parallel `xops scp`, 15 scriptable single-shot `xops sftp` subcommands, and an interactive SFTP shell.

## 1. Parallel Resumable Transfers (`xops scp`)

`xops scp` requires strictly one local operand and one remote `[user@]host:<remote_path>` operand:

```bash
# Upload a local file to a remote directory or exact file path
xops scp ./release.tar.gz web-01:/srv/releases/
xops scp --no-clobber --perm 0644 ./app.conf web-01:/etc/app/app.conf

# Recursive directory upload (parallel chunks + resume + preserve mode/times)
xops scp -r -p --resume --concurrency 4 --chunk-size 1048576 ./dist web-01:/srv/app/

# Download a remote file or directory (anchored inside ScopedRootFS)
xops scp web-01:/var/log/app.log ./app.log
xops scp -r --local-root ./downloads --max-files 500 --max-bytes 1073741824 web-01:/srv/artifacts ./artifacts

# Verify SHA-256 digest and emit a JSON/v2 report
xops scp --expected-digest sha256:<hex> --json web-01:/srv/release.bin ./release.bin
```

### `xops scp` Flags and Guarantees

| Flag | Description |
| --- | --- |
| `-P <port>` / `-l` / `-i` / `-J` / `-o` / `-F` | Standard OpenSSH connection options (uppercase `-P` sets port) |
| `-p` / `--preserve` | Preserve modification times (and permissions on upload) |
| `-r` / `--recursive` | Recursive transfer (recursive upload requires `--symlink-policy=reject` and uses `ScopedRootFS`) |
| `--resume` | Resume interrupted transfer with digest verification |
| `--no-clobber` | Refuse to overwrite an existing destination file |
| `--expand-into-dir[=bool]` | Expand uploaded filename into an existing remote directory (default `true`) |
| `--symlink-policy <policy>` | `reject` (strict default) \| `contained_relative` \| `follow_operator_source` (downloads allow `reject` or `contained_relative` only) |
| `--local-root <dir>` | Explicit `ScopedRootFS` sandbox directory for local I/O |
| `--perm <octal>` | Remote file mode (`0001..0777`) |
| `--chunk-size` / `--concurrency` | Parallel chunk size in bytes and concurrent worker count |
| `--max-files` / `--max-bytes` | Hard file-count and total-byte caps for transfers |
| `--expected-digest <sha256>` | Fail closed unless transferred content matches the expected SHA-256 digest |

## 2. Single-Shot Remote SFTP Operations (`xops sftp <op>`)

Perform atomic remote filesystem operations without requiring a remote shell (all subcommands support `--json` and `--policy`):

```bash
# Listing, stat, realpath, and symlink inspection
xops sftp ls web-01 /srv/app --json
xops sftp stat web-01 /srv/app/app.ini
xops sftp stat --follow-symlinks web-01 /srv/app/current
xops sftp realpath web-01 /srv/app/current
xops sftp readlink web-01 /srv/app/current

# Bounded read (read / cat)
xops sftp cat --max-bytes 65536 web-01 /srv/app/app.ini

# Atomic write from local file or stdin ("-")
xops sftp write --file ./app.ini --perm 0644 --create-parents web-01 /srv/app/app.ini
printf 'mode=prod\n' | xops sftp write --file - --no-clobber web-01 /srv/app/mode.env

# FSTAT-anchored text patch (concurrent remote edits fail closed with remote_anchor_mismatch / patch_conflict)
xops sftp patch --old "debug=true" --new "debug=false" web-01 /srv/app/app.ini
xops sftp patch --old "v1" --new "v2" --all web-01 /srv/app/app.ini

# Directory and metadata operations
xops sftp mkdir --perm 0755 web-01 /srv/app/releases/v2
xops sftp mv --no-clobber web-01 /srv/app/app.ini.new /srv/app/app.ini
xops sftp chmod 0640 web-01 /srv/app/app.ini
xops sftp rm web-01 /srv/app/tmp.bak
xops sftp rmdir web-01 /srv/app/empty-dir

# Recover interrupted dual-generation WAL transfers (omit target/id to scan all; --prune cleans superseded gens)
xops sftp recover --json
xops sftp recover --prune web-01 <transfer_id>
```

## 3. Interactive SFTP Shell (`xops sftp <target>`)

Start an interactive session by passing a target host (optionally with `--dir <remote_dir>` or `<target>:<remote_dir>`):

```bash
xops sftp web-01
xops sftp --dir /srv/app web-01
xops sftp web-01:/srv/app
```

> The interactive SFTP shell does not support `--json` (use single-shot subcommands for machine parsing). Pressing `Ctrl+C` during a slow transfer cancels only that command and returns cleanly to the `sftp> ` prompt.

### Interactive Shell Commands

| Group | Commands |
| --- | --- |
| **Navigation** | `pwd`, `cd [remote-path]`, `ls [-l] [-a] [remote-path]`, `lpwd`, `lcd <local-path>`, `lls [-l] [-a] [local-path]` |
| **Transfer & Atomic Ops** | `put [-r] [-n] [--resume] [-p] <local> [remote]`, `get [-r] [-n] [--resume] [-p] <remote> [local]`, `cat <remote>`, `write [-n] [-p] <remote> <text>`, `mv\|rename [-n] <old> <new>`, `mkdir [-m <octal>] <remote>`, `rm <remote>`, `rmdir <remote>` |
| **Metadata & Inspection** | `chmod <octal-mode> <remote>`, `chtimes <mtime> <remote>` (or `chtimes <atime> <mtime> <remote>`, RFC3339 or Unix epoch), `stat [-L] <remote>` (follows symlinks), `lstat <remote>` (no symlink follow), `realpath <remote>`, `readlink <remote>` |
| **Control** | `help [command]` (`?`), `exit` / `quit` / `bye` |

## 4. Honest Security and Atomicity Boundaries

- **Local Side (`core/osfs` `*os.Root`)**: Downloads and recursive uploads operate strictly inside a non-escaping `os.Root` sandbox with temp-file staging, fsync, and sidecar-locked atomic replacement, blocking path traversal and symlink escapes.
- **Remote Side (SFTP v3 Protocol)**: Write and patch flows use non-truncating open + `SSH_FXP_FSTAT` file-type/`(dev, ino)` anchor verification, then stage to a sibling temp file and publish atomically via OpenSSH `posix-rename@openssh.com`. Concurrent remote mutations or unsupported extensions fail closed rather than silently corrupting data.
