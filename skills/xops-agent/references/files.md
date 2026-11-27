# Remote Files and Transfers (XOps v2)

XOps v2 provides scriptable atomic SFTP subcommands (`xops sftp <op>`), parallel resumable `xops scp`, an interactive SFTP shell (`xops sftp <target>`), and MCP `file` / `transfer` tools.

## Single-Shot Atomic SFTP Operations (`xops sftp <op>`)

Prefer single-shot `xops sftp` subcommands with `--json` over shelling out with `sed`/`cat`—they require no remote shell, verify FSTAT `(dev, ino)` anchors on writes/patches, and publish atomically via `posix-rename@openssh.com`:

```bash
# Inspect directory, metadata, and symlinks
xops sftp ls --json web-01 /srv/app
xops sftp stat --json web-01 /srv/app/app.ini
xops sftp stat --follow-symlinks --json web-01 /srv/app/current
xops sftp realpath --json web-01 /srv/app/current
xops sftp readlink --json web-01 /srv/app/current

# Bounded read (read / cat)
xops sftp cat --max-bytes 65536 web-01 /srv/app/app.ini

# Atomic write from local file or stdin ("-")
xops sftp write --file ./app.ini --perm 0644 --create-parents --json web-01 /srv/app/app.ini
printf 'enabled=true\n' | xops sftp write --file - --no-clobber --json web-01 /srv/app/flag.env

# FSTAT-anchored text patch (fails closed with remote_anchor_mismatch / patch_conflict on concurrent edits)
xops sftp patch --old "debug=true" --new "debug=false" --json web-01 /srv/app/app.ini
xops sftp patch --old "v1" --new "v2" --all --json web-01 /srv/app/app.ini

# Directory & metadata mutations
xops sftp mkdir --perm 0755 --json web-01 /srv/app/releases/v2
xops sftp mv --no-clobber --json web-01 /srv/app/app.ini.new /srv/app/app.ini
xops sftp chmod --json web-01 0640 /srv/app/app.ini
xops sftp rm --json web-01 /srv/app/tmp.bak
xops sftp rmdir --json web-01 /srv/app/empty-dir

# Recover interrupted WAL transfer journals (--prune removes superseded generations)
xops sftp recover --json
xops sftp recover --local-root ./downloads --prune --json web-01 <transfer_id>
```

All `xops sftp` subcommands accept `-P/-p/-l/-i/-J/-o/-F`, `--policy`, `--lang <en|zh>` (valid before or after the subcommand verb before `--`, e.g. `xops sftp --lang zh ls web-01 /srv/app`), and `--json`.

## Parallel Resumable SCP (`xops scp`)

`xops scp` requires strictly one local path and one `[user@]host:<remote_path>` operand (no remote-to-remote or `--tag` selector on `scp`; use Playbook `copy`/`template` or loop per node for fleet distribution):

```bash
# Upload single file or recursive directory
xops scp --no-clobber --perm 0644 --json ./app.conf web-01:/srv/app/app.conf
xops scp -r -p --resume --concurrency 4 --chunk-size 1048576 --json ./dist web-01:/srv/app/

# Download file or directory inside a sandboxed local root
xops scp --local-root ./downloads --expected-digest sha256:<hex> --json web-01:/srv/release.bin release.bin
xops scp -r --local-root ./downloads --max-files 500 --max-bytes 1073741824 --json web-01:/srv/artifacts artifacts
```

Key `xops scp` safety constraints:
- Port flag is uppercase **`-P <port>`** (`-p` / `--preserve` preserves mtimes and modes).
- **Symlink policies** (`--symlink-policy`): `reject` (strict default), `contained_relative`, `follow_operator_source`.
  - Recursive upload (`-r`) requires `--symlink-policy=reject` and anchors inside `ScopedRootFS`.
  - Downloads permit only `reject` or `contained_relative`.
- `--expand-into-dir[=bool]` defaults to `true`; pass `--expand-into-dir=false` if uploading directly to an exact path.
- `--no-clobber` refuses overwriting an existing file. Always verify digests or read back critical files after transfer.

## Interactive SFTP Shell (`xops sftp <target>`)

For human interactive sessions only (rejects `--json`; inherits `--lang <en|zh>` / `XOPS_LANG` for help, status, and error/approval prompts):

```bash
xops sftp [--dir /srv/app] web-01
```

Built-in commands: `pwd`, `cd`, `ls [-l] [-a]`, `lpwd`, `lcd`, `lls [-l] [-a]`, `put [-r] [-n] [--resume] [-p]`, `get [-r] [-n] [--resume] [-p]`, `cat`, `write [-n] [-p]`, `mv|rename [-n]`, `mkdir [-m <octal>]`, `rm`, `rmdir`, `chmod`, `chtimes`, `stat [-L]`, `lstat`, `realpath`, `readlink`, `help`, `exit`/`quit`/`bye`. Single-command `Ctrl+C` returns cleanly to `sftp> `.

## MCP Equivalents (`file` & `transfer` tools)

- **`file`**: `read`, `write`, `patch` (with `edits`, `expected_anchor`, `expected_digest`), `stat`, `rename`, `list`, `mkdir`, `remove`, `removedir`. Zero `OperatorReadFS` access.
- **`transfer`**: `start`, `chunk`, `pull`, `commit`, `abort`, `resume`, `recover`, `inspect`. Supports up to 10 GiB with dual-generation CRC32 WAL and Streamable HTTP `/transfers/{transfer_id}/stream` (anchored strictly to `--transfer-root`). Never touch `TransferUncertainCommit` entries without inspecting remote state first.
- Tool descriptions, JSON Schemas, `approval_challenge` payloads, and `OutcomeUnknown` / `transfer_uncertain_commit` error responses remain invariant canonical English regardless of `--lang` or `XOPS_LANG`.
