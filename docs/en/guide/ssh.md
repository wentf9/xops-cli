# SSH, Tunnels, and Multiplexing

XOps v2 mirrors standard OpenSSH `ssh(1)` ergonomics while backing every connection with deterministic 4-layer option resolution, a structured connection pool, and a supervised ControlMaster daemon (`muxdaemon`).

## 1. Interactive SSH and Single Commands (`xops ssh`)

```bash
# Connect using a managed node alias or ~/.ssh/config host
xops ssh web-01

# Ad-hoc destination with port, user, identity file, and multi-hop ProxyJump
xops ssh -p 2222 -l deploy -i ~/.ssh/id_ed25519 192.0.2.10
xops ssh -J bastion1,bastion2 deploy@192.0.2.10

# Pass OpenSSH -o overrides and alternate config (-F none disables ~/.ssh/config)
xops ssh -o ConnectTimeout=10 -o ServerAliveInterval=30 -F ~/.ssh/config.work web-01

# Control PTY allocation (option parsing stops at the target host so remote flags pass through untouched)
xops ssh -t web-01 top
xops ssh -tt web-01 htop
xops ssh -T web-01 uname -a

# Non-interactive command with canonical JSON/v2 output
xops ssh --json web-01 uname -a
```

### Supported OpenSSH Flags

| Flag | Description |
| --- | --- |
| `-p <port>` / `-l <user>` | Override remote port / login username |
| `-i <identity_file>` | Private key path (repeatable) |
| `-J <proxy_jump>` | Single or multi-hop jump chain (comma-separated, e.g. `jump1,jump2`) |
| `-o <Key=Value>` | OpenSSH option override (repeatable, folded FirstWins into Tier-1) |
| `-F <configfile>` | Alternative OpenSSH config file (`none` disables) |
| `-t` / `-tt` / `-T` | Request PTY / force PTY even without local TTY / disable PTY |
| `-L` / `-R` / `-D` / `-w` | Local, remote, dynamic SOCKS5, and TUN/TAP forwarding (repeatable) |
| `-W <host:port>` | Parsed for CLI compatibility only; currently fails closed with `unsupported` (exit `255`); use `-J` (`ProxyJump`) or `-O proxy` / `xops mux proxy` instead |
| `-M` / `-MM` | Enable ControlMaster (`-M` = `yes`, `-MM` = `ask`) |
| `-S <ctl_path>` | ControlMaster socket path override (`none` disables; control subcommands use explicit `-S` literally without expanding `~`/`%C`) |
| `-O <ctl_cmd>` | Control an active master: `check` \| `forward` \| `cancel` \| `exit` \| `stop` \| `proxy` |
| `-N` / `-f` | Do not execute a remote command / hand off to in-process `muxdaemon` synchronously (no OS `fork()` detach—launch in a background/managed session; requires `-N`, `-M`, or forwards, and cannot include a remote command) |
| `--tun-mode <mode>` | `-w` tunnel mode: `point_to_point` (default) \| `ethernet` |
| `--lang <en\|zh>` | Override display language (place before the target host and `--`; remote command arguments after the target host such as `xops ssh web mytool --lang=fr` pass through untouched) |

> **Privilege Escalation**: Controlled `sudo`, `su`, and `doas` execution is handled by [`xops exec --sudo|--su|--doas`](./exec) using Vault references (`--password-ref`) or interactive prompts (`--prompt-password`), never plaintext CLI flags.

## 2. SSH Tunnels and Port Forwarding (`xops tunnel` / `xops forward`)

In addition to `xops ssh -N -L/-R/-D/-w`, XOps v2 provides a dedicated `xops tunnel` (alias `forward`) command with structured `--json` readiness summaries and deterministic shutdown cleanup:

```bash
# Local port forward (-L): local 127.0.0.1:18080 -> remote 127.0.0.1:80
xops tunnel local web-01 127.0.0.1:18080:127.0.0.1:80

# Remote port forward (-R): remote 127.0.0.1:9000 -> local 127.0.0.1:3000
xops tunnel remote worker-01 127.0.0.1:9000:127.0.0.1:3000

# Dynamic SOCKS5 proxy (-D)
xops tunnel dynamic web-01 127.0.0.1:1080

# Combine multiple forwards in one session (StreamLocal Unix sockets use OpenSSH path syntax starting with /, ./, ../, or ~/)
xops tunnel start -L 127.0.0.1:5432:127.0.0.1:5432 -L /tmp/app.sock:/run/app.sock -D 127.0.0.1:1080 web-01

# TUN/TAP layer-2/3 tunnel (-w / tun)
xops tunnel tun --tun-mode point_to_point gateway-01 0:0
```

### Platform Support

- **TCP `-L`/`-R`/`-D` and StreamLocal**: Supported natively on Linux, macOS, and Windows.
- **TUN/TAP (`-w` / `tunnel tun`)**: Supported on Linux (`/dev/net/tun`) and macOS (`AF_SYSTEM` `utun`) with appropriate device privileges; Windows and FreeBSD fail closed with `unsupported`.
- **Lifecycle**: On `SIGINT`/`SIGTERM`, forwards stop in strict reverse order before closing the underlying SSH session. Bind to `127.0.0.1` by default unless broader network exposure is explicitly required.

## 3. ControlMaster Multiplexing and Daemon (`xops mux`)

XOps v2 supports OpenSSH-compatible ControlMaster sockets and a Nursery-supervised `muxdaemon` via `xops ssh -M/-S/-O/-f` or `xops mux`:

```bash
# 1. Start a ControlMaster (--daemon / -f runs muxdaemon synchronously in the current process with no OS fork() detach; run in a background/managed session)
xops mux start -S /tmp/xops-mux-web01.sock -o ControlPersist=10m --daemon web-01 &
# Equivalent OpenSSH form:
xops ssh -M -f -N -S /tmp/xops-mux-web01.sock -o ControlPersist=10m web-01 &

# 2. Check master liveness and PID (explicit -S takes a literal path; omit -S when options.control.path is configured in config.yaml)
xops mux check -S /tmp/xops-mux-web01.sock web-01 --json
xops ssh -O check -S /tmp/xops-mux-web01.sock web-01

# 3. Dynamically add or cancel forwards on an active master
xops mux forward -S /tmp/xops-mux-web01.sock -L 127.0.0.1:18080:127.0.0.1:80 web-01
xops mux cancel  -S /tmp/xops-mux-web01.sock -L 127.0.0.1:18080:127.0.0.1:80 web-01

# 4. Run stdio proxy through the active master (-O proxy)
xops mux proxy -S /tmp/xops-mux-web01.sock web-01

# 5. Stop accepting new sessions (stop) or terminate immediately (exit)
xops mux stop -S /tmp/xops-mux-web01.sock web-01
xops mux exit -S /tmp/xops-mux-web01.sock web-01
```

### ControlMaster Internals

- **Verified Sockets & Stale Cleanup**: Control sockets are bound through `core/osfs` with owner-only permissions (`0600` and peer-credential verification on Unix). Stale sockets left by crashed masters are probed and safely cleaned before rebinding.
- **Literal `-S` vs. Config Path Templates**: Control commands (`xops mux check/forward/cancel/proxy/stop/exit` and `xops ssh -O`) pass an explicit `-S` path verbatim without expanding `~` or `%C`. To use automatic `~` and `%C`/`%h`/`%p`/`%r` token expansion, configure `options.control` (`master`, `path: "~/.xops/mux-%C"`, `persist: "10m"`) in `~/.xops/config.yaml` and omit `-S` on control commands.
- **In-Process Synchronous Supervisor & Non-Interactive Mode**: `xops mux start --daemon`, `xops mux daemon`, and `xops ssh -f` run `muxdaemon` synchronously in the current process until `ControlPersist` idle expiry, `mux exit`, or `SIGINT`/`SIGTERM` (no OS `fork()` detach)—scripts and AI agents should launch them in a background or managed session. Because `muxdaemon` runs without interactive stdin, configurations requiring `ControlMaster=ask/autoask` or interactive prompts fail closed rather than hanging.
- **OpenSSH `-O` Canonical English Control Receipts**: Regardless of `--lang` or `XOPS_LANG`, `xops ssh -O` and `xops mux check/forward/cancel/stop/exit` text control receipts (such as `mux check: master running (pid=...)`) stay in OpenSSH-compatible canonical English.

## 4. Host Key Trust (KnownHosts & SSHFP)

- Defaults to `StrictHostKeyChecking=ask` (prompts on interactive terminals; fails closed with `host_key_unknown` in non-interactive mode or when set to `yes`).
- Key mismatches and revoked keys fail closed with `host_key_mismatch` and `host_key_revoked`.
- Local `known_hosts` updates use `ScopedRootFS` with sidecar locks to prevent concurrent corruption.
