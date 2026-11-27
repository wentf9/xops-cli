# Tunnels, Port Forwarding, and ControlMaster Multiplexing (XOps v2)

XOps v2 provides dedicated `xops tunnel` (alias `forward`) and `xops mux` commands alongside OpenSSH-compatible `xops ssh` flags, plus the first-class MCP `tunnel` tool.

## SSH Tunnels (`xops tunnel` / `xops forward` & `xops ssh`)

Start tunnels in a managed process/session whose handle you retain while the forward is needed:

```bash
# Local TCP port forward (-L): local 127.0.0.1:18080 -> remote 127.0.0.1:80
xops tunnel local --json web-01 127.0.0.1:18080:127.0.0.1:80

# Remote TCP port forward (-R): remote 127.0.0.1:9000 -> local 127.0.0.1:3000
xops tunnel remote --json worker-01 127.0.0.1:9000:127.0.0.1:3000

# Dynamic SOCKS5 proxy (-D)
xops tunnel dynamic --json web-01 127.0.0.1:1080

# Multiple forwards + StreamLocal Unix sockets in one session (use OpenSSH path syntax starting with /, ./, ../, or ~/)
xops tunnel start -L 127.0.0.1:5432:127.0.0.1:5432 -L /tmp/app.sock:/run/app.sock -D 127.0.0.1:1080 --json web-01

# TUN/TAP tunnel (-w / tun; Linux /dev/net/tun & macOS utun; unsupported on Windows/FreeBSD)
xops tunnel tun --tun-mode point_to_point gateway-01 0:0

# OpenSSH-style equivalents via xops ssh (-N disables remote command; for multi-hop/stdio proxy use -J ProxyJump or xops mux proxy / xops ssh -O proxy — do NOT use -W, which fails closed with exit 255 unsupported)
xops ssh -N -L 127.0.0.1:18080:127.0.0.1:80 web-01
xops ssh -J bastion deploy@10.0.0.10 uname -a
```

### Operational Safety Rules for Tunnels

- Default to explicit loopback binds (`127.0.0.1`); expose broader interfaces only when explicitly authorized.
- Remember "local" is the host/container running `xops`. Verify end-to-end application reachability (e.g. HTTP or DB probe), not merely TCP port acceptance.
- Stop temporary tunnels by signaling only the exact owned process (`SIGINT`/`SIGTERM` triggers clean reverse-order teardown) and verify the listener is closed.

## ControlMaster Multiplexing (`xops mux` & `xops ssh -M/-S/-O/-f`)

Reuse an authenticated SSH transport across multiple commands or dynamic forwards:

```bash
# Start a ControlMaster supervisor in a background/managed session (--daemon / -f runs muxdaemon synchronously in-process with no OS fork() detach)
xops mux start -S /tmp/xops-mux-web01.sock -o ControlPersist=10m --daemon web-01
# Equivalent OpenSSH flags (also run in a background/managed session):
xops ssh -M -f -N -S /tmp/xops-mux-web01.sock -o ControlPersist=10m web-01

# Probe liveness and master PID (explicit -S is literal with no ~/%C expansion; omit -S if options.control.path is configured in config.yaml)
xops mux check -S /tmp/xops-mux-web01.sock --json web-01
xops ssh -O check -S /tmp/xops-mux-web01.sock --json web-01

# Dynamically add or cancel a forward on the running master
xops mux forward -S /tmp/xops-mux-web01.sock -L 127.0.0.1:18080:127.0.0.1:80 --json web-01
xops mux cancel  -S /tmp/xops-mux-web01.sock -L 127.0.0.1:18080:127.0.0.1:80 --json web-01

# Stdio proxy over active ControlMaster
xops mux proxy -S /tmp/xops-mux-web01.sock web-01

# Graceful stop (no new sessions) or immediate master exit
xops mux stop -S /tmp/xops-mux-web01.sock --json web-01
xops mux exit -S /tmp/xops-mux-web01.sock --json web-01
```

- `mux start --daemon`, `mux daemon`, and `ssh -f` run `muxdaemon` **synchronously in the current process** until `ControlPersist` idle expiry, `mux exit`, or `SIGINT`/`SIGTERM` (no OS `fork()` detach). Always launch them in a background/managed session (just like `xops tunnel`) rather than expecting immediate process return.
- `mux daemon` and `ssh -f` have no interactive stdin; configurations requiring `ControlMaster=ask/autoask` or interactive prompts fail closed.
- `-f` requires `-N`, `-M`, or at least one forward rule (`-L/-R/-D/-w`) and cannot be combined with a remote command or `-O`.
- Explicit `-S` on `mux check/forward/cancel/proxy/stop/exit` and `ssh -O` uses the socket path **verbatim** without expanding `~` or `%C`. Either pass a concrete literal socket path (such as `/tmp/xops-mux-web01.sock`) or configure `options.control.path: "~/.xops/mux-%C"` in `config.yaml` and omit `-S`.

## MCP Equivalent (`tunnel` tool)

In MCP mode (both `stdio` and Streamable HTTP), use the `tunnel` tool with generation-bound `handle` / `handle_token`:
- **Forwards**: `start_forward` (`direction`: `local` | `remote` | `dynamic` | `tun`, `bind_kind`/`target_kind`: `tcp` | `unix`), `inspect_forward`, `stop_forward`.
- **ControlMaster**: `start_mux`, `inspect_mux`, `stop_mux`, `probe_mux`, `control_mux` (`mux_action`: `check` | `forward` | `cancel` | `exit` | `stop`). Note: `start_mux` expands `~`/`%C`, whereas `probe_mux` and `control_mux` treat explicit `socket_path` verbatim—pass the concrete expanded `socket_path` returned by `start_mux` (or omit `socket_path` when `options.control.path` is configured).
- Ephemeral tunnel/mux handles are automatically revoked on `Halted` and cleaned up on MCP server close.
