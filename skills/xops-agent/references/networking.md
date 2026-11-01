# SSH tunnels

## Create an SSH tunnel

Resolve the SSH node, then start the appropriate CLI command in a command-runner session whose process handle you retain:

```bash
# Local browser/tests reach a service on the SSH node
xops ssh -n -N -L 127.0.0.1:18080:127.0.0.1:3000 web-01

# A remote worker reaches a service on the CLI machine
xops ssh -n -N -R 127.0.0.1:18080:127.0.0.1:8080 worker-01

# Local SOCKS5 proxy through the SSH node
xops ssh -n -N -D 127.0.0.1:1080 web-01
```

Choose one example for the task. `-N` runs forwarding without a remote command, and `-n` prevents reading stdin. Prefer the runner's managed session over `-f` when it makes process ownership and cleanup clearer. The session must remain alive while the tunnel is needed; do not use a short command timeout that immediately kills it.

| Mode | Listener location | Destination connection and name resolution |
| --- | --- | --- |
| `-L` | CLI machine | SSH node |
| `-R` | SSH node | CLI machine |
| `-D` | CLI machine | SSH node, with proxy-aware clients choosing destinations |

“Local” means the Agent's command environment, including a container or remote sandbox. The user's browser must be able to reach that listener. Use an explicit loopback bind by default; broader exposure must match the request. For `-R`, sshd `GatewayPorts` can affect actual bind scope, so inspect the remote listener if isolation matters.

Select an available port and record the node, direction, bind address, target, and process/session handle. Multiple `-L` or `-R` options can share a session; stopping that process closes all its forwards. Use a separate process when independent lifecycle control is needed.

## Inspect and stop

The CLI has no `xops tunnel create/list/status/stop`, request IDs, or managed tunnel TTL. Implement those operational steps with the owned process and connectivity checks:

1. Check that the session is still running and inspect stderr. `administratively prohibited`, target refusal, and other channel errors can occur after a listener starts. `-L`/`-D` open a forwarding channel on use; `-R` requests the remote listener at startup. `xops ssh` supports `-v`/`-vv`/`-vvv` for leveled connection, authentication, and forwarding channel diagnostics on `stderr`.
2. Probe the actual application. For the local HTTP example:

   ```bash
   curl --connect-timeout 5 --max-time 10 http://127.0.0.1:18080/
   ```

   Checking TCP connection acceptance alone cannot prove the forwarded destination works. Use a database client, HTTP probe, or another protocol-appropriate tool for the service.
3. For status, inspect the command runner's retained session/PID and the relevant listener (for example local `ss` on Linux or `Get-NetTCPConnection` on Windows). There is no persistent XOps tunnel inventory.
4. Stop only the session created for this task. Use the runner's stop/cancel action, or signal its exact owned PID, then wait for exit and verify the listener is gone. Avoid broad process-name kills. Remote port release can be delayed after network failure; do not claim release without a check.

SSH disconnect/keepalive failure ends forwarding and returns failure; there is no automatic reconnect. If the user requests a lifetime, bound the owned process accordingly and clean it up at that deadline; do not invent a CLI TTL flag. Leave a tunnel running only when ongoing access is part of the task, and report the handle/address needed to manage it.
