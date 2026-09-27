# SSH tunnels over MCP stdio

The stdio server started with `xops mcp serve` provides SSH local (`-L`) and remote (`-R`) forwarding. Use it to inspect a remote web application in a browser, connect local tests to a remote database, or let remote workers call a local development service. HTTP MCP does not register tunnel tools. Dynamic SOCKS5 forwarding (`-D`) is not exposed through MCP.

## Location and preparation

“Local” always means **the machine running the XOps MCP process**. When the stdio server runs inside a container or a remote development environment, local listeners and destination connections belong to that environment.

| Mode | Listener location | Destination resolution and connection location |
| --- | --- | --- |
| `local` (`-L`) | MCP process machine | SSH node |
| `remote` (`-R`) | SSH node | MCP process machine |

Configure nodes, credentials and trusted host keys first. Tunnels use the configured ProxyJump chain and never prompt for passwords or unknown host keys. They use the node configuration snapshot captured at server startup; restart MCP after changing that configuration.

`nodeID` accepts saved node IDs, aliases and OpenSSH IDs such as `openssh:web`. After creating through the OpenSSH alias `web`, the returned canonical ID `openssh:web` can be reused for creation retries, new tunnels and list filters. Unprefixed aliases prefer saved nodes when names collide; the `openssh:` prefix preserves the OpenSSH namespace.

OpenSSH identifiers, including IDs resolved from aliases, must not contain whitespace or control characters. Such requests fail before policy evaluation, keeping the policy key consistent with the name used for the connection.

## Tools and examples

| Tool | Input | Purpose |
| --- | --- | --- |
| `xops_tunnel_create` | `requestID`, `nodeID`, `mode`, `listenPort`, `targetHost`, `targetPort`; optional `listenHost`, `ttlSeconds` | Create a tunnel and return its state |
| `xops_tunnel_list` | Optional `nodeID`, `state` | List this process's tunnels and retained terminal records |
| `xops_tunnel_status` | `tunnelID` | Query one tunnel |
| `xops_tunnel_stop` | `tunnelID` | Stop listening and close existing forwarded connections |

Forward the loopback web service on SSH node `web-1` to an automatically allocated local port:

```json
{
  "requestID": "web-preview-001",
  "nodeID": "web-1",
  "mode": "local",
  "listenHost": "127.0.0.1",
  "listenPort": 0,
  "targetHost": "127.0.0.1",
  "targetPort": 3000,
  "ttlSeconds": 3600
}
```

The returned `tunnel.listenAddress` contains the allocated listening port. The browser must be able to reach that machine's listener; on the same machine, open `http://<listenAddress>`.

Let SSH node `worker-1` access a local development service through its loopback port:

```json
{
  "requestID": "worker-callback-001",
  "nodeID": "worker-1",
  "mode": "remote",
  "listenHost": "127.0.0.1",
  "listenPort": 18080,
  "targetHost": "127.0.0.1",
  "targetPort": 8080,
  "ttlSeconds": 1800
}
```

Here, destination `127.0.0.1:8080` is on the MCP process machine. The SSH server must permit TCP forwarding. Its `GatewayPorts` policy controls actual bind interfaces; the returned requested address does not prove loopback-only exposure.

`listenHost` defaults to `127.0.0.1` and accepts IP literals or `localhost`. Supply IPv6 literals without brackets, such as `::1`. `listenPort` accepts `0–65535`, with `0` requesting allocation; destination ports accept `1–65535`. Use a new `requestID` for each new tunnel and the returned `tunnelID` for status and stop calls.

## Lifecycle and limits

`running` means the listener is established, not that the destination service has been verified. Individual connection failures are recorded in `lastConnectionError`; the tunnel can accept later connections. Startup or SSH transport failures enter `failed`, with details in `error`.

| State | Meaning |
| --- | --- |
| `starting` | Establishing the SSH connection and listener |
| `running` | Listener established |
| `stopping` | Stop requested; cleanup in progress |
| `stopped` | Resources owned by this process have been released |
| `expired` | Lifetime ended and resources have been released |
| `failed` | Startup, transport or cleanup failed; inspect the error |

Cancellation before startup is committed aborts creation. After publication, the tunnel survives completion of the creating tool call. Retrying the same `requestID` with the same normalized parameters returns the existing record without renewing its lifetime. Changed parameters cause a conflict. Terminal records never restart; fix the cause and use a new request ID.

Explicit stop, expiry, SSH disconnect or MCP process exit triggers cleanup. Tunnels do not automatically reconnect or survive process restarts. If waiting for stop times out, cleanup continues; query status. Remote forwards report `remoteRelease: "unconfirmed"` after stopping: local cleanup does not confirm release of the remote port, particularly when a network failure delays detection by the SSH server.

An EOF caused by closing the listener during a normal stop is treated as cancellation and does not mark the task `failed`. Listener interruptions without a stop request and unexpected listener cleanup errors still report failure.

Cancellation, timeout or MCP shutdown during ProxyJump startup releases established jump connections even if the downstream SSH handshake is incomplete or the network is unresponsive.

| Limit | Current value |
| --- | --- |
| Default / maximum lifetime | 1 hour / 24 hours, selected with `ttlSeconds` |
| Startup timeout | 30 seconds, excluding approval |
| Active tunnels | 16 per MCP process, including startup and cleanup |
| Concurrent connections per tunnel | 64; excess connections are closed immediately |
| Terminal record retention | 24 hours; cleared on process exit |
| Total records | 1024; new creation is refused at capacity until records expire or the service restarts |

Each tunnel owns its SSH connection and jump chain. Stopping one leaves ordinary MCP SSH/SFTP connections and other tunnels intact. Forwarded reads and writes retain SSH forwarding time limits: five minutes for an idle read and one minute for a write before closing that connection.

## Approval and auditing

Loopback local forwards and stop operations are `moderate`; remote forwards and non-loopback local listeners are `dangerous`; list and status are `safe`. Approval depends on `guardrail` thresholds and node policies. Approval displays the direction, listener, destination and lifetime and binds the complete normalized parameters. Declines, cancellations and approval errors do not create a task.

Lists without `nodeID` check the global policy and every node represented in the results. If any policy requires approval, one approval covers the complete node set. Declines, cancellations and configured denial of execution without approval return no partial list. State filters include only nodes with matching records; approval and audit records include the complete node set. Results come from the snapshot checked by policy, so waiting for approval cannot add unchecked nodes. A modern approval continuation rejects an approval if the node set has changed; issue a fresh query.

The global threshold is checked independently. Node overrides such as `"*"` cannot lower approval requirements for a query without `nodeID`, even when the result is empty. Queries for an explicit node continue to use that node's override.

Creation, running and terminal events share an operation ID in the audit log. An audit failure before creation prevents startup; failures after startup appear in `auditError` and do not recreate the tunnel. Status queries do not add application authentication to forwarded traffic; destination services retain their own authentication requirements.
