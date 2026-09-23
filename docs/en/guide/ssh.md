# SSH and privilege escalation

```bash
xops ssh web-01
xops ssh -i ~/.ssh/id_ed25519 deploy@192.0.2.10
xops ssh -J bastion.example.com deploy@192.0.2.10
```

A single-label jump host must already exist as a node or alias. Explicit users on the same host keep separate credentials.

## Automatic node saving

When SSH, SFTP, SCP, or exec first connects to a new node, XOps prepares its connection details in memory. It saves the node, host, and identity only after the SSH handshake and authentication succeed. A timeout, refused connection, authentication failure, or cancellation before authentication creates no saved configuration. Saving another node cannot accidentally publish an unauthenticated pending node.

The save happens before opening a shell, executing a command, or starting a file transfer, so a later operation failure does not remove an authenticated node. Existing nodes remain saved after connection failures. Explicit additions and imports also verify by default and support `--skip-verify`; a failed `host add` asks whether to save, while imports support `--save-on-verify-failure`. `--remember never` only disables automatic saving of password-like secrets; successfully authenticated node details are still saved.

For example, if `xops ssh root@192.0.2.10` tries the default port 22 and fails, it leaves no `:22` node. If `xops ssh root@192.0.2.10:2222` then authenticates successfully, only the `:2222` node is saved, and a later command that omits the port can resolve to it. If multiple ports for the same host are genuinely saved, specify the port or a unique alias. Invalid nodes left by older versions must be removed manually.

If saving the node fails, XOps reports the error and closes the authenticated SSH connection before exposing it to the caller. If the configuration replacement was applied but syncing its directory failed, XOps does not automatically roll it back. Concurrent configuration changes are never overwritten.

## Privilege escalation

```bash
xops ssh --sudo web-01
xops exec -x --sudo web-01 id
```

The node configuration selects the escalation method: root, passwordless sudo, password sudo, su, and other supported modes. Hosts that only permit ordinary-user SSH login can use su with the root password inside that connection. Root SSH login is not required.

`ssh --sudo` opens an elevated interactive shell. `exec -x --sudo` executes an elevated command directly, retaining PTY authentication without an extra root shell prompt or injected command echo. Validate custom su/PAM multi-step authentication and login scripts on the target system.

## Tunnels

```bash
xops ssh -L 8080:127.0.0.1:80 -N web-01
xops ssh -D 1080 -N web-01
```

Tunnels close when the session ends. See [Troubleshooting](../troubleshooting/) for connection, host key, and credential issues.

With `-L`, `-R`, `-D`, or `-N`, XOps monitors the SSH connection. A lost connection closes the forwarding listeners and returns a failure status. Silent network loss is detected by SSH keepalive requests every 15 seconds, with a 10-second timeout per probe. Connections are not automatically reestablished; rerun the command after connectivity returns.
