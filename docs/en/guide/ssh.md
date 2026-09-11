# SSH and privilege escalation

```bash
xops ssh web-01
xops ssh -i ~/.ssh/id_ed25519 deploy@192.0.2.10
xops ssh -J bastion.example.com deploy@192.0.2.10
```

A single-label jump host must already exist as a node or alias. Explicit users on the same host keep separate credentials.

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
