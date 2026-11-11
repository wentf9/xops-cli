# SSH and privilege escalation

Use `xops ssh` to open interactive shell sessions, run one-off remote commands, or set up port-forwarding tunnels.

```bash
# Connect via node alias
xops ssh web-01

# Connect with an explicit private key and username
xops ssh -i ~/.ssh/id_ed25519 deploy@192.0.2.10

# Connect through a jump host (ProxyJump)
xops ssh -J bastion.example.com deploy@192.0.2.10
```

Direct jump hosts accept an IP, FQDN, or `host:port`; a single-label jump name (such as `-J jumphost`) must already exist as a saved node or alias. Connecting to the same host as a different user keeps credentials isolated per user.

## Connection diagnostics

```bash
xops ssh -v web-01
xops ssh -vv web-01 uptime
xops ssh -vvv -N -L 8080:127.0.0.1:80 web-01
xops ssh -v web-01 uptime >output.log 2>ssh.log
```

- `-v` shows connections, host-key verification, the final successful authentication method, negotiated algorithms and session results; `-vv` adds request confirmations, privilege interactions and forwarding connections; `-vvv` also shows terminal handoff and session cleanup. Diagnostics use OpenSSH-style `debug1/2/3:` prefixes on stderr without changing remote stdout.
- The authenticated line's `using "publickey"`, `using "password"` or `using "none"` identifies the method that actually completed the handshake; multi-stage authentication also shows the successful chain. `MAC: <implicit>` means AES-GCM or ChaCha20-Poly1305 provides integrity protection without a separate MAC, not that integrity checking is disabled. Non-AEAD algorithms display the actual HMAC name; unconfirmed values display `<unknown>`.
- `-q` hides diagnostics and tunnel-ready status, not remote output, failures or security confirmations. Like OpenSSH, order matters: `-qv` enables diagnostics, `-vq` disables them, and `-vqv` does not immediately restore DEBUG1.
- `--debug` / `--log-level` control separate internal logs and are not changed by `-v/-q`. Put a remote command's own `-v` after its command name, for example `xops ssh -v web-01 curl -v https://example.com`.
- Diagnostics omit user-command, script, password and private-key bodies. Escalation invocations redact their payloads, but logs include hosts, usernames, fingerprints, password prompt text and forwarding addresses. Review logs before sharing. `-vvv` is not a complete internal SSH packet trace.
- If a pipe does not support diagnostic output, redirect stderr to a regular log file. Diagnostic output failure makes the operation fail, but does not prove that the remote command never ran; do not blindly retry. With `-f -N`, only foreground validation diagnostics are visible; background logs are not retained.

## Running remote commands and piped scripts

In addition to interactive logins, `xops ssh` can execute a single command or stream a local script over stdin:

```bash
# Run a remote command natively (defaults to server passthrough mode)
xops ssh web-01 uptime
xops ssh --host web-01 --interpreter server uname -a

# Run with Bash without loading the login environment
xops ssh --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false id
```

- **Interpreter selection**: Uses the remote shell by default. To choose an interpreter, use `server`, `bash`, `sh`, `zsh`, `fish`, `powershell`, `pwsh`, or `cmd`. See [Command execution](./exec#interpreters-and-cross-platform-execution) for flag combinations. Terminal use is supported on Windows, macOS, and Linux.
- **Login environment**: `bash`, `zsh`, and `fish` support `--login-shell`; `--no-login` remains a Bash compatibility flag (non-login `bash -c`); `server` mode rejects login flags.
- **Pseudo-terminal (PTY) control**:
  - `-T` (`--disable-tty`): Disables pseudo-terminal allocation for the session (equivalent to `-o RequestTTY=no`).
  - `-t` (`--force-tty`): Forces PTY allocation for remote commands when local input is a terminal; specifying multiple times (`-tt`) forces remote PTY allocation even if local stdin is redirected or not a terminal (equivalent to `-o RequestTTY=no|yes|force|auto`). When multiple `-T` and `-t` flags appear on the command line, the last flag takes precedence, and explicit flags override `-o RequestTTY`.
- **Input and shell routing**:
  - **Terminal with no command**: Opens an interactive PTY login shell.
  - **Piped script with no command (e.g. `cat script.sh | xops ssh web-01`)**: The remote shell reads and runs the script by default. If the node specifies `bash`, `sh`, `zsh`, or `fish`, that interpreter and the node's login settings are used instead.
  - **Empty-command guard**: Passing an explicit empty command (e.g. `xops ssh web-01 ""`) fails immediately instead of opening an interactive shell.
- **Interrupting and saving output**: Press `Ctrl+C` to interrupt an operation. If piped output is reported as unsupported, run directly in the terminal or use a non-interactive `xops exec` command and save its output to a file.

## Automatic node saving on first connection

When `ssh`, `sftp`, `scp`, or `exec` connects to a new host for the first time, XOps **saves the node, host, and identity only after the connection and authentication succeed**:
- Timeouts, refused connections, authentication failures, or cancellations before authentication leave no stale entries behind.
- Saving occurs before opening a shell or running a command, so a subsequent command failure does not delete an authenticated node (nor do connection failures remove existing saved nodes).
- `--remember never` only prevents saving password/passphrase secrets; authenticated node address details are still saved.

For example, if `xops ssh root@192.0.2.10` fails on default port 22, no `:22` node is created. If `xops ssh root@192.0.2.10:2222` then authenticates, only the `:2222` node is saved, and future commands that omit the port will match it automatically (if multiple ports are saved for the same host, specify the port or use a unique alias).

If saving the node fails, the connection reports an error. If the message says the configuration may already have been saved, check `xops host list` before retrying.

## SSH authentication methods and multi-factor authentication (MFA)

XOps supports various standard SSHv2 authentication mechanisms as well as server-orchestrated multi-stage multi-factor authentication (MFA / 2FA) flows.

### Supported authentication methods

| Method | Protocol name | Description and capabilities |
| --- | --- | --- |
| **Public key** | `publickey` | Supports RSA, Ed25519, ECDSA, PKCS#8, and PEM private keys; supports passphrase-protected key files via interactive terminal prompt or piped `--passphrase-stdin`. |
| **Password** | `password` | Traditional static password authentication; saved in secure vaults with zero plaintext storage, supplied via secure interactive prompt or piped `--password-stdin`. |
| **Keyboard interactive** | `keyboard-interactive` (RFC 4256) | Server-initiated challenge/response questions (e.g., dynamic PAM prompts, static security questions). Supports **manual interactive replies** (with automatic echo suppression for passwords), **regex automated challenge rules** (`keyboard_interactive.rules`), reusing login passwords (`login_password`), reusing dynamic tokens (`otp`), vault-managed secrets (`secret`), and external command providers (`command`). |
| **One-time password** | `otp` (RFC 6238 / RFC 4226) | Time-based One-Time Passwords (TOTP). Built-in pure Go standard library RFC 6238 implementation (supports standard Base32 seeds and `otpauth://` URIs, SHA1/SHA256/SHA512, 6/8 digits, and custom steps). Supports vault-managed secrets (`totp_secret_ref`), external command providers (`command`), and per-session CLI overrides (`--otp` / `--otp-stdin`). |
| **Multi-stage MFA** | `PartialSuccessMethods` | Automatically tracks and progresses through multi-stage authentication requirements (e.g., public key + password, password + TOTP, public key + TOTP, password + security question) until full authentication is granted. |

### Configuration and examples

#### 1. Configuration file (`~/.xops/xops_config.yaml`)

XOps strictly adheres to the Schema v2 architecture and zero-plaintext security policy:
- `hosts` defines network hosts and ports;
- `identities` manages authentication credentials—passphrases, passwords, TOTP secrets, and challenge answers are stored in vaults, leaving only `*_ref` references in the configuration;
- `nodes` aggregates `host_ref` and `identity_ref` into directly connectable node definitions.

```yaml
hosts:
  bastion-host:
    address: 198.51.100.1
    port: 22

identities:
  opsadmin-mfa:
    user: opsadmin
    auth_type: auto             # Optional: auto, key, password, agent, otp, keyboard-interactive
    key_path: ~/.ssh/id_ed25519 # Private key for public key auth
    
    # Option A: TOTP (OTP) automated authentication
    otp:
      totp_secret_ref:          # Vault-managed TOTP seed reference (recorded via xops identity credential set)
        store_id: file
        item_id: totp-seed
      prompt_pattern: '(?i)verification code|otp' # Optional: automatically supplies OTP when prompt matches
      # Or obtain OTP via an external command (mutually exclusive with totp_secret_ref; shell metacharacters forbidden):
      # command: "/usr/local/bin/get-totp"
      # args: ["--account", "opsadmin"]
      # timeout: 5s

    # Option B: Keyboard-interactive automated challenge rules
    keyboard_interactive:
      rules:
        # Rule 1: Static security question answer managed by credential store (source: secret)
        - name: security_question
          prompt_pattern: '(?i)favorite city'          # Regex matching server prompt (required)
          instruction_pattern: '(?i)answer carefully' # Optional: regex matching server instruction
          source: secret                              # Source type: secret, command, login_password, otp
          secret_ref:                                 # Credential reference (recorded via xops identity credential set)
            store_id: file
            item_id: city-answer

        # Rule 2: External command provider (source: command) querying an external password manager
        - name: corporate_sso_token
          prompt_pattern: '(?i)one-time passcode'
          source: command
          command: "op"
          args: ["read", "op://Employee/bastion/passcode"]
          timeout: 5s

        # Rule 3: Automatically reuse login password when challenged
        - name: pam_password
          prompt_pattern: '(?i)password'
          source: login_password

        # Rule 4: Automatically reuse configured OTP when challenged
        - name: pam_otp
          prompt_pattern: '(?i)authenticator code'
          source: otp

nodes:
  bastion-mfa:
    host_ref: bastion-host
    identity_ref: opsadmin-mfa
    sudo_mode: none
```

#### 2. Storing credentials securely via CLI

Secrets do not (and cannot) be written in plaintext in the YAML file. Use `xops identity credential set` with `--password-stdin` to safely record secrets into the vault:

```bash
# Store login password and private-key passphrase
xops identity credential set opsadmin-mfa --kind login_password --password-stdin
xops identity credential set opsadmin-mfa --kind passphrase --password-stdin

# Store TOTP shared secret (supports Base32 string or otpauth:// URI; automatically binds totp_secret_ref)
printf '%s\n' 'JBSWY3DPEHPK3PXP' | xops identity credential set opsadmin-mfa --kind totp_secret --password-stdin

# Store challenge answer for a specific rule (rule name must already be declared in keyboard_interactive.rules)
printf '%s\n' 'Beijing' | xops identity credential set opsadmin-mfa --kind challenge_answer --rule security_question --password-stdin
```

#### 3. Ephemeral session overrides and manual fallback

- **Passing ephemeral one-time passwords (session overrides)**:
  When connecting to an MFA/2FA-enabled host from the terminal, supply the current OTP token directly via the command line without modifying persistent identity configurations:
  ```bash
  # Pass token via --otp
  xops ssh --otp 839201 bastion-mfa

  # Pass token safely via stdin pipeline (avoids process table exposure)
  printf '%s\n' '839201' | xops ssh --otp-stdin bastion-mfa
  ```

- **Interactive fallback when unconfigured**:
  If a server issues a `keyboard-interactive` challenge for which no rule matches, XOps will never make heuristic assumptions about the prompt type. Instead, it presents the server prompt directly to the terminal for manual user input:
  - If the server flags the challenge as secret (e.g. passwords or PINs), echo is suppressed to protect confidential input;
  - If the server flags the challenge as visible text, typed characters echo normally.

## Sudo / Su privilege escalation

```bash
# Open an elevated interactive shell
xops ssh --sudo web-01

# Diagnose escalation: mode selection, password interactions and remote readiness
xops ssh -vv --sudo web-01

# Run a single command with a PTY and privilege escalation
xops exec -x --sudo web-01 id
```

For escalation, `-v` shows mode selection, escalation invocations, attempts/retries, remote elevated-shell readiness and termination; `-vv` adds root/passwordless probes, credential lookup, password-matching patterns, actual recognized prompt text and response phases; `-vvv` also shows terminal handoff and restoration. sudo/su options, target users and control shells are visible. User command/script bodies appear as `<privileged payload>` and random prompt markers as `<password-prompt>` (for example, `[sudo: <password-prompt>] Password:`). Credential response values and control frames never enter diagnostics. Selecting a mode does not prove successful escalation, and elevated-shell readiness does not prove that the subsequent user command succeeds. Root and passwordless paths do not invent password interactions.

The node's `sudo_mode` controls how privileges are escalated (`auto`, `root`, passwordless `sudoer`, password `sudo`, or `su`):
- **Servers that disallow direct root SSH login**: Use `su` mode to log in over SSH as an ordinary user and switch to `root` inside the session without enabling `PermitRootLogin`.
- **Traditional `sudo` and `sudo-rs` compatibility**: XOps prompts again if credentials are missing or rejected. `exec -x --sudo` shows only the command output without extra root shell prompts.
- **sudo/PAM ignoring `-p`**: Explicitly set node-level or global `password_prompt_pattern`, for example `password_prompt_pattern: '(?m)^Password:[ \t]*$'`. sudo prefers its random marker and only falls back to this configured pattern when no marker matches; node settings take precedence. Missing/invalid patterns and patterns matching the empty string never enable the built-in default as a sudo fallback; passwordless `sudoer` mode does not fall back. `-vv` reports fallback rules and matches. Match the actual password prompt precisely, not banners or other input requests. This does not support OTP/multi-factor authentication or replay user commands.
- **Multi-shell escalation (`bash` / `sh` / `zsh` / `fish`)**:
  - Nodes configured with `launch_dialect: fish` + `interpreter: fish` (or `bash`/`sh`/`zsh`), or `launch_dialect: posix` + `interpreter: zsh`, support `xops ssh --sudo`, `xops exec --sudo`, and Playbook `sudo: true`.
  - The target must provide `/bin/sh`; using `su` also requires support for its `-s` option. See the [su manual](https://man7.org/linux/man-pages/man1/su.1.html).
  - CLI explicit `--interpreter` flags cannot currently be combined with `--sudo`; configure `execution` on the node or Playbook instead.

## Port forwarding and tunnels

```bash
# Local forward (-L): forward local 127.0.0.1:8080 to 127.0.0.1:80 from the remote server's perspective
xops ssh -L 8080:127.0.0.1:80 -N web-01

# Dynamic SOCKS5 proxy (-D): open a SOCKS5 proxy on local 127.0.0.1:1080
xops ssh -D 1080 -N web-01

# Remote forward (-R): forward remote 127.0.0.1:9000 to local 127.0.0.1:3000
xops ssh -R 9000:127.0.0.1:3000 -N web-01

# Standard I/O forward (-W): forward stdin/stdout over a secure channel to host:port (commonly used with ProxyCommand)
xops ssh -W 192.0.2.20:22 bastion

# Tunnel device forward (-w): create a point-to-point (tun) virtual network interface tunnel (requires PermitTunnel on the server)
xops ssh -w 0:0 -N gw

# Layer 2 Ethernet (tap) tunnel forwarding (-o Tunnel=ethernet must precede -w)
xops ssh -o Tunnel=ethernet -w 1:any -N gw
```

- **Binding and verification timing**: `-L` and `-D` open SSH channels on demand when local connections arrive; `-R` requests remote listening immediately at startup (with independent 10-second setup and teardown deadlines) and exits with an error if the server refuses.
- **Standard I/O forwarding (`-W host:port` / `--stdio-forward`)**:
  - Forwards the client's `stdin`/`stdout` over a secure SSH `direct-tcpip` channel to `host:port` reachable from the remote server. Commonly used as a jump proxy command with native OpenSSH in `~/.ssh/config`:
    ```sshconfig
    Host internal-host
        ProxyCommand xops ssh -W %h:%p bastion
    ```
  - Implicitly enables `-N` (no remote command), `-T` (no PTY), `ExitOnForwardFailure=yes`, and `ClearAllForwardings=yes` by default (can be explicitly overridden in configuration files or via `-o`, such as `-o ClearAllForwardings=no` or `-o ExitOnForwardFailure=no`).
  - `-W` provides a clean binary data stream channel and cannot be combined with a remote command, background mode (`-f`), `--sudo`, or multiplexing control commands (`-O`, except `-O proxy`).
- **Tunnel device forwarding (`-w local_tun[:remote_tun]` / `--tunnel-device`)**:
  - Creates a Layer 3 (`point-to-point`) or Layer 2 (`ethernet`) virtual network interface tunnel between client and server (requires `PermitTunnel yes` or appropriate permissions in the server's `sshd_config`).
  - Device unit numbers can be non-negative integers or `any` (system-assigned unused device). Omitting `:remote_tun` defaults to `any` (e.g. `-w 0` is equivalent to `-w 0:any`).
  - **Mode and ordering rules**: Defaults to `point-to-point` (Layer 3) mode unless `Tunnel` is specified beforehand. To use `ethernet` (Layer 2) mode, specify `-o Tunnel=ethernet` **before** `-w` (e.g. `xops ssh -o Tunnel=ethernet -w 0:0 gw`).
  - **Platform support notes**:
    - **Linux**: Natively supports `tun` (`point-to-point`) and `tap` (`ethernet`).
    - **macOS**: Natively supports `utun` (`point-to-point`); `tap` devices are not supported natively.
    - **Windows**: Local kernel virtual network interface creation is currently not supported (configuration items and `-o` parsing remain available and cross-platform compatible).
- **Per-connection error isolation**: Individual forwarding errors (such as `administratively prohibited` or an unreachable target port) are queued to controlled stderr output without tearing down the main SSH session or listener. `-N` ready status remains on stdout. Blocked output does not hold up forwarding callbacks; output failures are returned at shutdown. Unsupported pipes may omit auxiliary messages; redirect the affected stream to a regular file instead.
- **Keepalive and disconnect handling**: Sessions with `-L`, `-R`, `-D`, `-w`, or `-N` actively monitor the connection—sending an SSH heartbeat after 15 seconds of idle traffic and declaring a timeout only after 10 consecutive seconds with neither a reply nor data progress. When the connection drops, XOps closes local listeners and exits with a nonzero status. Combine `-f -N` to run tunnels in the background.
