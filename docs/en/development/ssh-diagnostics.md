# Leveled SSH diagnostics

## Scope and boundaries

`xops ssh -v/-vv/-vvv` reuses SCP's structured diagnostics and controlled output. It does not switch SSH backends or change authentication candidate order, host trust, connection leases, interpreter payloads or command retry policy.
`--debug` / `--log-level` still control independent internal logs. See the [SSH guide](../guide/ssh.md) for usage and restrictions.

References: [ssh(1)](https://man.openbsd.org/ssh.1), OpenSSH portable's
[ssh.c](https://github.com/openssh/openssh-portable/blob/master/ssh.c) and
[clientloop.c](https://github.com/openssh/openssh-portable/blob/master/clientloop.c).
Option ordering, diagnostic categories and `debug1/2/3:` style are aligned, not every output line.

## Options and levels

- `cmd/diagnostic_flags.go` owns shared ordered bool flags, OpenSSH log-level spacing and bounded string escaping.
- SSH has one log level: the first `-v` sets DEBUG1, later occurrences increment up to DEBUG3, and `-q` sets QUIET.
  Thus `-qv` enables diagnostics, `-vq` disables them, and `-vqv` reaches only FATAL, not DEBUG1.
- SCP retains separate native verbosity and SSH log levels, including SFTP diagnostics with `-vq`.
- DEBUG1: connections, trust, authentication, negotiation, session starts, actual termination results and forwarding listener lifecycle.
- DEBUG2: session opening, request sending/confirmation and forwarding connection acceptance/completion.
- DEBUG3: session channel cleanup results. This is not complete SSH packet, window-adjustment or rekey tracing.
- `cmd/argument_routing.go` still preserves arguments after the remote command; a remote `-v` does not become a local diagnostic flag.

## Event sources

`core/log.Diagnostic` adds negotiation, session request/start/finish/cleanup and forwarding lifecycle events, plus an exit code with explicit presence.
These are additive metadata. Callers without an observer produce no diagnostic output and acquire no extra protocol requests or monitor goroutines.

- `Connector.configureClient` injects the command-owned observer into newly created and reused Client wrappers.
- Authentication callbacks report observed `ClientAuthContext.Metadata/Algorithms` at most once per physical handshake, retaining available versions and algorithms even when authentication fails.
  Successful initial none authentication invents no attempts; the existing authenticated summary still uses actual handshake results. SCP skips the new pre-authentication negotiation event to preserve its summary behavior.
- `Client.sessionRequest` / `newSessionContext` observe actual request boundaries rather than claiming acceptance in advance.
- `Client.waitSession` observes `Session.Wait` before merging I/O/cancellation errors or applying legacy full-login-shell exit policy.
  Nonzero exits, signals and missing status remain distinct; missing status, disconnects and cancellation must not become exit code 0.
- `ExecuteCommand` still uses the original CommandResult's completed/not_started/unknown outcome and optional exit code, without replay.
- Forwarding reports from existing listener/handler lifecycles, without additional listeners or monitors; per-connection failure isolation remains unchanged. CLI error callbacks only enqueue controlled output instead of writing standard streams directly.

## Output and ownership

`cmd/diagnostic_output.go` replaces SCP's private output queue. SSH and SCP share it and the SSH event formatter.
SCP retains ownership of SFTP, transfer and progress formatting.

- The command owns the observer, capacity-128 queue, writer and output binding. Protocol callbacks only enqueue nonblocking updates; overflow drops auxiliary display and reports the omitted count at shutdown.
- SSH's `RunContext` retains the observer until tunnels, Client and Connector stop, then closes the queue, joins the writer and releases the binding. Borrowed standard streams are never closed.
- Verbose forwarding errors reuse the command's stderr queue. Without verbose logging, the existing `sshTunnelGroup` owns the error queue, draining and joining it after all forwarding callbacks exit. Failed writers skip subsequent error writes, without `logger.PrintErrorf` fallback.
- `-N` ready status retains its original stdout and text but uses a controlled queue owned by the tunnel group. There is no synchronous `fmt.Printf` bypass even when stdout/stderr share a blocked pipe. Queues use the command context; the tunnel group separately cancels its child and session contexts, so normal shutdown does not prematurely cancel output waiting to drain.
- Writes exceeding one second cancel the owned output binding. In-flight regular-file kernel writes must return before joining, so no hard cancellation deadline is promised. Unsupported sinks skip auxiliary output without raw Write fallback.
- The SSH writer coordinates with the existing prompt gate; output-context cancellation interrupts waiting, and diagnostics do not write while a password/trust prompt holds the gate.
  Terminal diagnostics and forwarding errors use CRLF rather than depending on OPOST in raw mode; log files retain LF. User-facing forwarding errors retain their original text and colors, outside Diagnostic fields reserved for public protocol metadata.
- SSH output failures use the existing `ssh.OutputError` to retain borrowed sink identity; SCP retains its `SCPOutputError` wrapper.
  Existing top-level `HasStandardOutputError` handling avoids printing errors back into failed or blocked standard streams.
- `-f -N` retains foreground validation followed by child reconnection with discarded child standard streams; no background log file is introduced.

Events exclude commands, scripts, credentials, private keys, environment values and arbitrary remote error text.
The CLI bounds and escapes untrusted strings. Public metadata still includes addresses, usernames, fingerprints and forwarding endpoints; logs are not anonymous.

## Validation entry points and platform limits

Regressions cover levels/quiet ordering, remote argument boundaries, independent internal logs, success/nonzero/signal/missing status/rejection/cancellation, legacy PTY exit policy and terminal restoration, forwarding listeners, redaction, prompt-gate cancellation, bounded queues, unsupported sinks, blocked pipes and output-error identity. Additional combination regressions cover local/remote/SOCKS5 forwarding with verbose logging both enabled and disabled: full stderr, diagnostic timeout, forwarding failure and shutdown. Ready-status tests cover blocked/failing stdout, normal draining and borrowed-stream ownership.
Windows blocking-output tests query the relevant write-direction buffer quota with `GetNamedPipeInfo`, complete a write of that quota, then verify that one additional byte blocks until cancellation. Canceling an oversized write alone does not prove a full pipe: Windows may discard pending data, leaving room for subsequent diagnostics or ready status. Unix still establishes the blocked condition using a large write with committed partial bytes.

System OpenSSH comparisons connect only to a loopback fixture with a pinned public key, never user servers, and do not snapshot complete output.

```sh
go test -race -shuffle=on -count=1 ./core/ssh ./cmd
python3 -m unittest discover -s scripts -p test_check_core.py
python3 scripts/check_core.py --race
npm run docs:check
```

Cross-compilation is not native terminal testing. Windows/macOS behavior still requires the corresponding native CI.
See [native cancelable output](./native-cancelable-output.md) for platform limits and [SCP diagnostics](./scp-diagnostics.md) for preserved SCP semantics.
