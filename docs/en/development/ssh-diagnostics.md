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
- DEBUG1: connections, trust, authentication, negotiation, session starts, actual termination results, privilege modes/attempts/readiness/results and forwarding listener lifecycle.
- DEBUG2: session opening, request sending/confirmation, privilege probes/credential lookup/password interactions and forwarding connection acceptance/completion.
- DEBUG3: terminal handoff/restoration and session channel cleanup results. This is not complete SSH packet, window-adjustment or rekey tracing.
- `cmd/argument_routing.go` still preserves arguments after the remote command; a remote `-v` does not become a local diagnostic flag.

## Event sources

`core/log.Diagnostic` adds negotiation, session request/start/finish/cleanup and forwarding lifecycle events, plus an exit code with explicit presence.
These are additive metadata. Callers without an observer produce no diagnostic output and acquire no extra protocol requests or monitor goroutines.

- `Connector.configureClient` injects the command-owned observer into newly created and reused Client wrappers.
- Authentication callbacks report observed `ClientAuthContext.Metadata/Algorithms` at most once per physical handshake, retaining available versions and algorithms even when authentication fails.
  Successful initial none authentication invents no attempts; SCP skips pre-authentication negotiation events.
- `authenticationTrace` belongs to one handshake, without a global map. It records actual callback-selected protocol methods and `PartialSuccessMethods`, clearing the preceding terminal selection on every callback. In x/crypto v0.57.0's authentication loop, failures/partial successes invoke the callback again while success returns directly. Only after `NewClientConn` succeeds does `Authenticated.Methods` contain the server-confirmed partial-success chain plus the terminal method; `Method` is the final successful method. Success without any callback proves initial none authentication. Unknown selection is never guessed from configuration. The recorder changes no callback return value, fallback or retry order, carries no credentials and is disabled without an observer.
- Raw AEAD `ReadMAC/WriteMAC` fields stay empty because no independent MAC is negotiated. The shared SSH/SCP formatter displays OpenSSH-style `<implicit>` for known AES-GCM and ChaCha20-Poly1305 ciphers, actual names for nonempty MACs, and `<unknown>` for empty metadata that is not known AEAD. Empty values alone are not evidence of AEAD.
- `Client.sessionRequest` / `newSessionContext` observe actual request boundaries rather than claiming acceptance in advance.
- `Client.waitSession` observes `Session.Wait` before merging I/O/cancellation errors or applying legacy full-login-shell exit policy.
  Nonzero exits, signals and missing status remain distinct; missing status, disconnects and cancellation must not become exit code 0.
- `ExecuteCommand` still uses the original CommandResult's completed/not_started/unknown outcome and optional exit code, without replay.
- Forwarding reports from existing listener/handler lifecycles, without additional listeners or monitors; per-connection failure isolation remains unchanged. CLI error callbacks only enqueue controlled output instead of writing standard streams directly.

## Privilege phases

`PrivilegeLifecycle` uses `Operation` for the escalation mode and `Outcome` for a fixed phase name. `Attempt` is a 1-based exchange attempt; password prompt/response events instead count password attempts within the current exchange, with 0 meaning not applicable. `core/ssh/privilege_diagnostics.go` only organizes metadata, owning no connection, terminal, credential or background task. Additive fields are `PrivilegeCommand` for a redacted invocation, `PrivilegePromptPattern` for the active matching rule, and `PrivilegePrompt` for actual recognized prompt text.

- `Client.maybeDetectSudoMode` / `detectRootOrSudoer` report root identity confirmation, passwordless sudo availability or unconfirmed probes, then the configured/discovered mode selection. Configured root/passwordless modes are not new authentication evidence; no additional probes run.
- `resolvePrivilegeMaterial` reports lookup, availability, interactive prompting and failure, without backend errors, paths or secret values. Available credentials are not verified credentials.
- `runPrivilegeOperation` and existing passwordless/one-shot sudo paths report attempts and final completed/failed/canceled/timed_out phases. Completed means termination under the original exit policy, not replacement of actual session exit status or a new retryable CommandResult. Legacy paths without control frames never invent authentication success.
- Escalation invocations are reported before sending. Normal and portable paths share wrapper builders between actual invocations and diagnostic views, replacing the complete control/user payload with `<privileged payload>` and random prompt markers with `<password-prompt>`, rather than guessing secrets with command regexes. Legacy sudo paths display their corresponding fixed invocation prefixes. Active patterns are reported before starting; prompt text is reported after a complete match and before consuming it, including fragmented and sudo-rs prompts. Core caps text at 1024 bytes and the CLI retains bounded escaping. Observers never access credential response buffers; post-ready user output is excluded from prompt diagnostics.
- sudo fallback accepts only a valid explicit node/global `password_prompt_pattern` at `Client` construction (node first); absent, invalid or empty-string-matching patterns never fall back to the built-in default. Only `SudoModeSudo` enables it, not `SudoModeSudoer`; su retains its existing defaults. `privilegeFrameWriter.findPrompt` prefers the random marker, retains complete sudo-rs envelope waiting and xtrace exclusion, and skips zero-width matches. Fallback applies only without a primary match or incomplete envelope; buffered ready takes precedence over a generic fallback challenge. The prompt buffer retains a 4096-byte look-behind, while trimming preserves per-stream physical-line prefix classification and regexp boundary classes without retaining discarded text. Matching includes boundary context that cannot be consumed by the prompt, avoiding fabricated `^`, `\A` and `\b` boundaries and retaining xtrace exclusion across trims. A stream-owned cached contextual regexp consumes one context rune outside the prompt capture before lazily searching real input. It no longer discards the first synthetic `FindAllIndex` candidate, which could mask a valid `\s*Password:` after a real newline. Resumed searches use the preceding real rune without resetting boundary semantics; zero-width candidates advance by rune. `regexp/syntax` normalization preserves captures, inline options and open `\Q` quotes when embedding the original expression. Only recognized prompts/control frames reset the protocol matching region; candidates consuming discarded context are rejected. No password prompts are recognized after readiness. Fallback reuses `respond`, the three-attempt bound and input gate, without additional sessions, replay or OTP support. `password_prompt_fallback_pattern` / `password_prompt_fallback` are DEBUG2 rule/match events. Existing stdin behavior of one-shot, non-gated sudo entries is unchanged.
- `privilegeExchange` reports `elevated_shell_ready` only upon parsing the actual ready frame, and `elevation_not_confirmed` when ending before starting. Password prompts, sent responses, repeated prompts and existing su rejection classification are distinct. Rejection events require the original `finish` exit/error conditions, never just rejection-like banner text. Nonzero user-command results and rejection-like output after escalation are not reclassified as authentication failures.
- `privilege_terminal` reports from existing activation/ACK/terminal-confirmation/input-forwarding/restoration boundaries. Diagnostics change no input gate, cancellation, restoration, confirmed-credential persistence or retry timing. Callbacks still only enqueue to the command's bounded queue, without additional I/O workers or raw writes.

Local SSH fixture regressions cover sudo/su retries followed by a nonzero command (executed only once), three rejections without consuming user stdin, root/passwordless/auto modes, credential lookup without claiming authentication, cancellation during prompting, terminal-handoff timeout and restoration failure. Assertions cover phase ordering, level filtering, and exclusion of passwords, user commands, control frames and raw errors. Invocation/prompt regressions additionally cover sudo, sudo -i, sudo-rs, su, fish/zsh portable control shells, passwordless -n, byte-by-byte and every two-chunk prompt split, bounded escaping, and exclusion of post-ready output from prompt diagnostics.

Fallback tests use a local fixture ignoring `-p`, covering normal/portable/PTY paths, retries followed by a nonzero command executed once, no password transmission without opt-in, three rejections, and cancellation during prompting without consuming stdin. Unit regressions cover node/global precedence, invalid/empty/zero-width patterns, marker priority, fragmented sudo-rs envelopes, xtrace, ready priority and opaque post-ready output. Long-line regressions cover xtrace exceeding 4 KiB, fabricated line/text/word boundaries, different trim boundaries, long leading-plus runs, recovery of real prompts and newline-free retries, and fragmented marker/sudo-rs recovery, asserting no false prompt queuing or sensitive diagnostics. Additional cases cover real `(?m)^\s*Password:` / `\s*Password:` prompts after long whitespace banners, resumed search after rejected xtrace, Unicode/zero-width matches, capture ranges and bounded regexp caching.

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

Events may include redacted sudo/su invocations and recognized password prompt text/patterns, but exclude user commands, scripts, credential responses, private keys, user environment values and arbitrary remote error text.
The CLI bounds and escapes untrusted strings. Public metadata still includes addresses, usernames, fingerprints and forwarding endpoints; logs are not anonymous.

## Validation entry points and platform limits

Authentication regressions cover fixed password/publickey, auto publickey, failed-publickey-to-password fallback, initial none, successful/failed publickey-plus-password multi-stage authentication, and actual negotiation metadata for three AEAD ciphers and AES-CTR/HMAC. Successful events must exclude failed attempts. CLI checks cover final methods, success chains, per-direction MACs and unknown values.

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
