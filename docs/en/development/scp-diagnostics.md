# SCP diagnostic levels

`cmd/scp.go` continues to transfer through the existing `core/ssh.Connector` and
`core/sftp.Client`. The optional `core/log.DiagnosticObserver` provides typed
lifecycle events independently of the project's `DebugLogger`. The SSH/SFTP
`WithDiagnostics` options only attach an observer; connection leases,
authentication order, host trust and cancellation retain their existing behavior.
CLI, MCP and Playbook consumers without an observer retain their existing
behavior. No protocol schema changes are involved.

## Flags and output

- Remove `--progress`. Progress appears on terminals by default and is omitted
  for redirected or piped output.
- `-q` disables progress and SSH warnings/diagnostics. Failures and necessary
  security confirmations remain visible; batch success/skip notices are hidden.
- `-v` enables SSH/SFTP lifecycle and SCP transfer diagnostics. Global `--debug`
  controls project logs independently and is not changed by `-q` or `-v`.
- As in OpenSSH, SCP verbosity and SSH log level are separate. `-qv` enables
  SSH diagnostics without progress. `-vq` hides both but retains SCP's own
  diagnostics, including SFTP initialization. The first SSH `-v` sets DEBUG1;
  subsequent occurrences increment the current level up to DEBUG3. `-q` sets
  QUIET, so `-vqv` does not restore DEBUG1. SCP itself adds DEBUG2/3 events with `-vv`/`-vvv`, independently of SSH quiet level.

References: [scp(1)](https://man.openbsd.org/scp.1),
[scp.c option handling](https://github.com/openssh/openssh-portable/blob/master/scp.c),
[ssh.c option handling](https://github.com/openssh/openssh-portable/blob/master/ssh.c).
The implementation aligns diagnostic categories and option semantics; it does
not claim to reproduce OpenSSH's output line for line with the Go SSH backend.

## Events, ownership and limits

- Connector events report connection establishment, proxy use, cache reuse,
  host key fingerprints and verification results, authentication completion,
  observed connection versions and negotiated algorithms. Negotiated metadata
  is read before wrapping the connection in `activitySSHConn`.
- Automatic authentication reports a protocol method only when its existing
  callback selects a candidate. The observer callback for fixed authentication
  returns nil to preserve dependency fallback selection. No successful method
  is inferred from configuration. Initial none-authentication success does not
  generate an invented password/publickey attempt.
- SFTP events report initialization start, failure and success; successful
  initialization means the dependency has validated SFTP v3. SCP reports the
  overall transfer start and final outcome. DEBUG2 reports advertised extensions, path requests and per-file outcomes.
  DEBUG3 reports actual SFTP packet types, request IDs, lengths, status codes and
  stream IDs. Remote stderr reports drained byte counts only, without its text.
- Events contain no credentials, private keys, file contents or raw errors.
  The CLI escapes control characters and bounds each string. Existing wrapped
  errors continue to report transfer failures.
- The command owns its observer until connector shutdown. Shared handshakes do
  not borrow an individual waiting caller's output lifetime. Diagnostic callbacks, progress writes and selector upload status messages enqueue
  without blocking into a 128-entry queue. Overflow drops auxiliary updates and
  reports their count without blocking protocols or transfers.
- With `ssh.BindOutput` support, the command owns a writer goroutine. A write
  exceeding one second cancels the output binding. Shutdown closes the queue,
  joins the writer and releases the binding. Borrowed stdout/stderr streams are never closed.
  Command cancellation also cancels the output binding.
- Windows synchronous/overlapped pipes, plus macOS terminals and
  already nonblocking pipes, use native cancelable bindings. Windows consoles, macOS blocking
  anonymous pipes and other unsupported sinks skip progress, diagnostics and
  upload status messages on that stream while transfers continue, with no direct writes at shutdown.
  Redirect stderr to a regular log file to retain diagnostics. Regular-file
  writes remain subject to native Write limitations and are not claimed to be interruptible.
- Selector upload skip messages remain on stderr and success messages on stdout,
  preserving colors and `-q` behavior. Both reuse the controlled queue, join
  and release their bindings on return, and propagate output failures.
- Auxiliary output failures preserve the stream name, error chain and nonzero exit
  status through `cmd.SCPOutputError`. Standard streams may share one pipe, so
  the CLI does not print these errors back to standard streams, avoiding another
  blocked write after the timeout. Other errors retain their existing reporting behavior.

## Validation scope

Local SSH/SFTP fixtures cover uploads, downloads, relays, single-host selectors,
errors, cancellation, truthful none-authentication reporting, authentication
fallback/failure and host key rejection. PTY fixtures check default progress and
quiet/redirected behavior. A Linux pipe fixture checks blocked-output shutdown;
a paused PTY checks nonblocking progress callbacks and transfer cancellation;
a full-pipe subprocess checks failure exit without rewriting standard streams.
Selector upload success/skip branches check bounded shutdown on full stdout/stderr
pipes, file contents and borrowed stream ownership. Additional
tests check queue bounds, control escaping, zero writes to unsupported sinks,
output errors and stderr ownership. Windows/macOS native console behavior remains for native CI;
cross-compilation does not establish native execution results.

## Follow-up implementation and dependency boundary

The selected approach retains existing dependencies without a fork, vendoring or
an alternate SSH backend. `x/crypto/ssh` exposes no public internal packet observer;
encrypted TCP traffic and SFTP packets are never presented as SSH packet traces.
`core/sftp/diagnostics.go` observes bytes already read/written at the existing
protocol pipe boundary and reconstructs metadata only. Protocol validation,
version support, failures and retry behavior remain with existing implementations.

- `core/log.Diagnostic.Level` selects levels 1–3; zero retains DEBUG1 behavior.
  Optional `DiagnosticLevel() int` capability filters higher-level events.
  DEBUG1 installs no protocol observer. Consumers without an observer gain no
  extra protocol I/O or goroutines.
- Each direction uses a fixed 16 KiB prefix buffer, never an allocation based on
  a declared packet length. Only version/extension metadata or the first path or
  extension name is retained. Paths are captured up to 512 bytes and displayed
  up to 256 bytes. Clipped paths and extension advertisements are marked.
- DATA, WRITE and HANDLE packets expose only allowed metadata such as type,
  request ID, length and status code. File contents and handles never enter the
  capture prefix or events. Extended requests retain only the extension name,
  not opaque arguments. STATUS message text is omitted.
- Each subsystem has a process-unique stream ID. Stream/request IDs correlate
  concurrent operations without an unbounded request map.
- Observers return the underlying n/error unchanged, perform no read-ahead or
  additional requests, and do not close borrowed readers. Writer Close delegates
  to the original pipe and can still interrupt a blocked write. The existing
  stderr worker drains all output and reports its count when it ends.
- Private-file subsystems reuse this observation boundary, with no parallel
  transfer implementation.

Regression tests cover single-byte/coalesced fragments, zero/short packets,
4 GiB declared lengths, unknown types, clipped metadata, short writes and Close
ownership, concurrent stream IDs, fuzzing, verbosity/quiet order and approximately
2 MiB concurrent uploads/downloads/relays. The local OpenSSH comparison still
connects only to a loopback fixture. Windows pipe support and console fallback were verified natively on `vm`;
macOS native execution remains pending CI.

Platform implementation and native acceptance boundaries are documented in
[native cancelable output](./native-cancelable-output.md).
