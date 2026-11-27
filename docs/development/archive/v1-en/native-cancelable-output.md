# Native cancelable output

The entry points remain `core/ssh.BindOutput` and `prepareContextOutputWithLimit`.
SCP diagnostics, progress and upload status reuse the same capabilities as shared
SSH streaming/PTY output. No separate SSH or transfer backend is introduced.

| Output target | Implementation | Ownership and limits |
|---|---|---|
| Linux terminals/pipes | Independently reopen `/proc/self/fd`, Go deadlines | Borrowed descriptor flags remain unchanged |
| macOS terminals | `F_GETPATH`, independently reopen nonblocking, verify identity, Go deadlines | Own handle; no terminal mode changes |
| macOS already nonblocking pipes | `F_DUPFD_CLOEXEC`, Go deadlines | Own descriptor, shared status; caller must keep the pipe nonblocking until release |
| macOS blocking anonymous pipes | Unsupported; retain the existing safe fallback | No shared `O_NONBLOCK` changes or helper processes |
| Windows consoles | Host-injected relay entry point, duplicate handle and lazily started pipe-backed subprocess; pipe requests/ACKs cancel with `CancelIoEx`/`CancelSynchronousIo` | Safe fallback without injection; cancellation checks process exit without closing the borrowed handle or changing console mode |
| Windows synchronous/overlapped pipes | Duplicate handle, thread cancellation and request-specific `CancelIoEx` | Own event and pinned request/buffer lifetime; never cancel other borrowed-handle requests |
| Regular files, including PTY redirection | Shared synchronous `regularFileOutput` | Check cancellation between writes; an in-flight kernel Write must finish before return, without a hard cancellation deadline |

Windows retries cancellation until completion, covering cancellation before the
system call starts. Each write joins native I/O and its cancellation worker before
releasing the event, pinned buffers and thread handle, or unlocking the thread.
The OVERLAPPED event low bit suppresses IOCP notification, so custom requests do
not reach an existing Go completion port on the borrowed pipe. NUL is identified
by handle object name rather than potentially zero device/pipe FileInfo IDs, which
could misclassify a console or pipe as an ordinary file.

For Windows consoles, the host explicitly supplies `work, cleanup := WithConsoleOutputRelay(ctx, ConsoleOutputRelay{Executable, Args, Env})`
and must retain `cleanup` until all command I/O finishes. The scope owns all bindings, including those whose local
`closeFn` failed. Scope cleanup cancels output before retrying reclamation and retains failed bindings for host retries.
There is no global manager or background retry goroutine. The CLI owns this scope in `cmd/root.go` and dispatches
`--xops-console-output-relay` to `ServeConsoleOutputRelay` in `cmd/cli/main.go` before normal startup. Core never reads a relay environment variable
or exits/takes over the host during package initialization. Importing core alone does not enable the relay.
The first nonempty write starts the helper; borrowed console handles and modes remain unchanged.

On Windows 10+, creation-time `PROC_THREAD_ATTRIBUTE_JOB_LIST` assignment atomically places the relay in a
non-inheritable kill-on-close Job Object. There is no start/assign race. Parent death closes the Job and terminates
the relay independently of pipe EOF, including while console output is blocked. Unsupported attributes or Job
constraints fail startup rather than falling back to an unowned helper.

Job termination is asynchronous. Cleanup releases process, ACK and Job handles only after `WAIT_OBJECT_0`.
It waits up to five seconds; failures/timeouts return `ssh.OutputError` retaining the sink identity, disable further
writes, and leave the command scope owning the binding for retry. SFTP treats output/cleanup failures as fatal,
without writing diagnostics to failed streams or restoring the line editor; cancellation/disconnect wrapping preserves
the original error chain. Closed scopes reject new bindings rather than falling back to direct I/O. Cleanup errors
do not mean the relay exited or that the terminal can safely be handed back.

macOS `/dev/fd` shares file status like dup; it is not equivalent to Linux
`/proc/self/fd`. SCP terminal detection uses `SyscallConn.Control`, avoiding
`File.Fd`, which can clear a pipe's `O_NONBLOCK` flag. Unsupported sinks retain
their existing contract: strict execution rejects them before starting; legacy
entry points retain their compatibility policy; SCP skips auxiliary output and
continues transferring. Callers retain original streams, cancel and join writes
before release; bindings release only their own resources.

## PTY regular-file redirection

`prepareContextOutputWithLimit` recognizes regular files before invoking native terminal/pipe adapters. Strict PTY output reuses the synchronous `regularFileOutput` already used by `BindOutput`, with no new goroutine, duplicate file handle, or file-relay subprocess. The binding borrows the file without closing, syncing, or changing its open flags; only requested writes advance its shared offset. Terminal input requirements and native terminal/pipe cancellation and per-write protection are unchanged.

Files have an explicitly weaker cancellation contract: check context before each write, but do not promise to interrupt a write already executing in the kernel. Wait for that write before returning. Cancellation/drain deadlines in `waitTerminalOutput`/`waitSessionOutput` signal shutdown and still join output workers; neither the one-second shutdown grace nor PTY write protection is a hard file-write deadline. Slow disks, NFS, or stalled filesystems may delay cancellation indefinitely. Never return early and leave delayed writes behind. Write errors retain `OutputError.Target` and the original file error; closed files are rejected before command dispatch.

Regressions cover portable append flags/ownership, pre-write cancellation, read-only/closed-file errors and a controlled in-flight-write waiter, plus Linux PTY separate/combined redirection, nonzero status, terminal restoration on failure, explicit privileged file output, and explicit-interpreter CLI redirection. SSH peers are fixtures; the controlled waiter does not inject a native kernel slow-disk fault. Native Windows/macOS PTY acceptance still belongs to platform CI.

## CLI integration

`BindOutput` recognizes the existing `LockedWriter`, binds its underlying sink,
and retains the same mutex. Waiting for that mutex also observes cancellation.
Unknown writers are never advertised as cancelable. Single-host and batch `exec`
streams retain execution-context cancellation and deadlines; final results,
Playbook reports and dry-run rendering use the same binding and release it after
rendering. Primary output has no SCP auxiliary one-second limit and is never
silently dropped. Unsupported sinks retain their legacy direct-output contract.
Playbook global logs/step messages are separate from the report writer and still
follow the logger's own contract.

Explicit `ssh` execution no longer rejects by client OS name; core checks actual
I/O capabilities before sending requests. Ordinary commands and non-PTY shells
choose strict or compatible entry points based on output capabilities, without
retrying after execution failure. Windows file stdin honors the host-injected `Environment.InputBridge`; it is
rejected before remote requests only when no bridge is available (including a
typed nil). Preflight and the input pipeline use the same capability.
`ssh.OutputError.Target` retains the borrowed sink identity and preserves failure
causes. Only standard-stream failures suppress CLI error reporting and `exec`
result printing. Independent log-file failures remain visible on healthy stderr,
including joined execution and cleanup errors. Every joined branch is checked,
so a log error cannot hide a simultaneous standard-stream failure. Playbook retains
execution, step and report-output failures together.

## Validation and boundaries

The relay implementation and review fixes still require native Windows CI. Historical `vm` results below
cover only the original pipe/console-fallback implementation, not the new relay. Regressions require entering
actual console output before cancellation and proving relay process exit before resuming ConPTY draining.
They also cover fallback without injection, environment variables not taking over process startup,
command-scope ownership of failed bindings, rejecting new bindings after scope closure, and parent-death reclamation
without Go defers. Portable SFTP regressions cover direct, wrapped and joined output errors (including interruption),
asserting zero diagnostic writes and preserved errors.

Platform tests cover Windows blocking synchronous/overlapped pipe cancellation,
borrowed handles, console relay binding and blocked-write cancellation with an unread ConPTY
output pipe (`integration`). macOS tests cover paused terminals, nonblocking pipe
cancellation, rejection of blocking pipes, borrowed flags and terminal reuse.
Existing native Windows/macOS CI runs these tests; Windows ConPTY has a dedicated
regression step. Windows pipes and console fallback were verified natively on
the Windows 11 `vm` node. macOS still awaits native CI; cross-compilation and
Wine do not establish native platform execution results.

On `vm`, core `TestWindowsOutput*`, regular-file/NUL/standard-handle binding tests,
and CLI blocked-pipe diagnostics, unsupported-output and write-error tests passed
with `-test.count=3`. Uploaded test programs were removed and no matching test
processes remained. This native run did not enable race detection. Linux
`core/ssh` and `cmd` race tests passed; Windows/macOS race validation remains with
native CI. The `vm` record covers platform adapters. Subsequent CLI integration
regressions were run with Linux fixtures and cross-compiled for Windows amd64
and macOS arm64; these new cases have not yet been executed natively.

References: [CancelSynchronousIo](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelsynchronousio),
[I/O cancellation races and completion](https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations),
[OVERLAPPED events and completion ports](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus),
[Apple XNU dupfdopen](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_descrip.c).
