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
| Windows consoles | Unsupported; retain the safe fallback | Native Windows 11 ConPTY writes did not reliably cancel with `CancelSynchronousIo`; no helper processes |
| Windows synchronous/overlapped pipes | Duplicate handle, thread cancellation and request-specific `CancelIoEx` | Own event and pinned request/buffer lifetime; never cancel other borrowed-handle requests |
| Regular files | Existing implementation | A filesystem Write already in progress is not promised to be interruptible |

Windows retries cancellation until completion, covering cancellation before the
system call starts. Each write joins native I/O and its cancellation worker before
releasing the event, pinned buffers and thread handle, or unlocking the thread.
The OVERLAPPED event low bit suppresses IOCP notification, so custom requests do
not reach an existing Go completion port on the borrowed pipe. NUL is identified
by handle object name rather than potentially zero device/pipe FileInfo IDs, which
could misclassify a console or pipe as an ordinary file.

macOS `/dev/fd` shares file status like dup; it is not equivalent to Linux
`/proc/self/fd`. SCP terminal detection uses `SyscallConn.Control`, avoiding
`File.Fd`, which can clear a pipe's `O_NONBLOCK` flag. Unsupported sinks retain
their existing contract: strict execution rejects them before starting; legacy
entry points retain their compatibility policy; SCP skips auxiliary output and
continues transferring. Callers retain original streams, cancel and join writes
before release; bindings release only their own resources.

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

Platform tests cover Windows blocking synchronous/overlapped pipe cancellation,
borrowed handles, console fallback and safe fallback with an unread ConPTY
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
