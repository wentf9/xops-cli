# MCP Streamable HTTP and file streaming design

Status: HTTP transport, instance-owned Runtime, durable task journal, SFTP forwarding and offline recovery are implemented. Section 2 records protocol and client validation; see the [guide](../guide/mcp-http) for setup and operation.

## 1. Scope and goals

| Area | Constraint |
| --- | --- |
| Clients | Codex and Antigravity CLI connecting through remote Streamable HTTP |
| Deployment | One process on a LAN, one inventory and credential configuration, shared Bearer Token |
| Transport | Preserve stdio; add `/mcp`; no legacy HTTP+SSE `/sse` endpoint |
| File data | Client-local commands exchange binary HTTP streams; the server forwards through SFTP |
| File scope | Ordinary single files over HTTP initially; clients archive directories; the server does not extract archives |
| Exclusions | OAuth, per-user isolation, local MCP bridges, resume, automatic file-write retries, multi-instance scheduling |
| Compatibility | Preserve stdio tool names, schemas, synchronous completion semantics and existing directory transfers |

The server does not store complete file contents or route binary data through JSON/Base64 or model context. Temporary upload files on the target, temporary downloads on the client and small server-side task metadata are not relay content caches.

## 2. Protocol and client compatibility gate

Streamable HTTP is a transport; protocol revision dates are a separate compatibility dimension. HTTP support or successful tool discovery does not prove support for the newest request lifecycle or approval mechanism.

The baseline is SDK-managed stateful `2025-11-25` Streamable HTTP, selected from revisions usable by the target clients. Codex 0.156.1 rejected a service restricted to `2026-07-28`. SDK support does not establish client support. Explicitly restrict the protocol baseline and do not add a legacy HTTP+SSE endpoint.

Client validation record (2026-09-26): loopback HTTP with an in-memory SSH/SFTP target, without production writes.

| Client | Covered | Limits |
| --- | --- | --- |
| Codex 0.157.0 app-server | Discovery, tool calls, approval acceptance/refusal/cancellation, upload and verified local download | Approval responses came from a test controller; manual UI interaction was not validated |
| Antigravity CLI 1.2.11 | Discovery, upload/download preparation, file roundtrip using the helper through a local controller | Approval forms were automatically cancelled; the CLI terminal-permission workflow was not covered |

Antigravity approval acceptance must not be marked as passed; approval-required operations remain denied. Desktop/IDE is outside the validation scope. Client tool confirmation is not an XOps approval.

This HTTP baseline uses elicitation; do not mix InputRequests from another revision into the connection. Protocol changes require a new client matrix. New HTTP configuration defaults to denying unsupported approvals. Existing explicit stdio fallback settings remain unchanged; refusal, cancellation, error and timeout never permit execution.

The Agent's actual command environment also needs LAN reachability, local file access and credentials. Reachability from the MCP host does not imply reachability from a remote sandbox. Version probes must not launch desktop apps or trigger upgrades.

References: [Codex MCP](https://developers.openai.com/codex/mcp/) and [Antigravity MCP](https://antigravity.google/docs/mcp/). These document HTTP and header configuration, not end-to-end compatibility with a particular protocol revision.

## 3. Runtime and configuration

`cmd/mcp.go` remains the composition root for configuration and credentials. A `Runtime` instance owns the SDK Server, SSH connector, guardrail, transfer manager and audit writer. Remove MCP package-global connector/configuration state and register tools with explicit dependencies.

The HTTP pipeline separates authentication and Host/Origin validation, the MCP handler and transfer handlers. Delegate MCP protocol handling to the SDK. The transfer manager must not depend on temporary SDK `ServerSession` objects.

Configuration precedence is explicit CLI options, YAML, then defaults. Public options are `--transport stdio|http`, `--listen`, `--public-url`, `--token-file`, `--token-env`, `--state-dir`, `--allowed-hosts` and `--allowed-origins`. Secrets may also come from a designated environment variable; there is no plaintext token argument. Stdio remains the default. HTTP defaults to `127.0.0.1:8080`; LAN binding is explicit. Validate conflicts, addresses, configuration and credential availability before startup.

HTTP uses an immutable service configuration snapshot rather than hot reload. Restart invalidates unexecuted grants. Preserve noninteractive credentials, host-key verification and ProxyJump behavior; do not expose credential unlock or entry through HTTP.

The Runtime root context owns keepalive, tasks and cleanup. Completion of a task-creation MCP request does not cancel the prepared task. A streaming request context controls only its transfer. Never wait for network I/O or resource closure while holding a global lock.

`xops mcp` and `xops mcp serve` share option validation and startup. Stdio stdout contains protocol data only. HTTP startup messages and diagnostics use stderr with authentication headers redacted.

## 4. MCP and HTTP contracts

The HTTP tool set reuses existing node, command and remote-file operations, replacing the two transfer tools that depend on server-local paths:

| Proposed tool | Input and result |
| --- | --- |
| `xops_prepare_upload` | `requestID`, `nodeID`, `remotePath`, `size`, `sha256`, `overwrite=false`; returns a prepared task |
| `xops_prepare_download` | `requestID`, `nodeID`, `remotePath`; returns source metadata and a prepared task |
| `xops_transfer_status` | `transferID`; returns state, phase, bytes, digest, timestamps, errors and cleanup status |
| `xops_transfer_cancel` | `transferID`; idempotent cancellation, reporting commit state rather than fabricating cancellation success |

HTTP does not expose the server-local `localPath` parameter of `xops_upload` and `xops_download`. Stdio continues registering those tools. Add new names to risk classification, schemas and documentation rather than relying on the default risk for unknown tools.

Preparation returns `transferID`, `operationID`, `state=ready`, a transfer URL from a fixed trusted origin, method, required headers, size/digest information, `startBefore` and `statusExpiresAt`. Never return the long-lived shared token. Client-local paths are consumed only by local commands, not by the server filesystem.

| HTTP endpoint | Behavior |
| --- | --- |
| `POST /mcp` | SDK-managed modern protocol requests and streaming responses, service authentication |
| `PUT /v1/transfers/{id}/content` | Upload request body, `application/octet-stream`, task authentication |
| `GET /v1/transfers/{id}/content` | Download response body, task authentication |
| `GET /v1/transfers/{id}` | Repeatable task status lookup, task authentication |
| `DELETE /v1/transfers/{id}` | Idempotent task cancellation, task authentication |

Data endpoints execute only the operation stored in an approved task. They do not accept a new node, path, overwrite policy or source URL. Unprepared or unauthorized requests must not dial, open files or write to the target. HTTP errors contain stable codes and operation IDs. Errors after a response starts must be recorded in task status, not inferred solely from the HTTP status code.

MCP returns structured task data, not server-generated scripts to execute. Provide fixed POSIX shell and PowerShell client procedures; `curl` can serve as the basic data transport. The optional `scripts/mcp/transfer.py` helper implements origin checks, streaming and verified local publication; it is not mandatory and does not run a local MCP bridge.

## 5. Authentication and approvals

The shared Bearer Token authenticates MCP and its management tools. Each task receives an independent, high-entropy, short-lived Bearer credential scoped to its data direction, status and cancellation. Task IDs are not credentials. Store only task credential digests, compare in constant time and omit credentials from logs, URLs, errors and task listings.

`startBefore` limits when data transfer may start; status credential lifetime is separate. Expired start permission must not prevent terminal status lookup. An active large transfer is not interrupted merely because its start window ends. An atomic state transition prevents a second data request from claiming the task; status queries do not consume the start opportunity.

Bind approval to the service instance/authentication domain, operation, resolved target, normalized path, overwrite policy and complete input digest, with task credentials independent of MCP session lifetime. A shared token defines one trust domain; it cannot distinguish its holders or prevent deliberate credential sharing within that domain. Approval still requires `approved=true`, a two-minute expiry and single consumption. Errors, refusal, cancellation and expiry never issue a transfer grant.

Resolve and normalize paths before guardrail evaluation, checking protected paths against both requested and resolved locations. Grants and transfer parameters remain immutable. Data handlers validate grants, expiry and state rather than creating another unapproved operation.

Audit `authorized`, `ready`, `started`, `commit_started`, terminal results and cleanup with the same `operationID`. Record execution intent before remote side effects. Do not reuse synchronous “handler returned means executed” auditing for task creation. If audit persistence fails after commit, report “committed, audit failure” without encouraging a retry.

LAN access also requires a token. Prefer HTTPS termination at an existing reverse proxy, without adding certificate issuance. Explicit HTTP deployment provides no claim of credential or content encryption. Validate Host/Origin against configuration; native clients without Origin may connect with valid authentication. Do not enable broad CORS or blindly trust forwarded headers. Public URLs come from trusted configuration; clients must not forward credentials across origins on redirects. Disable proxy buffering for streaming routes and configure appropriate stream timeouts.

## 6. Single-file transfer procedures

### Upload

1. The client checks for an ordinary file and computes size and SHA-256 before preparing the task. Changes after hashing are rejected by the final digest check.
2. The server resolves the target, applies policy and approval, then persists an immutable task before returning `ready`. Preparation does not leave remote files open while waiting for the client.
3. An authenticated data request acquires capacity, destination write ownership and task ownership in one atomic scheduling operation, then creates a dedicated SFTP subsystem. Insufficient capacity or a busy destination returns busy while retaining `ready` without consuming the start opportunity. A failed successfully claimed task cannot reuse its data endpoint.
4. Exclusively create a uniquely named temporary ordinary file beside the destination and record its ownership and path. Never reuse another task's temporary file or an old leftover.
5. Forward through fixed buffers while hashing. Validate declared and actual lengths and digest. Short/long input, nonordinary files and write/close errors must not reach commit.
6. Recheck destination and overwrite conditions, persist `committing`, then perform remote promotion. New-file creation uses verified rename semantics that cannot replace an existing destination. Explicit overwrite requires atomic replacement; no backup-and-rename fallback.
7. Persist the terminal result and return it, recording cleanup errors separately. If a network failure makes rename outcome uncertain, use `unknown` rather than asserting the original file is unchanged.

The default is `overwrite=false`. Serialize transfer writes by resolved SSH target, account and normalized destination; aliases must not bypass that lock. This coordinates only this service's transfer tasks, not external writers, arbitrary SSH commands or other clients. Do not implement no-overwrite as `Stat` followed by unconditional replacement.

Reject existing destination symlinks, directories and special files. Resolve parent paths and evaluate path protection. SFTP cannot universally provide race-free traversal against external parent-directory mutations; destination directories must be controlled by trusted accounts. Path validation is not an operating-system sandbox.

Uploads create mode `0600`, including explicit overwrite. Ownership, ACLs, extended attributes and complete original metadata preservation are out of scope. State this mode in tool descriptions and approval details. Permission preservation is a separate future feature.

### Download

1. Read ordinary-file metadata during preparation and recheck when starting. Read through one opened handle. Reject directories, symlinks and special files.
2. Forward bytes into the HTTP response while hashing. Persist byte count, SHA-256 and `streamed` after sending finishes. Preserve failures in task status even after HTTP 200 has been sent.
3. The client exclusively creates a temporary file beside its destination, checks the command exit status, queries task status and compares local size and digest.
4. Only after server state is `streamed` and local verification passes does the client promote the local file and report success. Refuse existing local destinations by default. The server cannot observe client filesystem commit.

Client scripts remove only their own temporary files on ordinary failure or interruption and preserve the original destination. Client crash leftovers are handled on the client, outside server cleanup. A server `streamed` result must not mask local write, close or rename errors.

Digest verification proves received bytes match sent bytes, not snapshot consistency of a concurrently modified source. Treat obvious size/metadata changes as failure. A stable target-side copy is required when snapshot consistency matters.

No Range, append or resume support initially. Empty files still pass length, digest and commit checks. Final filenames come from approved parameters or explicit client paths, not automatically from response headers.

## 7. State, idempotency and recovery

| State | Meaning and handling |
| --- | --- |
| `ready` | Authorized but unstarted; may expire or be cancelled |
| `transferring` | One data request owns the task; no second start |
| `verifying` | Length, digest and upload close checks before commit |
| `committing` | Upload commit intent is durable; remote rename is in progress |
| `completed` | Upload commit is confirmed and recorded, regardless of whether the client received the response |
| `streamed` | Download sending and server digest are complete; local saving is not confirmed |
| `failed` | Known failure with phase and cleanup details; not a claim that all effects were reversed |
| `cancelled` | Confirmed stopped before commit; temporary-file cleanup is separate |
| `expired` | Start deadline elapsed without any data transfer |
| `unknown` | Commit may have occurred but cannot be confirmed; no automatic retry or rollback |

Cancellation can stop precommit transfer. Once `committing`, use an independent bounded commit context so client disconnect/cancellation cannot overwrite actual success with cancellation. Cancellation returns “committing/cannot guarantee stop” and a status address. Commit timeout or connection failure may produce `unknown`, based on evidence. Shutdown follows the same boundary.

If remote commit is confirmed but terminal-state persistence fails, the running process reports “committed, state persistence failure,” not ordinary failure. A restart that sees only commit intent recovers as `unknown`. Keep uncertain destinations blocked for new uploads and reconstruct these blocks from the journal on restart until verification resolves them. Read-only verification can establish content matches without claiming to reconstruct the original operation's exact execution history.

`requestID` is a client-generated creation idempotency key, separate from the JSON-RPC request ID. The same authentication domain, key and input digest returns the existing task; a different input under the same key is rejected. Lookup never repeats side effects. Approval continuations keep the same key and input; retries cannot bypass incomplete approval.

If preparation response delivery is lost, reissue a task credential only while the original task is still `ready`, atomically revoking the old credential without extending the start window. Started tasks return status without reopening their data endpoint. Cancellation and terminal lookup are idempotent. Do not claim exactly-once commit across the service and a remote filesystem.

Error and warning diagnostics are normalized to valid UTF-8 and truncated at character boundaries to at most 4096 bytes, preserving the byte limit across JSON persistence and reload.

Use a versioned local metadata journal with directory mode `0700`, file mode `0600`, single-process ownership and reliable atomic-write/sync ordering. No database or general task queue is required. Record task IDs, input digests, resolved target identity, destination/temporary paths, necessary sizes/digests, transitions and cleanup results. Exclude shared tokens, plaintext task credentials, SSH passwords and file contents. Retain credential digests and minimal lookup data under bounded policies.

Restart does not resume streams or automatically recommit. Invalidate `ready` grants, fail and clean known precommit interruptions, and mark interrupted `committing` tasks `unknown`. Preserve confirmed terminal records. Matching file size alone cannot establish success. Never delete a destination when commit is uncertain. Expose target identity, path, expected digest and phase when manual verification is needed.

Cleanup touches only temporary files explicitly owned by journal records, never a suffix-based bulk scan. Use fresh bounded cleanup contexts and SFTP channels. When a target is unreachable or its identity changes, expose `cleanup_pending` with bounded retries. Expire ordinary terminal records by retention policy, but never silently discard unresolved results or cleanup records. Reject new tasks when the metadata quota is reached.

Provide a local recovery maintenance entry point that exclusively locks metadata and therefore runs only while the service is stopped. Default to read-only inspection of uncertain outcomes, current destination content and leftovers. Separate explicit actions clean verified owned temporary files, record operator verification and release destination write blocks. Releasing a block neither fabricates historical success nor writes/deletes the final destination; a later upload still requires a new authorized task. Audit acknowledgements and cleanup before normal retention can reclaim records. This maintenance capability belongs to the initial recovery implementation and does not require clients to install a helper for ordinary transfer.

Authenticated JSON-RPC replies and valid cancellation notifications share a separate control admission pool of up to `max_requests`, independent of ordinary HTTP requests and tool execution. Reading/classifying POST bodies has an equally bounded pool, a 4 MiB limit and a body-read deadline. Control admission accepts responses with an ID and result/error without a method, plus `notifications/cancelled` notifications without top-level id/result/error and with a string/integer requestId and optional string reason in params. All other messages use ordinary admission; session, response-ID and cancellation-target validation remains with the SDK.

## 8. Timeouts, resources and shutdown

The following implemented defaults can be adjusted to the deployment resource budget. Zero values must not accidentally disable limits:

| Limit | Initial value |
| --- | --- |
| HTTP header read | 10 seconds |
| MCP JSON body | 4 MiB, separate from file routes |
| Ordinary MCP tool call | 5 minutes maximum; shorter tool limits win |
| Approval challenge | 2 minutes |
| Transfer start window | 5 minutes |
| File stream no-progress timeout | 60 seconds |
| Total file transfer | 2 hours |
| File size | 10 GiB |
| Transfer concurrency | 4 total, 2 per resolved target |
| Ready tasks / metadata records | 256 / 4096 |
| Ordinary terminal retention | 24 hours |
| Upload commit / individual cleanup | 30 seconds / 10 seconds |
| Service shutdown | 45 seconds |

Reject excess work with recognizable busy errors instead of unbounded queues. Fix the acquisition order for capacity, task state and target locks. Do not hold manager-wide locks during transfer.

Fixed application buffers and bounded SFTP request windows make memory scale with concurrency, not file size. File routes enforce their own exact-length limits rather than MCP's 4 MiB JSON limit. Network operations have deadlines. SSE and file streams use renewable write deadlines and bounded lifetimes rather than a short global `WriteTimeout` that breaks long connections.

Clear body-read deadlines for bodyless downloads so net/http background disconnect detection cannot cancel healthy streams. A progress-renewed child context enforces inactivity across post-claim upload metadata inspection, SFTP and HTTP, with its worker joined on completion/cancellation and stopped before the independent commit window. The Python client actively interrupts response reads at its absolute deadline, including trickling bodies/headers and connection-close responses, rather than relying on individual socket timeouts.

Each task owns its SFTP channels. The v1 client cannot attach creation permissions to OPEN. Private uploads use an additional serial channel and the public packet codec pinned to `github.com/pkg/sftp/v2 v2.0.0-alpha2`, limited to INIT/OPEN/WRITE/CLOSE, without its client scheduler. Bounded packets and the existing SSH setup/cancellation/closure lifecycle are reused; metadata and rename semantics remain on v1. Cancel that task's resources first. If unblocking requires closing shared SSH transport, report affected tasks as transfer errors and rebuild connections for later operations; do not replay tools or writes. Document this failure scope rather than promising absolute isolation.

Shutdown stops task creation and data claims, cancels precommit transfers, completes or classifies committing work within bounds, performs cleanup under fresh contexts, closes MCP sessions and active HTTP connections, joins workers, then closes the SSH connector and aggregates errors. Force-close remaining network connections at the shutdown deadline rather than waiting only on `http.Server.Shutdown`.

## 9. Implementation phases

| Phase | Deliverable and exit condition |
| --- | --- |
| P0 Compatibility | Protocol, approval and command-environment matrix for both clients; concrete blockers if unsuccessful |
| P1 Runtime | Instance dependencies and common closure; stdio regressions pass |
| P2 HTTP MCP | SDK handler, configuration, authentication, request boundaries and modern approval; real tool invocation passes |
| P3 Tasks and streams | Immutable grants, durable state, recovery maintenance, SFTP stream interfaces, upload/download and status/cancellation endpoints |
| P4 Fault validation | Concurrency, disconnect, cancellation, audit failures, commit windows and restart recovery |
| P5 Clients and docs | Fixed client procedures, LAN/proxy configuration, bilingual help and guides |

Change only necessary boundaries. Do not rewrite MCP, change general SSH/SFTP command overwrite policies, or make a dedicated helper or background queue prerequisites.

## 10. Acceptance matrix

| Area | Required coverage |
| --- | --- |
| Clients | Real Codex/Antigravity discovery, calls, approval/denial/cancellation and local-command file round trips |
| Protocol | Supported/unsupported revisions, metadata and headers, JSON/SSE responses, cancellation, no stdin prompts |
| Authorization | Invalid/expired tokens, cross-task credentials, wrong direction, unknown IDs, replay, idempotency conflicts, approval/input tampering |
| Files | Empty/binary files, Unicode/spaces, large files, wrong length/digest, client source changes |
| Destination | No-overwrite, explicit atomic overwrite, unsupported replacement, directories/symlinks/special files, protected paths and concurrent destination writes |
| Network | Slow readers/writers, disconnects, full client/target disks, SFTP close failures and errors after download HTTP 200 |
| Failure windows | Lost preparation response, process exit around commit intent, successful rename with lost reply, final-state/audit failure and cancellation during commit |
| Recovery | No resume on restart, no automatic unknown-state retry, visible cleanup failures, owned-temp-only deletion, retention and quotas |
| Resources | State races, credential-reissue/start races, shutdown/commit races, no goroutine/connection leaks, memory independent of file size |
| Regressions | Existing stdio schemas/behavior, risk classification, noninteractive credentials, host keys, ProxyJump and SSH reconnect |

Local integration tests use fault-injectable HTTP/SFTP services and controlled subprocesses for actual exit/recovery behavior. Real client/target checks use explicitly scoped test directories and verify cleanup. Keep a per-client, per-case result matrix; SDK unit tests or discovery alone are not end-to-end evidence.

After implementation, run `go build ./...`, `go test ./...`, `golangci-lint run ./...`, relevant race/leak tests, `npm run docs:build` and `git diff --check`. Generate CLI references from help and i18n rather than editing generated pages. Design-only validation checks documentation and must not be described as feature acceptance.
