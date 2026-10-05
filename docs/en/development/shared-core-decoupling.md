# Shared core and MCP interface decoupling

Status: shared-core decoupling and direct CLI consumption are implemented. D1 leaves and the D2 SSH/SFTP implementation live in core; old Go API facades have been removed. Explicit Environment, KeySource/KeyLease, HostKeyVerifier, InputBridge, and ConnectPlan/PlanConnection/RetirePlan are available. D3 guardrails, transfer/tunnel state machines, streamed-file adapter, ports, and sshexec execution adapter are implemented. The runtime implementation now lives in core/mcp/runtime; internal/mcphost owns CLI configuration, credential, and OpenSSH adapters; internal/sshenv owns local SSH discovery and the Windows input bridge. D4 publication coordination, atomic admission, persistence-outcome barriers, affected-pool retirement and noncommitting revocation are implemented. D5 private bindings, v1/v2 journals and retained-transport commit handoff are implemented. D6 provides extraction and consumer acceptance checks; xops-mcp records its fixed version and remote-download evidence in docs/reuse-baseline.md. Baseline: `73892b0791e3222bbd08abee1f21ed067b1c41c8`. The [xops-mcp](https://github.com/wentf9/xops-mcp) consumer records its integration obligations in `docs/en/interface-decoupling.md`.

Current checks: `go test ./internal/clicontract` verifies CLI configuration serialization and MCP schemas; `python3 scripts/check_core.py --race` checks platform dependency graphs and an isolated build of the migrated subtree. Schema fixtures were compared with the original remote module. Migrated core passed isolated Linux race tests. Native Windows amd64 non-race checks cover SSH/SFTP, ports, state, transfer, sshexec and selected runtime file-task tests. Windows/macOS dependency checks and test binaries cross-build successfully. Native macOS and Windows race are not established by this validation. Concrete vault integration stays in pkg/adapter through public APIs; pure SSH and native sudo tests moved with the implementation to core/ssh. Local integration does not replace published consumer-version acceptance.

ConnectPlan returns an explicit lease: Close releases a reference without closing transports still leased elsewhere. RetirePlan only invalidates the cache; it does not replace the future ExecutionGate. Plans capture the entire ordered chain and source versions and never re-read the parent connector's mutable provider during execution.

The 2026-10-02 decoupling regression fixes pass Linux regression/race checks and Windows amd64 test cross-compilation. The native Windows environment was unreachable, so these fixes have no new native execution evidence; earlier native results apply to the earlier migration state.

## 1. Objective and scope

Shared code must be extractable into an independently maintained Go module. This includes removing reverse dependencies on CLI configuration, business models, concrete credential stores, terminal UI, personal directories, and global output; database injection alone is insufficient.

Consolidate the shared implementation under a planned `core/` subtree, using the existing root module and Go 1.26+. Do not create a third repository or nested module yet. Prove isolation through an extraction check. A future extraction should move that subtree, fixtures, and module metadata, update import paths and application adapters, and preserve the application contracts.

The first consumer remains xops-mcp. Web and SQLite/PostgreSQL implementations belong there. Preserve CLI/TUI, stdio and HTTP MCP, SSH/SFTP, and native Windows input behavior. HTTP tunnels, SOCKS, multi-tenancy, and distributed operation are outside this refactor.

## 2. Dependency baseline before decoupling

| Location | Coupling | Resolution |
| --- | --- | --- |
| MCP server construction | ConfigProvider, full snapshots, adapter, connector construction | Small ports plus internal/mcphost composition |
| Guardrail/policy | Configuration-owned types and personal audit path defaults | Neutral policy values and explicit audit injection |
| Inventory tools | Separate node/host/identity reads | One coherent display or operation snapshot |
| Transfer tools/HTTP | NodeID/TargetID persisted, connection resolved again later | Distinct resource, generation, and authorization identities |
| SSH errors/recovery | Imports config and credential error definitions | Direct use of neutral core/auth errors |
| SSH connector/authentication | Implicit home, known_hosts, key paths, agent environment | Host-provided explicit sources |
| SSH interactive input | Standard streams and root terminal internals | Explicit I/O and cancellable input bridge |
| Logger | Interfaces share a package with global colored output | Interface/Nop isolated from CLI output |

At this baseline, `go list -deps ./pkg/ssh` includes config, models, i18n, and concrete encrypted-store support. New constructors in the same package do not remove those compile-time dependencies.

## 3. Target package boundary

```text
xops-cli commands, UI, and adapters ──┐
                                    ├──> xops-cli/core/*
xops-mcp server adapters ────────────┘

core/mcp/runtime -> guardrail, policy, transfer, tunnel
core/mcp/runtime + core/mcp/sshexec -> core/mcp/ports
core/mcp/sshexec -> core/mcp/remotefile + core/ssh + core/sftp
core/sftp -> core/ssh -> core/auth + core/log + core/concurrent
```

| Target | Shared responsibility | Remains application-owned |
| --- | --- | --- |
| `core/ssh` | Connections, jump plans, commands, privilege protocol, remote PTYs, forwarding | Inventory resolution, prompt UI, environment defaults |
| `core/sftp` | Subsystems, file operations, permissions, atomic replacement, cancellation | CLI parsing, progress UI, interactive shell |
| `core/auth` | Neutral authentication errors/value contracts | Registry, vaults, unlock UI, encrypted database format |
| `core/log` | DebugLogger and Nop | Global/color/standard-stream logger |
| `core/concurrent` | Containers actually shared | Unrelated utility code |
| `core/mcp/runtime` | One implementation of schemas, handlers, protocol, and orchestration | YAML conversion and default paths |
| `core/mcp/{policy,guardrail}` | Policy values, evaluation, challenges, audit events | Database queries and administrator identity |
| `core/mcp/{transfer,tunnel}` | Task state machines and lifecycle | Web APIs, SQL stores, user config |
| `core/mcp/sshexec` | Shared SSH/SFTP execution adapter | CLI/database-to-snapshot conversion |

Production code, tests, fixtures, and generated code under core must not import root `cmd/**`, `pkg/**`, `internal/**`, or xops-mcp. Dependencies are limited to the standard library, the subtree itself, and explicitly listed third-party protocol libraries. Public APIs must not expose CLI configuration/models, credential registries, SQL/ORM types, or flag definitions.

Core implementation helpers may live under `core/internal`; application adapters cannot cross that Go internal boundary. Consumers import shared containers directly from `core/concurrent`.

## 4. Direct CLI consumption and one implementation

CLI, TUI, playbooks, and application adapters directly import `core/ssh`, `core/sftp`, `core/concurrent`, `core/auth`, `core/log`, and `core/mcp/*`. `pkg/ssh`, `pkg/sftp`, `pkg/utils/concurrent`, and `pkg/mcpserver` including its subpackages are removed. Old Go import paths, aliases, error re-exports, and constructor compatibility are no longer maintained.

- `internal/sshenv.Discover` selects home paths, known_hosts, default keys, SSH agent, standard streams, and the platform input bridge. CLI adapters and TUI explicitly inject this environment into `core/ssh.Connector`; caller options can still override defaults.
- `internal/mcphost.Config.RuntimeOptions` converts CLI configuration, credentials, audit paths, and transport settings into core options. Commands directly call `core/mcp/runtime.NewRuntime`, `Run`, `ServeHTTP`, and `RecoverTransfers`, and own cleanup.
- stdio resolves configuration per invocation; HTTP and recovery preserve startup snapshots. Configured tool deadlines and the HTTP default deny policy remain effective.
- `pkg/config.Configuration.Guardrail` directly uses `core/mcp/policy.Config`. YAML fields and persistence formats are unchanged; the CLI host expands AuditLog paths.
- Consumers use shared errors directly from `core/auth`, preserving `errors.Is`/`errors.As` semantics without matching error strings.
- `pkg/logger` retains CLI output and `DefaultLogger`; the diagnostic interface and Nop come directly from `core/log`. Configuration, concrete vaults, and TUI remain application responsibilities.
- Protocol and core behavior tests follow their implementations. CLI configuration, credentials, OpenSSH, and terminal behavior stay in application tests. `internal/clicontract` retains YAML serialization and HTTP/stdio schema baselines; old Go API compilation-only checks are removed.

New servers import only `core/*`. All consumer production and test graphs exclude upstream application packages.

## 5. Four runtime dependency roles

These contracts now exist in `core/mcp/ports`; supporting values are specified below. Runtime now consumes these ports through WithDependencies; dynamic publication coordination and persisted deferred-operation bindings are integrated. The separate contract package lets runtime and sshexec share interfaces without an import cycle; interface availability does not imply completed runtime decoupling.

```go
type Dependencies struct {
	State      StateSource
	Gate       ExecutionGate
	NewBackend func(context.Context) (Backend, error)
	Audit      AuditSink
}

type StateSource interface {
	DomainID() string
	List(context.Context, NodeQuery) (InventorySnapshot, error)
	Resolve(context.Context, ResolveRequest) (OperationSnapshot, error)
}

type ExecutionGate interface {
	DomainID() string
	Enter(context.Context, Admission) (Permit, error)
}

type Permit interface {
	Context() context.Context
	Snapshot() OperationSnapshot
	Binding() Binding
	Phase() Phase
	Close() error
}

type AuditSink interface {
	Append(context.Context, AuditEvent) error
}
```

| Value | Required contents |
| --- | --- |
| Query/resolve request | Filters or complete selector set; resolve multiple targets together |
| InventorySnapshot | Consistent display data, policy, revision; no secrets, key paths, or database entities |
| OperationSnapshot | Canonical nodes, destinations/accounts, complete jump plans, versioned auth/privilege/trust references, policy; no plaintext secrets |
| Binding | Scope, tool, full normalized-input digest, relevant node/chain versions, policy version, purpose; not merely a global revision |
| Admission | OperationID, binding, snapshot, deadline and phase: inspection, execution, transfer start, commit, or recovery |
| AuditEvent | Existing audit data plus binding digest, phase, result, and whether execution occurred |

State and Gate must expose equal, nonempty DomainID values, validated at construction. That read-only method performs no I/O. Use defensive copies/read-only values and validate them in Runtime. Clients cannot submit internal snapshots, permits, or version credentials through MCP inputs.

Policy arrives with the snapshot, avoiding inconsistent separate reads. Each snapshot independently normalizes NoElicitFallback: omission selects the shared downgrade default rather than retaining a startup allow setting. HTTP hosts still supply deny explicitly as their default. Database calls have deadlines; no transaction remains open while awaiting approval. Do not add database I/O to context-free legacy GetConfig methods.

Audit is fixed at construction. Avoid unsynchronized writer replacement. Failed intent audit prevents execution; failed post-execution audit preserves the executed/non-retryable result. Final audit uses a separate bounded cleanup context so request cancellation does not silently discard results or permit an unbounded wait. A context-aware database sink must not be simulated by wrapping a blocking writer in an unjoinable goroutine.

## 6. Execution and ownership

```go
type Backend interface {
	Run(context.Context, Permit, string, Command) (CommandResult, error)
	OpenFiles(context.Context, Permit, string) (FileSession, error)
	Inspect(context.Context, Permit, string, InspectRequest) (FileMetadata, error)
	OpenTransfer(context.Context, Permit, string) (TransferSession, error)
	Shutdown(context.Context) error
}
```

FileSession retains shared SFTP Do, Upload, Download, CreatePrivateExclusive and Close operations while owning its permit and connection-lease lifetime. It does not expose the shared SSH transport. The moved `core/mcp/remotefile.Remote` contract retains exclusive-create and commit-outcome distinctions. Supplied streams remain cancellable and deadline-bound.

The permit limits targets, versions, and allowed phase. An inspection permit allows metadata inspection only, never OpenFiles or write capability. Execution methods must not re-resolve current configuration from a bare node name. Backends honor both the call context and permit cancellation/deadline; a longer call context cannot bypass revocation.

Multi-target operations bind all nodes together. Stdio uses an optional dedicated TunnelBackend with an authorized snapshot; each tunnel owns independent SSH connections. Do not register those tools over HTTP.

| Resource | Owner and release |
| --- | --- |
| State, Gate, Audit, DB | Host-owned, borrowed by Runtime; close after all runtimes |
| Backend factory result | Exclusively owned by one Runtime, including construction rollback |
| MCP sessions, task managers, journal lock | Runtime, released after task shutdown and journal settlement |
| Permit, SFTP subsystem, transfer remote | Acquiring operation, immediately deferred on success |
| Physical SSH pool | Backend; subsystem close does not close the shared transport |
| Tunnel connector | Individual tunnel, stopped/joined on TTL, stop, disconnect, or shutdown |

Runtime provides Shutdown(ctx) and Close with a configured bounded shutdown budget. Preserve transfer graceful wait, forced interruption, and final journal settlement. Do not close host audit/DB or release the journal lock too early. Commit work retains its separate deadline and unknown-outcome semantics.

## 7. SSH ports

1. Add ConnectPlan(ctx, plan), with complete immutable jump steps and versioned auth/privilege/trust references. Legacy Connect converts existing provider data. Authentication and privilege rechecks must use the bound view, not a global mutable provider.
2. Retain independent secret resolution, bound to node, target, purpose, and version. Return the requested version or fail; no fallback to latest credentials or implicit remembering.
3. Add KeySource/KeyLease for parsed signers. Database adapters decrypt and parse keys; file adapters take explicit paths. Avoid temporary private keys in personal directories. Release material on failures/cancellation without claiming deterministic erasure of all Go signer memory.
4. Add HostKeyVerifier using node, canonical endpoint, trust version, actual remote address, and public key. Core neither reads personal known_hosts nor accepts unknown hosts by default. Custom HostKeyVerifier calls use a deadline-bound child of the handshake coordinator context, so handshake timeout also cancels context-aware database/network verification.
5. Hosts discover home, SSH_AUTH_SOCK, and standard streams. Explicit file/agent adapters may remain public.
6. Move relevant error contracts and logger interfaces down, using core contracts directly and preserving error matching.
7. Keep remote PTY and privilege mechanics in core; inject a local cancellable InputBridge. Existing Windows duplicate-handle/VT/pipe handling stays in a CLI adapter initially, with native regressions. Do not replace it with uninterruptible stdin copying. Sudo/su command input and interactive privilege handoff also carry the operation context and injected InputBridge; cancellation joins input copying without closing borrowed stdin.

Proposed authentication/input signatures use cryptoSSH for `golang.org/x/crypto/ssh`; request values carry target/version binding:

```go
type KeySource interface {
	OpenKey(context.Context, KeyRequest) (KeyLease, error)
}

type KeyLease interface {
	Signer() cryptoSSH.Signer
	Close() error
}

type HostKeyVerifier interface {
	Verify(context.Context, HostKeyRequest, cryptoSSH.PublicKey) error
}

// Optional HostKeyVerifier capability for snapshot-bound negotiation.
type HostKeyAlgorithmSource interface {
	HostKeyAlgorithms(context.Context, HostKeyRequest) ([]string, error)
}

type InputBridge interface {
	Start(context.Context, InteractiveIO, io.Writer) (InputCopy, error)
}

type InputCopy interface {
	Wait(context.Context) error
	Close() error
}
```

InputCopy closes only owned duplicates/cancellation handles, never borrowed standard streams. Close interrupts reading; Wait honors its deadline. Input bridge cleanup stops the copy and joins it under an independent one-second budget. Cancelling the completed operation does not cancel that join or fabricate a command failure. Cleanup timeouts and real errors still propagate. KeyLease ownership transfers upon successful return. Do not switch credentials or terminal behavior between runtimes by mutating process environment.

Pinned-trust hosts can implement HostKeyAlgorithmSource when a peer offers multiple host-key algorithms. Selection uses the handshake coordinator context and deadline, with NodeID, Host, Port, User and trust version; Remote/Hostname are not available before negotiation. Only the SSH library's securely supported algorithms are accepted. Empty lists, lookup failures and timeouts fail closed without default fallback. RSA pins select rsa-sha2-512/rsa-sha2-256. Verify must still compare the actual key exactly. Existing verifiers without this optional capability retain default negotiation.

Avoid speculative plugin frameworks, ORM repositories, or arbitrary protocol executors.

## 8. Approval, updates, and pooling

```text
validate -> resolve one snapshot -> evaluate policy -> bounded read-only inspection
         -> approve full input/target/policy binding -> intent audit
         -> Gate.Enter recheck/register -> bound execution -> result audit/release
```

Reject explicitly forbidden requests before remote inspection. Allowed path normalization uses a short inspection permit, then reevaluates normalized paths before approval. Never retain an inspection permit while waiting for user input.

Gate.Enter and update publication serialize version comparison plus operation registration in a short critical section without network/database I/O. Relevant changes after approval but before admission return stale binding; re-resolve and approve instead of silently retargeting.

Updates use an affected-admission barrier, a bounded database transaction, publication plus generation invalidation, then resume admission. Rollback removes the barrier. A committed-but-unpublished change keeps it closed while reloading; do not blindly repeat the mutation. An asynchronous invalidation event alone is insufficient.

Ordinary edits affect subsequently admitted work; existing work keeps its original target. Disablement/deletion and credential/trust revocation stop new admission and cancel affected noncommitting work. Already started remote commands cannot be promised rollback.

| Identity | Meaning |
| --- | --- |
| NodeID | Stable business identity, never reused after deletion |
| TargetID | Existing canonical address/default-port/account resource lock; excludes credential version and NodeID |
| ConnectionKey | Scope, ordered chain, destination, auth/privilege/trust versions |
| Binding | Complete input, canonical targets, relevant versions and policy |

Alias/tag changes invalidate bindings when they affect policy, not by automatically invalidating the whole database. Retire old connection generations from new allocations; drain/cancel references as specified. Avoid global CloseAll for an individual edit.

## 9. Deferred transfer compatibility

Preparation, claim, commit, and recovery/cleanup all need a binding. Existing TargetID alone does not capture credentials, jumps, or policy.

- Keep RequestDigest tied to original request input; persist Binding separately. Never rebuild a task silently when the current configuration changes.
- Retries return the original task. Invalidate stale ready tasks without issuing new data tokens; retain completed/unknown results.
- Require both transfer claim and execution admission before opening write capability.
- A short commit reservation orders commit against revocation. Once reserved, the durable-intent window is already a phase where cancellation cannot be promised. Failed reservation or definite intent-write failure sends no rename and releases the reservation; uncertain storage outcomes retain conservative recovery rules.
- Send rename only after reservation and durable BeginCommit both succeed. Thereafter retain the independent commit deadline; lost confirmation means unknown, never automatic retry or confirmed cancellation.
- Version the new journal format. Continue reading v1 status and unknown locks; do not replay unbound unfinished records against current inventory. Reject unknown future versions without rewriting files.
- Recovery/cleanup must prove the original recorded target. Missing/deleted/retargeted nodes preserve records and blocking. Recovery using new credentials requires explicit authorization and target verification.
- Existing transfer.Store lacks context; keep the local journal in this phase. SQL task storage is a separate design.

Gate orders versions and revocation; the transfer manager remains the sole authority for task states and outcomes.

## 10. Delivery sequence

| Step | Upstream work | Acceptance |
| --- | --- | --- |
| D1 | Export/schema baseline; neutral logging, containers, policy/errors; direct core imports | Dependency boundaries remain visible |
| D2 | Move SSH/SFTP; explicit auth/trust/environment/input; bound plans | External adapters, real SSH/jumps/privilege/SFTP and native regressions |
| D3 | Move MCP implementation and inject four roles; CLI host composition | Equivalent tool contracts, construction rollback and shutdown |
| D4 | Admission, generations, approval binding, update barrier | Deterministic concurrency tests for identities/jumps/revocation |
| D5 | Deferred operations and journal dual-version reading | Old fixtures, unknown protection, commit/revocation ordering |
| D6 | Standalone fixtures and extraction check | Consumer uses core with pinned remote module version |

Keep every step buildable. D3 may initially use static legacy adapters; do not advertise live Web editing until D4/D5 pass. Database implementation remains outside this upstream refactor.

## 11. Extraction acceptance

1. Check production/test dependency graphs for Linux, Windows, macOS and relevant build tags; forbid same-module imports outside core.
2. Inspect implicit home/environment discovery, global printing, standard streams, and file writes. Explicit file/stdio transports remain allowed when their resources are host-supplied.
3. Copy only core, fixtures, and license into a temporary module. Rewrite internal core import prefixes and run tidy/build/test. Forbid replacements back to the checkout and any dependency on the original module; inspect the resulting package and module graph.
4. Core unit/race/real SSH/SFTP fixtures run independently. CLI-dependent integration tests remain in the application repository.
5. Preserve upstream build/test/lint, transport contracts, and relevant native platform gates. Cross-compilation is separate evidence.
6. Keep only core consumer probes in xops-mcp. Forbid upstream packages outside core in every production/test graph on Linux, Windows, and macOS. Validate remotely available pins, not only local workspaces.

Extraction proves source closure, not ABI, database, high-availability, or native support on every platform. Later externalization updates CLI/server adapter dependencies; avoid exposing duplicate named types from old and new module paths, using a coordinated version upgrade where required.

## 12. Current runtime integration and remaining work

Runtime accepts State/Gate/Backend factory/Audit through WithDependencies, validates publication domains, policy and deadlines, and closes partially acquired backends on construction failure. Ordinary SSH/SFTP tools resolve one snapshot and enter the gate after approval; inventory returns display data and policy from one read. NewRuntime does not load CLI configuration, initialize global logging, or discover personal credentials/standard streams.

HTTP defaults to `HTTPOptions.ToolTimeout`; the public stdio runtime defaults to five minutes. `WithToolTimeout` explicitly overrides the tool timeout in either mode regardless of option order. HTTP requests, SDK middleware and tool handlers use the same effective value while preserving earlier caller deadlines. Request-body, stream-idle, GET-session, file-transfer and commit timeouts remain independently configured.

Dynamic hosts can use core/mcp/state.Coordinator for both StateSource and ExecutionGate. Deferred tasks use the same admission domain. Database transactions, durable version generation, credential storage and trust adapters remain host responsibilities.

D4/D5 cover publication barriers, committed-but-unpublished failures, affected pool retirement, persisted canonical input/dependencies, claim/commit/recovery checks and dual journal versions. Database/Web product implementation remains a later phase; xops-mcp records consumer dependency versions and upgrade acceptance separately.

Protocol/network tests moved with the core implementation. Concrete credential-store and OpenSSH tests remain at the application boundary and use public MCP entry points. The transfer client's canonical source is core/mcp/transferclient; scripts/mcp/transfer.py is generated to preserve standalone downloads. Run `python3 scripts/check_core.py --sync-client` after editing it. Extraction verifies synchronization and runs both Go and Python tests in the isolated module.

## 13. Implemented publication coordinator

core/mcp/state.Coordinator owns a complete immutable view. BeginUpdate blocks affected admission before a database transaction while unrelated nodes remain available. BeginPersistence marks the potentially committed boundary. ConfirmCommit records known success; ConfirmRollback records proven non-application. Unknown outcomes retain the barrier until an authoritative reload establishes a conclusion. Abort is only valid before persistence was attempted.

Publish orders state publication, version comparison and operation registration under one in-memory lock. Old-pool retirement runs outside it. Publication/retirement failure keeps Pending true: do not repeat the database transaction or reopen affected admission. After confirming the committed candidate against storage, retry Publish with a fresh deadline. Snapshot is an administrative view and can expose a committed revision that is not yet activated.

Ordinary address edits preserve the target of admitted work. Authentication/trust changes, disablement/deletion and policy changes cancel affected noncommitting permits. Previously admitted commit permits retain their own deadlines. This coordinates permission rather than remote outcome; the transfer state machine remains authoritative and rollback is not promised.

Shared jump authentication, trust and endpoint data must agree across complete plans, including hops with no standalone Targets entry. Both initial construction and publication compare every repeated hop identity; updating only one dependent plan is rejected. Incomplete dependent updates are rejected; disabled jumps make downstream nodes unavailable. Deleted IDs cannot be reused within a coordinator lifetime, and database adapters must enforce this across restarts. Tombstones cover every hop in active plans. Disabled nodes may retain history, but deleted hops must be removed before re-enabling them.

Retirement covers admission that preceded an edit but has not connected yet. Such work may finish, but newly acquired old-generation connections use uncached leases. Retirement history is bounded; reaching its limit makes new generations uncached for the connector lifetime instead of forgetting retirement markers.

Barrier-based tests and real MCP/SSH tests cover edits after approval, preserved admitted targets, unknown persistence, publication failure after commit, shared-jump rotation, revocation versus reserved commits, retirement outside the lock, display edits, identity/alias constraints and capacity release. Transfer preparation and tunnel creation now read invocation policy and re-enter admission after approval. Persisted ready-task validation also applies at claim/commit/recovery.

CLI host tunnels execute through TunnelBackend. Enter freezes the provider once for both binding validation and the private provider retained in the permit context. The backend creates a dedicated connector from that view; it neither retains a startup runner snapshot nor rereads a mutable Repository before dialing. New requests observe published edits, while ordinary edits after admission do not redirect admitted requests. Credential sources remain adapter-private and never enter public OperationSnapshot values.

The full tunnel-list pipeline shares the caller context and tool deadline. Retained canonical node IDs remain recognizable after disablement/deletion; other aliases use current inventory resolution. The result snapshot is captured before approval and authorized using current metadata policy. Historical identity recognition grants no execution authority.


## 14. Persisted tasks and commit handoff

Runtime writes private v2 records through PrepareBound, retaining OperationSnapshot and Binding without changing public Spec/Status or MCP schemas. RequestDigest identifies original client input; Binding.InputDigest covers canonical Spec including paths, size, hash, overwrite and target. Authentication/privilege versions use lossless base64 persistence for legacy binary CAS tokens. Snapshots contain no plaintext credentials.

The complete persisted record, including authorization, is limited to 64 KiB. Preparation reserves space for the derived temporary path, longest state name, timestamp, byte count, checksum and all three diagnostic fields. Each diagnostic has a 4096-byte JSON content budget; system messages are safely truncated, while oversized operator reasons are rejected. Manager and Journal share encoding validation; size and format failures return before Store.Save, without disabling storage or leaving a new task. Actual Save errors may follow an applied write, so they still block new mutations until recovery. Historical full records retain their original disk evidence and are classified in memory as expired/failed/unknown with a warning. They cannot be replayed, unknown destination locks remain active, and exhausted metadata headroom does not prevent service startup.

Preparation retries inspect the original record. Ready tasks must pass admission before credential rotation; stale binding invalidates only ready work. Completed/unknown results remain unchanged. Data requests enter TransferStart with the original binding before ClaimBound, so an old token cannot operate on the current same-named node.

OpenTransfer returns a TransferSession owning the original SFTP subsystem and connection lease. After verification, obtain a separate Commit permit, complete Lease.ReserveCommit under the same manager lock as task cancellation, hand it to TransferSession.ReserveCommit(ctx, permit), then durably record intent with BeginCommitBound. Send rename only after all steps succeed. ClaimBound receives the original request context separately from streaming authority. Task/request cancellation or expiry before reservation prevents rename; cancellation after reservation is rejected. Stream revocation following publication is not mistaken for prior caller cancellation. Revocation after reservation cannot cancel the admitted commit or force reauthentication. Streaming authority cannot commit and commit authority cannot upload.

Commit admission supplies the current TransferStart permit through Admission.Previous. The same coordinator verifies ownership, OperationID, Binding, liveness and phase, then atomically transfers the existing capacity slot to Commit. Full capacity does not block this handoff, and matching operation IDs alone cannot bypass quotas. The old permit becomes unusable; closing it does not release the new slot. Cross-operation, foreign-coordinator and replay attempts are rejected. Finished or failed streams release admission before temporary cleanup requests Recovery authority. Journal failure prevents rename; lost confirmation after sending remains unknown.

Commit-journal fault tests cover failure before writing and errors returned after an applied write. Neither path invokes remote rename; commit reservations are released, temporary files are removed, and the durable result records failure before remote commit.

Cleanup and remote verification require Recovery admission of the recorded binding. Deleted/retargeted nodes and changed authentication/trust/policy leave evidence pending instead of contacting a replacement target. There is no automatic recovery override using new credentials; operators must verify the original target and handle it explicitly. Unbound v1 records retain listing, recovery classification and manual unknown resolution, but cannot gain remote execution or cleanup authority. Future versions fail loading without rewriting files. Original Prepare/Retry/Claim remain available for standalone legacy state-machine consumers; Runtime uses bound entries exclusively.

DomainID and dependency versions must survive restarts within a deployment. Display-only changes do not affect execution digests. A random per-process domain cannot represent deployment identity. Host versions must cover actual credential material and trust changes.

The CLI host adapter derives a stable credential-dependency digest over the complete hop chain: identity references, login/passphrase/privilege references, key fingerprints, legacy password fields, and referenced store configurations. Read-only Provider snapshots participate through Target.Version even without UpdateRef. This digest is not a credential-write CAS token and contains no plaintext secrets. Unrelated stores, aliases and tags are excluded. Credential ItemIDs remain immutable by the store contract; rotation must produce a new reference.

## 15. Consumer and publication acceptance

xops-mcp keeps core consumer tests in internal/coreconsumer and removes internal/legacycompat. internal/dependencycheck verifies the remote pin and all production/test dependencies on three platforms; upstream imports must stay under core. scripts/check_core_consumer.py --upstream creates a disposable local replacement and runs three-platform dependency checks, build, race and lint. Neither repository receives a replacement. The probe covers HTTP authentication, tool inventory, command execution, file roundtrips, dynamic disablement and cleanup.

After the upstream commit is available on a remote branch, --version validates the exact downloadable module version without replacement before updating consumer go.mod/go.sum. A canonical pseudo-version pins that commit without requiring a release tag. Consumer CI validates its committed pin; local integration does not replace remote-download acceptance.



Concurrent-container performance and stress checks use `make bench` and `make stress`, targeting `core/concurrent/...`. The `pkg/utils/concurrent` facade is no longer provided.

Direct CLI consumption also covers stdio inventory publication, HTTP/recovery startup snapshots, audit paths, concrete vault recovery, and the Windows input bridge. Historical native-platform results are not native execution evidence for this migration.

## MCP HTTP client authentication API

`runtime.HTTPOptions.TokenVerifier` integrates host-owned token storage and is mutually exclusive with static `Token`. Honor the supplied bounded context and return `auth.TokenInfo` with a stable, nonempty `UserID`. Optional `Extra["tokenID"]` identifies the credential. Authentication failures do not expose backend diagnostics.

Dynamic authentication acquires an independent slot before calling the host, bounded by `MaxRequests`. Saturation immediately returns HTTP 429 `authentication_limit`. The slot is released when verification returns; subsequent parsing, SSE and tool execution do not retain authentication capacity. Ordinary requests and control messages keep their separate admission lanes. See `core/mcp/runtime/http_auth_admission_test.go` for concurrency, timeout-release and control-message regressions.

The SDK binds sessions to `UserID`. `runtime.ClientIdentityFromContext` exposes verified client and token IDs to tool invocations. Core uses the client ID for operation bindings and transfer scopes, isolating retry, lookup and cancellation. Static-token and stdio scopes retain their existing behavior. Previously issued short-lived transfer credentials retain their original authorization; the verifier does not promise to interrupt admitted work.

`core/mcp/runtime/http_identity_test.go` covers two clients, identity on detached tool calls, transfer isolation, missing identity and redacted errors.
