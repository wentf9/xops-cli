# Shared XOps core

This subtree is independent of the CLI application and can be extracted into
a separately maintained Go module. It currently shares the repository's
Go 1.26+ module; no nested module is used.

Implemented packages:

- `auth`: storage-independent authentication errors used directly by consumers.
- `concurrent`: the concurrent map implementation and its original tests.
- `log`: diagnostic interface and a no-op logger without process initialization.
- `mcp/policy`: policy configuration values with legacy serialization preserved.
- `mcp/guardrail`: shared policy/approval engine with per-invocation policy and
  binding contexts, plus bounded host-owned audit sinks.
- `mcp/transfer` and `mcp/tunnel`: existing task state machines and journals.
- `mcp/remotefile`: the single implementation of streamed SFTP file operations.
- `mcp/ports`: snapshot, binding, phase-limited permit and backend contracts.
- `mcp/sshexec`: lease-owning SSH/SFTP execution for those contracts, with
  independent tunnel connections and distinct streaming/commit permits.
- `mcp/runtime`: protocol, tools, transfers, recovery and shutdown, composed
  through explicit State/Gate/Backend/Audit dependencies.
- `mcp/state`: atomic inventory publication/admission, persistence-outcome
  barriers, affected-plan retirement and noncommitting operation revocation.
- `mcp/transferclient`: canonical standalone Python transfer client and tests.
- `ssh`: the shared connection/command/forwarding implementation, explicit local
  environment, signer and host-trust sources, input bridges, and captured plans.
- `sftp`: the shared subsystem and file-transfer implementation.
- `testutil/testleak`: portable secret-leak assertions used by core and CLI tests.

Persisted transfer authorization, dual-version journals and retained-connection
commit handoff are implemented. Independent extraction and local external
consumer probes pass. The consumer records its remotely downloadable fixed pin
and acceptance evidence in xops-mcp/docs/reuse-baseline.md.
Production database, version-generation and trust/credential adapters belong
to the consuming host. Domain and dependency versions must survive restarts.
CLI and server consumers import core directly; old Go API facades are removed.
Core packages and tests must never import application `pkg/*` or root
`internal/*` packages.

New SSH consumers supply `Environment` and/or `KeySource` / `HostKeyVerifier`.
Pinned-trust verifiers can also implement `HostKeyAlgorithmSource` to select
supported host-key algorithms before the handshake, using the same endpoint and
trust version as verification. Empty, unsupported, failed, or timed-out selections
fail closed; `Verify` still checks the exact server key. RSA pins should select
`rsa-sha2-512` / `rsa-sha2-256`, not the obsolete `ssh-rsa` SHA-1 signature.
Core does not discover personal home directories, agent sockets, default keys,
or standard streams. CLI adapters explicitly inject defaults and the Windows
input bridge from `internal/sshenv`. `internal/mcphost` converts CLI configuration
and credentials into core runtime options; commands own runtime construction
and shutdown.

`ConnectPlan` accepts a scope and a complete ordered hop snapshot containing no
plaintext secrets. It returns a `PlanConnection` lease; defer its `Close` rather
than closing its borrowed `Client`. `RetirePlan` drains that generation after
existing leases finish. It is cache invalidation, not an authorization gate.
The host must validate current operation bindings before requesting a plan.

From the repository root:

```sh
python3 -m unittest discover -s scripts -p test_check_core.py
python3 scripts/check_core.py --race
go test ./internal/clicontract ./internal/mcphost
make bench
make stress
```

The bench and stress targets run `core/concurrent/...`, where the benchmark and
stress implementations live.

The generated `scripts/mcp/transfer.py` remains a standalone download. Regenerate
it with `python3 scripts/check_core.py --sync-client` after changing the canonical
client; the isolation checker rejects distribution drift.

The isolation checker inspects Linux/Windows/macOS production and test imports,
then copies only this subtree and module metadata into a temporary module. It
rewrites core import prefixes, removes unused application dependencies, and
builds/tests without the original module or replacements. Cross-platform import
inspection is not native execution evidence.

CLI configuration and protocol contract tests stay outside core. MCP schemas, descriptions,
and annotations are compared against fixtures verified using the original
remote module `v0.13.1-0.20260930042335-73892b0791e3`. Updating those fixtures
requires an explicit compatibility review, not a routine refactor regeneration.
Comparison ignores JSON formatting, including CRLF checkout line endings;
description text, schema values and array ordering remain significant.

See the [design](../docs/development/shared-core-decoupling.md) for application
boundaries and acceptance criteria.

For a finite ordinary command, `ssh.PlanCommand` freezes the command, interpreter,
launch dialect, login mode, stdin bytes, timeout, and output limit. Its private
state and digest can be shared across targets without rereading mutable defaults.
`Client.ExecuteCommand` executes that plan once and returns `CommandResult` with
`not_started`, `completed`, or `unknown`, optional exit code/signal, combined
output and truncation, and separate execution/I/O/cleanup errors. Use `Err()` to
report all errors; do not infer success from a missing exit code or replay an
unknown result. The digest is not an authorization permit.

The new API defaults to unchanged server commands, a 5-minute timeout, and a
5 MiB output window. Explicit Bash requires `LaunchPOSIX` and defaults to
non-login mode. Original commands and generated exec payloads are each limited to 64 KiB,
including quote expansion. Input is copied, finite, and limited to 16 MiB; output is captured
internally, without external blocking reader/writer callbacks. Channel startup
uses the connector's handshake timeout; cancellation joins workers and may
interrupt a shared transport after a 1-second channel-shutdown grace period.
PTY, scripts, privilege escalation, external I/O bridges, and delegation from
legacy APIs remain subsequent implementation steps. Legacy execution defaults
are preserved. See the [implementation plan](../docs/development/ssh-execution-implementation.md).
