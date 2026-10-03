# Shared XOps core

This subtree is being separated from the CLI application so it can eventually
be maintained as an independent Go module. It currently shares the repository's
Go 1.26+ module; no nested module is used.

Implemented packages:

- `auth`: storage-independent authentication errors shared by old and new APIs.
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
Existing `pkg/*` imports are compatibility entry points;
core packages and tests must never import them or root `internal/*` packages.

New SSH consumers supply `Environment` and/or `KeySource` / `HostKeyVerifier`.
Core does not discover personal home directories, agent sockets, default keys,
or standard streams. The old SSH constructor supplies the CLI defaults and the
Windows input bridge outside core.

`ConnectPlan` accepts a scope and a complete ordered hop snapshot containing no
plaintext secrets. It returns a `PlanConnection` lease; defer its `Close` rather
than closing its borrowed `Client`. `RetirePlan` drains that generation after
existing leases finish. It is cache invalidation, not an authorization gate.
The host must validate current operation bindings before requesting a plan.

From the repository root:

```sh
python3 -m unittest discover -s scripts -p test_check_core.py
python3 scripts/check_core.py --race
go test ./internal/corecontract
make bench
make stress
```

The bench and stress targets run `core/concurrent/...`, where the benchmark and
stress implementations live; legacy compatibility packages contain no such tests.

The generated `scripts/mcp/transfer.py` remains a standalone download. Regenerate
it with `python3 scripts/check_core.py --sync-client` after changing the canonical
client; the isolation checker rejects distribution drift.

The isolation checker inspects Linux/Windows/macOS production and test imports,
then copies only this subtree and module metadata into a temporary module. It
rewrites core import prefixes, removes unused application dependencies, and
builds/tests without the original module or replacements. Cross-platform import
inspection is not native execution evidence.

The legacy-facing contract tests stay outside core. MCP schemas, descriptions,
and annotations are compared against fixtures verified using the original
remote module `v0.13.1-0.20260930042335-73892b0791e3`. Updating those fixtures
requires an explicit compatibility review, not a routine refactor regeneration.

See the [design](../docs/development/shared-core-decoupling.md) for the remaining
migration and acceptance criteria.
