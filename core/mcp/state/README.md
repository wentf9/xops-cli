# Inventory publication and admission

`Coordinator` implements `ports.StateSource` and `ports.ExecutionGate` over
immutable, complete connection snapshots. It is host-owned; runtimes borrow it.
Close runtimes before closing the coordinator and persistence resources.

An update follows this sequence:

1. Prepare a complete candidate with a new revision and the same publication
   domain. Shared jump snapshots must agree across all dependent plans, including
   hops that have no standalone entry in the target map.
2. Call `BeginUpdate(ctx, expectedRevision, candidate)` before writing storage.
   Affected nodes are blocked; unrelated operations can still be admitted.
3. Call `BeginPersistence()` before attempting the external transaction.
4. On a known commit, call `ConfirmCommit()`. On a proven rollback, call
   `ConfirmRollback()`. On an unknown outcome, retain the update and reload the
   authoritative store before choosing either conclusion. `Abort()` only works
   before persistence has been attempted.
5. Call `Publish(ctx, backend.RetirePlans)`. Publication, admission comparison,
   and operation registration are ordered under one in-memory lock. Retirement
   runs outside that lock while the affected barrier remains in place.

If publication fails after commit, `Pending()` stays true. The host must not
repeat the transaction or claim activation succeeded. After confirming the
committed candidate from storage, retry `Publish` with a fresh deadline and an
idempotent retirement callback. `Snapshot()` is an administrative view and can
show the committed revision while activation is pending.

Ordinary endpoint edits preserve already-admitted operations. Credential/trust
changes, disablement, deletion, and policy changes cancel affected noncommitting
permits. A commit permit admitted before the update remains valid until its
own deadline or explicit close. This does not promise rollback of remote work.

For an upload's TransferStart-to-Commit transition, pass its live permit in
Admission.Previous with the same OperationID and Binding. The coordinator
revalidates the snapshot and atomically replaces the registration in its existing
capacity slot. No extra slot is required at MaxActive. A foreign, closed,
replayed, or mismatched permit cannot transfer capacity. Rejection leaves the
original registration intact; after success, closing the old permit cannot
release the new slot. Runtime retains the original SSH/SFTP transport through
this change and releases finished stream admission before temporary cleanup.
Host gates with their own capacity accounting must implement the same handoff;
ports.NewPermit alone does not implement a quota ledger.

Display-only changes do not alter execution bindings or retire SSH connections.
Hosts must change execution versions when displayed attributes affect policy.
Deleted node IDs cannot be reused during a coordinator's lifetime; the host
database must preserve that identity rule across process restarts. Every hop in
an active candidate is checked against tombstones, including jumps absent from
the current target map. Disabled records may retain old plans but cannot be
re-enabled until those references are removed.

Connection retirement also covers work that was admitted before an edit but
has not acquired its transport yet. Those old plans use uncached leases rather
than recreating a retired pool. Retirement history is bounded; once full, new
generations remain uncached for that connector's lifetime.

This component does not persist tasks or inventory. Deferred transfer binding,
journal format migration, and database/Web adapters are separate integration
work; a coordinator alone is not a complete dynamic MCP deployment.
