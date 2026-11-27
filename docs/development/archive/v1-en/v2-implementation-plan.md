# XOps v2 Clean-Slate Phased Implementation Plan

> **Architecture Authority**: [XOps v2 Clean-Slate Architecture Specification (Architecture RFC v2.2)](./v2-architecture-rfc.md) (ADR-001 – ADR-016)  
> **Plan Status**: Pre-flight calibrated & persisted (**no Go source code written yet**)  
> **Execution Mandate**: **Go 1.27+** · Zero `replace` across all 3 `go.mod` files (`core/` & `tools/xopsvet/` always run `GOWORK=off`; root CLI runs via `go.work` during branch dev and `GOWORK=off` once `core/v2.0.0` is tagged) · **Guardrails & progressive 3-OS CI from `P0-T1`** · **Walking Skeleton right after Gate G2** · Zero dual-track patches

---

## 1. Execution Strategy & Clean-Room Protocol

1. **Dedicated Rewrite Branch**: Branch `refactor/v2-architecture` from the finalized planning commit; keep `master` and `feat/openssh-compatibility` untouched (historical domain reference via `git show b15df20:<path>`).
2. **Commit-0 Clean-Room Clearance**: Clear legacy Go trees (`cmd/`, `pkg/`, `core/`, `internal/`) on `refactor/v2-architecture` and initialize the **Go 1.27+** 3-module workspace at canonical import paths.
3. **Guardrails First + Early Vertical Proof**: Complete all 8 precision `tools/xopsvet` analyzers in `Phase 0`; right after `Gate G2`, deliver **`Phase 2.5 Walking Skeleton`** across native Linux/Windows(ConPTY)/macOS before parallel Phases 3 & 4 fan-out.
4. **Hard Ceilings & Purity**: Package <= 3,000 LOC; file <= 500 LOC (<= 800 LOC for `*_spec.go`/`*_variants.go`/`*_codec.go`); **`gocognit <= 15`**; 0 inline `//nolint` outside whitelists; **0 `sync`/`sync/atomic` in `core/domain/**`**; no bare `time.Duration` in `encoding/json/v2` DTOs.

---

## 2. Phase-by-Phase Work Breakdown (28 Work Packages, 7 Mandatory Gates)

### Phase 0: Go 1.27+ Multi-Module Workspace, Progressive 3-OS CI, Guardrails & Concurrency Foundation
- **`P0-T1`**: Initialize `go.work`, `go.mod`, `core/go.mod`, `tools/xopsvet/go.mod` (`go 1.27.0`, **zero `replace` in all 3 `go.mod` files**); configure `.golangci.yml` (**`gocognit <= 15`**); **front-load `.github/workflows/ci.yml` to a progressive Go 1.27+ Linux/Windows/macOS native pipeline** (removing `scripts/check_core.py`, testing landed modules natively so Gate G2 `core/osfs` & Gate G2.5 ConPTY execute natively from day 1); update `Makefile` with absolute `VETTOOL="$(pwd)/bin/xopsvet$(go env GOEXE)"` and `./cmd/xops`.
- **`P0-T2`**: `tools/xopsvet` Group A: `archbound` (enforcing zero `domain -> sync/sync/atomic`, zero `pool -> sshnet/osfs`, zero `gate -> pool/osfs`, zero `usecase/entry -> osfs`, zero `mcpruntime -> OperatorReadFS`), `noimplicit` (no `init()`, mutable globals, `context.WithValue` outside `trace`, anonymous interface assertions, inline `//nolint:`, or bare `time.Duration` in JSON v2 DTOs), and `osboundary`.
- **`P0-T3`**: `tools/xopsvet` Group B: `sumexhaust`, scoped `failclosed` (exempting pure `errors.Is`/`AsType` classifiers), `digestcover`, local `linearlease` (no bare `go` outside `conc` + `//xops:borrowed` closure non-escape), and type/local direct-sink `secrettaint` (no false scalar taint on `len(plain)`).
- **`P0-T4`**: `core/internal/foundation/conc` (`Nursery`, **two-stage `select` `DualActor[Req, Ctrl]`** with `actorDone` non-hang shutdown, `CtxMutex`) and `trace` (`TraceID`/`OpID` + `LeaseScope`).
- **`Gate G0`**: All 8 analyzers pass positive/negative `analysistest`; `conc` passes `-race -shuffle=on -count=50` + `goleak`.

### Phase 1: 100% Zero-`sync` Pure Functional Domain Kernel (`core/domain/**`)
- **`P1-T1`**: `algebraic` (`Option[T]` for struct fields only, `NonEmpty[T]`, `FirstWins[T]`, **`Duration` implementing `TextAppender`/`TextMarshaler`/`TextUnmarshaler`**), single-goroutine `secret.SecretBox` (plain `wiped bool`, `//xops:borrowed`, deliberately zero `json/v2` marshalers for native `SemanticError`), `netaddr` (`Endpoint`/`HostPort`/`CanonicalHost` with `TextAppender`).
- **`P1-T2`**: `pathalg` (`RemotePath`, `RemoteName`, `LocalRootedDest`, `LocalDir`, `LocalSourcePath`, `ValidateLocalComponent`, symlink policy `(b)` + NFC/NFD folding collision, UTF-8 `ProtectedPathMatcher`).
- **`P1-T3`**: `option` (4-tier OpenSSH monoids + pure `ResolveEffectivePolicy`; `*_spec.go`/`*_codec.go` <= 800 LOC).
- **`P1-T4`**: Pure math `security` (`Verdict`/`RiskLevel`/`Decision` lattices, `NodeOverrides`, phantom `Capability`, `OperationID`, `OperationBinding`, `ApprovalEnvelope` — **`Authorized[C]` lives in `core/internal/gate`**).
- **`P1-T5`**: `execution` (`CommandPlan` + `ExecutionOutcome` ADT), `inventory` (DAG + `ImportBundle`), `plan` (zero-reflect Merkle `HopDigest` + `ManagedHandle[K]`).
- **`P1-T6`**: `playbook` (discriminated `StepAction` + `FoldPlaybookReport`) and `fsm` (5 pure Mealy FSMs).
- **`Gate G1`**: `GOWORK=off` build + `xopsvet` 0 issues + `golangci-lint` (`gocognit <= 15`) 0 issues + 100% algebraic law, `json/v2` round-trip, and Fuzz suites green.

### Phase 2: Driven Ports, TCK, `core/osfs` & Decoupled Core Runtime Engine
- **`P2-T1`**: `core/ports` (**`ScopedRootFS`** + **`OperatorReadFS`**, scoped **`SecretVault.WithSecret`**, `FormatImporter`, `AuditSink`+Reconciler, `DialerPort`, `MuxSocketPort`, `RemoteFSPort`, etc.) + `core/ports/tck`.
- **`P2-T2`**: `core/osfs` (Go `*os.Root` `ScopedRootFS` with **sidecar `<name>.lock` locking**, `OperatorReadFS`, `OpenRegular`, `CreateExclusive`, `OpenLockedContext`, `AtomicReplace`, `SocketSlot`, Windows Handle DACL + `\\?\` + `AF_UNIX` peer token, Unix peer UID).
- **`P2-T3`**: `core/events` (Sealed `Event` ADT passing `json/v2` round-trips, `OperationStream`, `AuditDispatcher`, `SystemBus`).
- **`P2-T4`**: `core/internal/gate` (compiler-sealed **`Authorized[C]`** + package-level **`gate.WithAuthorized[C]`**, `OnHaltFunc` outbound callback, `StrictAgentProfile` **`Halted` circuit breaker**, `ReconcileCrashedAudits`).
- **`P2-T5`**: `core/internal/pool` (**depends ONLY on `core/ports`, zero `sshnet`/`osfs`**; two-stage `DualActor`, control/data plane separation, `actorDone`-guarded `ReleaseLease`, `trace.LeaseScope` injected strictly upon user-callback entry, topological `WithMultiLease`, parent `Epoch` CAS, 90ms teardown, SlotMap, `GateHalted` revocation).
- **`P2-T6`**: `core/internal/sim` (`SimClock`, `SeededRand`, `SimScopedRootFS`, `SimOperatorReadFS`, fault-injecting ports passing `tck`) + 10,000-seed DST verifying crash audit reconciliation, `Halted` breaker (confirming `WithAuthorized`-outer / `WithLease`-inner has no self-deadlock), mailbox saturation, reentrancy guard, and 5 global invariants.
- **`Gate G2`**: 3-OS cross-build + `osfs`/`sim` TCK + 10k-seed DST (`-race -shuffle=on` + `goleak` 0 leaks) + `xopsvet` 0 issues.

### Phase 2.5: Walking Skeleton Vertical Slice (Zero Legacy Bridges)
- **`P2.5-T1`**: Minimal `sshnet/{dial,hostkey}` (with `WithSecret` + mandatory `Nursery` **`ssh.Channel` Watchdog** + single locked `knownHostsDB`) and minimal `internal/host/{openssh,sys,audit}` (read-only `~/.ssh/config`, Unix PTY + Windows ConPTY/JobObject Relay, JSONL `AuditSink` with **append-only `~/.xops/run/<ProcessInstanceID>.lock` O(1) crash reconciliation**).
- **`P2.5-T2`**: Minimal read-only **`usecase/inventory.ResolveTarget`** (`OriginAdHoc` & `OriginOpenSSHVirtual`, avoiding temporary hacks in `session` or `cmd/xops`), minimal `usecase/session` (`WithAuthorized` wrapping `WithLease`), minimal `core/engine` (wiring `sshnet` -> `pool` and `gate.OnHaltFunc` -> `pool.GateHalted`), minimal `entry/cli` (`xops ssh` + `version`), and `cmd/xops` (injecting `ScopedRootFS` + `OperatorReadFS`).
- **`Gate G2.5`**: Real pure-v2 `bin/xops` verified end-to-end on native Linux, Windows (`windows-latest` ConPTY), and macOS (with absolute `VETTOOL` + `GOEXE`, `core/` `GOWORK=off`, root via `go.work`) + Watchdog `goleak` & multi-terminal crash-lock tests green.

### Phase 3 & Phase 4 (Independent Parallel Tracks Feeding Into Phase 5)
> Any rare tweak to a `Gate G2.5`-locked `core/ports` signature during parallel work MUST update `core/ports/tck` + `core/internal/sim` and pass `Gate G2` in the same commit.
- **Phase 3 (`usecase/*` + `mcpruntime` + `core/engine`)**: `P3-T1` full `inventory`/`credential` (`FormatImporter`, `WithSecret`), `P3-T2` full `session`, `P3-T3` full `transfer` (`OperatorReadFS` sources + `ScopedRootFS` targets), `P3-T4` `automation`/`observability`, `P3-T5` `mcpruntime` (**physically zero `OperatorReadFS`**) + full `core/engine` -> **`Gate G3`**.
- **Phase 4 (`sshnet/*` + `internal/host/*`)**: `P4-T1` full `sshnet/{dial,hostkey,priv,probe}`, `P4-T2` full `sshnet/{sftp+FSTAT,forward,mux}`, `P4-T3` full `host/{store,openssh,audit}`, `P4-T4` full `host/{vault(WithSecret),sys}` -> **`Gate G4`** (100% TCK + `ssh -G` differential + native 3-OS CI — independent of `Gate G3`).

### Phase 5: Full Thin Entries, Final Composition Root & Release Cutover
- **`P5-T1`**: Full `internal/entry/cli` (incl. unified `config import`, `--json`, `--policy`).
- **`P5-T2`**: `internal/entry/tui` + `internal/entry/sftpshell`.
- **`P5-T3`**: `internal/entry/{mcpcmd,muxdaemon}` + complete `cmd/xops` (startup O(1) crash reconciliation + reverse-order shutdown).
- **`P5-T4`**: Release pipeline finalization (tag `core/v2.0.0`, pin root `go.mod` & verify full 3-module `GOWORK=off`), `Makefile` release targets, rewritten bilingual docs, `AGENTS.md`, `skills/xops-agent/`.
- **`Gate G5`**: `core/` & `tools/xopsvet/` `GOWORK=off` + root CLI (`go.work` on dev branch, `GOWORK=off` on `core/v2.0.0` release tag) + absolute `VETTOOL` `xopsvet` 0 issues + `golangci-lint` (`gocognit <= 15`) 0 issues + 10k DST + native 3-OS CI + `npm run docs:check` green.

---

## 3. Phase 0 / Phase 2 Implementation Notes (Day-1 Pitfall Prevention)

> These coding-level notes complement the frozen v2.2 RFC for `P0-T2`/`P0-T3`/`P0-T4`/`P1-T1`/`P2-T1`/`P2-T4`/`P2.5-T1` without changing architecture boundaries:

1. **`xopsvet/linearlease` synchronous nested bracket closures with recursive tracking (`P0-T3`)**: Allow `//xops:borrowed` parameters to be captured by inner `*ast.FuncLit` closures passed directly to synchronous scoped functions (`With*` / `Use` / `//xops:syncclosure`), while **recursively continuing non-escape tracking inside the inner closure body** so captured outer borrowed identifiers can never be smuggled into `Nursery.Go`, returns, or outer vars/fields/containers/channels.
2. **`xopsvet/archbound` symbol ban & fail-closed `core/domain` stdlib allowlist (`P0-T2`)**:
   - Keep `ScopedRootFS` and `OperatorReadFS` together in `core/ports/localfs.go` and enforce via `pass.TypesInfo.Uses` that `core/internal/mcpruntime` never references `core/ports.OperatorReadFS`.
   - Enforce a **fail-closed pure-stdlib allowlist** on `core/domain/**` (`bytes`, `cmp`, `crypto/sha256`, `crypto/subtle`, `encoding`, `encoding/base64`, `encoding/binary`, `encoding/hex`, `encoding/json/jsontext`, `encoding/json/v2`, `errors`, `fmt`, `hash`, `io`, `iter`, `maps`, `math`, `math/bits`, `net/netip`, `path`, `regexp`, `slices`, `sort`, `strconv`, `strings`, `time`, `unicode`, `unicode/utf8`, `unicode/utf16`) while banning `time.Now`/`Since`/`Until`/`NewTimer`/`NewTicker`/`After`/`Sleep` via `TypesInfo.Uses`.
3. **`conc.DualActor` truly unbounded control channel (`P0-T4`)**: Implement `SendControl(msg Ctrl)` via a tiny-mutex unbounded ring/slice queue (enqueue/dequeue only inside the lock, zero business logic) + 1-buffered `controlReady chan struct{}` wakeup signal + `actorDone` check, rather than a fixed-buffer raw `chan Ctrl`.
4. **Append-only `.lock` protocol, strict `Stage -> Audit` ordering & slow-path verification (`P2-T4` / `P2.5-T1`)**: Never truncate-and-rewrite while concurrent ops are active — make `.lock` strictly **append-only** (`+<opID>\n` on `Stage`, `-<opID>\n` on `Unstage`, guarded by in-process mutex + active map; allow `Truncate(0)` **only when in-memory active set reaches 0**, or after brief admission quiesce/drain on long-lived MCP HTTP servers). Execute `Stage(+opID) -> Audit(Authorized) -> run() -> Audit(Finalized) -> Unstage(-opID)`. Clean startup (99.999%) performs O(1) zero read of `audit.jsonl`; on crash recovery slow path (0.001%), after winning exclusive `TryLock`, replay `+`/`-` diff and cross-check `audit.jsonl` for that `ProcessInstanceID` to append `AbortedByCrash` ONLY for `opID`s that actually have `Authorized` without `Finalized`.
5. **Windows-safe locked `.lock` cleanup (`P2-T2` / `P2.5-T1`)**: Avoid `ERROR_SHARING_VIOLATION` by executing **truncate/clear contents while holding exclusive lock -> unlock & close handle -> `Remove` (ignoring `ErrNotExist`)**, guaranteeing idempotency across all 3 platforms.
6. **Inbound `SecretBox` closure construction (`P1-T1` / `P2-T1`)**: Provide `secret.WithBytes(raw []byte, fn func(box *SecretBox) error) error` (deep-copy + immediate `clear(raw)` + unconditional `defer box.Wipe()`) and callback-scoped `InteractionPort.PromptSecret(ctx, req, func(box *SecretBox) error) error` so even interactive password input + `Vault.PutAndVerify` requires zero manual `defer box.Wipe()`.

---

## 4. Persistent Execution Checklist

- **Phase 0**: `[ ] P0-T1` · `[ ] P0-T2` · `[ ] P0-T3` · `[ ] P0-T4` · **`[ ] Gate G0`**
- **Phase 1**: `[ ] P1-T1` · `[ ] P1-T2` · `[ ] P1-T3` · `[ ] P1-T4` · `[ ] P1-T5` · `[ ] P1-T6` · **`[ ] Gate G1`**
- **Phase 2**: `[ ] P2-T1` · `[ ] P2-T2` · `[ ] P2-T3` · `[ ] P2-T4` · `[ ] P2-T5` · `[ ] P2-T6` · **`[ ] Gate G2`**
- **Phase 2.5 (Walking Skeleton)**: `[ ] P2.5-T1` · `[ ] P2.5-T2` · **`[ ] Gate G2.5`**
- **Phase 3**: `[ ] P3-T1` · `[ ] P3-T2` · `[ ] P3-T3` · `[ ] P3-T4` · `[ ] P3-T5` · **`[ ] Gate G3`**
- **Phase 4**: `[ ] P4-T1` · `[ ] P4-T2` · `[ ] P4-T3` · `[ ] P4-T4` · **`[ ] Gate G4`**
- **Phase 5**: `[ ] P5-T1` · `[ ] P5-T2` · `[ ] P5-T3` · `[ ] P5-T4` · **`[ ] Gate G5`**
