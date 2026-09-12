# Credential experience implementation plan

Status: core implementation and review fixes are complete. Final acceptance requires native evidence tied to the candidate commit. Based on the [accepted experience decisions](./credential-experience-design).

## Phase 1: Entry points and configuration contract

- Map configuration loading, credential reads, authentication, success callbacks, and persistence; identify read-only paths and interaction capabilities.
- Define default store ID, directories, and key-file path using cross-platform configuration conventions, not the binary directory.
- Distinguish explicit none from an unset backend. Specify per-invocation/global no-save options, precedence, and migration behavior.
- Define password-rejection classification, retry limits, ownership of shared private-key passphrases, and verification success signals.
- Audit reusable transaction components for v1 upgrades and v2 backend migration; define commands, recovery, and source cleanup.

Deliver entry-point matrices, configuration/command contracts, and boundary tests. Discuss unresolved user-visible tradeoffs before changing accepted decisions.

## Phase 2: Default offline storage and automatic saving

Implement lazy initialization, concurrent process initialization, key generation/reuse, and verified-success callbacks for the three reusable secret categories. Keep references separate from secrets. Preserve successful connections after save errors; permit temporary interactive input after read errors, with clear unattended failures.

## Phase 3: Authentication rejection and updates

Implement bounded, cancellable retries and update only on corresponding verification success. Cover sudo and servers requiring ordinary-user login followed by su. Verify key decryption separately from final SSH authentication. Never persist one-time responses.

## Phase 4: Automatic upgrades and advanced migration

Implement upgrades at normal usage entry points using backup, write, read-back, CAS, and durable publication ordering. Cover interruption recovery and continued legacy use on failure. Support explicit v2 offline-to-other-backend migration and the reverse. Distinguish default selection from reference migration; never automatically remove source credentials or recovery material.

## Phase 5: Bilingual documentation and release gates

Update both languages for getting started, credentials, migration, troubleshooting, CLI help, and release notes. Turn the [release draft](./credential-experience-release) into verified user instructions including real paths, configuration fields, complete migration commands, and recovery steps. Keep pending status until implementation is complete.

| Acceptance scenario | Required evidence |
| --- | --- |
| Fresh user with only the binary | No manual initialization; save after successful verification; no repeated input on the second connection |
| Linux without desktop/DBus/secret-tool | Default flow has no dependency on these; old-Linux regression checks pass |
| Native Windows/macOS | Paths, permissions, locks, initialization, and recovery verified on native runners |
| Existing/missing/invalid/lost key-file | Generate or reuse for new stores; never replace a lost key for an existing store or damage recovery material |
| Concurrent or interrupted initialization | No overwrite or false success; retries reuse material safely |
| Save failure or read-only/unreadable store | Keep successful connections; allow temporary input when interactive; unattended execution does not block |
| Password changes and rejected retries | Retry only on explicit rejection; replace only after success, retaining the old record on failure |
| Private keys, agents, and multiple auth methods | Save only after corresponding key decryption; another method's success does not validate a passphrase |
| sudo, su, and OTP | Separate escalation credentials; never persist one-time codes |
| No-save controls and explicit backend | Initialization and upgrades respect user choices |
| Automatic v1 upgrade | No manual migration prerequisite; verified reference switch; usable legacy configuration on failure; no automatic cleanup |
| Migration interruption or concurrent config edits | Recovery and CAS outcomes are distinguishable; preserve sources and never switch to unverified targets |
| v2 backend migration and return | Dry-run has no writes; default/reference semantics are clear; failures recoverable |
| Help, completion, doctor, dry-run | Loading configuration does not implicitly write or migrate |
| All composition roots | CLI/TUI/transfers/automation/task overrides follow the same saving and interaction rules |

Run capped-concurrency build, test, lint, shuffled race, and credential integration race (including umask 077) serially to avoid high load. Use GitHub Actions native Linux/Windows/macOS amd64 and ARM64 runners. Windows ARM64 runs ordinary tests where Go does not support race; state that evidence limit. Process-crash recovery does not prove physical power-loss recovery.

Release requires acceptance evidence on the final commit, bilingual examples matching real commands, and prominent disclosure of automatic upgrades and retained legacy materials.

## Implementation progress (unreleased)

New installations default to the offline store with key-file, initialized on write. Automatic legacy migration and never opt-outs are implemented, preserving explicit backend choices and recovery materials. The default `credentials/` directory and `credentials.key` are relative to the configuration file. Reads and dry-run do not initialize stores; interrupted initialization still requires explicit recovery.

SSH passwords and key passphrases support bounded retries. Interactive read failures allow temporary input; persistence failures retain connections and disable subsequent writes with uncertain versions. Snapshot conflicts, cancellation, and unattended paths retain error behavior.

### Commands, scripts, and streaming privilege execution

`RunWithSudo`, `RunScriptWithSudo`, and `RunCommandWithIO` use a separate privilege handshake. The elevated process emits a random readiness signal before the user command and waits for client acknowledgement before executing it. The full readiness signal is not literal in the remote command, preventing command echo from impersonating readiness. Script/user input is withheld until the handshake; passwords are sent only in response to authentication prompts.

Sudo permits at most three password attempts within the same process. Su starts another authentication session only after explicit rejection before readiness, with at most three attempts. A user command that might have started is never automatically replayed. Unknown errors, output failures, cancellation, and timeouts do not trigger retry. Unattended calls still check credentials early and return errors.

Readiness plus an observed password exchange confirms the credential independently of the command exit code. Nonzero exit codes remain visible to callers and are not treated as rejected passwords. Interactive persistence failures retain the connection and disable further writes. Passwordless/cached interactive calls do not read, send, or save a password.

Sudo uses a separate privilege reference, falling back to the login candidate with its version check when absent. Legacy SuPwd is never used as a sudo password; existing su references are not reinterpreted as sudo references. Auto detection does not prompt for and discard a su candidate or introduce another su preflight.

Acceptance covers one command execution after retries, saving verified credentials despite nonzero command exit, three rejected attempts leaving input untouched, no rejected-password persistence, passwordless input isolation, fragmented frames, opaque command output, and cancellation cleanup. Actual Bash tests verify that missing/incorrect acknowledgement prevents execution and that the acknowledgement line does not enter command stdin.

### Standalone interactive PTYs

`ShellWithSudo` and `RunInteractiveWithSudo` now use the same authentication handshake, with borrowed-stream variants `ShellWithSudoIO` and `RunInteractiveWithSudoIO`. Local input remains in normal mode during password prompts and enters raw mode only after authentication. The remote PTY disables echo for passwords and acknowledgement; after acknowledgement, `stty echo` restores echo and a terminal handoff signal releases client keyboard input. The remote handoff uses Bash and standard terminal utilities.

Retries never replay a command that might have started. Interactive shell/exec preserve their previous ordinary process-exit handling; authentication failures, cancellation, I/O errors, and restoration failures are not hidden by an exit status. Verified credentials can be saved even when an interactive command exits nonzero.

Resize monitoring is cancellable and joined. The stdin reader and resize worker stop before the original terminal mode is restored and control returns to the caller. Real Linux PTY tests cover canonical mode during prompts, the first input character, and mode restoration. An actual Bash/PTY test verifies that acknowledgement is not echoed and that echo is restored before handoff. Deterministic tests cover cancellation, handoff timeout, and restoration errors. Final native Windows/macOS runtime gates remain pending.

### TUI integration

Enter, monitoring, and log connections use `tea.Exec` to release the terminal before authentication. An owned action cancels and joins shared SSH handshakes before restoring the UI. Scoped ports prohibit background prompts/writeback and mark credential reads non-interactive. SSH sessions share the existing repository instead of spawning another CLI process; list references, filtering, selection, and checked items refresh on return, including errors after a successful save.

The TUI inherits remember policy and supports the `--remember` override. `never` disables automatic migration and saving while explicit management actions remain available. Saving initialization failure permits session-only connections with a visible status; write failures keep authenticated connections and preserve a warning when the UI resumes. Vault unlock uses the released terminal's cancellable context.

Tests cover actual SSH authentication and Linux PTY Enter sessions, shared-repository persistence, always/ask/never, fresh target connections, background no-prompt/no-write behavior, release failure, cancellation, save failures, and filter preservation. Shared SSH output writes are serialized to support a common destination without racing `io.ReaderFrom` optimizations.

### Remaining work

General v2 backend migration is implemented; final six-platform native acceptance remains pending. TUI/terminal behavior has local Linux runtime evidence; final Windows/macOS checks are still required. Overall acceptance is not complete.

### V2 backend migration

`credential migrate --to <store>` supports both v1 upgrades and v2 backend migration. V2 deduplicates current references, copies into new references, compares values and expiry metadata on read-back, and switches all references and the default store with configuration CAS. Never policies do not block explicit migration. Source credentials remain; legacy v1 material and v2 records are separate. Rerun after interruption; explicit `--restart` archives the previous plan and replans after concurrent edits without rollback or credential deletion.

Tests cover shared references, three credential kinds, offline round-trips and key-file reuse, read-only dry-run, interruption recovery, configuration conflicts and restart, corrupt destinations, uncertain writes, and v1 backup retention. Offline runtime evidence here comes from local Linux; final six-platform native acceptance remains separate. See the [migration guide](../guide/migration).


### Review fixes and native verification gates

Offline corruption retains its original cause while exposing the backend-neutral unavailable classification. Interactive input may recover temporarily; non-interactive and canceled requests fail closed. A real corrupt-vault test covers successful authentication, keeping the connection after a failed save, and preserving the key and damaged CURRENT.

SSH, interactive exec, and single-target SCP now permit session-only use when persistence initialization fails, as TUI already does. All automatic recording is explicitly disabled to prevent legacy configuration writes. Regression tests cover always/ask/never, non-interactive boundaries, notice-output failure, and unchanged configuration.

The six-platform workflow includes configuration initialization/migration, real corrupt-vault recovery, and Windows ConPTY checks. The native system-backend round-trip requires XOPS_TEST_NATIVE_MIGRATION=1: CI provisions an isolated Linux Secret Service and temporary macOS Keychain, and uses Windows Credential Manager. Random test references exercise three credential purposes, source retention and key-file reuse; system test credentials are cleaned afterward. A skip without a provisioned service is not native acceptance evidence.

These gates do not replace complete Windows/macOS TUI and privilege-terminal experience acceptance or prove physical power-loss recovery. Release still requires checking results for the final candidate commit.

Native credential fixtures use physical temporary paths so the macOS /var symlink does not trigger path rejection. Production vaults still reject symlink directories. Keychain cleanup runs only after successful test-keychain provisioning.
