# Offline vault compatibility

Linux, Windows, and macOS implementations on amd64/arm64 share the v1 format and transaction protocol. They do not require Secret Service, D-Bus, pass, or an external credential manager. Password derivation runs in a private child of the XOps binary.

## Validation matrix

| Environment | Coverage |
| --- | --- |
| Ubuntu 24.04, Linux amd64 | Native unit tests, real KDF, maintenance and process-crash recovery |
| Ubuntu 24.04, Linux ARM64 | Same coverage |
| CentOS 7, Linux 3.10, XFS, amd64 | End-to-end disposable vault operations and real KDF on a server |
| Windows amd64 | Native ACLs, locking, maintenance and process-crash recovery |
| Windows ARM64 | Separate native CI; Go does not support its race detector on this target |
| macOS ARM64 / Intel | Native ACLs, locking, real KDF, maintenance and process-crash recovery |

See the [native compatibility workflow](https://github.com/wentf9/xops-cli/actions/workflows/offline-compatibility.yml) for current results. A successful cross-build is not native validation. Hosted process-crash tests are not physical power-loss tests.

## Check before initializing

```bash
xops credential store probe file
xops credential store init file
xops credential store inspect file --verify
```

`probe` explicitly creates and removes a private scratch directory to check exclusive file publication, replacement, exclusive directory publication, locks, and synchronization calls. Existing targets are checked on their own filesystem, with a lock for initialized vaults. Absent targets use their parent directory. The probe does not initialize a vault, create a key file, or read credentials. Default read-only doctor checks do not perform these write probes.

## Platform behavior

- Linux prefers statx mount IDs and falls back to proc fdinfo on older kernels. Ordinary replacement uses POSIX rename.
- macOS uses native exclusive rename and full file synchronization. Extended ACL data grants are checked in addition to POSIX mode bits.
- Windows uses private ACLs, reparse-point rejection, native file locks, and write-through publication. Existing read-only key files can be reused.
- KDF admission observes Linux cgroup v1/v2 limits. Windows uses a kill-on-close Job Object; macOS monitors parent exit.

## Required boundaries

Storage must provide reliable permissions, locking, atomic publication, and persistence. Unsupported Linux exclusive publication is rejected explicitly instead of using a racy check-then-overwrite sequence. Symlinks, unsafe ACLs, and insecure permissions remain rejected.

Context cancellation cannot forcibly interrupt every kernel filesystem stall. Network/FUSE storage and physical power-loss behavior need deployment-specific validation. One successful probe is not a guarantee against future failures or across all storage media.

This native validation run passed: [CI 34571151620](https://github.com/wentf9/xops-cli/actions/runs/34571151620), commit `0d7d574`.
