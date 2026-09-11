# Offline vault platform compatibility

The v1 vault format and credential-reference model are shared by Linux, Windows
and macOS implementations on amd64/arm64. This branch adds native CI coverage;
building for a target is not evidence that its runtime semantics work.

- Linux keeps handle-relative no-follow access, device/mount checks and flock.
  Old kernels may obtain mount IDs from proc fdinfo. Ordinary replacement uses
  POSIX rename; exclusive publication still requires atomic no-replace support.
- macOS uses native exclusive rename and full file synchronization.
- Windows uses protected ACLs, reparse-point rejection, byte-range file locks
  and write-through rename. Directory flushing follows Windows semantics.
- The password KDF runs in a private child. Windows contains it in a kill-on-close
  job; macOS watches the parent. Linux retains Pdeathsig and cgroup-aware admission.
- cgroup memory observation supports both v1 and v2, including mounted subtrees.

`xops credential store probe <storeID>` tests operations in a disposable private
directory on the target filesystem (or its parent when not yet initialized). It does not initialize the configured vault or read secrets.
An existing vault is locked during the probe; separately-mounted targets are checked on their own filesystem.

The native verification program checks key-file creation, missing-key rejection,
real password derivation, rewrap, clone, reencrypt and deletion. Integration tests
exercise transaction recovery after process crashes. Hosted CI does not prove
physical power-loss durability, and context deadlines cannot forcibly interrupt
all kernel filesystem stalls.
