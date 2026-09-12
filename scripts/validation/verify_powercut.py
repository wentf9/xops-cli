#!/usr/bin/env python3
"""Destroy only disposable QEMU guests at authenticated-vault file hooks.

Requires a prepared initramfs containing vm-init.sh and the vaultpowercut test.
All disks/logs are created in a new directory under --output; no host block
device, existing VM, network interface, or credential configuration is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time


CASES = [
    ("reencrypt", "admin:stage-2"),
    ("reencrypt", "admin:budget:file-sync"),
    ("reencrypt", "admin:budget:publish"),
    ("reencrypt", "admin:budget:dir-sync"),
    ("reencrypt", "admin:item:publish"),
    ("reencrypt", "admin:stage-3"),
    ("reencrypt", "admin:current:file-sync"),
    ("reencrypt", "admin:current:publish"),
    ("reencrypt", "admin:current:dir-sync"),
    ("reencrypt", "admin:archive"),
    ("prune", "admin:unlink"),
    ("prune", "admin:unlink-sync"),
    ("prune", "admin:rmdir"),
    ("prune", "admin:prune-archive"),
]


def boot(kernel, initrd, disk, log, phase, operation="reencrypt", point="none", filesystem="ext4"):
    args = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "512",
            "-smp", "2", "-display", "none", "-serial", "stdio", "-monitor", "none",
            "-nic", "none", "-no-reboot", "-kernel", str(kernel), "-initrd", str(initrd),
            "-append", f"console=ttyS0 quiet panic=-1 xops_vault_lab=1 xops_phase={phase} xops_operation={operation} xops_point={point} xops_filesystem={filesystem}",
            "-drive", f"file={disk},format=raw,if=virtio,cache=none,aio=threads"]
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    output = bytearray()
    cut = False
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 70
        while time.monotonic() < deadline:
            for key, _events in selector.select(0.2):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    break
                output.extend(chunk)
                if len(output) > 4 * 1024 * 1024:
                    raise RuntimeError("VM output exceeded limit")
                if phase == "cut" and b"XOPS_POWER_CUT_READY" in output:
                    os.killpg(process.pid, signal.SIGKILL)
                    cut = True
                    break
            if cut or (process.poll() is not None and not selector.get_map()):
                break
        else:
            raise TimeoutError("VM phase deadline exceeded")
        code = process.wait(timeout=3)
        if phase == "cut":
            if not cut or code != -signal.SIGKILL:
                raise RuntimeError("VM did not reach the requested power-cut hook")
        elif code != 0 or b"XOPS_VM_PHASE_PASSED" not in output or b"XOPS_VM_PHASE_FAILED" in output:
            raise RuntimeError("VM phase verification failed")
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        process.stdout.close()
        log.write_bytes(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--initrd", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--filesystem", choices=("ext4", "xfs", "btrfs"), default="ext4")
    args = parser.parse_args()
    kernel = args.kernel.resolve(strict=True)
    initrd = args.initrd.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="powercut-", dir=args.output.resolve(strict=True)))
    print(f"Evidence directory: {root}", flush=True)
    baseline = root / "baseline.img"
    subprocess.run(["qemu-img", "create", "-f", "raw", str(baseline), "512M"], check=True, timeout=10)
    subprocess.run([f"mkfs.{args.filesystem}", "-q", str(baseline)], check=True, timeout=20)
    boot(kernel, initrd, baseline, root / "prepare.log", "prepare", filesystem=args.filesystem)
    results = []
    for number, (operation, point) in enumerate(CASES):
        disk = root / f"case-{number:02d}.img"
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(baseline), str(disk)], check=True, timeout=20)
        boot(kernel, initrd, disk, root / f"case-{number:02d}-cut.log", "cut", operation, point, args.filesystem)
        boot(kernel, initrd, disk, root / f"case-{number:02d}-verify.log", "verify", operation, point, args.filesystem)
        results.append({"operation": operation, "point": point, "recovery": "passed"})
        print(json.dumps(results[-1]), flush=True)
    report = {"kernel_sha256": hashlib.sha256(kernel.read_bytes()).hexdigest(),
              "initrd_sha256": hashlib.sha256(initrd.read_bytes()).hexdigest(),
              "disk_cache": "none", "network": "none", "filesystem": args.filesystem, "cases": results,
              "scope": "guest power loss, not physical host/controller power loss"}
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
