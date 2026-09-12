#!/usr/bin/env python3
"""Offline vault release drill using only public fixtures and the supplied binary.

Run in an isolated network namespace with --require-isolation for release evidence.
Python drives the drill; XOps receives an empty PATH and needs no external helper.
All vault/configuration mutations are under a private temporary directory.
"""
import argparse
import hashlib
import json
import os
import errno
import pty
import selectors
import signal
import time
from pathlib import Path
import shutil
import subprocess
import tempfile


def digest_tree(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("unexpected link in archive")
        if path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def private_write(path, data):
    path.write_bytes(data)
    path.chmod(0o600)



def prompt_command(binary, env, operation, count):
    password = b"release-drill-public-master-password"
    master, slave = pty.openpty()
    process = None
    selector = selectors.DefaultSelector()
    transcript = b""
    sent = 0
    try:
        args = [str(binary), "credential", "store", operation, "offline", "--json"]
        if operation == "inspect":
            args.append("--verify")
        process = subprocess.Popen(args, env=env, stdin=slave, stderr=slave,
                                   stdout=subprocess.PIPE, start_new_session=True)
        os.close(slave)
        slave = -1
        selector.register(master, selectors.EVENT_READ)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            for _key, _events in selector.select(0.1):
                try:
                    chunk = os.read(master, 8192)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    chunk = b""
                transcript += chunk
                if len(transcript) > 65536:
                    raise RuntimeError("prompt output limit exceeded")
                prompts = transcript.count(b"Master password for ")
                if prompts > sent and transcript.endswith(b": "):
                    if sent >= count:
                        raise RuntimeError("unexpected extra password prompt")
                    os.write(master, password + b"\n")
                    sent += 1
            if process.poll() is not None:
                break
        if process.wait(timeout=1) != 0:
            raise RuntimeError("prompt-mode command failed")
        output = process.stdout.read(65537)
        if len(output) > 65536 or sent != count or password in transcript + output:
            raise RuntimeError("invalid or echoed password interaction")
        if json.loads(output)["code"] != "ok":
            raise RuntimeError("prompt command result failed")
    finally:
        selector.close()
        os.close(master)
        if slave != -1:
            os.close(slave)
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            if process.stdout is not None:
                process.stdout.close()


def run_drill(binary, root, verifier):
    config = root / "config"
    config.mkdir(mode=0o700)
    key = root / "key"
    private_write(key, bytes([37]) * 32)  # Public fixture, never a production key.
    source = root / "source"
    filename = config / "xops_config.yaml"
    text = f"""schema_version: 2
credential:
  default_store: offline
  stores:
    offline:
      type: encrypted-file
      path: {json.dumps(str(source))}
      unlock: key-file
      key_file: {json.dumps(str(key))}
identities:
  demo:
    user: demo
hosts: {{}}
nodes: {{}}
"""
    private_write(filename, text.encode())
    env = {"PATH": "", "XOPS_CONFIG_DIR": str(config),
           "XOPS_JOURNAL_DIR": str(root / "journals"), "LANG": "C.UTF-8"}

    def command(args, value=None):
        result = subprocess.run([str(binary), *args], input=value, env=env,
                                capture_output=True, timeout=45, check=False)
        if result.returncode:
            raise RuntimeError(f"command {args[0:3]} failed with exit {result.returncode}")
        return result.stdout

    def store(op, *args):
        result = json.loads(command(["credential", "store", op, "offline", "--json", *args]))
        if result["code"] != "ok":
            raise RuntimeError("store result not successful")
        return result

    def verify_original():
        result = subprocess.run([str(verifier), str(filename)], env=env,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError("original fixture reference/value verification failed")
        record = json.loads(result.stdout)
        if record.get("verified") is not True or not record.get("ref"):
            raise RuntimeError("fixture verifier did not confirm reference/value")
        return record["ref"]

    store("init")
    public_secret = b"release-drill-public-secret"
    command(["identity", "credential", "set", "demo", "--password-stdin",
             "--store", "offline"], public_secret + b"\n")
    original_ref = verify_original()
    initial = store("inspect", "--verify")["inspection"]
    if public_secret in filename.read_bytes():
        raise RuntimeError("secret persisted in configuration")

    # Every XOps process has exited before the stopped archive is copied.
    archive = root / "archive"
    archive.mkdir(mode=0o700)
    shutil.copytree(source, archive / "vault")
    shutil.copy2(filename, archive / "config.yaml")
    shutil.copy2(key, archive / "key")
    before = digest_tree(archive)
    work = root / "backup-work"
    shutil.copytree(archive / "vault", work)
    target = root / "restored"
    next_key = root / "new-key"
    private_write(next_key, bytes([73]) * 32)
    current = filename.read_text().replace(str(source), str(target)).replace(str(key), str(next_key))
    private_write(filename, current.encode())
    selected_hash = hashlib.sha256(filename.read_bytes()).hexdigest()
    result = store("restore", "--from", str(work), "--source-unlock", "key-file",
                   "--source-key-file", str(archive / "key"),
                   "--backup-config", str(archive / "config.yaml"))
    if not result["outcome"]["durable"]:
        raise RuntimeError("restore publication not durable")
    if hashlib.sha256(filename.read_bytes()).hexdigest() != selected_hash:
        raise RuntimeError("restore rewrote configuration")
    restored = store("inspect", "--verify")["inspection"]
    if restored["generation"] <= initial["generation"]:
        raise RuntimeError("restore reused source generation")
    if digest_tree(archive) != before:
        raise RuntimeError("archive changed")
    # Check the ORIGINAL ref and value before any rotation can hide lost data.
    if verify_original() != original_ref:
        raise RuntimeError("restored fixture reference changed")
    # Normal Service Put/read-back/CAS/Delete must work after restore.
    command(["identity", "credential", "set", "demo", "--password-stdin",
             "--store", "offline"], b"release-drill-after-restore\n")
    store("reencrypt")
    plan = store("prune")
    if not plan.get("revisions"):
        raise RuntimeError("old revision missing from cleanup plan")
    store("prune", "--apply")
    final = store("inspect", "--verify")["inspection"]
    if (config / "secret.key").exists():
        raise RuntimeError("legacy key unexpectedly created")
    prompt_config = text.replace(str(source), str(root / "password-vault"))
    prompt_config = prompt_config.replace("unlock: key-file", "unlock: prompt")
    prompt_config = "\n".join(line for line in prompt_config.splitlines() if "key_file:" not in line) + "\n"
    private_write(filename, prompt_config.encode())
    prompt_command(binary, env, "init", 2)
    prompt_command(binary, env, "inspect", 1)
    return {"password_kdf_offline": True, "result": "passed", "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "initial_generation": initial["generation"], "restored_generation": restored["generation"],
            "final_generation": final["generation"], "archive_unchanged": digest_tree(archive) == before,
            "external_helper_path": "empty", "original_reference_verified": True, "original_value_verified": True,
            "verifier_sha256": hashlib.sha256(verifier.read_bytes()).hexdigest(),
            "restore_checks": "independent Get through original reference and fixture value comparison before rotation"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--verifier", required=True, type=Path, help="offline-vault-verify test driver")
    parser.add_argument("--require-isolation", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    verifier = args.verifier.resolve(strict=True)
    devices = {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line}
    isolated = devices <= {"lo"} and len(Path("/proc/net/route").read_text().splitlines()) <= 1
    if args.require_isolation and not isolated:
        raise RuntimeError("network isolation not established")
    with tempfile.TemporaryDirectory(prefix="xops-release-") as directory:
        report = run_drill(binary, Path(directory), verifier)
    report["network_isolated"] = isolated
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
