#!/usr/bin/env python3
"""Check shared-code dependencies and build an isolated copy of core."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


EXTRACTED_MODULE = "example.com/xops-core-extraction"


def sync_client_distribution(root: Path, write: bool = False) -> None:
    """Keep the historical download path standalone without a second source."""
    source = root / "core/mcp/transferclient/transfer.py"
    if not source.exists():
        return
    lines = source.read_bytes().splitlines(keepends=True)
    header = b"# Generated from core/mcp/transferclient/transfer.py; edit the canonical source\n"
    expected = b"".join(lines[:1]) + header + b"".join(lines[1:])
    destination = root / "scripts/mcp/transfer.py"
    if write:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(expected)
    elif not destination.exists() or destination.read_bytes() != expected:
        raise ValueError("standalone transfer client differs; run scripts/check_core.py --sync-client")


def json_stream(text: str) -> list[dict]:
    decoder = json.JSONDecoder()
    records = []
    offset = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        record, offset = decoder.raw_decode(text, offset)
        if not isinstance(record, dict):
            raise ValueError("Go package metadata must contain objects")
        records.append(record)
    return records


def boundary_errors(packages: list[dict], module: str) -> list[str]:
    errors = []
    for package in packages:
        name = package.get("ImportPath", "").split(" [", 1)[0]
        if name == module or (
            name.startswith(module + "/")
            and name not in (module + "/core", module + "/core.test")
            and not name.startswith(module + "/core/")
        ):
            errors.append(name)
        if name == "github.com/wentf9/xops-mcp" or name.startswith("github.com/wentf9/xops-mcp/"):
            errors.append(name)
        if package.get("Error") or package.get("DepsErrors"):
            errors.append(f"unresolved package: {name}")
    return sorted(set(errors))


def run_go(root: Path, *args: str, target: str | None = None) -> str:
    environment = dict(os.environ, GOWORK="off")
    if target is not None:
        environment.update(GOOS=target, GOARCH="amd64", CGO_ENABLED="0")
    result = subprocess.run(
        ["go", *args], cwd=root, env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"go {' '.join(args)} failed:\n{result.stdout}{result.stderr}")
    return result.stdout


def copy_core(root: Path, target: Path, module: str) -> None:
    source = root / "core"
    if not source.is_dir():
        raise ValueError("core subtree is missing")
    for path in sorted(source.rglob("*")):
        if "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
            continue
        if path.is_symlink():
            raise ValueError(f"core extraction cannot follow a symlink: {path.relative_to(root)}")
        destination = target / path.relative_to(source)
        if path.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix == ".go":
                destination.write_text(
                    path.read_text().replace(module + "/core", EXTRACTED_MODULE)
                )
            else:
                shutil.copy2(path, destination)
    # Seed the exact selected dependency versions; tidy removes CLI-only entries.
    for name in ("go.mod", "go.sum", "LICENSE"):
        shutil.copy2(root / name, target / name)


def assert_no_original_module(packages: list[dict], module: str) -> None:
    for package in packages:
        name = package.get("ImportPath", "")
        if name == module or name.startswith(module + "/"):
            raise ValueError(f"extracted code still imports the original module: {name}")


def check(root: Path, graph_only: bool, race: bool, tags: str) -> None:
    sync_client_distribution(root)
    module_info = json.loads(run_go(root, "list", "-m", "-json"))
    module = module_info["Path"]
    tag_args = ["-tags=" + tags] if tags else []
    for target in ("linux", "windows", "darwin"):
        packages = json_stream(run_go(
            root, "list", "-deps", "-test", "-json", *tag_args, "./core/...", target=target
        ))
        if not packages:
            raise ValueError("core dependency graph is empty")
        errors = boundary_errors(packages, module)
        if errors:
            raise ValueError(f"{target} core dependencies escape the subtree: {', '.join(errors)}")
        print(f"{target}: core production/test dependency boundary passed", flush=True)
    if graph_only:
        return
    with tempfile.TemporaryDirectory(prefix="xops-core-") as directory:
        isolated = Path(directory)
        copy_core(root, isolated, module)
        if module_info.get("Replace"):
            raise ValueError("the source module must not use a replacement")
        manifest = json.loads(run_go(isolated, "mod", "edit", "-json"))
        if manifest.get("Replace"):
            raise ValueError("extraction forbids replacement directives")
        run_go(isolated, "mod", "edit", "-module=" + EXTRACTED_MODULE)
        run_go(isolated, "mod", "tidy")
        modules = json_stream(run_go(isolated, "list", "-m", "-json", "all"))
        if any(item["Path"] == module or item.get("Replace") for item in modules):
            raise ValueError("extracted module retains the original module or a replacement")
        packages = json_stream(run_go(isolated, "list", "-deps", "-test", "-json", *tag_args, "./..."))
        assert_no_original_module(packages, module)
        run_go(isolated, "build", *tag_args, "./...")
        race_args = ["-race"] if race else []
        output = run_go(isolated, "test", *race_args, "-count=1", "-timeout=300s", *tag_args, "./...")
        print(output, end="", flush=True)
        client = isolated / "mcp" / "transferclient"
        if client.is_dir():
            subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", str(client), "-p", "*_test.py"],
                cwd=isolated, check=True, timeout=120,
            )
        print("isolated module: build/tests passed without the original module or replacements", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph-only", action="store_true")
    parser.add_argument("--race", action="store_true", help="run isolated tests with the race detector")
    parser.add_argument("--tags", default="", help="additional Go build tags")
    parser.add_argument("--sync-client", action="store_true", help="regenerate the standalone legacy client download")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.sync_client:
        sync_client_distribution(root, write=True)
        return
    check(root, args.graph_only, args.race, args.tags)


if __name__ == "__main__":
    main()
