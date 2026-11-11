#!/usr/bin/env python3
"""Classify changed files for GitHub Actions CI matrix optimization."""

from __future__ import annotations

import os
from pathlib import PurePosixPath
import re
import subprocess
import sys

DOCS_EXACT = {
    "README.md",
    "README_en.md",
    "AGENTS.md",
    "LICENSE",
    ".github/workflows/docs.yml",
    ".github/dependabot.yml",
}

CORE_EXACT = {
    "go.mod",
    "go.sum",
    "scripts/check_core.py",
    "scripts/test_check_core.py",
    ".github/workflows/ci.yml",
    "scripts/ci_changes.py",
}

CROSS_PLATFORM_PREFIXES = (
    "core/ssh/",
    "core/sftp/",
    "core/mcp/transfer/",
    "core/testutil/",
    "internal/",
    "pkg/config/",
    "pkg/credential/",
    "pkg/crypto/",
    "pkg/adapter/",
    "pkg/tui/",
    "pkg/utils/",
    "cmd/sftpshell/",
    "cmd/ssh",
)

CROSS_PLATFORM_EXACT = {
    "Makefile",
    "cmd/makefile_test.go",
    "go.mod",
    "go.sum",
    "scripts/verify_native_platform.sh",
    ".github/workflows/ci.yml",
    "scripts/ci_changes.py",
}

PLATFORM_GO_RE = re.compile(
    r"_(windows|darwin|unix|nonwindows|other|platform)(_test)?\.go$"
)


def normalize_path(path: str) -> str:
    cleaned = path.strip().replace("\\", "/")
    posix = PurePosixPath(cleaned).as_posix()
    while posix.startswith("./"):
        posix = posix[2:]
    return posix


def is_docs_only_file(path: str) -> bool:
    if path.startswith("docs/"):
        return True
    if path in DOCS_EXACT:
        return True
    if path.endswith("/AGENTS.md"):
        return True
    if path.startswith("skills/"):
        return True
    return False


def is_core_file(path: str) -> bool:
    if is_docs_only_file(path):
        return False
    if path.startswith("core/"):
        return True
    if path in CORE_EXACT:
        return True
    if path.startswith("scripts/mcp/"):
        return True
    return False


def is_cross_platform_file(path: str) -> bool:
    if is_docs_only_file(path):
        return False
    for prefix in CROSS_PLATFORM_PREFIXES:
        if path.startswith(prefix):
            return True
    if path in CROSS_PLATFORM_EXACT:
        return True
    if path.endswith(".go"):
        basename = path.rsplit("/", 1)[-1]
        if PLATFORM_GO_RE.search(basename):
            return True
    return False


def is_zero_sha(sha: str) -> bool:
    s = sha.strip()
    return not s or all(c == "0" for c in s)


def default_git_runner(args: list[str], cwd: str | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout
    except Exception:
        return -1, ""


def get_changed_files(
    event_name: str,
    base_sha: str = "",
    before_sha: str = "",
    cwd: str | None = None,
    git_runner=None,
) -> tuple[list[str], bool]:
    """Obtain changed file list for the event.

    Returns:
        (changed_files, fallback)
    """
    if git_runner is None:
        git_runner = default_git_runner

    if not event_name or event_name == "workflow_dispatch":
        return [], True

    if event_name == "pull_request":
        # 1. Check if HEAD is a synthetic merge commit
        code, _ = git_runner(["rev-parse", "--verify", "--quiet", "HEAD^2"], cwd=cwd)
        if code == 0:
            diff_code, out = git_runner(
                ["diff", "--name-only", "HEAD^1", "HEAD"], cwd=cwd
            )
            if diff_code == 0:
                files = [
                    normalize_path(line)
                    for line in out.splitlines()
                    if line.strip()
                ]
                return files, False
            return [], True

        # 2. Otherwise check GITHUB_BASE_SHA
        if base_sha and not is_zero_sha(base_sha):
            diff_code, out = git_runner(
                ["diff", "--name-only", f"{base_sha}...HEAD"], cwd=cwd
            )
            if diff_code == 0:
                files = [
                    normalize_path(line)
                    for line in out.splitlines()
                    if line.strip()
                ]
                return files, False
            return [], True

        return [], True

    if event_name == "push":
        if not before_sha or is_zero_sha(before_sha):
            return [], True
        diff_code, out = git_runner(
            ["diff", "--name-only", before_sha, "HEAD"], cwd=cwd
        )
        if diff_code == 0:
            files = [
                normalize_path(line)
                for line in out.splitlines()
                if line.strip()
            ]
            return files, False
        return [], True

    return [], True


def classify_changes(
    changed_files: list[str],
    fallback: bool,
    event_name: str,
    is_draft: bool,
) -> dict[str, bool]:
    """Classify changes into code, core, and cross_platform."""
    if fallback:
        code = True
        core = True
        if event_name == "pull_request" and is_draft:
            cross_platform = False
        elif event_name != "pull_request":
            cross_platform = code
        else:
            cross_platform = True
        return {"code": code, "core": core, "cross_platform": cross_platform}

    # Non-fallback classification
    code = any(not is_docs_only_file(p) for p in changed_files)
    core = any(is_core_file(p) for p in changed_files)

    if event_name == "pull_request" and is_draft:
        cross_platform = False
    elif event_name != "pull_request":
        cross_platform = code
    else:
        cross_platform = any(is_cross_platform_file(p) for p in changed_files)

    return {"code": code, "core": core, "cross_platform": cross_platform}


def main() -> None:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "").strip()
    base_sha = os.environ.get("GITHUB_BASE_SHA", "").strip()
    before_sha = os.environ.get("GITHUB_BEFORE_SHA", "").strip()
    is_draft = os.environ.get("PR_DRAFT", "false").strip().lower() == "true"

    changed_files, fallback = get_changed_files(
        event_name=event_name,
        base_sha=base_sha,
        before_sha=before_sha,
    )

    if not fallback and len(changed_files) == 0:
        if event_name == "push":
            fallback = True
        # For pull_request with empty changed_files, non-fallback naturally yields all False

    result = classify_changes(
        changed_files=changed_files,
        fallback=fallback,
        event_name=event_name,
        is_draft=is_draft,
    )

    sys.stderr.write(
        f"[ci_changes] event={event_name!r} draft={is_draft} fallback={fallback} "
        f"files_count={len(changed_files)}\n"
    )
    if changed_files:
        sample = changed_files[:5]
        sys.stderr.write(f"[ci_changes] sample files: {sample}\n")
    sys.stderr.write(
        f"[ci_changes] classification: code={result['code']} core={result['core']} cross_platform={result['cross_platform']}\n"
    )

    sys.stdout.write(f"code={'true' if result['code'] else 'false'}\n")
    sys.stdout.write(f"core={'true' if result['core'] else 'false'}\n")
    sys.stdout.write(f"cross_platform={'true' if result['cross_platform'] else 'false'}\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
