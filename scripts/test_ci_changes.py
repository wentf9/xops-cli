#!/usr/bin/env python3
"""Unit and integration tests for CI change detection script."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import ci_changes


class TestCIChangesClassification(unittest.TestCase):
    """Test classification rules in isolation."""

    def test_docs_only_pr(self):
        """Case 1: Docs-only PR -> code=false, core=false, cross_platform=false."""
        files = [
            "docs/guide/intro.md",
            "README.md",
            "core/domain/AGENTS.md",
            "skills/foo/SKILL.md",
            ".github/workflows/docs.yml",
        ]
        result = ci_changes.classify_changes(
            changed_files=files,
            fallback=False,
            event_name="pull_request",
            is_draft=False,
        )
        self.assertEqual(
            result,
            {"code": False, "core": False, "cross_platform": False},
        )

        # Additional docs-only entries
        more_docs = [
            "README_en.md",
            "AGENTS.md",
            "LICENSE",
            ".github/dependabot.yml",
            "docs/development/v2-architecture-rfc.md",
        ]
        res_more = ci_changes.classify_changes(
            changed_files=more_docs,
            fallback=False,
            event_name="pull_request",
            is_draft=False,
        )
        self.assertEqual(
            res_more,
            {"code": False, "core": False, "cross_platform": False},
        )

    def test_draft_pr_with_core_osfs(self):
        """Case 2: Draft PR even with core/osfs/root.go -> code=true, core=true, cross_platform=false."""
        files = ["core/osfs/root.go"]
        result = ci_changes.classify_changes(
            changed_files=files,
            fallback=False,
            event_name="pull_request",
            is_draft=True,
        )
        self.assertEqual(
            result,
            {"code": True, "core": True, "cross_platform": False},
        )

    def test_ready_pr_core_pure_math_and_scripts(self):
        """Case 3: Ready PR changing non-cross-platform script or pure domain logic."""
        # 3a: [scripts/local-ci/run.sh] -> code=true, core=false, cross_platform=false
        files_3a = ["scripts/local-ci/run.sh"]
        result_3a = ci_changes.classify_changes(
            changed_files=files_3a,
            fallback=False,
            event_name="pull_request",
            is_draft=False,
        )
        self.assertEqual(
            result_3a,
            {"code": True, "core": False, "cross_platform": False},
        )

        # 3b: [core/domain/algebraic/duration.go] -> code=true, core=true, cross_platform=false
        files_3b = ["core/domain/algebraic/duration.go"]
        result_3b = ci_changes.classify_changes(
            changed_files=files_3b,
            fallback=False,
            event_name="pull_request",
            is_draft=False,
        )
        self.assertEqual(
            result_3b,
            {"code": True, "core": True, "cross_platform": False},
        )

    def test_ready_pr_cross_platform_paths(self):
        """Case 4: Ready PR changing cross-platform paths -> cross_platform=true."""
        paths_to_verify = [
            ("core/osfs/root.go", True, True, True),
            ("internal/host/sys/pty.go", True, False, True),
            ("internal/entry/cli/root.go", True, False, True),
            ("Makefile", True, False, True),
            ("go.mod", True, True, True),
        ]
        for path, exp_code, exp_core, exp_cross in paths_to_verify:
            with self.subTest(path=path):
                result = ci_changes.classify_changes(
                    changed_files=[path],
                    fallback=False,
                    event_name="pull_request",
                    is_draft=False,
                )
                self.assertEqual(
                    result,
                    {"code": exp_code, "core": exp_core, "cross_platform": exp_cross},
                )

        # Additional cross platform prefixes and exact matches
        additional_paths = [
            ("core/ports/fs.go", True, True, True),
            ("core/internal/foundation/conc/nursery.go", True, True, True),
            ("core/internal/sshnet/dial/dialer.go", True, True, True),
            ("core/internal/pool/actor.go", True, True, True),
            ("core/internal/gate/gate.go", True, True, True),
            ("tools/xopsvet/cmd/xopsvet/main.go", True, True, True),
            ("cmd/xops/main.go", True, False, True),
            ("go.work", True, True, True),
            ("core/go.mod", True, True, True),
            ("tools/xopsvet/go.mod", True, True, True),
            (".golangci.yml", True, True, True),
            ("scripts/verify_native_platform.sh", True, False, True),
            (".github/workflows/ci.yml", True, True, True),
            ("scripts/ci_changes.py", True, True, True),
            ("scripts/test_ci_changes.py", True, True, True),
            ("core/internal/mcpruntime/journal_windows.go", True, True, True),
            ("core/internal/foundation/conc/nursery_windows_test.go", True, True, True),
        ]
        for path, exp_code, exp_core, exp_cross in additional_paths:
            with self.subTest(path=path):
                result = ci_changes.classify_changes(
                    changed_files=[path],
                    fallback=False,
                    event_name="pull_request",
                    is_draft=False,
                )
                self.assertEqual(
                    result,
                    {"code": exp_code, "core": exp_core, "cross_platform": exp_cross},
                )

    def test_push_to_master(self):
        """Case 5: push to master."""
        # 5a: Upper script change -> code=true, core=false, cross_platform=true (mainline safe fallback)
        res_code = ci_changes.classify_changes(
            changed_files=["scripts/local-ci/run.sh"],
            fallback=False,
            event_name="push",
            is_draft=False,
        )
        self.assertEqual(
            res_code,
            {"code": True, "core": False, "cross_platform": True},
        )

        # 5b: Docs-only change -> code=false, core=false, cross_platform=false
        res_docs = ci_changes.classify_changes(
            changed_files=["docs/guide/intro.md"],
            fallback=False,
            event_name="push",
            is_draft=False,
        )
        self.assertEqual(
            res_docs,
            {"code": False, "core": False, "cross_platform": False},
        )

        # 5c: Initial push (before SHA is 40 zeros) -> fallback=True -> all true
        files, fallback = ci_changes.get_changed_files(
            event_name="push",
            before_sha="0000000000000000000000000000000000000000",
        )
        self.assertTrue(fallback)
        res_initial = ci_changes.classify_changes(
            changed_files=files,
            fallback=fallback,
            event_name="push",
            is_draft=False,
        )
        self.assertEqual(
            res_initial,
            {"code": True, "core": True, "cross_platform": True},
        )

    def test_workflow_dispatch(self):
        """Case 6: workflow_dispatch -> all true without git diff."""
        files, fallback = ci_changes.get_changed_files(event_name="workflow_dispatch")
        self.assertTrue(fallback)
        self.assertEqual(files, [])
        result = ci_changes.classify_changes(
            changed_files=files,
            fallback=fallback,
            event_name="workflow_dispatch",
            is_draft=False,
        )
        self.assertEqual(
            result,
            {"code": True, "core": True, "cross_platform": True},
        )

        # Unset event_name also acts as full fallback
        files_none, fallback_none = ci_changes.get_changed_files(event_name="")
        self.assertTrue(fallback_none)
        result_none = ci_changes.classify_changes(
            changed_files=files_none,
            fallback=fallback_none,
            event_name="",
            is_draft=False,
        )
        self.assertEqual(
            result_none,
            {"code": True, "core": True, "cross_platform": True},
        )

    def test_empty_diff_handling(self):
        """Case 4 of file detection: empty diff on push vs pull_request."""
        # On push, 0 diff -> fallback=True -> all True
        files = []
        fallback = False
        event_name = "push"
        if not fallback and len(files) == 0:
            if event_name == "push":
                fallback = True
        res_push = ci_changes.classify_changes(files, fallback, event_name, is_draft=False)
        self.assertEqual(res_push, {"code": True, "core": True, "cross_platform": True})

        # On pull_request, 0 diff -> all False
        files_pr = []
        fallback_pr = False
        res_pr = ci_changes.classify_changes(files_pr, fallback_pr, "pull_request", is_draft=False)
        self.assertEqual(res_pr, {"code": False, "core": False, "cross_platform": False})

    def test_path_normalization(self):
        """Test Windows backslashes and leading ./ normalization."""
        self.assertEqual(ci_changes.normalize_path(".\\core\\ssh\\client.go"), "core/ssh/client.go")
        self.assertEqual(ci_changes.normalize_path("./pkg/config/AGENTS.md"), "pkg/config/AGENTS.md")
        self.assertEqual(ci_changes.normalize_path(".///internal/terminal/conpty.go"), "internal/terminal/conpty.go")


class TestGitIntegrationAndFailSafe(unittest.TestCase):
    """Case 7: Git integration tests in temporary repository and fail-safe fallbacks."""

    def _run_git(self, repo: str, *args: str) -> str:
        proc = subprocess.run(
            ["git"] + list(args),
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return proc.stdout.strip()

    def test_synthetic_merge_commit_calculation(self):
        """Verify GitHub PR synthetic merge commit (HEAD^1 and HEAD^2).

        Verifies that even if GITHUB_BASE_SHA is behind HEAD^1, diffing HEAD^1..HEAD
        only captures the net PR changes and ignores changes committed on master.
        """
        with tempfile.TemporaryDirectory() as td:
            # 1. Initialize git repo on master
            self._run_git(td, "init", "-b", "master")
            self._run_git(td, "config", "user.name", "CI Tester")
            self._run_git(td, "config", "user.email", "ci@example.com")
            self._run_git(td, "config", "commit.gpgsign", "false")

            base_file = Path(td) / "base.txt"
            base_file.write_text("initial base\n")
            self._run_git(td, "add", "base.txt")
            self._run_git(td, "commit", "-m", "C0: initial base commit")
            c0_sha = self._run_git(td, "rev-parse", "HEAD")

            # 2. Branch feature from C0 and commit scripts/local-ci/run.sh
            self._run_git(td, "checkout", "-b", "feature")
            script_dir = Path(td) / "scripts" / "local-ci"
            script_dir.mkdir(parents=True, exist_ok=True)
            (script_dir / "run.sh").write_text("#!/usr/bin/env bash\n")
            self._run_git(td, "add", "scripts/local-ci/run.sh")
            self._run_git(td, "commit", "-m", "C1: feature change")
            c1_sha = self._run_git(td, "rev-parse", "HEAD")

            # 3. Master advances with an unrelated commit C2 (e.g. core/osfs/root.go)
            self._run_git(td, "checkout", "master")
            core_dir = Path(td) / "core" / "osfs"
            core_dir.mkdir(parents=True, exist_ok=True)
            (core_dir / "root.go").write_text("package osfs\n")
            self._run_git(td, "add", "core/osfs/root.go")
            self._run_git(td, "commit", "-m", "C2: master advanced")

            # 4. Create synthetic merge commit (merging feature into master)
            self._run_git(td, "merge", "--no-ff", "feature", "-m", "Merge PR synthetic commit")
            merge_head = self._run_git(td, "rev-parse", "HEAD")

            # Verify HEAD^2 matches C1
            self.assertEqual(self._run_git(td, "rev-parse", "--verify", "--quiet", "HEAD^2"), c1_sha)

            # Test get_changed_files with GITHUB_BASE_SHA set to outdated C0
            changed_files, fallback = ci_changes.get_changed_files(
                event_name="pull_request",
                base_sha=c0_sha,
                cwd=td,
            )
            self.assertFalse(fallback)
            # Only scripts/local-ci/run.sh should be detected, NOT core/osfs/root.go from master
            self.assertEqual(changed_files, ["scripts/local-ci/run.sh"])

            # Classification should be code=true, core=false, cross_platform=false
            res = ci_changes.classify_changes(
                changed_files=changed_files,
                fallback=fallback,
                event_name="pull_request",
                is_draft=False,
            )
            self.assertEqual(res, {"code": True, "core": False, "cross_platform": False})

    def test_non_merge_pr_commit_diff(self):
        """Test PR branch diff when HEAD is not a merge commit."""
        with tempfile.TemporaryDirectory() as td:
            self._run_git(td, "init", "-b", "master")
            self._run_git(td, "config", "user.name", "CI Tester")
            self._run_git(td, "config", "user.email", "ci@example.com")
            self._run_git(td, "config", "commit.gpgsign", "false")

            base_file = Path(td) / "base.txt"
            base_file.write_text("initial\n")
            self._run_git(td, "add", "base.txt")
            self._run_git(td, "commit", "-m", "C0")
            c0_sha = self._run_git(td, "rev-parse", "HEAD")

            self._run_git(td, "checkout", "-b", "feature")
            doc_file = Path(td) / "README.md"
            doc_file.write_text("new readme\n")
            self._run_git(td, "add", "README.md")
            self._run_git(td, "commit", "-m", "C1")

            changed_files, fallback = ci_changes.get_changed_files(
                event_name="pull_request",
                base_sha=c0_sha,
                cwd=td,
            )
            self.assertFalse(fallback)
            self.assertEqual(changed_files, ["README.md"])

    def test_failsafe_fallback_on_git_failure(self):
        """Test fail-safe fallback when git fails or repository is invalid."""
        with tempfile.TemporaryDirectory() as non_repo:
            # 1. Non-repo PR fallback (ready)
            files, fallback = ci_changes.get_changed_files(
                event_name="pull_request",
                base_sha="invalid-sha",
                cwd=non_repo,
            )
            self.assertTrue(fallback)
            self.assertEqual(files, [])
            res_ready = ci_changes.classify_changes(
                changed_files=files,
                fallback=fallback,
                event_name="pull_request",
                is_draft=False,
            )
            self.assertEqual(res_ready, {"code": True, "core": True, "cross_platform": True})

            # 2. Non-repo PR fallback (draft): cross_platform MUST be false
            res_draft = ci_changes.classify_changes(
                changed_files=files,
                fallback=fallback,
                event_name="pull_request",
                is_draft=True,
            )
            self.assertEqual(res_draft, {"code": True, "core": True, "cross_platform": False})

            # 3. Non-repo push fallback: all true
            files_push, fallback_push = ci_changes.get_changed_files(
                event_name="push",
                before_sha="invalid-sha",
                cwd=non_repo,
            )
            self.assertTrue(fallback_push)
            res_push = ci_changes.classify_changes(
                changed_files=files_push,
                fallback=fallback_push,
                event_name="push",
                is_draft=False,
            )
            self.assertEqual(res_push, {"code": True, "core": True, "cross_platform": True})

    def test_cli_execution_and_stdout_format(self):
        """Test CLI execution produces exactly 3 lines of key=value on stdout."""
        script_path = SCRIPTS_DIR / "ci_changes.py"

        # Test workflow_dispatch via CLI
        env = os.environ.copy()
        env["GITHUB_EVENT_NAME"] = "workflow_dispatch"
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(
            proc.stdout.splitlines(),
            ["code=true", "core=true", "cross_platform=true"],
        )
        self.assertIn("[ci_changes]", proc.stderr)

        # Test Draft PR with fail-safe via CLI
        env = os.environ.copy()
        env["GITHUB_EVENT_NAME"] = "pull_request"
        env["PR_DRAFT"] = "TRUE"
        env["GITHUB_BASE_SHA"] = ""
        proc_draft = subprocess.run(
            [sys.executable, str(script_path)],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(
            proc_draft.stdout.splitlines(),
            ["code=true", "core=true", "cross_platform=false"],
        )


if __name__ == "__main__":
    unittest.main()
