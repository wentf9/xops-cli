"""Regression coverage for extraction boundaries, not core implementation tests."""

import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

import check_core


class CoreBoundaryTests(unittest.TestCase):
    def test_generated_client_remains_standalone_and_checks_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "core/mcp/transferclient/transfer.py"
            source.parent.mkdir(parents=True)
            source.write_text('#!/usr/bin/env python3\nprint("standalone")\n')
            check_core.sync_client_distribution(root, write=True)
            check_core.sync_client_distribution(root)
            detached = root / "detached.py"
            detached.write_bytes((root / "scripts/mcp/transfer.py").read_bytes())
            self.assertEqual(subprocess.check_output([sys.executable, str(detached)], text=True).strip(), "standalone")
            source.write_text(source.read_text() + "# changed\n")
            with self.assertRaisesRegex(ValueError, "differs"):
                check_core.sync_client_distribution(root)

    def test_rejects_transitive_and_test_only_cli_dependencies(self):
        module = "example.com/cli"
        packages = [
            {"ImportPath": module + "/core/ssh"},
            {"ImportPath": module + "/core"},
            {"ImportPath": module + "/core/ssh [" + module + "/core/ssh.test]"},
            {"ImportPath": module + "/pkg/config"},
            {"ImportPath": module + "/internal/terminal [" + module + "/core/ssh.test]"},
            {"ImportPath": "golang.org/x/crypto/ssh"},
        ]
        self.assertEqual(check_core.boundary_errors(packages, module), [
            module + "/internal/terminal", module + "/pkg/config",
        ])

    def test_reverse_server_dependency_is_rejected(self):
        self.assertEqual(check_core.boundary_errors([
            {"ImportPath": "github.com/wentf9/xops-mcp/internal/service"},
        ], "example.com/cli"), ["github.com/wentf9/xops-mcp/internal/service"])

    def test_unresolved_packages_cannot_pass(self):
        self.assertEqual(check_core.boundary_errors([
            {"ImportPath": "example.com/cli/core/ssh", "DepsErrors": [{"Err": "missing"}]},
        ], "example.com/cli"), ["unresolved package: example.com/cli/core/ssh"])

    def test_parses_concatenated_go_metadata(self):
        records = [{"ImportPath": "first"}, {"ImportPath": "second", "Error": {"Err": "x"}}]
        self.assertEqual(check_core.json_stream("\n".join(map(json.dumps, records))), records)

    def test_original_module_dependency_is_not_rewritten_away(self):
        with self.assertRaisesRegex(ValueError, "original module"):
            check_core.assert_no_original_module([
                {"ImportPath": "example.com/cli/pkg/config"},
            ], "example.com/cli")

    def test_extraction_copies_only_core_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            target = Path(directory) / "target"
            (root / "core/ssh/testdata").mkdir(parents=True)
            (root / "pkg").mkdir()
            target.mkdir()
            (root / "core/ssh/ssh.go").write_text('package ssh\nimport "example.com/cli/core/auth"\n')
            (root / "core/ssh/testdata/input").write_bytes(b"fixture")
            (root / "core/ssh/__pycache__").mkdir()
            (root / "core/ssh/__pycache__/stale.pyc").write_bytes(b"not portable")
            (root / "pkg/config.go").write_text("package config\n")
            for name in ("go.mod", "go.sum", "LICENSE"):
                (root / name).write_text(name)
            check_core.copy_core(root, target, "example.com/cli")
            self.assertFalse((target / "pkg").exists())
            self.assertFalse((target / "ssh/__pycache__").exists())
            self.assertEqual((target / "ssh/testdata/input").read_bytes(), b"fixture")
            self.assertIn(check_core.EXTRACTED_MODULE + "/auth", (target / "ssh/ssh.go").read_text())
            (root / "core/external").symlink_to(root / "pkg", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                check_core.copy_core(root, target, "example.com/cli")


if __name__ == "__main__":
    unittest.main()
