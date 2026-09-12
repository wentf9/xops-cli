#!/usr/bin/env python3
"""Test the host driver's success criteria without starting a VM."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import verify_powercut


class DriverTests(unittest.TestCase):
    def run_phase(self, script, phase, filesystem="ext4"):
        real_popen = subprocess.Popen

        def fixture(_args, **kwargs):
            self.assertIn(f"xops_filesystem={filesystem}", _args[_args.index("-append") + 1])
            return real_popen([sys.executable, "-c", script], **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(verify_powercut.subprocess, "Popen", side_effect=fixture):
                verify_powercut.boot(root / "kernel", root / "initrd", root / "disk",
                                     root / "log", phase, filesystem=filesystem)
            self.assertTrue((root / "log").is_file())

    def test_success_requires_pass_marker(self):
        self.run_phase("print('XOPS_VM_PHASE_PASSED')", "verify")
        with self.assertRaisesRegex(RuntimeError, "verification failed"):
            self.run_phase("print('unverified')", "verify")

    def test_failure_exit_overrides_pass_marker(self):
        with self.assertRaisesRegex(RuntimeError, "verification failed"):
            self.run_phase("print('XOPS_VM_PHASE_PASSED'); raise SystemExit(1)", "verify")

    def test_missing_cut_hook_fails(self):
        with self.assertRaisesRegex(RuntimeError, "requested power-cut hook"):
            self.run_phase("print('XOPS_VM_PHASE_PASSED')", "cut")

    def test_cut_kills_and_reaps_own_child(self):
        self.run_phase("import time; print('XOPS_POWER_CUT_READY', flush=True); time.sleep(5)", "cut")

    def test_filesystem_reaches_guest(self):
        for filesystem in ("ext4", "xfs", "btrfs"):
            with self.subTest(filesystem=filesystem):
                self.run_phase("print('XOPS_VM_PHASE_PASSED')", "verify", filesystem)


if __name__ == "__main__":
    unittest.main(verbosity=2)
