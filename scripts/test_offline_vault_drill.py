#!/usr/bin/env python3
"""Positive and fault-injected release-drill tests; all data is temporary/public."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("drill", Path(__file__).with_name("verify_offline_vault.py"))
drill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drill)


class RestoreDrillTests(unittest.TestCase):
    binary = None
    verifier = None

    def test_original_value_is_verified(self):
        with tempfile.TemporaryDirectory(prefix="xops-release-positive-") as directory:
            report = drill.run_drill(self.binary, Path(directory), self.verifier)
        self.assertTrue(report["original_reference_verified"])
        self.assertTrue(report["original_value_verified"])
        self.assertTrue(report["archive_unchanged"])

    def check_fault(self, fault):
        with tempfile.TemporaryDirectory(prefix="xops-release-negative-") as directory:
            root = Path(directory)
            wrapper = root / "candidate"
            # Faults occur after real restore succeeds, before the verifier reads.
            wrapper.write_text("""#!/usr/bin/python3
import os, subprocess, sys
from pathlib import Path
binary = BINARY
fault = FAULT
result = subprocess.run([binary, *sys.argv[1:]], stdout=subprocess.PIPE)
if result.returncode == 0 and sys.argv[1:4] == ['credential', 'store', 'restore']:
    root = Path(os.environ['XOPS_CONFIG_DIR']).parent
    assert root.name.startswith('xops-release-')
    items = list((root / 'restored' / 'revisions').glob('*/items/*.enc'))
    assert items
    for item in items:
        if fault == 'missing':
            item.unlink()
        else:
            data = bytearray(item.read_bytes())
            data[-1] ^= 1
            item.write_bytes(data)
sys.stdout.buffer.write(result.stdout)
sys.exit(result.returncode)
""".replace("BINARY", json.dumps(str(self.binary))).replace("FAULT", json.dumps(fault)))
            wrapper.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError, "original fixture reference/value verification failed"):
                drill.run_drill(wrapper, root, self.verifier)

    def test_missing_restored_item_fails(self):
        self.check_fault("missing")

    def test_tampered_restored_item_fails(self):
        self.check_fault("tampered")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--verifier", required=True, type=Path)
    args = parser.parse_args()
    RestoreDrillTests.binary = args.binary.resolve(strict=True)
    RestoreDrillTests.verifier = args.verifier.resolve(strict=True)
    unittest.main(argv=[sys.argv[0]], verbosity=2)
