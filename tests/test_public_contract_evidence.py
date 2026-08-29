from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/public_contract_evidence.py"


def load_module():
    spec = importlib.util.spec_from_file_location("public_contract_evidence", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


evidence = load_module()


class PublicContractEvidenceTests(unittest.TestCase):
    def test_evidence_surface_is_deterministic_and_provider_neutral(self):
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "cloud-build.json"
            second = Path(directory) / "github-actions.json"
            for output in (first, second):
                subprocess.run(
                    [sys.executable, str(SCRIPT), "--source-sha", head, "--output", str(output)],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            value = json.loads(first.read_text())
            self.assertEqual(
                set(value),
                {"schema_version", "source_sha", "contract_version", "profile_version", "adapter", "commands", "artifacts"},
            )
            self.assertNotIn("provider", first.read_text())
            self.assertNotIn("timestamp", first.read_text())
            self.assertEqual(value["adapter"]["sha256"], evidence.sha256(ROOT / value["adapter"]["ref"]))

    def test_stale_source_sha_fails_closed(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--source-sha", "0" * 40, "--output", "ignored.json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((ROOT / "ignored.json").exists())


if __name__ == "__main__":
    unittest.main()
