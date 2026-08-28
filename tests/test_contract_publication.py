from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path); assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module); return module

lr = load("local_reference_publication_test", ROOT / "scripts/local_reference.py")
class ContractPublicationTests(unittest.TestCase):
    def test_all_json_is_canonicalizable_and_schemas_are_sidecars(self):
        for path in sorted((ROOT / "execution").rglob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(lr.canonical_bytes(value), lr.canonical_bytes(json.loads(lr.canonical_bytes(value))))
        self.assertTrue((ROOT / "registry/schema/pipeline.schema.json").exists())

    def test_portable_fixture_binds_literal_reviewed_contract(self):
        requirements = lr.load_json(ROOT / "execution/fixtures/portable-local-success.json")
        reviewed = (ROOT / "execution/fixtures/portable-reviewed-contract.json").read_bytes()
        lr.validate_requirements(requirements)
        lr.verify_reviewed_binding(requirements, reviewed, lr.canonical_sha256(requirements))

    def test_publication_rejects_private_and_sensitive_synthetic_data(self):
        protected_project = "PVT" + "SSF_lAHOCabcdef"
        protected_path = "/" + "Users/example/private"
        for value in ({"note": "synthetic-private-marker"}, {"note": protected_project}, {"stdout": "safe"}, {"note": protected_path}):
            with self.assertRaises(lr.ContractError):
                lr.validate_public_disclosure(value, ("synthetic-private-marker",))
        lr.validate_public_disclosure({"adapter_id": "local-reference-v1", "conclusion": "success"})


if __name__ == "__main__": unittest.main()
