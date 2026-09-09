"""Synthetic regression coverage for ambiguous publication YAML inputs."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import traceback
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKER = "SYNTHETIC_AMBIGUITY_SENTINEL"


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


checker = load_script("yaml_regression_checker", "publication-check.py")
exporter = load_script("yaml_regression_exporter", "publication-export.py")

DENYLIST = (
    "schema_version: 1\nliterals:\n"
    "  - rule_id: private.synthetic\n"
    f"    value: {MARKER}\n"
    "    case_sensitive: true\n"
)
MANIFEST = (
    "schema_version: 1\ncontract: public-engine-export-v1\n"
    "history:\n  mode: new-repository\n"
    "  commit_date: '2026-01-01T00:00:00+0000'\n"
    "  commit_message: synthetic\n"
    "files:\n  - source: sample.txt\n    destination: sample.txt\n"
)


def denylist_cases():
    yield "root-last-empty", DENYLIST + "literals: []\n"
    yield "root-first-empty", "literals: []\n" + DENYLIST
    for first, second in ((MARKER, "harmless"), ("harmless", MARKER)):
        yield "nested-" + first, DENYLIST.replace(
            f"    value: {MARKER}\n", f"    value: {first}\n    value: {second}\n"
        )
    yield "merge-collision", DENYLIST.replace(
        "  - rule_id: private.synthetic\n",
        f"  - <<: {{value: {MARKER}}}\n    rule_id: private.synthetic\n",
    )
    yield "repeated-merge", (
        "schema_version: 1\nliterals:\n"
        "  - <<: {rule_id: private.synthetic}\n"
        f"    <<: {{value: {MARKER}, case_sensitive: true}}\n"
    )
    yield "nested-repeated-merge", (
        "schema_version: 1\nliterals:\n  - <<: &item\n"
        "      <<: {rule_id: private.synthetic}\n"
        f"      <<: {{value: {MARKER}, case_sensitive: true}}\n"
    )
    yield "unhashable", f"? [{MARKER}]\n: ignored\n"


def manifest_cases():
    yield "root", MANIFEST + "schema_version: 1\n"
    for first, second in ((MARKER, "harmless"), ("harmless", MARKER)):
        yield "history-" + first, MANIFEST.replace(
            "  commit_message: synthetic\n",
            f"  commit_message: {first}\n  commit_message: {second}\n",
        )
        yield "file-" + first, MANIFEST.replace(
            "    destination: sample.txt\n",
            f"    destination: {first}\n    destination: {second}\n",
        )
    yield "merge-collision", MANIFEST.replace(
        "  commit_message: synthetic\n",
        f"  <<: {{commit_message: {MARKER}}}\n  commit_message: synthetic\n",
    )
    yield "repeated-merge", MANIFEST.replace(
        "  mode: new-repository\n",
        "  <<: {mode: new-repository}\n"
        f"  <<: {{commit_message: {MARKER}}}\n",
    ).replace("  commit_message: synthetic\n", "")
    yield "nested-repeated-merge", MANIFEST.replace(
        "history:\n  mode: new-repository\n",
        "history:\n  <<: &history\n    <<: {mode: new-repository}\n"
        f"    <<: {{commit_message: {MARKER}}}\n",
    ).replace("  commit_message: synthetic\n", "")
    yield "unhashable", f"? [{MARKER}]\n: ignored\n"


class PublicationYamlTests(unittest.TestCase):
    def assert_redacted(self, value, root):
        self.assertNotIn(MARKER, value)
        self.assertNotIn(str(root), value)

    def assert_loader_rejects(self, loader, error_type, message, cases):
        for label, contents in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "input.yaml"
                path.write_text(contents, encoding="utf-8")
                with self.assertRaises(error_type) as caught:
                    loader(path)
                self.assertEqual(str(caught.exception), message)
                self.assert_redacted("".join(traceback.format_exception(caught.exception)), root)

    def test_denylist_loader_rejects_ambiguity(self):
        self.assert_loader_rejects(checker.load_denylist, checker.ContractError,
                                   "denylist could not be read", denylist_cases())

    def test_manifest_loader_rejects_ambiguity(self):
        self.assert_loader_rejects(exporter.load_manifest, exporter.ExportError,
                                   "export manifest could not be read", manifest_cases())

    def test_valid_synthetic_inputs_load_without_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            denylist = root / "denylist.yaml"
            denylist.write_text(DENYLIST, encoding="utf-8")
            self.assertEqual(checker.load_denylist(denylist)[0].value, MARKER)
            manifest = root / "manifest.yaml"
            manifest.write_text(MANIFEST, encoding="utf-8")
            self.assertEqual(exporter.load_manifest(manifest)["files"][0]["source"], "sample.txt")

    def test_denylist_cli_rejects_without_disclosure(self):
        for label, contents in denylist_cases():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                candidate = root / "synthetic"
                candidate.mkdir()
                (candidate / "sample.txt").write_text(MARKER, encoding="utf-8")
                denylist = root / "denylist.yaml"
                denylist.write_text(contents, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/publication-check.py"),
                     str(candidate), "--denylist", str(denylist), "--require-denylist"],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("denylist could not be read", result.stderr)
                self.assert_redacted(result.stdout + result.stderr, root)

    def test_manifest_cli_and_api_reject_before_destination(self):
        for label, contents in manifest_cases():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "source"
                source.mkdir()
                (source / "sample.txt").write_text("synthetic sample", encoding="utf-8")
                destination = root / "destination"
                manifest = root / "manifest.yaml"
                manifest.write_text(contents, encoding="utf-8")
                denylist = root / "denylist.yaml"
                denylist.write_text(DENYLIST, encoding="utf-8")
                with self.assertRaises(exporter.ExportError) as caught:
                    exporter.export_candidate(source, destination, manifest, denylist,
                                              initialize_history=False)
                self.assertEqual(str(caught.exception), "export manifest could not be read")
                self.assert_redacted("".join(traceback.format_exception(caught.exception)), root)
                self.assertFalse(destination.exists())
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/publication-export.py"),
                     "export", str(source), str(destination), "--manifest", str(manifest),
                     "--denylist", str(denylist), "--no-init-git"],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("export manifest could not be read", result.stderr)
                self.assert_redacted(result.stdout + result.stderr, root)
                self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
