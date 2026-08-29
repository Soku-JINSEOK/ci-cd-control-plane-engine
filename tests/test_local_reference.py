from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("local_reference", ROOT / "scripts/local_reference.py")
assert SPEC and SPEC.loader
lr = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lr
SPEC.loader.exec_module(lr)


def native_platform():
    return {"os": "darwin", "architecture": "arm64", "shell": "none"}


class LocalReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Synthetic Test"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "test@example.invalid"], check=True)
        (self.root / "verify.py").write_text("from pathlib import Path\nPath('result.txt').write_text('ok\\n', encoding='utf-8')\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "verify.py"], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture"], check=True)
        self.sha = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        self.adapter = json.loads((ROOT / "execution/adapters/local-reference-v1.json").read_text())
        self.req = {
            "schema_version": "execution-requirements-v1", "pipeline_template_id": "synthetic-pipeline-v1", "profile_id": "portable-test", "source_sha": self.sha,
            "contract_sha256": "a" * 64, "platform": native_platform(), "network": "public", "capabilities": ["process-execution"],
            "commands": [{"id": "verify-source", "argv": [sys.executable, "verify.py"], "cwd": ".", "timeout_seconds": 10}],
            "artifacts": [{"id": "verification-record", "path": "result.txt", "sha256": hashlib.sha256(b"ok\n").hexdigest()}],
        }
        self.reviewed = lr.canonical_bytes({"pipeline_template_id": self.req["pipeline_template_id"], "profile_id": self.req["profile_id"], "commands": self.req["commands"], "artifacts": self.req["artifacts"]})
        self.req["contract_sha256"] = hashlib.sha256(self.reviewed).hexdigest()
        self.expected = lr.canonical_sha256(self.req)

    def tearDown(self):
        self.temp.cleanup()

    def run_it(self, req=None, *, rebind=False, adapter=None, **kwargs):
        selected = req or self.req
        reviewed = self.reviewed
        expected = self.expected
        if rebind:
            reviewed = lr.canonical_bytes({"pipeline_template_id": selected["pipeline_template_id"], "profile_id": selected["profile_id"], "commands": selected["commands"], "artifacts": selected["artifacts"]})
            selected["contract_sha256"] = hashlib.sha256(reviewed).hexdigest()
            expected = lr.canonical_sha256(selected)
        with mock.patch.object(lr.platform, "system", return_value="Darwin"), mock.patch.object(
            lr.platform, "machine", return_value="arm64"
        ):
            return lr.execute(selected, adapter or self.adapter, self.root, reviewed_contract=reviewed, expected_requirements_sha256=expected, started_at="2026-08-28T00:00:00Z", ended_at="2026-08-28T00:00:01Z", **kwargs)

    def test_positive_and_deterministic_evidence(self):
        first = self.run_it()
        (self.root / "result.txt").unlink()
        second = self.run_it()
        self.assertEqual("success", first["conclusion"])
        self.assertEqual(lr.canonical_bytes(first), lr.canonical_bytes(second))
        self.assertEqual(lr.canonical_sha256(first), lr.canonical_sha256(second))
        self.assertNotIn("stdout", first)
        self.assertNotIn("stderr", first)
        lr.validate_evidence(first, self.req, self.adapter)

    def test_success_evidence_rejects_missing_reordered_and_stale_bindings(self):
        evidence = self.run_it()
        for mutation in ("missing", "reordered", "stale", "artifacts", "executor", "malformed", "extra"):
            changed = copy.deepcopy(evidence)
            if mutation == "missing": changed["commands"] = []
            elif mutation == "reordered": changed["commands"] = list(reversed(changed["commands"] + [{"id": "extra-step", "conclusion": "success"}]))
            elif mutation == "stale": changed["source_sha"] = "0" * 40
            elif mutation == "artifacts": changed["artifacts"] = []
            elif mutation == "executor": changed["executor"] = {}
            elif mutation == "malformed": changed["commands"][0]["conclusion"] = "skipped"
            else: changed["commands"][0]["extra"] = True
            with self.assertRaises(lr.ContractError): lr.validate_evidence(changed, self.req, self.adapter)

    def test_non_success_evidence_and_timestamps_fail_closed(self):
        success = self.run_it()
        invalid = []
        failure_empty = copy.deepcopy(success); failure_empty.update(conclusion="failure", commands=[], artifacts=[]); invalid.append(failure_empty)
        failure_wrong = copy.deepcopy(success); failure_wrong.update(conclusion="failure", commands=[{"id":"other-step", "conclusion":"failure"}], artifacts=[]); invalid.append(failure_wrong)
        partial_wrong = copy.deepcopy(success); partial_wrong.update(conclusion="partial", commands=[{"id":"other-step", "conclusion":"success"}], artifacts=[]); invalid.append(partial_wrong)
        superseded_claim = copy.deepcopy(success); superseded_claim["conclusion"] = "superseded"; invalid.append(superseded_claim)
        date_only = copy.deepcopy(success); date_only["started_at"] = "2026-08-28"; invalid.append(date_only)
        naive = copy.deepcopy(success); naive["started_at"] = "2026-08-28T00:00:00"; invalid.append(naive)
        reversed_time = copy.deepcopy(success); reversed_time["started_at"] = "2026-08-28T00:00:02Z"; invalid.append(reversed_time)
        duplicate_caps = copy.deepcopy(success); duplicate_caps["executor"]["capabilities"] *= 2; invalid.append(duplicate_caps)
        for evidence in invalid:
            with self.assertRaises(lr.ContractError): lr.validate_evidence(evidence, self.req, self.adapter)

    def test_stale_sha_and_dirty_tree_fail_closed(self):
        stale = copy.deepcopy(self.req); stale["source_sha"] = "0" * 40
        with self.assertRaisesRegex(lr.ContractError, "SHA mismatch"): self.run_it(stale, rebind=True)
        (self.root / "dirty.txt").write_text("dirty")
        with self.assertRaisesRegex(lr.ContractError, "dirty"): self.run_it()

    def test_command_contract_rejects_string_wrapper_and_changes(self):
        for argv in ("python verify.py", ["sh", "-c", "python verify.py"]):
            changed = copy.deepcopy(self.req); changed["commands"][0]["argv"] = argv
            with self.assertRaises(lr.ContractError): lr.validate_requirements(changed, self.root)
        reviewed = copy.deepcopy(self.req["commands"])
        for commands in ([], self.req["commands"] * 2, list(reversed(self.req["commands"] + [{"id":"extra-step", "argv":["true"], "cwd":".", "timeout_seconds":1}]))):
            changed = copy.deepcopy(self.req); changed["commands"] = commands
            with self.assertRaises(lr.ContractError):
                self.run_it(changed)
        rewritten = copy.deepcopy(self.req); rewritten["commands"][0]["argv"] = [sys.executable, "-V"]
        with self.assertRaises(lr.ContractError): self.run_it(rewritten)

    def test_independent_hashes_and_synthetic_adapters_fail_before_execution(self):
        wrong_contract = copy.deepcopy(self.req); wrong_contract["contract_sha256"] = "0" * 64
        with self.assertRaisesRegex(lr.ContractError, "requirements expected hash"): self.run_it(wrong_contract)
        with self.assertRaisesRegex(lr.ContractError, "reviewed contract hash"): lr.execute(self.req, self.adapter, self.root, reviewed_contract=b"{}\n", expected_requirements_sha256=self.expected, started_at="2026-08-28T00:00:00Z", ended_at="2026-08-28T00:00:01Z")
        bad_adapter = copy.deepcopy(self.adapter); bad_adapter["implementation_sha256"] = "0" * 64
        with self.assertRaisesRegex(lr.ContractError, "implementation hash"): self.run_it(adapter=bad_adapter)
        for name in ("gcp-cloud-build-v1.synthetic.json", "jenkins-hybrid-v1.synthetic.json"):
            adapter = json.loads((ROOT / "execution/adapters" / name).read_text())
            self.assertEqual("unsupported", self.run_it(adapter=adapter)["conclusion"])

    def test_paths_reject_absolute_traversal_home_backslash_and_symlink(self):
        outside = self.root.parent / "outside"
        outside.mkdir(exist_ok=True)
        (self.root / "escape").symlink_to(outside, target_is_directory=True)
        for value in ("/tmp", "../outside", "~/x", "a\\b", "escape"):
            changed = copy.deepcopy(self.req); changed["commands"][0]["cwd"] = value
            with self.assertRaises(lr.ContractError): lr.validate_requirements(changed, self.root)

    def test_unsupported_dimensions_fail_closed(self):
        cases = (("platform", "os", "windows" if native_platform()["os"] != "windows" else "linux"), ("platform", "architecture", "amd64" if native_platform()["architecture"] != "amd64" else "arm64"))
        for section, key, value in cases:
            changed = copy.deepcopy(self.req); changed[section][key] = value
            self.assertEqual("unsupported", self.run_it(changed, rebind=True)["conclusion"])
        for key, value in (("network", "none"), ("capabilities", ["licensed-tool"])):
            changed = copy.deepcopy(self.req); changed[key] = value
            self.assertEqual("unsupported", self.run_it(changed, rebind=True)["conclusion"])
        changed = copy.deepcopy(self.req); changed["platform"]["shell"] = "bash"
        with self.assertRaises(lr.ContractError): lr.validate_requirements(changed, self.root)

    def test_failure_timeout_cancelled_superseded_and_partial(self):
        failed = copy.deepcopy(self.req); failed["commands"][0]["argv"] = [sys.executable, "-c", "raise SystemExit(3)"]; failed["artifacts"] = []
        self.assertEqual("failure", self.run_it(failed, rebind=True)["conclusion"])
        timeout_script = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',\"import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(1.4); open('timeout-descendant-lived','w').write('bad')\"]); time.sleep(5)"
        timeout = copy.deepcopy(self.req); timeout["commands"][0]["argv"] = [sys.executable, "-c", timeout_script]; timeout["commands"][0]["timeout_seconds"] = 1; timeout["artifacts"] = []
        self.assertEqual("timeout", self.run_it(timeout, rebind=True)["conclusion"])
        time.sleep(0.6)
        self.assertFalse((self.root / "timeout-descendant-lived").exists())
        self.assertEqual("cancelled", self.run_it(cancelled=lambda: True)["conclusion"])
        self.assertEqual("superseded", self.run_it(superseded=True)["conclusion"])
        partial = copy.deepcopy(self.req); partial["artifacts"][0]["sha256"] = "0" * 64
        self.assertEqual("partial", self.run_it(partial, rebind=True)["conclusion"])
        for conclusion in ("failure", "timeout", "cancelled", "superseded", "unsupported", "partial"):
            self.assertNotEqual("success", conclusion)

    def test_mid_process_cancellation_terminates_descendants(self):
        script = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',\"import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(.4); open('descendant-lived','w').write('bad')\"]); time.sleep(5)"
        request = copy.deepcopy(self.req)
        request["commands"][0]["argv"] = [sys.executable, "-c", script]
        request["artifacts"] = []
        started = time.monotonic()
        evidence = self.run_it(request, rebind=True, cancelled=lambda: time.monotonic() - started > 0.1)
        self.assertEqual("cancelled", evidence["conclusion"])
        time.sleep(0.6)
        self.assertFalse((self.root / "descendant-lived").exists())

    def test_adapter_fixtures_and_delivery_boundary(self):
        for path in sorted((ROOT / "execution/adapters").glob("*.json")):
            adapter = json.loads(path.read_text())
            lr.validate_adapter(adapter)
            self.assertEqual("none", adapter["delivery_authority"])
        deprecated = copy.deepcopy(self.adapter); deprecated["lifecycle"] = "deprecated"
        with self.assertRaises(lr.UnsupportedError): lr.check_capabilities(self.req, deprecated)
        self.assertEqual(
            hashlib.sha256((ROOT / "scripts/local_reference.py").read_bytes()).hexdigest(),
            self.adapter["implementation_sha256"],
        )

    def test_artifact_symlink_escape_is_rejected(self):
        outside = self.root.parent / "secret-result"
        outside.write_text("ok\n")
        (self.root / "result.txt").symlink_to(outside)
        with self.assertRaises(lr.ContractError): self.run_it()


if __name__ == "__main__": unittest.main()
