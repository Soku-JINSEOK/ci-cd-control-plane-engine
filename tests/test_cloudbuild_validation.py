from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class CloudBuildValidationTests(unittest.TestCase):
    def test_trigger_contract_preserves_region_comment_and_authority(self):
        contract = json.loads((ROOT / "cloudbuild/trigger-contract.json").read_text())
        self.assertEqual(
            contract,
            {
                "schema_version": "public-validation-trigger-contract-v1",
                "region": "asia-northeast1",
                "pull_request_comment_control": "COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY",
                "service_account_class": "validation-only",
                "delivery_authority": "none",
            },
        )

    def test_build_runs_only_the_repository_contract_with_exact_sha_guard(self):
        source = (ROOT / "cloudbuild/validation.yaml").read_text()
        config = yaml.safe_load(source)
        self.assertEqual(config["options"]["logging"], "CLOUD_LOGGING_ONLY")
        self.assertEqual(config["timeout"], "300s")
        ids = [step["id"] for step in config["steps"]]
        self.assertEqual(
            ids,
            ["verify-exact-source", "install-validation-dependency", "verify-public-contract"],
        )
        self.assertIn("actual != expected", config["steps"][0]["args"][1])
        self.assertEqual(config["steps"][2]["args"], ["scripts/verify-public-contract.sh"])
        for step in config["steps"]:
            self.assertRegex(step["name"], r"@sha256:[0-9a-f]{64}$")
        lowered = source.lower()
        for forbidden in ("deploy", "terraform apply", "docker push", "gcloud run", "artifact push"):
            self.assertNotIn(forbidden, lowered)


if __name__ == "__main__":
    unittest.main()
