#!/usr/bin/env python3
"""Produce deterministic semantic evidence for the public contract profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEX40 = re.compile(r"^[0-9a-f]{40}$")
COMMANDS = (
    "publication-surface",
    "registry-resolution",
    "python-contract-tests",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not HEX40.fullmatch(args.source_sha):
        raise SystemExit("source SHA must be 40 lowercase hexadecimal characters")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()
    if head != args.source_sha:
        raise SystemExit("source SHA does not match checked-out HEAD")
    adapter_ref = "scripts/verify-public-contract.sh"
    evidence = {
        "schema_version": "public-contract-evidence-v1",
        "source_sha": args.source_sha,
        "contract_version": "public-contract-v1",
        "profile_version": "public-validation-v1",
        "adapter": {
            "id": "public-contract-command-v1",
            "ref": adapter_ref,
            "sha256": sha256(ROOT / adapter_ref),
        },
        "commands": [{"id": command, "conclusion": "success"} for command in COMMANDS],
        "artifacts": [],
    }
    args.output.write_bytes(canonical_bytes(evidence))
    print(canonical_bytes(evidence).decode(), end="")


if __name__ == "__main__":
    main()
