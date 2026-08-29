#!/usr/bin/env python3
"""Validate the tracked and proposed publication files without VCS metadata."""

from __future__ import annotations

import shutil
import subprocess
import importlib.util
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "publication_check", ROOT / "scripts/publication-check.py"
)
assert SPEC and SPEC.loader
publication_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publication_check
SPEC.loader.exec_module(publication_check)


def main() -> None:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    relative_paths = [Path(raw.decode()) for raw in listed.split(b"\0") if raw]
    with tempfile.TemporaryDirectory(prefix="public-contract-") as directory:
        candidate = Path(directory)
        for relative in relative_paths:
            source = ROOT / relative
            target = candidate / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target, follow_symlinks=False)
        findings = publication_check.check_candidate(candidate)
    if findings:
        for finding in findings:
            print(f"{finding.rule_id} {finding.relative_path}:{finding.line}")
        raise SystemExit(f"publication worktree check failed: {len(findings)} finding(s)")
    print("Publication worktree check passed: 0 findings")


if __name__ == "__main__":
    main()
