"""Deterministic self-reproduction coverage for the public export contract."""

from __future__ import annotations

import hashlib
import importlib.util
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "publication" / "export-manifest.yaml"

FROZEN_SECURITY = {
    "scripts/publication-check.py": (
        "9397ea433e79cb34b1889273f32a7896c45d3560c21f5eabcb13c5bef42e8f16",
        0o755,
    ),
    "scripts/publication-export.py": (
        "da5b1edf037707895babb3298a5df714337bd1edaf51cfa978294f8f192c8ce8",
        0o755,
    ),
    "tests/test_publication_yaml.py": (
        "ceda819d386aceee9250b7ae9d2fdf885b01880f8b166e1a8f72d9260e7f308d",
        0o644,
    ),
}

EXECUTABLE_HEAD_PATHS = {
    "scripts/public_contract_evidence.py",
    "scripts/publication-check.py",
    "scripts/publication-export.py",
    "scripts/publication_worktree_check.py",
    "scripts/resolve-registry.py",
    "scripts/verify-public-contract.sh",
}

ADDITIVE_PATHS = {
    "publication/export-manifest.yaml",
    "tests/test_publication_export_generation.py",
    "tests/test_publication_yaml.py",
}


def load_exporter():
    spec = importlib.util.spec_from_file_location(
        "generation_exporter", ROOT / "scripts" / "publication-export.py"
    )
    if spec is None or spec.loader is None:
        raise AssertionError("publication exporter could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


exporter = load_exporter()


def run_git(*args: str, cwd: Path = ROOT) -> str:
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.rstrip("\n")


def head_inventory() -> dict[str, tuple[str, str]]:
    inventory: dict[str, tuple[str, str]] = {}
    for line in run_git("ls-tree", "-r", "--full-tree", "HEAD").splitlines():
        metadata, relative = line.split("\t", 1)
        mode, kind, object_id = metadata.split()
        if kind != "blob":
            raise AssertionError(f"HEAD path is not a blob: {relative}")
        inventory[relative] = (mode, object_id)
    return inventory


HEAD_INVENTORY = head_inventory()
HEAD_PATHS = set(HEAD_INVENTORY)
EXPECTED_PATHS = HEAD_PATHS | ADDITIVE_PATHS


def file_mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def source_status() -> tuple[tuple[str, str], ...]:
    entries: list[tuple[str, str]] = []
    for line in run_git(
        "status", "--porcelain=v1", "--untracked-files=all"
    ).splitlines():
        if len(line) < 4:
            raise AssertionError(f"malformed git status line: {line!r}")
        entries.append((line[:2], line[3:]))
    return tuple(sorted(entries))


EXPECTED_UNCOMMITTED_STATUS = tuple(
    sorted(
        {
            (" M", "scripts/publication-check.py"),
            (" M", "scripts/publication-export.py"),
            ("??", "publication/export-manifest.yaml"),
            ("??", "tests/test_publication_export_generation.py"),
            ("??", "tests/test_publication_yaml.py"),
        }
    )
)
INITIAL_SOURCE_STATUS = source_status()
if INITIAL_SOURCE_STATUS not in {(), EXPECTED_UNCOMMITTED_STATUS}:
    raise AssertionError(
        "source status must be either the approved candidate state or clean"
    )


def source_snapshot() -> dict[str, tuple[int, bytes]]:
    snapshot: dict[str, tuple[int, bytes]] = {}
    for relative in sorted(EXPECTED_PATHS):
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise AssertionError(f"source path is not a regular file: {relative}")
        snapshot[relative] = (file_mode(path), path.read_bytes())
    return snapshot


def tree_snapshot(root: Path) -> dict[str, tuple[int, bytes]]:
    snapshot: dict[str, tuple[int, bytes]] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if path.is_symlink():
            raise AssertionError(f"candidate contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise AssertionError(f"candidate contains a non-file: {relative}")
        snapshot[relative] = (file_mode(path), path.read_bytes())
    return snapshot


def tree_digest(snapshot: dict[str, tuple[int, bytes]]) -> str:
    digest = hashlib.sha256()
    for relative in sorted(snapshot):
        mode, content = snapshot[relative]
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{mode:o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def git_identity(root: Path) -> dict[str, str]:
    return {
        "root": run_git("rev-parse", "HEAD", cwd=root),
        "tree": run_git("rev-parse", "HEAD^{tree}", cwd=root),
        "branch": run_git("symbolic-ref", "--short", "HEAD", cwd=root),
        "count": run_git("rev-list", "--all", "--count", cwd=root),
        "remote": run_git("remote", cwd=root),
        "status": run_git("status", "--porcelain", cwd=root),
    }


def git_commit_bytes(root: Path) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), "cat-file", "commit", "HEAD"],
        check=True,
        capture_output=True,
    )
    return result.stdout


class PublicationExportGenerationTests(unittest.TestCase):
    def assert_source_unchanged(self, before: dict[str, tuple[int, bytes]]) -> None:
        self.assertEqual(source_status(), INITIAL_SOURCE_STATUS)
        after = source_snapshot()
        self.assertEqual(set(after), EXPECTED_PATHS)
        self.assertEqual(after, before)

        for relative in HEAD_PATHS - set(FROZEN_SECURITY):
            self.assertEqual(after[relative], before[relative], relative)
            expected_mode = 0o755 if relative in EXECUTABLE_HEAD_PATHS else 0o644
            self.assertEqual(after[relative][0], expected_mode, relative)

        for relative, (expected_hash, expected_mode) in FROZEN_SECURITY.items():
            actual_hash = hashlib.sha256(after[relative][1]).hexdigest()
            self.assertEqual(actual_hash, expected_hash, relative)
            self.assertEqual(after[relative][0], expected_mode, relative)
            self.assertEqual(after[relative], before[relative], relative)

    def assert_manifest_contract(self) -> None:
        manifest = exporter.load_manifest(MANIFEST)
        entries = manifest["files"]
        destinations = [item["destination"] for item in entries]
        self.assertEqual(len(entries), 35)
        self.assertEqual(destinations, sorted(destinations))
        self.assertEqual(set(destinations), EXPECTED_PATHS)
        self.assertEqual(
            [item["source"] for item in entries], destinations
        )
        for item in entries:
            self.assertEqual(
                item["executable"], item["destination"] in EXECUTABLE_HEAD_PATHS
            )

        self.assertEqual(
            manifest["history"],
            {
                "mode": "new-repository",
                "commit_date": "2026-01-01T00:00:00+0000",
                "commit_message": "🔒️ security(publication): reproduce public engine contract",
            },
        )
        manifest_text = MANIFEST.read_text(encoding="utf-8")
        for forbidden in (
            "Soku-JINSEOK",
            "control-plane",
            "c661506",
            "65470c6",
            "publication/fixtures",
        ):
            self.assertNotIn(forbidden, manifest_text)

    def assert_candidate(self, candidate: Path, expected: dict[str, tuple[int, bytes]]) -> dict[str, str]:
        actual = tree_snapshot(candidate)
        self.assertEqual(actual, expected)
        self.assertEqual(tree_digest(actual), tree_digest(expected))
        identity = git_identity(candidate)
        self.assertEqual(identity["branch"], "main")
        self.assertEqual(identity["count"], "1")
        self.assertEqual(identity["remote"], "")
        self.assertEqual(identity["status"], "")
        self.assertEqual(identity["root"], run_git("rev-parse", "HEAD", cwd=candidate))
        self.assertNotIn(b"\ngpgsig ", git_commit_bytes(candidate))
        return identity

    def test_public_tree_reproduces_with_default_manifest(self):
        before = source_snapshot()
        self.assertEqual(HEAD_PATHS | ADDITIVE_PATHS, EXPECTED_PATHS)
        self.assert_manifest_contract()

        with tempfile.TemporaryDirectory(prefix="public-engine-generation-") as raw:
            temporary = Path(raw)
            denylist = temporary / "denylist.yaml"
            denylist.write_text("schema_version: 1\nliterals: []\n", encoding="utf-8")
            first = temporary / "candidate-one"
            second = temporary / "candidate-two"
            closure = temporary / "candidate-closure"

            first_result = exporter.export_candidate(
                ROOT, first, MANIFEST, denylist, initialize_history=True,
                require_denylist=True,
            )
            second_result = exporter.export_candidate(
                ROOT, second, MANIFEST, denylist, initialize_history=True,
                require_denylist=True,
            )
            expected = source_snapshot()
            self.assertEqual(first_result.file_count, 35)
            self.assertEqual(second_result.file_count, 35)
            self.assertTrue(first_result.fresh_clone_verified)
            self.assertTrue(second_result.fresh_clone_verified)
            self.assertEqual(first_result.manifest_sha256, second_result.manifest_sha256)
            self.assertEqual(first_result.candidate_sha256, second_result.candidate_sha256)

            first_identity = self.assert_candidate(first, expected)
            second_identity = self.assert_candidate(second, expected)
            self.assertEqual(first_identity, second_identity)
            self.assertEqual(tree_snapshot(first), tree_snapshot(second))
            self.assertEqual(tree_digest(tree_snapshot(first)), tree_digest(expected))

            clone_count, clone_digest = exporter.verify_fresh_clone(first, denylist)
            self.assertEqual(clone_count, 35)
            self.assertEqual(clone_digest, first_result.candidate_sha256)

            closure_result = exporter.export_candidate(
                first,
                closure,
                first / "publication" / "export-manifest.yaml",
                denylist,
                initialize_history=True,
                require_denylist=True,
            )
            self.assertEqual(closure_result.file_count, 35)
            self.assertTrue(closure_result.fresh_clone_verified)
            self.assertEqual(closure_result.candidate_sha256, first_result.candidate_sha256)
            self.assertEqual(tree_snapshot(closure), tree_snapshot(first))
            self.assertEqual(git_identity(closure), first_identity)

            self.assert_source_unchanged(before)

        self.assertFalse(temporary.exists())
        self.assert_source_unchanged(before)


if __name__ == "__main__":
    unittest.main()
