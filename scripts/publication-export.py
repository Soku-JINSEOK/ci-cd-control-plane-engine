#!/usr/bin/env python3
"""Create and verify a deterministic, new-history public engine candidate."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "publication" / "export-manifest.yaml"
PUBLICATION_CHECK_PATH = ROOT / "scripts" / "publication-check.py"


class ExportError(ValueError):
    """Raised when the public export contract cannot be satisfied."""


@dataclass(frozen=True)
class ExportResult:
    """Redacted deterministic export evidence."""

    file_count: int
    candidate_sha256: str
    manifest_sha256: str
    history_initialized: bool
    fresh_clone_verified: bool


def _load_checker():
    """Load the hyphenated publication checker without making it a package."""
    spec = importlib.util.spec_from_file_location(
        "publication_check_for_export", PUBLICATION_CHECK_PATH
    )
    if spec is None or spec.loader is None:
        raise ExportError("publication checker could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _relative_path(value: Any, field: str) -> str:
    """Validate and normalize a manifest-relative POSIX path."""
    if not isinstance(value, str) or not value or "\\" in value:
        raise ExportError(f"manifest {field} path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ExportError(f"manifest {field} path is invalid")
    return path.as_posix()


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    """Load the strict, explicit export allowlist."""
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ExportError("export manifest could not be read") from error
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "contract",
        "history",
        "files",
    }:
        raise ExportError("export manifest root contract is invalid")
    if value["schema_version"] != 1 or value["contract"] != "public-engine-export-v1":
        raise ExportError("export manifest version or contract is invalid")
    history = value["history"]
    if not isinstance(history, dict) or set(history) != {
        "mode",
        "commit_date",
        "commit_message",
    }:
        raise ExportError("export manifest history contract is invalid")
    if (
        history["mode"] != "new-repository"
        or not isinstance(history["commit_date"], str)
        or not isinstance(history["commit_message"], str)
        or "\n" in history["commit_message"]
        or not history["commit_message"].strip()
    ):
        raise ExportError("export manifest history values are invalid")
    entries = value["files"]
    if not isinstance(entries, list) or not entries:
        raise ExportError("export manifest must contain at least one file")
    seen_sources: set[str] = set()
    seen_destinations: set[PurePosixPath] = set()
    normalized: list[dict[str, Any]] = []
    for item in entries:
        if not isinstance(item, dict) or set(item) - {
            "source",
            "destination",
            "executable",
        } or "source" not in item or "destination" not in item:
            raise ExportError("export manifest file entry is invalid")
        source = _relative_path(item["source"], "source")
        destination = _relative_path(item["destination"], "destination")
        executable = item.get("executable", False)
        if not isinstance(executable, bool):
            raise ExportError("export manifest executable flag is invalid")
        if destination == ".git" or destination.startswith(".git/"):
            raise ExportError("export manifest cannot write Git metadata")
        destination_path = PurePosixPath(destination)
        if source in seen_sources or destination_path in seen_destinations:
            raise ExportError("export manifest contains a duplicate path")
        if any(
            existing in destination_path.parents
            or destination_path in existing.parents
            for existing in seen_destinations
        ):
            raise ExportError("export manifest contains conflicting destination paths")
        seen_sources.add(source)
        seen_destinations.add(destination_path)
        normalized.append(
            {"source": source, "destination": destination, "executable": executable}
        )
    return {**value, "files": normalized}


def _inside(root: Path, other: Path) -> bool:
    """Return whether other is inside root after resolution."""
    try:
        other.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def resolve_manifest_source(source_root: Path, relative_source: str) -> Path:
    """Return a regular allowlisted source without following descendant symlinks.

    The caller must pass the already-canonicalized source root. Filesystem
    ancestors above that selected root are outside this manifest boundary.
    """
    normalized = _relative_path(relative_source, "source")
    current = source_root
    parts = PurePosixPath(normalized).parts
    for index, part in enumerate(parts):
        current /= part
        try:
            mode = current.lstat().st_mode
        except OSError as error:
            raise ExportError("allowlisted source is unavailable") from error
        if stat.S_ISLNK(mode):
            raise ExportError("allowlisted source contains a symlink")
        if index < len(parts) - 1 and not stat.S_ISDIR(mode):
            raise ExportError("allowlisted source is unavailable")
        if index == len(parts) - 1 and not stat.S_ISREG(mode):
            raise ExportError("allowlisted source is not a regular file")
    try:
        resolved = current.resolve(strict=True)
        relative = resolved.relative_to(source_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise ExportError("allowlisted source escapes the source root") from error
    if not relative.parts:
        raise ExportError("allowlisted source is not a regular file")
    return resolved


def _run_git(root: Path, *args: str, capture: bool = True) -> str:
    """Run a Git command without exposing command output."""
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=capture,
        text=capture,
    )
    return result.stdout.strip() if capture else ""


def candidate_digest(root: Path) -> tuple[int, str]:
    """Hash candidate-relative paths and bytes, excluding Git metadata."""
    digest = hashlib.sha256()
    paths: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        if path.is_symlink():
            raise ExportError("candidate contains a symlink")
        if not path.is_file():
            continue
        paths.append(path)
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    return len(paths), digest.hexdigest()


def _check(root: Path, denylist: Path) -> None:
    """Run the redacted publication checker and translate failures."""
    checker = _load_checker()
    try:
        findings = checker.check_candidate(
            root, denylist_path=denylist, require_denylist=True
        )
    except checker.ContractError as error:
        raise ExportError(f"publication input contract failed: {error}") from error
    if findings:
        first = findings[0]
        location = first.relative_path + (f":{first.line}" if first.line else "")
        raise ExportError(
            f"publication check failed: {first.rule_id} {location}"
        )


def _initialize_history(root: Path, history: dict[str, Any]) -> None:
    """Initialize exactly one new root commit with stable metadata."""
    try:
        _run_git(root, "init", "--quiet", "--initial-branch=main", capture=False)
        _run_git(root, "config", "user.name", "Public Engine Export", capture=False)
        _run_git(
            root,
            "config",
            "user.email",
            "public-engine@example.invalid",
            capture=False,
        )
        _run_git(root, "add", "--all", capture=False)
        environment = os.environ.copy()
        environment["GIT_AUTHOR_DATE"] = history["commit_date"]
        environment["GIT_COMMITTER_DATE"] = history["commit_date"]
        subprocess.run(
            ["git", "-C", str(root), "commit", "--quiet", "--no-gpg-sign", "-m", history["commit_message"]],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        if _run_git(root, "rev-list", "--all", "--count") != "1":
            raise ExportError("new candidate history must contain one commit")
        if _run_git(root, "remote"):
            raise ExportError("new candidate history must not contain a remote")
        if _run_git(root, "status", "--porcelain"):
            raise ExportError("new candidate worktree is not clean")
    except (OSError, subprocess.CalledProcessError) as error:
        raise ExportError("new candidate Git history could not be initialized") from error


def _extract_archive(archive: tarfile.TarFile, root: Path) -> None:
    """Extract a Git archive without permitting path traversal or symlinks."""
    for member in archive.getmembers():
        relative = PurePosixPath(member.name)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise ExportError("candidate archive contains an invalid path")
        target = root / Path(*relative.parts)
        if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
            raise ExportError("candidate archive contains a non-regular path")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            raise ExportError("candidate archive contains an unreadable file")
        target.write_bytes(source.read())


def verify_fresh_clone(candidate: Path, denylist: Path) -> tuple[int, str]:
    """Clone a new-history candidate and inspect its source archive."""
    if not candidate.is_dir() or not (candidate / ".git").is_dir():
        raise ExportError("fresh-clone verification requires a Git candidate")
    try:
        with tempfile.TemporaryDirectory(prefix="public-engine-clone-") as directory:
            clone = Path(directory) / "clone"
            subprocess.run(
                ["git", "clone", "--quiet", "--no-local", str(candidate), str(clone)],
                check=True,
                capture_output=True,
                text=True,
            )
            if _run_git(clone, "rev-list", "--all", "--count") != "1":
                raise ExportError("fresh clone does not contain new single-commit history")
            archive_bytes = subprocess.run(
                ["git", "-C", str(clone), "archive", "--format=tar", "HEAD"],
                check=True,
                capture_output=True,
            ).stdout
            source_root = Path(directory) / "source"
            source_root.mkdir()
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
                _extract_archive(archive, source_root)
            _check(source_root, denylist)
            return candidate_digest(source_root)
    except (OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        raise ExportError("fresh-clone verification failed") from error


def export_candidate(
    source: Path,
    destination: Path,
    manifest_path: Path = DEFAULT_MANIFEST,
    denylist: Path | None = None,
    initialize_history: bool = True,
    require_denylist: bool = True,
) -> ExportResult:
    """Export an allowlisted candidate outside source and optionally initialize it."""
    source = source.resolve()
    destination = destination.resolve()
    if not source.is_dir():
        raise ExportError("source root must be a directory")
    if destination.exists():
        raise ExportError("destination must not already exist")
    if _inside(source, destination) or _inside(destination, source):
        raise ExportError("source and destination must be separate trees")
    if require_denylist and denylist is None:
        raise ExportError("an external denylist is required")
    if denylist is None:
        raise ExportError("denylist path is required")
    denylist = denylist.resolve()
    if _inside(destination, denylist) or _inside(source, denylist):
        raise ExportError("denylist must remain outside source and candidate")

    manifest = load_manifest(manifest_path)
    manifest_bytes = manifest_path.read_bytes()
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}-", dir=destination.parent)
    )
    try:
        for item in manifest["files"]:
            source_path = resolve_manifest_source(source, item["source"])
            target = staging / item["destination"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source_path.read_bytes())
            target.chmod(0o755 if item["executable"] else 0o644)
        _check(staging, denylist)
        file_count, digest = candidate_digest(staging)
        fresh_clone_verified = False
        if initialize_history:
            _initialize_history(staging, manifest["history"])
            clone_count, clone_digest = verify_fresh_clone(staging, denylist)
            if clone_count != file_count or clone_digest != digest:
                raise ExportError("fresh clone changed the exported source digest")
            fresh_clone_verified = True
        os.replace(staging, destination)
        staging = Path()
        return ExportResult(
            file_count=file_count,
            candidate_sha256=digest,
            manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            history_initialized=initialize_history,
            fresh_clone_verified=fresh_clone_verified,
        )
    finally:
        if staging != Path() and staging.exists():
            shutil.rmtree(staging)


def main(argv: Sequence[str] | None = None) -> int:
    """Run export or fresh-clone verification with redacted output."""
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    export = subcommands.add_parser("export")
    export.add_argument("source", type=Path)
    export.add_argument("destination", type=Path)
    export.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    export.add_argument("--denylist", type=Path, required=True)
    export.add_argument("--no-init-git", action="store_true")
    verify = subcommands.add_parser("verify")
    verify.add_argument("candidate", type=Path)
    verify.add_argument("--denylist", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "export":
            result = export_candidate(
                args.source,
                args.destination,
                args.manifest,
                args.denylist,
                initialize_history=not args.no_init_git,
            )
        else:
            file_count, digest = verify_fresh_clone(args.candidate.resolve(), args.denylist.resolve())
            result = ExportResult(file_count, digest, "", True, True)
    except (ExportError, OSError, yaml.YAMLError) as error:
        print(f"publication export failed: {error}", file=sys.stderr)
        return 1
    print(
        yaml.safe_dump(
            {
                "candidate_sha256": result.candidate_sha256,
                "file_count": result.file_count,
                "fresh_clone_verified": result.fresh_clone_verified,
                "history_initialized": result.history_initialized,
                "manifest_sha256": result.manifest_sha256,
            },
            sort_keys=True,
        ).strip()
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
