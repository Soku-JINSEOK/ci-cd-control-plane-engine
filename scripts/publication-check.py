#!/usr/bin/env python3
"""Reject protected identifiers and files from a publication candidate."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

PROJECT_NODE = re.compile(
    r"\b(?:PVT|PVTI|PVTF|PVTSSF|PVTO|MDQ6UHJvamVjdFZ)[A-Za-z0-9_-]{6,}\b"
)
PROJECT_URL = re.compile(r"https://github\.com/(?:users|orgs)/[^/\s]+/projects/\d+")
SERVICE_ACCOUNT = re.compile(
    r"\b[a-z][a-z0-9-]{4,28}[a-z0-9]@"
    r"[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com\b"
)
CLOUD_RESOURCE = re.compile(r"\bprojects/[a-z][a-z0-9-]{4,28}[a-z0-9]/[^\s]+")
LOCAL_PATH = re.compile(
    r"(?:/(?:home|Users)/[^/\s]+/|[A-Za-z]:\\Users\\[^\\\s]+\\|"
    r"\\\\[^\\\s]+\\[^\\\s]+\\)"
)


class ContractError(ValueError):
    """An input contract failed without containing protected values."""


@dataclass(frozen=True)
class ProtectedLiteral:
    """A private literal loaded from an external denylist."""

    rule_id: str
    value: str
    case_sensitive: bool


@dataclass(frozen=True, order=True)
class Finding:
    """A redacted publication finding."""

    relative_path: str
    line: int
    rule_id: str


CONTENT_RULES = (
    ("github.project-id", PROJECT_NODE),
    ("github.project-url", PROJECT_URL),
    ("cloud.service-account", SERVICE_ACCOUNT),
    ("cloud.resource-name", CLOUD_RESOURCE),
    ("local.absolute-path", LOCAL_PATH),
)


def _path_rule(path: str) -> str | None:
    """Return the protected path rule for a candidate-relative path."""
    parts = path.casefold().split("/")
    name = parts[-1]
    if ".git" in parts or any(
        part in {".venv", "node_modules", ".next", "__pycache__", ".cache"}
        for part in parts
    ):
        return "source.cache"
    if ".terraform" in parts or name.endswith((".tfstate", ".tfstate.backup")):
        return "terraform.state"
    if name.endswith((".tfvars", ".tfplan")) or name.startswith("backend."):
        return "terraform.state"
    if name == ".clasprc.json" or name == ".env" or name.startswith(".env."):
        return "source.credential-file"
    if name.endswith((".pem", ".key", ".p12", ".pfx")):
        return "source.credential-file"
    if any(
        token in name
        for token in ("credential", "service-account", "service_account")
    ) and name.endswith((".json", ".yaml", ".yml")):
        return "source.credential-file"
    if (
        "mutation-manifest" in name
        or "repository-operations-snapshot" in name
        or any(token in name for token in ("incident-evidence", "rollout-evidence"))
    ):
        return "operations.evidence"
    return None


def load_denylist(path: Path | None) -> tuple[ProtectedLiteral, ...]:
    """Load and strictly validate an external private-literal denylist."""
    if path is None:
        return ()
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ContractError("denylist could not be read") from error
    if not isinstance(value, dict) or set(value) != {"schema_version", "literals"}:
        raise ContractError("denylist root contract is invalid")
    if value["schema_version"] != 1 or not isinstance(value["literals"], list):
        raise ContractError("denylist schema version or literals are invalid")

    literals: list[ProtectedLiteral] = []
    seen: set[tuple[str, str, bool]] = set()
    for item in value["literals"]:
        if not isinstance(item, dict) or set(item) != {
            "rule_id",
            "value",
            "case_sensitive",
        }:
            raise ContractError("denylist literal contract is invalid")
        rule_id = item["rule_id"]
        literal = item["value"]
        case_sensitive = item["case_sensitive"]
        if (
            not isinstance(rule_id, str)
            or not re.fullmatch(r"private\.[a-z][a-z0-9-]*", rule_id)
            or not isinstance(literal, str)
            or len(literal) < 6
            or not isinstance(case_sensitive, bool)
        ):
            raise ContractError("denylist literal fields are invalid")
        normalized = literal if case_sensitive else literal.casefold()
        key = (rule_id, normalized, case_sensitive)
        if key in seen:
            raise ContractError("denylist contains a duplicate literal")
        seen.add(key)
        literals.append(ProtectedLiteral(rule_id, literal, case_sensitive))
    return tuple(literals)


def _inside(candidate: Path, other: Path) -> bool:
    """Return whether other resolves inside candidate."""
    try:
        other.resolve().relative_to(candidate.resolve())
    except ValueError:
        return False
    return True


def check_candidate(
    root: Path,
    denylist_path: Path | None = None,
    require_denylist: bool = False,
) -> list[Finding]:
    """Return stable redacted findings for a publication candidate."""
    if not root.is_dir():
        raise ContractError("candidate root must be a directory")
    if require_denylist and denylist_path is None:
        raise ContractError("an external denylist is required")
    if denylist_path is not None and _inside(root, denylist_path):
        raise ContractError("denylist must be outside the candidate")
    literals = load_denylist(denylist_path)

    findings: list[Finding] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append(Finding(relative, 0, "source.symlink"))
            continue
        if not path.is_file():
            continue
        path_rule = _path_rule(relative)
        if path_rule is not None:
            findings.append(Finding(relative, 0, path_rule))
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            findings.append(Finding(relative, 0, "source.unreadable"))
            continue
        if b"\x00" in raw:
            findings.append(Finding(relative, 0, "source.binary"))
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            findings.append(Finding(relative, 0, "source.binary"))
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule_id, pattern in CONTENT_RULES:
                if pattern.search(line):
                    findings.append(Finding(relative, line_number, rule_id))
            for literal in literals:
                haystack = line if literal.case_sensitive else line.casefold()
                needle = (
                    literal.value
                    if literal.case_sensitive
                    else literal.value.casefold()
                )
                if needle in haystack:
                    findings.append(
                        Finding(
                            relative,
                            line_number,
                            f"private.literal.{literal.rule_id.removeprefix('private.')}",
                        )
                    )
    return sorted(set(findings))


def main() -> int:
    """Run the redacted publication candidate check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--denylist", type=Path)
    parser.add_argument("--require-denylist", action="store_true")
    args = parser.parse_args()
    try:
        findings = check_candidate(
            args.root,
            denylist_path=args.denylist,
            require_denylist=args.require_denylist,
        )
    except ContractError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if findings:
        for finding in findings:
            location = finding.relative_path
            if finding.line:
                location += f":{finding.line}"
            print(f"{finding.rule_id} {location}", file=sys.stderr)
        print(f"Publication check failed: {len(findings)} finding(s)")
        return 1
    print("Publication check passed: 0 findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
