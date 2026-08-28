#!/usr/bin/env python3
"""Fail-closed provider-neutral local reference executor."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable

CONCLUSIONS = ("success", "failure", "timeout", "cancelled", "superseded", "unsupported", "partial")
SHELL_WRAPPERS = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell", "pwsh"}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
PROTECTED_TEXT = (
    re.compile(r"\b(?:PVT|PVTI|PVTF|PVTSSF|PVTO)[A-Za-z0-9_-]{6,}\b"),
    re.compile(r"https://github\.com/(?:users|orgs)/[^/\s]+/projects/\d+"),
    re.compile(r"\b[a-z][a-z0-9-]+@[a-z][a-z0-9-]+\.iam\.gserviceaccount\.com\b"),
    re.compile(r"(?:/(?:Users|home)/[^/\s]+/|[A-Za-z]:\\Users\\)"),
)
SENSITIVE_KEYS = {"stdout", "stderr", "environment", "credentials", "token", "secret", "private_endpoint", "machine_name"}


class ContractError(ValueError):
    """A contract is invalid or cannot be executed faithfully."""


class UnsupportedError(ContractError):
    """A valid requirement cannot be satisfied by this executor."""


def canonical_bytes(value: Any) -> bytes:
    """Return the contract's canonical UTF-8 JSON representation."""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate_public_disclosure(value: Any, private_literals: tuple[str, ...] = ()) -> None:
    """Reject private identifiers and fields before normalized publication."""
    def walk(item: Any) -> None:
        if isinstance(item, dict):
            if any(key.casefold() in SENSITIVE_KEYS for key in item):
                raise ContractError("sensitive field is not publishable")
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)
        elif isinstance(item, str):
            if any(pattern.search(item) for pattern in PROTECTED_TEXT) or any(literal in item for literal in private_literals):
                raise ContractError("protected literal is not publishable")
    walk(value)


def verify_reviewed_binding(requirements: dict[str, Any], reviewed_contract: bytes, expected_requirements_sha256: str) -> None:
    """Bind requirements to independently pinned bytes before execution."""
    if not HEX64.fullmatch(expected_requirements_sha256) or canonical_sha256(requirements) != expected_requirements_sha256:
        raise ContractError("requirements expected hash mismatch")
    if hashlib.sha256(reviewed_contract).hexdigest() != requirements["contract_sha256"]:
        raise ContractError("reviewed contract hash mismatch")
    try:
        reviewed = json.loads(reviewed_contract.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("reviewed contract is invalid JSON") from error
    _exact_keys(reviewed, {"pipeline_template_id", "profile_id", "commands", "artifacts"}, "reviewed contract")
    if requirements["pipeline_template_id"] != reviewed["pipeline_template_id"] or requirements["profile_id"] != reviewed["profile_id"] or requirements["commands"] != reviewed["commands"] or requirements["artifacts"] != reviewed["artifacts"]:
        raise ContractError("requirements differ from the reviewed contract")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("JSON contract could not be read") from error
    if not isinstance(value, dict):
        raise ContractError("contract root must be an object")
    return value


def _exact_keys(value: Any, expected: set[str], name: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ContractError(f"{name} fields are invalid")


def _ids(values: list[dict[str, Any]], name: str) -> None:
    ids = [item.get("id") for item in values]
    if any(not isinstance(item, str) or not ID.fullmatch(item) for item in ids) or len(ids) != len(set(ids)):
        raise ContractError(f"{name} IDs are invalid or duplicated")


def relative_path(root: Path, raw: Any, field: str, *, must_exist: bool) -> Path:
    """Resolve a portable repository-relative path without symlink escape."""
    if not isinstance(raw, str) or not raw or "\\" in raw or raw.startswith("~"):
        raise ContractError(f"{field} path is invalid")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or any(part in {"", ".."} for part in pure.parts):
        raise ContractError(f"{field} path is invalid")
    candidate = root.joinpath(*pure.parts)
    try:
        resolved = candidate.resolve(strict=must_exist)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as error:
        raise ContractError(f"{field} path escapes source root") from error
    return resolved


def validate_requirements(value: dict[str, Any], root: Path | None = None) -> None:
    _exact_keys(value, {"schema_version", "pipeline_template_id", "profile_id", "source_sha", "contract_sha256", "platform", "network", "capabilities", "commands", "artifacts"}, "requirements")
    if value["schema_version"] != "execution-requirements-v1" or not isinstance(value["pipeline_template_id"], str) or not ID.fullmatch(value["pipeline_template_id"]) or not isinstance(value["profile_id"], str) or not ID.fullmatch(value["profile_id"]):
        raise ContractError("requirements identity is invalid")
    if not isinstance(value["source_sha"], str) or not HEX40.fullmatch(value["source_sha"]):
        raise ContractError("source SHA is invalid")
    if not isinstance(value["contract_sha256"], str) or not HEX64.fullmatch(value["contract_sha256"]):
        raise ContractError("contract hash is invalid")
    _exact_keys(value["platform"], {"os", "architecture", "shell"}, "platform")
    if value["platform"]["os"] not in {"linux", "darwin", "windows"} or value["platform"]["architecture"] not in {"amd64", "arm64"} or value["platform"]["shell"] != "none":
        raise ContractError("platform is invalid")
    if value["network"] not in {"none", "public", "gcp-private", "on-premises"}:
        raise ContractError("network is invalid")
    if not isinstance(value["capabilities"], list) or any(not isinstance(item, str) or not ID.fullmatch(item) for item in value["capabilities"]) or len(value["capabilities"]) != len(set(value["capabilities"])):
        raise ContractError("capabilities are invalid")
    if not isinstance(value["commands"], list) or not value["commands"]:
        raise ContractError("commands must be a non-empty array")
    _ids(value["commands"], "command")
    for command in value["commands"]:
        _exact_keys(command, {"id", "argv", "cwd", "timeout_seconds"}, "command")
        argv = command["argv"]
        if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in argv):
            raise ContractError("command argv must be a non-empty string array")
        if Path(argv[0]).name.casefold() in SHELL_WRAPPERS:
            raise ContractError("shell wrapper execution is prohibited")
        if not isinstance(command["timeout_seconds"], int) or isinstance(command["timeout_seconds"], bool) or not 1 <= command["timeout_seconds"] <= 86400:
            raise ContractError("command timeout is invalid")
        if root is not None:
            path = relative_path(root, command["cwd"], "command cwd", must_exist=True)
            if not path.is_dir():
                raise ContractError("command cwd is not a directory")
        else:
            relative_path(Path.cwd(), command["cwd"], "command cwd", must_exist=False)
    if not isinstance(value["artifacts"], list):
        raise ContractError("artifacts must be an array")
    _ids(value["artifacts"], "artifact")
    for artifact in value["artifacts"]:
        _exact_keys(artifact, {"id", "path", "sha256"}, "artifact")
        if not isinstance(artifact["sha256"], str) or not HEX64.fullmatch(artifact["sha256"]):
            raise ContractError("artifact hash is invalid")
        if root is not None:
            relative_path(root, artifact["path"], "artifact", must_exist=False)
        else:
            relative_path(Path.cwd(), artifact["path"], "artifact", must_exist=False)


def validate_adapter(value: dict[str, Any]) -> None:
    _exact_keys(value, {"schema_version", "adapter_id", "implementation_sha256", "lifecycle", "execution_mode", "supported", "source_binding", "failure_semantics", "conclusions", "delivery_authority"}, "adapter")
    if value["schema_version"] != "adapter-descriptor-v1" or not isinstance(value["adapter_id"], str) or not re.fullmatch(r"[a-z][a-z0-9-]*-v[0-9]+", value["adapter_id"]):
        raise ContractError("adapter identity is invalid")
    if not isinstance(value["implementation_sha256"], str) or not HEX64.fullmatch(value["implementation_sha256"]):
        raise ContractError("adapter implementation hash is invalid")
    if value["lifecycle"] not in {"experimental", "reviewed", "deprecated", "disabled"}:
        raise ContractError("adapter lifecycle is invalid")
    if value["execution_mode"] not in {"local-executable", "synthetic-only"}:
        raise ContractError("adapter execution mode is invalid")
    _exact_keys(value["supported"], {"requirements_versions", "evidence_versions", "os", "architectures", "shells", "networks", "capabilities"}, "adapter support")
    support = value["supported"]
    allowed = {
        "requirements_versions": {"execution-requirements-v1"},
        "evidence_versions": {"normalized-evidence-v1"},
        "os": {"linux", "darwin", "windows"},
        "architectures": {"amd64", "arm64"},
        "shells": {"none"},
        "networks": {"none", "public", "gcp-private", "on-premises"},
    }
    for field, choices in allowed.items():
        items = support[field]
        if not isinstance(items, list) or not items or len(items) != len(set(items)) or not set(items).issubset(choices):
            raise ContractError(f"adapter supported {field} is invalid")
    capabilities = support["capabilities"]
    if not isinstance(capabilities, list) or len(capabilities) != len(set(capabilities)) or any(not isinstance(item, str) or not ID.fullmatch(item) for item in capabilities):
        raise ContractError("adapter supported capabilities are invalid")
    expected_failure = {"command_order": "exact-reviewed-order", "failure": "fail-fast", "timeout": "terminate-process-group", "cancellation": "terminate-process-group", "supersession": "no-process-start"}
    if value["source_binding"] != "exact-clean-git-sha" or value["failure_semantics"] != expected_failure or value["delivery_authority"] != "none" or value["conclusions"] != list(CONCLUSIONS):
        raise ContractError("adapter authority or conclusion contract is invalid")


def validate_evidence(value: dict[str, Any], requirements: dict[str, Any], adapter: dict[str, Any]) -> None:
    """Validate normalized evidence identity, ordering, and non-success rules."""
    _exact_keys(value, {"schema_version", "source_sha", "pipeline_template_id", "profile_id", "contract_sha256", "requirements_sha256", "adapter_id", "adapter_sha256", "executor", "commands", "artifacts", "started_at", "ended_at", "conclusion", "disclosure"}, "evidence")
    if value["schema_version"] != "normalized-evidence-v1" or value["disclosure"] != "redacted-metadata-only" or value["conclusion"] not in CONCLUSIONS:
        raise ContractError("evidence version, disclosure, or conclusion is invalid")
    executor = value["executor"]
    _exact_keys(executor, {"os", "architecture", "capabilities"}, "executor")
    if executor["os"] not in {"linux", "darwin", "windows"} or executor["architecture"] not in {"amd64", "arm64"} or not isinstance(executor["capabilities"], list) or len(executor["capabilities"]) != len(set(executor["capabilities"])) or any(not isinstance(item, str) or not ID.fullmatch(item) for item in executor["capabilities"]):
        raise ContractError("executor identity is invalid")
    parsed_times = []
    for field in ("started_at", "ended_at"):
        try:
            if not isinstance(value[field], str) or not RFC3339.fullmatch(value[field]):
                raise ValueError
            parsed = datetime.fromisoformat(value[field].replace("Z", "+00:00"))
            if parsed.utcoffset() is None:
                raise ValueError
            parsed_times.append(parsed)
        except (AttributeError, ValueError) as error:
            raise ContractError("evidence timestamp is invalid") from error
    if parsed_times[1] < parsed_times[0]:
        raise ContractError("evidence timestamps are reversed")
    for result in value["commands"]:
        _exact_keys(result, {"id", "conclusion"}, "command result")
        if not isinstance(result["id"], str) or not ID.fullmatch(result["id"]) or result["conclusion"] not in {"success", "failure", "timeout", "cancelled"}:
            raise ContractError("command result is invalid")
    for result in value["artifacts"]:
        _exact_keys(result, {"id", "sha256"}, "artifact result")
        if not isinstance(result["id"], str) or not isinstance(result["sha256"], str) or not ID.fullmatch(result["id"]) or not HEX64.fullmatch(result["sha256"]):
            raise ContractError("artifact result is invalid")
    bindings = (("source_sha", requirements["source_sha"]), ("pipeline_template_id", requirements["pipeline_template_id"]), ("profile_id", requirements["profile_id"]), ("contract_sha256", requirements["contract_sha256"]), ("requirements_sha256", canonical_sha256(requirements)), ("adapter_id", adapter["adapter_id"]), ("adapter_sha256", canonical_sha256(adapter)))
    if any(value[field] != expected for field, expected in bindings):
        raise ContractError("evidence identity binding mismatch")
    command_ids = [item["id"] for item in value["commands"]]
    required_ids = [item["id"] for item in requirements["commands"]]
    if command_ids != required_ids[:len(command_ids)]:
        raise ContractError("evidence command IDs are not an exact required prefix")
    required_artifacts = [{"id": item["id"], "sha256": item["sha256"]} for item in requirements["artifacts"]]
    artifact_ids = [item["id"] for item in value["artifacts"]]
    required_artifact_ids = [item["id"] for item in required_artifacts]
    if artifact_ids != required_artifact_ids[:len(artifact_ids)]:
        raise ContractError("evidence artifacts are not an exact required prefix")
    conclusion = value["conclusion"]
    exact_executor = executor["os"] == requirements["platform"]["os"] and executor["architecture"] == requirements["platform"]["architecture"] and executor["capabilities"] == sorted(requirements["capabilities"])
    if conclusion != "unsupported" and not exact_executor:
        raise ContractError("evidence has incomplete executor identity")
    if conclusion == "unsupported" and executor["capabilities"]:
        raise ContractError("unsupported evidence cannot claim capabilities")
    if conclusion == "success":
        if command_ids != required_ids or any(item["conclusion"] != "success" for item in value["commands"]) or value["artifacts"] != required_artifacts:
            raise ContractError("successful evidence is incomplete")
    elif conclusion in {"failure", "timeout"}:
        if not value["commands"] or value["artifacts"] or value["commands"][-1]["conclusion"] != conclusion or any(item["conclusion"] != "success" for item in value["commands"][:-1]):
            raise ContractError("failure or timeout evidence is invalid")
    elif conclusion == "cancelled":
        if value["artifacts"] or (value["commands"] and (value["commands"][-1]["conclusion"] != "cancelled" or any(item["conclusion"] != "success" for item in value["commands"][:-1]))):
            raise ContractError("cancelled evidence is invalid")
    elif conclusion in {"superseded", "unsupported"}:
        if value["commands"] or value["artifacts"]:
            raise ContractError("non-execution evidence claims execution")
    elif conclusion == "partial":
        if command_ids != required_ids or any(item["conclusion"] != "success" for item in value["commands"]) or not len(value["artifacts"]) < len(required_artifacts) or value["artifacts"] != required_artifacts[:len(value["artifacts"])]:
            raise ContractError("partial evidence is invalid")
    validate_public_disclosure(value)


def check_capabilities(requirements: dict[str, Any], adapter: dict[str, Any]) -> None:
    if adapter["lifecycle"] in {"deprecated", "disabled"}:
        raise UnsupportedError("adapter is not selectable")
    support = adapter["supported"]
    checks = (("schema_version", "requirements_versions"), ("network", "networks"))
    for required, supported in checks:
        if requirements[required] not in support[supported]:
            raise UnsupportedError(f"unsupported {required}")
    platform_value = requirements["platform"]
    for required, supported in (("os", "os"), ("architecture", "architectures"), ("shell", "shells")):
        if platform_value[required] not in support[supported]:
            raise UnsupportedError(f"unsupported {required}")
    if not set(requirements["capabilities"]).issubset(set(support["capabilities"])):
        raise UnsupportedError("unsupported capability")


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContractError("source Git identity could not be verified") from error


def verify_source(root: Path, expected_sha: str) -> None:
    if _git(root, "rev-parse", "HEAD") != expected_sha:
        raise ContractError("source SHA mismatch")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ContractError("source tree is dirty")


def _native_platform() -> tuple[str, str]:
    os_name = {"linux": "linux", "darwin": "darwin", "windows": "windows"}.get(platform.system().casefold(), platform.system().casefold())
    machine = platform.machine().casefold()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "amd64" if machine in {"x86_64", "amd64"} else machine
    return os_name, arch


def _terminate_process_group(process: subprocess.Popen[Any], grace_seconds: float = 0.2) -> None:
    """Terminate the full POSIX process group even if its leader exits first."""
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace_seconds
    group_alive = True
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            group_alive = False
            break
        time.sleep(0.02)
    if group_alive:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait()


def execute(requirements: dict[str, Any], adapter: dict[str, Any], root: Path, *, reviewed_contract: bytes, expected_requirements_sha256: str, started_at: str, ended_at: str, cancelled: Callable[[], bool] | None = None, superseded: bool = False) -> dict[str, Any]:
    """Preflight then execute exact argv commands without a shell."""
    validate_requirements(requirements, root)
    validate_adapter(adapter)
    verify_reviewed_binding(requirements, reviewed_contract, expected_requirements_sha256)
    native_os, native_arch = _native_platform()
    try:
        if adapter["adapter_id"] != "local-reference-v1" or adapter["execution_mode"] != "local-executable":
            raise UnsupportedError("descriptor is not executable by the local runner")
        implementation = Path(__file__).read_bytes()
        if hashlib.sha256(implementation).hexdigest() != adapter["implementation_sha256"]:
            raise ContractError("adapter implementation hash mismatch")
        check_capabilities(requirements, adapter)
        if requirements["platform"]["os"] != native_os or requirements["platform"]["architecture"] != native_arch:
            raise UnsupportedError("requirements do not match the local executor")
    except UnsupportedError:
        evidence = {
            "schema_version": "normalized-evidence-v1", "source_sha": requirements["source_sha"], "pipeline_template_id": requirements["pipeline_template_id"], "profile_id": requirements["profile_id"],
            "contract_sha256": requirements["contract_sha256"], "requirements_sha256": canonical_sha256(requirements),
            "adapter_id": adapter["adapter_id"], "adapter_sha256": canonical_sha256(adapter),
            "executor": {"os": native_os, "architecture": native_arch, "capabilities": []},
            "commands": [], "artifacts": [], "started_at": started_at, "ended_at": ended_at,
            "conclusion": "unsupported", "disclosure": "redacted-metadata-only",
        }
        validate_evidence(evidence, requirements, adapter)
        return evidence
    verify_source(root, requirements["source_sha"])
    command_results: list[dict[str, str]] = []
    conclusion = "superseded" if superseded else "success"
    for command in requirements["commands"]:
        if conclusion != "success":
            break
        if cancelled and cancelled():
            conclusion = "cancelled"
            break
        cwd = relative_path(root, command["cwd"], "command cwd", must_exist=True)
        process = subprocess.Popen(command["argv"], cwd=cwd, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + command["timeout_seconds"]
        while process.poll() is None:
            active_conclusion = "cancelled" if cancelled and cancelled() else "timeout" if time.monotonic() >= deadline else None
            if active_conclusion:
                _terminate_process_group(process)
                conclusion = active_conclusion
                break
            time.sleep(0.02)
        else:
            conclusion = "success" if process.returncode == 0 else "failure"
        command_results.append({"id": command["id"], "conclusion": conclusion})
    artifacts: list[dict[str, str]] = []
    if conclusion == "success":
        for artifact in requirements["artifacts"]:
            path = relative_path(root, artifact["path"], "artifact", must_exist=True)
            if not path.is_file() or path.is_symlink():
                conclusion = "partial"
                break
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != artifact["sha256"]:
                conclusion = "partial"
                break
            artifacts.append({"id": artifact["id"], "sha256": digest})
    if conclusion == "success" and len(command_results) != len(requirements["commands"]):
        conclusion = "partial"
    evidence = {
        "schema_version": "normalized-evidence-v1",
        "source_sha": requirements["source_sha"],
        "pipeline_template_id": requirements["pipeline_template_id"],
        "profile_id": requirements["profile_id"],
        "contract_sha256": requirements["contract_sha256"],
        "requirements_sha256": canonical_sha256(requirements),
        "adapter_id": adapter["adapter_id"],
        "adapter_sha256": canonical_sha256(adapter),
        "executor": {"os": native_os, "architecture": native_arch, "capabilities": sorted(requirements["capabilities"])},
        "commands": command_results,
        "artifacts": artifacts,
        "started_at": started_at,
        "ended_at": ended_at,
        "conclusion": conclusion,
        "disclosure": "redacted-metadata-only",
    }
    validate_public_disclosure(evidence)
    validate_evidence(evidence, requirements, adapter)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", required=True, type=Path)
    parser.add_argument("--adapter", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--reviewed-contract", required=True, type=Path)
    parser.add_argument("--expected-requirements-sha256", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--ended-at", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        evidence = execute(load_json(args.requirements), load_json(args.adapter), args.source, reviewed_contract=args.reviewed_contract.read_bytes(), expected_requirements_sha256=args.expected_requirements_sha256, started_at=args.started_at, ended_at=args.ended_at)
    except ContractError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    payload = canonical_bytes(evidence)
    if args.output:
        args.output.write_bytes(payload)
    else:
        sys.stdout.buffer.write(payload)
    return 0 if evidence["conclusion"] == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
