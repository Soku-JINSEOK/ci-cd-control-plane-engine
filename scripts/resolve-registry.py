#!/usr/bin/env python3
"""Resolve a repository to its registry-owned pipeline and safe targets."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def load(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def templates() -> dict[str, dict[str, Any]]:
    result = {}
    for path in (ROOT / "pipelines").glob("*.yaml"):
        value = load(path)
        if isinstance(value, dict) and isinstance(value.get("template"), str):
            result[value["template"]] = value
    return result


def resolve_project(
    registry: dict[str, Any],
    template_map: dict[str, dict[str, Any]],
    repository: str,
    environment: str | None = None,
) -> dict[str, Any]:
    matches = [p for p in registry.get("projects", []) if p.get("repository") == repository]
    if len(matches) != 1:
        raise ValueError(f"unregistered repository: {repository}")
    project = matches[0]
    selected = project["pipeline"]
    template = template_map.get(selected["template"])
    if template is None:
        raise ValueError(f"unknown pipeline template: {selected['template']}")
    if selected["kind"] != template.get("kind"):
        raise ValueError("registry pipeline kind does not match its template")
    if project["project_type"] not in template.get("project_types", []):
        raise ValueError("registry project type is not supported by its template")
    if template.get("delivery", {}).get("enabled") is not False:
        raise ValueError("delivery must remain disabled until explicit approval")

    targets = project.get("targets", {})
    if template["kind"] == "cloud-run":
        required = {"artifact_registry", "cloud_build", "cloud_run", "health_check"}
        if not required.issubset(targets):
            raise ValueError("cloud-run target metadata is incomplete")
        environments = targets["cloud_run"].get("environments", {})
        if environment is not None:
            if environment not in {"staging", "production"}:
                raise ValueError(f"unsupported Cloud Run environment: {environment}")
            targets = {
                **targets,
                "cloud_run": environments[environment],
                "cloud_run_environments": environments,
            }
    if template["kind"] == "manual-deploy" and "apps_script" not in targets:
        raise ValueError("Apps Script target metadata is missing")

    return {
        "repository": repository,
        "project_type": project["project_type"],
        "pipeline": selected,
        "template": template["template"],
        "delivery_enabled": template["delivery"]["enabled"],
        "targets": targets,
        "validation": template["validation"],
    }


def resolve(repository: str, environment: str | None = None) -> dict[str, Any]:
    registry = load(ROOT / "registry/projects.yaml")
    return resolve_project(registry, templates(), repository, environment)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--environment", choices=["staging", "production"])
    parser.add_argument("--registry-ref")
    args = parser.parse_args()
    try:
        if args.registry_ref is not None and not SHA_RE.fullmatch(args.registry_ref):
            raise ValueError("registry-ref must be a full 40-character commit SHA")
        print(json.dumps(resolve(args.repository, args.environment), sort_keys=True))
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
