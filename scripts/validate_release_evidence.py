from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

REQUIRED_ARTIFACTS: tuple[str, ...] = (
    "ci-success.json",
    "distribution-summary.json",
    "hardening-summary.json",
    "migration-validation.json",
    "sbom.spdx.json",
    "trivy-image-results.sarif",
    "compatibility-report.json",
    "lab-evidence.json",
)


@dataclass(frozen=True)
class ReleaseEvidenceValidationResult:
    valid: bool
    missing_artifacts: tuple[str, ...]
    invalid_artifacts: tuple[str, ...] = ()


def validate_release_evidence(evidence_dir: Path) -> ReleaseEvidenceValidationResult:
    missing: list[str] = []
    invalid: list[str] = []

    for artifact in REQUIRED_ARTIFACTS:
        artifact_path = evidence_dir / artifact
        if not artifact_path.is_file():
            missing.append(artifact)
            continue
        if artifact_path.stat().st_size == 0:
            invalid.append(artifact)
            continue
        parsed: object | None = None
        if artifact.endswith((".json", ".sarif")):
            try:
                parsed = json.loads(artifact_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                invalid.append(artifact)
                continue
        if artifact == "compatibility-report.json" and not _valid_compatibility_report(parsed):
            invalid.append(artifact)
        if artifact == "lab-evidence.json" and not _valid_lab_evidence(parsed):
            invalid.append(artifact)

    return ReleaseEvidenceValidationResult(
        valid=not missing and not invalid,
        missing_artifacts=tuple(missing),
        invalid_artifacts=tuple(invalid),
    )


def _valid_compatibility_report(payload: object | None) -> bool:
    if not isinstance(payload, dict) or _contains_sensitive_key(payload):
        return False

    report = cast(dict[str, object], payload)
    status = report.get("status")
    if report.get("schema_version") != 1 or status not in {
        "qualified",
        "preview",
        "blocked",
    }:
        return False

    matrix = report.get("matrix")
    if not isinstance(matrix, list) or not matrix:
        return False

    for row in cast(list[object], matrix):
        if not isinstance(row, dict):
            return False
        typed_row = cast(dict[str, object], row)
        if not all(
            isinstance(typed_row.get(field), str) and typed_row.get(field)
            for field in ("proxmox_version", "topology", "evidence_status")
        ):
            return False
        evidence_status = typed_row.get("evidence_status")
        if evidence_status not in {
            "qualified",
            "preview_lab_evidence",
            "release_gate_evidence",
            "not_yet_claimed",
            "blocked",
        }:
            return False
        artifacts = typed_row.get("evidence_artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            return False
        typed_artifacts = cast(list[object], artifacts)
        if any(not isinstance(artifact, str) or not artifact for artifact in typed_artifacts):
            return False
        if status == "qualified":
            if evidence_status != "qualified":
                return False
            if "operator-lab-run-required" in typed_artifacts:
                return False

    return True


def _valid_lab_evidence(payload: object | None) -> bool:
    if not isinstance(payload, dict) or _contains_sensitive_key(payload):
        return False

    report = cast(dict[str, object], payload)
    status = report.get("status")
    if report.get("schema_version") != 1 or status not in {
        "qualified",
        "preview",
        "blocked",
    }:
        return False

    lab = report.get("lab")
    if not isinstance(lab, dict):
        return False
    typed_lab = cast(dict[str, object], lab)
    if not all(
        isinstance(typed_lab.get(field), str) and typed_lab.get(field)
        for field in ("endpoint", "node")
    ):
        return False

    test_runs = report.get("test_runs")
    if not isinstance(test_runs, list) or not test_runs:
        return False
    for run in cast(list[object], test_runs):
        if not isinstance(run, dict):
            return False
        typed_run = cast(dict[str, object], run)
        if typed_run.get("status") not in {"passed", "failed", "skipped"}:
            return False
        if not isinstance(typed_run.get("name"), str):
            return False
        if status == "qualified" and typed_run.get("status") != "passed":
            return False

    promoted_tools = report.get("promoted_tools")
    if not isinstance(promoted_tools, list):
        return False
    for tool in cast(list[object], promoted_tools):
        if not isinstance(tool, dict):
            return False
        typed_tool = cast(dict[str, object], tool)
        if not isinstance(typed_tool.get("tool"), str):
            return False
        if typed_tool.get("status") not in {"live_supported", "guarded_not_implemented"}:
            return False
        evidence = typed_tool.get("evidence")
        if typed_tool.get("status") == "live_supported" and (
            not isinstance(evidence, str)
            or not evidence.strip()
            or evidence.lower() in {"pending", "todo", "tbd"}
        ):
            return False

    return True


def _contains_sensitive_key(payload: object) -> bool:
    if isinstance(payload, dict):
        for key, value in cast(dict[Any, object], payload).items():
            if isinstance(key, str) and _is_sensitive_key(key):
                return True
            if _contains_sensitive_key(value):
                return True
    if isinstance(payload, list):
        return any(_contains_sensitive_key(item) for item in cast(list[object], payload))
    return False


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(
        marker in normalized
        for marker in (
            "password",
            "token",
            "secret",
            "private_key",
            "credential",
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate GA release evidence artifacts.")
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        required=True,
        help="Directory containing release evidence artifacts.",
    )
    args = parser.parse_args(argv)

    result = validate_release_evidence(args.evidence_dir)
    if result.valid:
        print("Release evidence validation passed.")
        return 0

    if result.missing_artifacts:
        print("Missing release evidence artifacts:", file=sys.stderr)
        for artifact in result.missing_artifacts:
            print(f"- {artifact}", file=sys.stderr)
    if result.invalid_artifacts:
        print("Invalid release evidence artifacts:", file=sys.stderr)
        for artifact in result.invalid_artifacts:
            print(f"- {artifact}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
