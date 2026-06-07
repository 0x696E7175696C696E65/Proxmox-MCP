from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

REQUIRED_ARTIFACTS: tuple[str, ...] = (
    "artifact-manifest.json",
    "ci-success.json",
    "distribution-summary.json",
    "hardening-summary.json",
    "migration-validation.json",
    "sbom.spdx.json",
    "trivy-image-results.sarif",
    "compatibility-report.json",
    "lab-evidence.json",
)

KNOWN_LAB_PROFILES: frozenset[str] = frozenset(
    {
        "pve-9-single-node-no-ceph",
        "pve-9-storage-local-local-lvm",
        "pve-9-single-node-with-guests",
        "pve-9-ceph-enabled",
        "pve-9-ha-enabled",
        "pve-9-multi-node",
        "pve-9-pbs-enabled",
    }
)

REQUIRED_RELEASE_SUMMARY_FIELDS: tuple[str, ...] = (
    "ci",
    "hardening",
    "distribution",
    "sbom",
    "trivy",
    "lab",
    "migration",
)


@dataclass(frozen=True)
class ReleaseEvidenceValidationResult:
    valid: bool
    missing_artifacts: tuple[str, ...]
    invalid_artifacts: tuple[str, ...] = ()


def validate_release_evidence(evidence_dir: Path) -> ReleaseEvidenceValidationResult:
    missing: list[str] = []
    invalid: list[str] = []
    parsed_artifacts: dict[str, object] = {}

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
            parsed_artifacts[artifact] = parsed
        if artifact == "compatibility-report.json" and not _valid_compatibility_report(parsed):
            invalid.append(artifact)
        if artifact == "lab-evidence.json" and not _valid_lab_evidence(parsed):
            invalid.append(artifact)
        if artifact == "artifact-manifest.json" and not _valid_artifact_manifest(
            parsed,
            evidence_dir,
        ):
            invalid.append(artifact)

    if (
        "compatibility-report.json" not in invalid
        and "lab-evidence.json" not in invalid
        and "compatibility-report.json" in parsed_artifacts
        and "lab-evidence.json" in parsed_artifacts
        and not _valid_profile_evidence_alignment(
            parsed_artifacts["compatibility-report.json"],
            parsed_artifacts["lab-evidence.json"],
        )
    ):
        invalid.append("lab-evidence.json")

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

    release_summary = report.get("release_summary")
    if not isinstance(release_summary, dict):
        return False
    typed_release_summary = cast(dict[str, object], release_summary)
    if not all(
        isinstance(typed_release_summary.get(field), str) and typed_release_summary.get(field)
        for field in REQUIRED_RELEASE_SUMMARY_FIELDS
    ):
        return False

    matrix = report.get("matrix")
    if not isinstance(matrix, list) or not matrix:
        return False

    profiles = report.get("profiles")
    profile_names: set[str] = set()
    if profiles is not None:
        if not isinstance(profiles, list):
            return False
        for profile in cast(list[object], profiles):
            if not _valid_profile(profile):
                return False
            typed_profile = cast(dict[str, object], profile)
            profile_name = cast(str, typed_profile["name"])
            if profile_name in profile_names:
                return False
            profile_names.add(profile_name)

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
        profile = typed_row.get("profile")
        if profile is not None:
            if not isinstance(profile, str) or profile not in KNOWN_LAB_PROFILES:
                return False
            if profile_names and profile not in profile_names:
                return False
        if status == "qualified":
            if evidence_status != "qualified":
                return False
            if "operator-lab-run-required" in typed_artifacts:
                return False

    return True


def _valid_artifact_manifest(payload: object | None, evidence_dir: Path) -> bool:
    if not isinstance(payload, dict) or _contains_sensitive_key(payload):
        return False
    manifest = cast(dict[str, object], payload)
    if manifest.get("schema_version") != 1:
        return False
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        return False
    typed_artifacts = cast(dict[str, object], artifacts)
    expected_artifacts = set(REQUIRED_ARTIFACTS) - {"artifact-manifest.json"}
    if set(typed_artifacts) != expected_artifacts:
        return False
    for artifact_name in expected_artifacts:
        entry = typed_artifacts.get(artifact_name)
        if not isinstance(entry, dict):
            return False
        typed_entry = cast(dict[str, object], entry)
        expected_sha = typed_entry.get("sha256")
        if not isinstance(expected_sha, str) or len(expected_sha) != 64:
            return False
        artifact_path = evidence_dir / artifact_name
        if not artifact_path.is_file():
            return False
        actual_sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            return False
    return True


def _valid_profile(profile: object) -> bool:
    if not isinstance(profile, dict):
        return False
    typed_profile = cast(dict[str, object], profile)
    name = typed_profile.get("name")
    if not isinstance(name, str) or name not in KNOWN_LAB_PROFILES:
        return False
    if typed_profile.get("status") not in {"qualified", "preview", "blocked", "not_yet_claimed"}:
        return False
    for field in ("required_tests", "expected_skips"):
        values = typed_profile.get(field)
        if not isinstance(values, list):
            return False
        if any(not isinstance(value, str) or not value for value in cast(list[object], values)):
            return False
    optional_tests = typed_profile.get("optional_tests", [])
    if not isinstance(optional_tests, list):
        return False
    return not any(
        not isinstance(value, str) or not value for value in cast(list[object], optional_tests)
    )


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
            or not any(profile in evidence for profile in KNOWN_LAB_PROFILES)
        ):
            return False

    return True


def _valid_profile_evidence_alignment(
    compatibility_payload: object,
    lab_payload: object,
) -> bool:
    if not isinstance(compatibility_payload, dict) or not isinstance(lab_payload, dict):
        return False

    compatibility = cast(dict[str, object], compatibility_payload)
    lab_evidence = cast(dict[str, object], lab_payload)
    requires_qualified_lab = _compatibility_requires_qualified_lab(compatibility)
    if lab_evidence.get("status") != "qualified":
        return not requires_qualified_lab

    if not requires_qualified_lab:
        return True

    lab = lab_evidence.get("lab")
    if not isinstance(lab, dict):
        return False
    profile_name = cast(dict[str, object], lab).get("profile")
    if not isinstance(profile_name, str):
        return False

    profiles = compatibility.get("profiles")
    if not isinstance(profiles, list):
        return False

    profile = _profile_by_name(cast(list[object], profiles), profile_name)
    if profile is None:
        return False

    required_tests = profile.get("required_tests")
    if not isinstance(required_tests, list):
        return False
    test_runs = lab_evidence.get("test_runs")
    if not isinstance(test_runs, list):
        return False

    passed_runs = {
        cast(str, run["name"])
        for run in cast(list[dict[str, object]], test_runs)
        if isinstance(run, dict)
        and isinstance(run.get("name"), str)
        and run.get("status") == "passed"
        and run.get("failed") == 0
    }
    return all(test_name in passed_runs for test_name in cast(list[str], required_tests))


def _compatibility_requires_qualified_lab(compatibility: dict[str, object]) -> bool:
    if compatibility.get("status") == "qualified":
        return True
    matrix = compatibility.get("matrix")
    if isinstance(matrix, list) and any(
        isinstance(row, dict) and row.get("evidence_status") == "qualified"
        for row in cast(list[object], matrix)
    ):
        return True
    profiles = compatibility.get("profiles")
    return isinstance(profiles, list) and any(
        isinstance(profile, dict) and profile.get("status") == "qualified"
        for profile in cast(list[object], profiles)
    )


def _profile_by_name(
    profiles: list[object],
    profile_name: str,
) -> dict[str, object] | None:
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        typed_profile = cast(dict[str, object], profile)
        if typed_profile.get("name") == profile_name:
            return typed_profile
    return None


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
            "authorization",
            "bearer",
            "cookie",
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
