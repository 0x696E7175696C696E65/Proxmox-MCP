from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

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
        if artifact.endswith((".json", ".sarif")):
            try:
                json.loads(artifact_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                invalid.append(artifact)

    return ReleaseEvidenceValidationResult(
        valid=not missing and not invalid,
        missing_artifacts=tuple(missing),
        invalid_artifacts=tuple(invalid),
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
