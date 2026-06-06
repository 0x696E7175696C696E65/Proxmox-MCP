from __future__ import annotations

import json
from pathlib import Path

from scripts.validate_release_evidence import validate_release_evidence


def test_release_evidence_validation_reports_missing_required_artifacts(tmp_path: Path) -> None:
    result = validate_release_evidence(tmp_path)

    assert not result.valid
    assert "migration-validation.json" in result.missing_artifacts
    assert "sbom.spdx.json" in result.missing_artifacts
    assert "trivy-image-results.sarif" in result.missing_artifacts
    assert "compatibility-report.json" in result.missing_artifacts
    assert "lab-evidence.json" in result.missing_artifacts


def test_release_evidence_validation_accepts_complete_artifact_set(tmp_path: Path) -> None:
    artifacts: dict[str, dict[str, object]] = {
        "ci-success.json": {"status": "success"},
        "distribution-summary.json": {"status": "success"},
        "hardening-summary.json": {"status": "success"},
        "migration-validation.json": {"status": "success"},
        "sbom.spdx.json": {"spdxVersion": "SPDX-2.3"},
        "trivy-image-results.sarif": {"version": "2.1.0", "runs": list[object]()},
        "compatibility-report.json": {"status": "qualified"},
        "lab-evidence.json": {"status": "qualified"},
    }
    for name, payload in artifacts.items():
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")

    result = validate_release_evidence(tmp_path)

    assert result.valid
    assert result.missing_artifacts == ()
