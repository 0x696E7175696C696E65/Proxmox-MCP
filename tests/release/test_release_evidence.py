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
        "compatibility-report.json": _compatibility_report(),
        "lab-evidence.json": _lab_evidence(),
    }
    for name, payload in artifacts.items():
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8")

    result = validate_release_evidence(tmp_path)

    assert result.valid
    assert result.missing_artifacts == ()


def test_release_evidence_validation_rejects_weak_compatibility_report(
    tmp_path: Path,
) -> None:
    _write_complete_artifacts(tmp_path, compatibility_report={"status": "qualified"})

    result = validate_release_evidence(tmp_path)

    assert not result.valid
    assert "compatibility-report.json" in result.invalid_artifacts


def test_release_evidence_validation_rejects_lab_evidence_with_secrets(
    tmp_path: Path,
) -> None:
    lab_evidence = _lab_evidence()
    lab_evidence["lab"] = {
        "endpoint": "https://pve.example.test:8006",
        "node": "test",
        "password": "redacted-but-forbidden-key",
    }
    _write_complete_artifacts(tmp_path, lab_evidence=lab_evidence)

    result = validate_release_evidence(tmp_path)

    assert not result.valid
    assert "lab-evidence.json" in result.invalid_artifacts


def test_release_evidence_validation_rejects_qualified_failed_lab_run(
    tmp_path: Path,
) -> None:
    lab_evidence = _lab_evidence()
    lab_evidence["status"] = "qualified"
    lab_evidence["test_runs"] = [
        {
            "name": "read-only lab smoke",
            "status": "skipped",
            "passed": 0,
            "skipped": 6,
            "failed": 0,
        }
    ]
    _write_complete_artifacts(tmp_path, lab_evidence=lab_evidence)

    result = validate_release_evidence(tmp_path)

    assert not result.valid
    assert "lab-evidence.json" in result.invalid_artifacts


def test_release_evidence_validation_rejects_qualified_placeholder_compatibility(
    tmp_path: Path,
) -> None:
    compatibility_report = _compatibility_report()
    compatibility_report["status"] = "qualified"
    compatibility_report["matrix"] = [
        {
            "proxmox_version": "Proxmox VE 8.x",
            "topology": "multi-node",
            "evidence_status": "not_yet_claimed",
            "evidence_artifacts": ["operator-lab-run-required"],
        }
    ]
    _write_complete_artifacts(tmp_path, compatibility_report=compatibility_report)

    result = validate_release_evidence(tmp_path)

    assert not result.valid
    assert "compatibility-report.json" in result.invalid_artifacts


def test_release_evidence_examples_match_validator_schema(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    compatibility_report = json.loads(
        (repo_root / "docs/release-evidence/compatibility-report.example.json").read_text(
            encoding="utf-8"
        )
    )
    lab_evidence = json.loads(
        (repo_root / "docs/release-evidence/lab-evidence.example.json").read_text(encoding="utf-8")
    )
    _write_complete_artifacts(
        tmp_path,
        compatibility_report=compatibility_report,
        lab_evidence=lab_evidence,
    )

    result = validate_release_evidence(tmp_path)

    assert result.valid


def _write_complete_artifacts(
    path: Path,
    *,
    compatibility_report: dict[str, object] | None = None,
    lab_evidence: dict[str, object] | None = None,
) -> None:
    artifacts: dict[str, dict[str, object]] = {
        "ci-success.json": {"status": "success"},
        "distribution-summary.json": {"status": "success"},
        "hardening-summary.json": {"status": "success"},
        "migration-validation.json": {"status": "success"},
        "sbom.spdx.json": {"spdxVersion": "SPDX-2.3"},
        "trivy-image-results.sarif": {"version": "2.1.0", "runs": list[object]()},
        "compatibility-report.json": compatibility_report or _compatibility_report(),
        "lab-evidence.json": lab_evidence or _lab_evidence(),
    }
    for name, payload in artifacts.items():
        (path / name).write_text(json.dumps(payload), encoding="utf-8")


def _compatibility_report() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "preview",
        "generated_at": "2026-06-06T00:00:00Z",
        "matrix": [
            {
                "proxmox_version": "fresh Proxmox VE lab",
                "topology": "single-node",
                "evidence_status": "preview_lab_evidence",
                "evidence_artifacts": ["lab-evidence.json"],
            }
        ],
    }


def _lab_evidence() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "preview",
        "generated_at": "2026-06-06T00:00:00Z",
        "lab": {
            "endpoint": "https://pve.example.test:8006",
            "node": "test",
        },
        "test_runs": [
            {
                "name": "read-only smoke",
                "status": "passed",
                "passed": 5,
                "skipped": 1,
                "failed": 0,
            }
        ],
        "promoted_tools": [
            {
                "tool": "enter_lxc_console",
                "status": "live_supported",
                "evidence": "durable session and recording contract tests",
            }
        ],
    }
