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


def test_release_evidence_validation_rejects_missing_release_summary(
    tmp_path: Path,
) -> None:
    compatibility_report = _compatibility_report()
    compatibility_report.pop("release_summary")
    _write_complete_artifacts(tmp_path, compatibility_report=compatibility_report)

    result = validate_release_evidence(tmp_path)

    assert not result.valid
    assert "compatibility-report.json" in result.invalid_artifacts


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


def test_release_evidence_validation_rejects_unknown_profile_name(
    tmp_path: Path,
) -> None:
    compatibility_report = _compatibility_report()
    compatibility_report["matrix"] = [
        {
            "proxmox_version": "Proxmox VE 9.1.1",
            "topology": "single-node",
            "profile": "pve-10-unknown",
            "evidence_status": "preview_lab_evidence",
            "evidence_artifacts": ["lab-evidence.json"],
        }
    ]
    _write_complete_artifacts(tmp_path, compatibility_report=compatibility_report)

    result = validate_release_evidence(tmp_path)

    assert not result.valid
    assert "compatibility-report.json" in result.invalid_artifacts


def test_release_evidence_validation_rejects_qualified_missing_required_profile_run(
    tmp_path: Path,
) -> None:
    compatibility_report = _compatibility_report()
    compatibility_report["status"] = "qualified"
    compatibility_report["matrix"] = [
        {
            "proxmox_version": "Proxmox VE 9.1.1",
            "topology": "single-node",
            "profile": "pve-9-single-node-no-ceph",
            "evidence_status": "qualified",
            "evidence_artifacts": ["lab-evidence.json"],
        }
    ]
    compatibility_report["profiles"] = [
        {
            "name": "pve-9-single-node-no-ceph",
            "status": "qualified",
            "required_tests": ["read-only smoke", "registered MCP read tool smoke"],
            "optional_tests": [],
            "expected_skips": [],
        }
    ]
    lab_evidence = _lab_evidence()
    lab_evidence["status"] = "qualified"
    lab_evidence["lab"] = {
        "endpoint": "https://pve.example.test:8006",
        "node": "test",
        "profile": "pve-9-single-node-no-ceph",
    }

    _write_complete_artifacts(
        tmp_path,
        compatibility_report=compatibility_report,
        lab_evidence=lab_evidence,
    )

    result = validate_release_evidence(tmp_path)

    assert not result.valid
    assert "lab-evidence.json" in result.invalid_artifacts


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


def test_release_evidence_examples_record_current_pve_9_lab_result() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    compatibility_report = json.loads(
        (repo_root / "docs/release-evidence/compatibility-report.example.json").read_text(
            encoding="utf-8"
        )
    )
    lab_evidence = json.loads(
        (repo_root / "docs/release-evidence/lab-evidence.example.json").read_text(encoding="utf-8")
    )

    matrix = compatibility_report["matrix"]
    pve_9_row = next(row for row in matrix if row["proxmox_version"] == "Proxmox VE 9.1.1")
    assert pve_9_row["profile"] == "pve-9-single-node-no-ceph"
    assert pve_9_row["evidence_status"] == "preview_lab_evidence"
    profiles = {profile["name"]: profile for profile in compatibility_report["profiles"]}
    assert profiles["pve-9-single-node-no-ceph"]["status"] == "preview"
    assert (
        "LXC lifecycle when no template exists"
        in profiles["pve-9-single-node-no-ceph"]["expected_skips"]
    )

    lab = lab_evidence["lab"]
    assert lab["proxmox_version"] == "9.1.1"
    assert lab["profile"] == "pve-9-single-node-no-ceph"
    assert lab["node"] == "test"
    assert lab["storage_ids"] == ["local", "local-lvm"]
    assert "username" not in lab
    assert all(
        "profile" not in row or not str(row["profile"]).startswith("pve-9-")
        for row in matrix
        if row["proxmox_version"] == "Proxmox VE 8.x"
    )

    runs = {run["name"]: run for run in lab_evidence["test_runs"]}
    assert runs["read-only lab smoke"]["passed"] == 4
    assert runs["read-only lab smoke"]["skipped"] == 1
    assert runs["disposable VM mutation smoke"]["passed"] == 1
    assert runs["registered MCP read tool smoke"]["passed"] == 4
    assert runs["LXC smoke"]["status"] == "skipped"
    assert runs["backup create/list smoke"]["passed"] == 2
    assert runs["storage profile smoke"]["passed"] == 3


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
        "release_summary": {
            "ci": "success",
            "hardening": "success",
            "distribution": "success",
            "sbom": "present",
            "trivy": "success",
            "lab": "preview",
            "migration": "success",
        },
        "matrix": [
            {
                "proxmox_version": "fresh Proxmox VE lab",
                "topology": "single-node",
                "profile": "pve-9-single-node-no-ceph",
                "evidence_status": "preview_lab_evidence",
                "evidence_artifacts": ["lab-evidence.json"],
            }
        ],
        "profiles": [
            {
                "name": "pve-9-single-node-no-ceph",
                "status": "preview",
                "required_tests": ["read-only smoke"],
                "optional_tests": [],
                "expected_skips": ["Ceph status when Ceph is not installed"],
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
            "profile": "pve-9-single-node-no-ceph",
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
