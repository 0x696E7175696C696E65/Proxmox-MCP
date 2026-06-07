from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

from scripts.collect_release_evidence import collect_release_evidence


def test_collect_release_evidence_writes_manifest_with_hashes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    source_artifacts: dict[str, dict[str, object]] = {
        "ci-success.json": {"status": "success"},
        "distribution-summary.json": {"status": "success"},
        "hardening-summary.json": {"status": "success"},
        "migration-validation.json": {"status": "success"},
        "sbom.spdx.json": {"spdxVersion": "SPDX-2.3"},
        "trivy-image-results.sarif": {"version": "2.1.0", "runs": []},
        "compatibility-report.json": {"schema_version": 1, "status": "preview"},
        "lab-evidence.json": {"schema_version": 1, "status": "preview"},
    }
    for name, payload in source_artifacts.items():
        (source / name).write_text(json.dumps(payload), encoding="utf-8")

    manifest = collect_release_evidence(source, target)
    artifacts = cast(dict[str, dict[str, object]], manifest["artifacts"])

    assert (target / "artifact-manifest.json").is_file()
    assert sorted(artifacts) == sorted(
        name for name in artifacts if name != "artifact-manifest.json"
    )
    assert "ci-success.json" in artifacts
    assert len(cast(str, artifacts["ci-success.json"]["sha256"])) == 64
    assert (target / "ci-success.json").is_file()


def test_collect_release_evidence_generates_lab_evidence_when_junit_present(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    generated_source_artifacts: dict[str, object] = {
        "ci-success.json": {"status": "success"},
        "distribution-summary.json": {"status": "success"},
        "hardening-summary.json": {"status": "success"},
        "migration-validation.json": {"status": "success"},
        "sbom.spdx.json": {"spdxVersion": "SPDX-2.3"},
        "trivy-image-results.sarif": {"version": "2.1.0", "runs": []},
        "compatibility-report.json": {"schema_version": 1, "status": "preview"},
    }
    for name, payload in generated_source_artifacts.items():
        (source / name).write_text(json.dumps(payload), encoding="utf-8")
    (source / "lab-preflight.json").write_text(
        json.dumps(
            {
                "endpoint": "https://pve.example.test:8006",
                "node": "pve-a",
                "profile": "pve-9-single-node-no-ceph",
            }
        ),
        encoding="utf-8",
    )
    (source / "lab-junit.xml").write_text(
        '<testsuite name="read-only lab smoke" tests="1" failures="0" errors="0" skipped="0" />',
        encoding="utf-8",
    )

    manifest = collect_release_evidence(source, target)

    lab_evidence = json.loads((target / "lab-evidence.json").read_text(encoding="utf-8"))
    artifacts = cast(dict[str, dict[str, object]], manifest["artifacts"])
    assert lab_evidence["test_runs"][0]["name"] == "read-only lab smoke"
    assert "lab-evidence.json" in artifacts


def test_collect_release_evidence_cli_runs_when_invoked_by_path(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    for name in (
        "ci-success.json",
        "distribution-summary.json",
        "hardening-summary.json",
        "migration-validation.json",
        "sbom.spdx.json",
        "trivy-image-results.sarif",
        "compatibility-report.json",
        "lab-evidence.json",
    ):
        (source / name).write_text("{}", encoding="utf-8")

    result = subprocess.run(  # noqa: S603 - fixed interpreter/script invocation in test
        [
            sys.executable,
            "scripts/collect_release_evidence.py",
            "--source-dir",
            str(source),
            "--output-dir",
            str(target),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert (target / "artifact-manifest.json").is_file()
