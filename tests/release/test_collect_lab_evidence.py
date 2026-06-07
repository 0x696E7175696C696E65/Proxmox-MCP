from __future__ import annotations

import json
from pathlib import Path

from scripts.collect_lab_evidence import collect_lab_evidence


def test_collect_lab_evidence_from_junit_and_preflight_metadata(tmp_path: Path) -> None:
    junit = tmp_path / "lab-junit.xml"
    junit.write_text(
        """
        <testsuites>
          <testsuite name="tests.lab.read_only" tests="3" failures="0" errors="0" skipped="1" />
          <testsuite name="tests.lab.node_update" tests="1" failures="0" errors="0" skipped="0" />
        </testsuites>
        """,
        encoding="utf-8",
    )
    preflight = {
        "endpoint": "https://pve.example.test:8006",
        "node": "pve-a",
        "profile": "pve-9-single-node-no-ceph",
        "proxmox_version": "9.1.1",
        "storage_ids": ["local", "local-lvm"],
        "tls_verify": False,
    }
    output = tmp_path / "lab-evidence.json"

    evidence = collect_lab_evidence(
        junit_path=junit,
        output_path=output,
        lab_metadata=preflight,
        status="preview",
    )

    assert output.is_file()
    assert evidence["schema_version"] == 1
    assert evidence["status"] == "preview"
    assert evidence["lab"]["profile"] == "pve-9-single-node-no-ceph"
    assert evidence["test_runs"] == [
        {
            "name": "tests.lab.read_only",
            "status": "skipped",
            "passed": 2,
            "skipped": 1,
            "failed": 0,
        },
        {
            "name": "tests.lab.node_update",
            "status": "passed",
            "passed": 1,
            "skipped": 0,
            "failed": 0,
        },
    ]
    assert "password" not in output.read_text(encoding="utf-8").lower()


def test_generated_lab_evidence_validates_with_release_schema(tmp_path: Path) -> None:
    junit = tmp_path / "lab-junit.xml"
    junit.write_text(
        '<testsuite name="read-only lab smoke" tests="1" failures="0" errors="0" skipped="0" />',
        encoding="utf-8",
    )
    collect_lab_evidence(
        junit_path=junit,
        output_path=tmp_path / "lab-evidence.json",
        lab_metadata={
            "endpoint": "https://pve.example.test:8006",
            "node": "pve-a",
            "profile": "pve-9-single-node-no-ceph",
        },
        status="preview",
    )

    lab_evidence = json.loads((tmp_path / "lab-evidence.json").read_text(encoding="utf-8"))

    assert lab_evidence["promoted_tools"] == []
