from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from xml.etree import ElementTree

LabEvidenceStatus = Literal["qualified", "preview", "blocked"]


def collect_lab_evidence(
    *,
    junit_path: Path,
    output_path: Path,
    lab_metadata: Mapping[str, object],
    status: LabEvidenceStatus = "preview",
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "status": status,
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "lab": _sanitized_lab_metadata(lab_metadata),
        "test_runs": _test_runs_from_junit(junit_path),
        "promoted_tools": [],
        "operator_notes": [_generated_note()],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def _test_runs_from_junit(junit_path: Path) -> list[dict[str, object]]:
    root = ElementTree.fromstring(  # noqa: S314 - parses local pytest JUnit output.
        junit_path.read_text(encoding="utf-8")
    )
    suites = [root] if root.tag == "testsuite" else list(root.findall(".//testsuite"))
    runs: list[dict[str, object]] = []
    for suite in suites:
        tests = _int_attr(suite, "tests")
        skipped = _int_attr(suite, "skipped")
        failed = _int_attr(suite, "failures") + _int_attr(suite, "errors")
        passed = max(tests - skipped - failed, 0)
        status = "failed" if failed else "skipped" if skipped else "passed"
        runs.append(
            {
                "name": suite.attrib.get("name", "lab tests"),
                "status": status,
                "passed": passed,
                "skipped": skipped,
                "failed": failed,
            }
        )
    if runs:
        return runs
    return [{"name": "lab tests", "status": "skipped", "passed": 0, "skipped": 1, "failed": 0}]


def _sanitized_lab_metadata(metadata: Mapping[str, object]) -> dict[str, object]:
    blocked_keys = {"password", "token", "secret", "cookie", "authorization", "bearer"}
    sanitized: dict[str, object] = {}
    for key, value in metadata.items():
        normalized = key.lower()
        if any(blocked in normalized for blocked in blocked_keys):
            continue
        if isinstance(value, str) and value:
            sanitized[key] = value
        elif isinstance(value, bool):
            sanitized[key] = value
        elif isinstance(value, list):
            sanitized[key] = [item for item in value if isinstance(item, str) and item]
    sanitized.setdefault("endpoint", "generated-lab-evidence")
    sanitized.setdefault("node", "unknown")
    return sanitized


def _int_attr(element: ElementTree.Element, name: str) -> int:
    try:
        return int(element.attrib.get(name, "0"))
    except ValueError:
        return 0


def _generated_note() -> str:
    return "Generated from sanitized lab metadata and pytest JUnit output; credentials are omitted."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect sanitized Proxmox lab evidence.")
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    parser.add_argument("--status", choices=("qualified", "preview", "blocked"), default="preview")
    args = parser.parse_args(argv)
    metadata = cast(
        dict[str, object],
        json.loads(args.preflight.read_text(encoding="utf-8")),
    )
    collect_lab_evidence(
        junit_path=args.junit,
        output_path=args.output_file,
        lab_metadata=metadata,
        status=cast(LabEvidenceStatus, args.status),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
