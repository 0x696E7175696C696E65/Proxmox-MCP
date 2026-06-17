from __future__ import annotations

import json
from pathlib import Path

from scripts.emit_ci_summary import emit_ci_summary


def test_emit_ci_summary_writes_schema_versioned_payload(tmp_path: Path) -> None:
    output_path = tmp_path / "ci-success.json"

    payload = emit_ci_summary(
        output_path,
        workflow="ci",
        status="success",
        details={"gate": "sqlite"},
    )

    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert written["workflow"] == "ci"
    assert written["status"] == "success"
    assert written["details"] == {"gate": "sqlite"}
    assert payload["schema_version"] == 1
