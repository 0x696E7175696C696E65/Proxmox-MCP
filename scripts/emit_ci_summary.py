from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def emit_ci_summary(
    output_path: Path,
    *,
    workflow: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "workflow": workflow,
        "status": status,
        "generated_at": datetime.now(UTC).isoformat(),
        "details": {} if details is None else details,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit sanitized CI or hardening summary JSON.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--status", choices=("success", "failure"), required=True)
    parser.add_argument("--detail", action="append", default=[], help="key=value detail entries")
    args = parser.parse_args(argv)

    details: dict[str, Any] = {}
    for entry in args.detail:
        key, _, value = entry.partition("=")
        details[key] = value

    emit_ci_summary(args.output, workflow=args.workflow, status=args.status, details=details)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
