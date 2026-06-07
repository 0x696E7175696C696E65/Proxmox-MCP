from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

try:
    from scripts.collect_lab_evidence import collect_lab_evidence
    from scripts.validate_release_evidence import REQUIRED_ARTIFACTS
except ModuleNotFoundError:  # pragma: no cover - exercised by path-based CLI invocation
    from collect_lab_evidence import collect_lab_evidence
    from validate_release_evidence import REQUIRED_ARTIFACTS


def collect_release_evidence(source_dir: Path, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    _generate_lab_evidence_when_present(source_dir, output_dir)
    artifacts: dict[str, dict[str, object]] = {}
    for artifact in REQUIRED_ARTIFACTS:
        if artifact == "artifact-manifest.json":
            continue
        source = source_dir / artifact
        target = output_dir / artifact
        if source.is_file() and source.resolve() != target.resolve():
            shutil.copy2(source, target)
        if target.is_file():
            artifacts[artifact] = {
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                "size_bytes": target.stat().st_size,
            }

    manifest: dict[str, Any] = {
        "schema_version": 1,
        "artifacts": artifacts,
    }
    (output_dir / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def _generate_lab_evidence_when_present(source_dir: Path, output_dir: Path) -> None:
    if (source_dir / "lab-evidence.json").is_file() or (output_dir / "lab-evidence.json").is_file():
        return
    junit_path = source_dir / "lab-junit.xml"
    preflight_path = source_dir / "lab-preflight.json"
    if not junit_path.is_file() or not preflight_path.is_file():
        return
    metadata = json.loads(preflight_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        return
    collect_lab_evidence(
        junit_path=junit_path,
        output_path=output_dir / "lab-evidence.json",
        lab_metadata=metadata,
        status="preview",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect sanitized release evidence artifacts.")
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    collect_release_evidence(args.source_dir, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
