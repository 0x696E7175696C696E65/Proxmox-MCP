from __future__ import annotations

from pathlib import Path


def test_public_preview_documentation_artifacts_exist() -> None:
    for relative_path in (
        "README.md",
        "docs/release-hardening.md",
        "docs/proxmox-compatibility.md",
        "docs/release-evidence/compatibility-report.example.json",
        "docs/release-evidence/lab-evidence.example.json",
    ):
        assert Path(relative_path).is_file()


def test_readme_presents_preview_status_without_ga_claims() -> None:
    readme = Path("README.md").read_text(encoding="utf-8").lower()

    assert "status-preview_ready" in readme
    assert "actively developed public preview" in readme
    assert "not yet certified for unattended production control" in readme
    assert "production-ready" not in readme
    assert "status-ga" not in readme
