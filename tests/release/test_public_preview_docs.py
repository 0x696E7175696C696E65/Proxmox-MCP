from __future__ import annotations

from pathlib import Path


def test_public_preview_documentation_artifacts_exist() -> None:
    for relative_path in (
        "README.md",
        "docs/release-hardening.md",
        "docs/lab-runbook.md",
        "docs/proxmox-compatibility.md",
        "docs/release-candidate-notes.md",
        "docs/release-evidence/compatibility-report.example.json",
        "docs/release-evidence/lab-evidence.example.json",
    ):
        assert Path(relative_path).is_file()


def test_readme_presents_preview_status_without_ga_claims() -> None:
    readme = Path("README.md").read_text(encoding="utf-8").lower()

    assert "status-public_preview" in readme
    assert "actively developed, evidence-backed public preview" in readme
    assert "not certified for unattended production control" in readme
    assert "production-ready" not in readme
    assert "status-ga" not in readme


def test_release_candidate_notes_separate_claim_categories() -> None:
    notes = Path("docs/release-candidate-notes.md").read_text(encoding="utf-8").lower()

    assert "preview capabilities" in notes
    assert "profile-gated capabilities" in notes
    assert "operator-qualified deployment gates" in notes
    assert "still-guarded capabilities" in notes
    assert "artifact-manifest.json" in notes
    assert "verify_backup" in notes
    assert "apply_node_updates" in notes
