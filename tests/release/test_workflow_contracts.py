from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml


def _workflow(path: str) -> dict[str, Any]:
    return cast(dict[str, Any], yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def _steps(workflow: dict[str, Any], job_name: str) -> list[dict[str, Any]]:
    jobs = cast(dict[str, Any], workflow["jobs"])
    job = cast(dict[str, Any], jobs[job_name])
    return cast(list[dict[str, Any]], job["steps"])


def test_ci_runs_secret_scan_and_manifest_contracts() -> None:
    workflow = _workflow(".github/workflows/ci.yml")
    runtime_steps = _steps(workflow, "runtime-checks")
    step_names = {cast(str, step.get("name", "")) for step in runtime_steps}
    run_commands = "\n".join(
        cast(str, step.get("run", "")) for step in runtime_steps if "run" in step
    )
    action_uses = "\n".join(
        cast(str, step.get("uses", "")) for step in runtime_steps if "uses" in step
    )

    assert "Secret scan" in step_names
    assert "Manifest and release gate validation" in step_names
    assert "gitleaks" in action_uses.lower()
    assert "tests/deploy/test_kubernetes_manifest.py" in run_commands
    assert "tests/release/test_workflow_contracts.py" in run_commands


def test_workflows_opt_into_node_24_actions_runtime() -> None:
    for workflow_path in (
        ".github/workflows/ci.yml",
        ".github/workflows/distribution.yml",
        ".github/workflows/hardening.yml",
        ".github/workflows/release-candidate.yml",
    ):
        workflow = _workflow(workflow_path)
        workflow_env = cast(dict[str, Any], workflow.get("env", {}))

        assert workflow_env["FORCE_JAVASCRIPT_ACTIONS_TO_NODE24"] == "true"


def test_hardening_validates_migrations_against_postgresql() -> None:
    workflow = _workflow(".github/workflows/hardening.yml")
    jobs = cast(dict[str, Any], workflow["jobs"])
    migration_job = cast(dict[str, Any], jobs["migration-validation"])
    services = cast(dict[str, Any], migration_job["services"])
    steps = _steps(workflow, "migration-validation")
    run_commands = "\n".join(cast(str, step.get("run", "")) for step in steps if "run" in step)
    step_env = {key for step in steps for key in cast(dict[str, Any], step.get("env", {}))}

    assert "postgres" in services
    assert "PROXMOX_MCP_TEST_POSTGRES_URL" in step_env
    assert "test_alembic_upgrade_creates_schema_matching_postgresql" in run_commands


def test_release_candidate_workflow_requires_evidence_artifacts() -> None:
    workflow = _workflow(".github/workflows/release-candidate.yml")
    jobs = cast(dict[str, Any], workflow["jobs"])
    validate_job = cast(dict[str, Any], jobs["validate-release-evidence"])
    run_commands = "\n".join(
        cast(str, step.get("run", ""))
        for step in cast(list[dict[str, Any]], validate_job["steps"])
        if "run" in step
    )

    assert "scripts/validate_release_evidence.py" in run_commands
    assert "--evidence-dir" in run_commands


def test_hardening_uses_resolvable_pinned_trivy_action() -> None:
    workflow = _workflow(".github/workflows/hardening.yml")
    steps = _steps(workflow, "docker-build")
    action_refs = {
        cast(str, step.get("uses", ""))
        for step in steps
        if str(step.get("uses", "")).startswith("aquasecurity/trivy-action@")
    }

    assert action_refs == {"aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25"}


def test_hardening_image_scan_fails_on_actionable_fixed_vulnerabilities() -> None:
    workflow = _workflow(".github/workflows/hardening.yml")
    scan_steps = [
        step
        for step in _steps(workflow, "docker-build")
        if cast(str, step.get("name", "")) == "Scan image"
    ]

    assert len(scan_steps) == 1
    scan_config = cast(dict[str, str], scan_steps[0]["with"])
    assert scan_config["severity"] == "CRITICAL,HIGH"
    assert scan_config["exit-code"] == "1"
    assert scan_config["ignore-unfixed"] == "true"
