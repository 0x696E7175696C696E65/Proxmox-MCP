from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field

from proxmox_mcp.schemas.envelope import ToolRequest
from proxmox_mcp.ssh.client import SshClientError, SshCommand, SshTarget
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolExecutionError, ToolRegistry

PRIMARY_HELPER_REPO = "https://github.com/community-scripts/ProxmoxVE"
FALLBACK_HELPER_REPO = "https://github.com/0x696E7175696C696E65/ProxmoxVE"
_HELPER_DIRS = ("ct", "vm", "install", "tools", "misc", "turnkey")
_SAFE_SCRIPT_ID = re.compile(r"^(ct|vm|install|tools|misc|turnkey)/[A-Za-z0-9_.@+/-]+\.sh$")
_SAFE_HELPER_ENV_KEY = re.compile(r"^(?:TERM|mode|var_[A-Za-z0-9_]{1,80})$")
_SAFE_HELPER_ENV_VALUE = re.compile(r"^[A-Za-z0-9_.:/@+;=,-]{0,256}$")
_REMOTE_SOURCE = re.compile(
    r"source\s+<\(\s*(?:curl|wget)\s+[^)]*?"
    r"(https://raw\.githubusercontent\.com/[^)\s]+)\s*\)"
)
_MAX_SCRIPT_BYTES = 2_000_000
_MAX_HELPER_DEPENDENCY_DEPTH = 4
_RISK_PATTERNS: tuple[tuple[str, str], ...] = (
    ("remote_source_execution", r"source\s+<\(\s*(curl|wget)\s+"),
    ("remote_pipe_execution", r"(curl|wget)[^\n|]*\|\s*(bash|sh)"),
    ("package_source_change", r"(/etc/apt/sources\.list|apt-key|signed-by=)"),
    ("ssh_key_change", r"(authorized_keys|ssh-keygen|/etc/ssh/)"),
    ("firewall_change", r"(iptables|nft\s|ufw\s|pve-firewall)"),
    ("disk_destructive", r"(wipefs|sgdisk|parted|mkfs\.|dd\s+if=)"),
)


class HelperScriptSourceError(RuntimeError):
    pass


class HelperScript(BaseModel):
    model_config = ConfigDict(extra="forbid")

    script_id: str
    name: str
    category: str
    path: str
    download_url: str
    blob_sha: str
    size: int = Field(ge=0)
    sha256: str | None = None
    risk_hints: tuple[str, ...] = ()


class HelperScriptCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_repo: str
    source_commit: str
    fallback_used: bool
    scripts: tuple[HelperScript, ...]


class HelperCatalogParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SearchHelperParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str | None = None
    category: str | None = None


class ScriptIdParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    script_id: str = Field(min_length=1)


class StageHelperParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    script_id: str = Field(min_length=1)
    sha256: str | None = None


class ExecuteHelperParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    script_id: str = Field(min_length=1)
    sha256: str | None = None
    mode: Literal["default", "generated"] = "default"
    environment: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=900, ge=1, le=3600)
    max_output_bytes: int = Field(default=4096, ge=0, le=65536)


class RunHelperAppInstallParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str | None = Field(default=None, min_length=1)
    script_id: str | None = Field(default=None, min_length=1)
    sha256: str | None = None
    mode: Literal["default", "generated"] = "generated"
    environment: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=900, ge=1, le=3600)


class HelperExecutionLookupParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(min_length=1)


class HelperScriptSource(Protocol):
    repo_url: str

    async def load_catalog(self, *, fallback_used: bool) -> HelperScriptCatalog: ...

    async def fetch_content(self, script: HelperScript, source_commit: str) -> str: ...


class HelperScriptCatalogProvider(Protocol):
    async def load_catalog(self) -> HelperScriptCatalog: ...

    async def fetch_script_content(
        self, script_id: str
    ) -> tuple[HelperScriptCatalog, HelperScript, str]: ...


@dataclass(frozen=True, slots=True)
class GitHubHelperScriptSource:
    repo_url: str
    owner: str
    repo: str
    ref: str = "main"

    async def load_catalog(self, *, fallback_used: bool) -> HelperScriptCatalog:
        commit = await asyncio.to_thread(_fetch_json, self._api_url(f"commits/{self.ref}"))
        source_commit = _commit_sha(commit)
        scripts: list[HelperScript] = []
        for directory in _HELPER_DIRS:
            try:
                entries = await asyncio.to_thread(
                    _fetch_json,
                    self._api_url(f"contents/{directory}?ref={source_commit}"),
                )
            except HelperScriptSourceError:
                continue
            if not isinstance(entries, list):
                continue
            for entry in cast(list[object], entries):
                script = _script_from_entry(entry, source_commit)
                if script is not None:
                    scripts.append(script)
        return HelperScriptCatalog(
            source_repo=self.repo_url,
            source_commit=source_commit,
            fallback_used=fallback_used,
            scripts=tuple(scripts),
        )

    async def fetch_content(self, script: HelperScript, source_commit: str) -> str:
        _validate_allowed_raw_url(script.download_url, source_commit)
        return await asyncio.to_thread(_fetch_text, script.download_url)

    def _api_url(self, path: str) -> str:
        return f"https://api.github.com/repos/{self.owner}/{self.repo}/{path}"


class HelperScriptCatalogResolver:
    def __init__(
        self,
        *,
        primary: HelperScriptSource | None = None,
        fallback: HelperScriptSource | None = None,
    ) -> None:
        self.primary = primary or GitHubHelperScriptSource(
            repo_url=PRIMARY_HELPER_REPO,
            owner="community-scripts",
            repo="ProxmoxVE",
        )
        self.fallback = fallback or GitHubHelperScriptSource(
            repo_url=FALLBACK_HELPER_REPO,
            owner="0x696E7175696C696E65",
            repo="ProxmoxVE",
        )

    async def load_catalog(self) -> HelperScriptCatalog:
        try:
            return await self.primary.load_catalog(fallback_used=False)
        except HelperScriptSourceError:
            return await self.fallback.load_catalog(fallback_used=True)

    async def fetch_script_content(
        self, script_id: str
    ) -> tuple[HelperScriptCatalog, HelperScript, str]:
        _validate_script_id(script_id)
        catalog = await self.load_catalog()
        script = _script_by_id(catalog.scripts, script_id)
        content = await (self.fallback if catalog.fallback_used else self.primary).fetch_content(
            script,
            catalog.source_commit,
        )
        content = await _prepare_helper_artifact_content(
            content,
            source_repo=catalog.source_repo,
            source_commit=catalog.source_commit,
        )
        if len(content.encode("utf-8")) > _MAX_SCRIPT_BYTES:
            raise HelperScriptSourceError("helper script exceeds maximum allowed size")
        sha = sha256(content.encode("utf-8")).hexdigest()
        script = script.model_copy(update={"sha256": sha, "risk_hints": _risk_hints_for(content)})
        return catalog, script, content


def register_helper_script_tools(
    registry: ToolRegistry,
    *,
    catalog_resolver: HelperScriptCatalogProvider | None = None,
) -> None:
    resolver = catalog_resolver or HelperScriptCatalogResolver()
    registry.register(
        ToolDefinition(
            name="sync_helper_script_catalog",
            description=(
                "Fetch/refresh the community-scripts helper catalog from the pinned upstream repo "
                "(with the maintainer fork as fallback). Read-only. Returns catalog metadata and "
                "the resolved commit."
            ),
            category="helpers",
            permission="helper.catalog.read",
            risk="low",
            dry_run=False,
            approval_default=False,
            connector="hybrid",
            parameters_model=HelperCatalogParameters,
            handler=lambda request, context: _sync_catalog(request, context, resolver),
        )
    )
    registry.register(
        ToolDefinition(
            name="search_helper_scripts",
            description=(
                "Read-only: search the helper-script catalog. Requires parameters.query. Returns "
                "matching scripts with script_id, name, and pinned sha256."
            ),
            category="helpers",
            permission="helper.catalog.read",
            risk="low",
            dry_run=False,
            approval_default=False,
            connector="hybrid",
            parameters_model=SearchHelperParameters,
            handler=lambda request, context: _search_catalog(request, context, resolver),
        )
    )
    registry.register(
        ToolDefinition(
            name="get_helper_script_details",
            description=(
                "Read-only: return metadata for one helper script. Requires parameters.script_id "
                "(e.g. ct/alpine.sh), including its pinned sha256 and detected risk hints."
            ),
            category="helpers",
            permission="helper.catalog.read",
            risk="low",
            dry_run=False,
            approval_default=False,
            connector="hybrid",
            parameters_model=ScriptIdParameters,
            handler=lambda request, context: _script_details(request, context, resolver),
        )
    )
    registry.register(
        ToolDefinition(
            name="preview_helper_script",
            description=(
                "Preview the resolved, pinned content of a helper script without executing it. "
                "Requires parameters.script_id. Dry-run only; returns the script body, sha256, and "
                "risk hints so you can review before staging/executing."
            ),
            category="helpers",
            permission="helper.script.preview",
            risk="medium",
            dry_run=True,
            approval_default=False,
            connector="hybrid",
            parameters_model=ScriptIdParameters,
            handler=lambda request, context: _preview_script(request, context, resolver),
        )
    )
    registry.register(
        ToolDefinition(
            name="stage_helper_script",
            description=(
                "High-risk: upload a pinned helper script to the target node over controlled SSH "
                "without running it. Requires parameters.script_id and parameters.sha256 (content "
                "pin). Dry-run by default; approval required. Target: SSH host."
            ),
            category="helpers",
            permission="helper.script.stage",
            risk="high",
            dry_run=True,
            approval_default=True,
            connector="ssh",
            parameters_model=StageHelperParameters,
            handler=lambda request, context: _stage_script(request, context, resolver),
        )
    )
    registry.register(
        ToolDefinition(
            name="execute_helper_script",
            description=(
                "CRITICAL: stage and run a pinned community helper script on the target node over "
                "controlled SSH. Requires parameters.script_id and parameters.sha256 (pins the "
                "exact reviewed content); optional mode, environment (allowlisted var_* keys), and "
                "timeout_seconds. Dry-run by default; approval required. Target: SSH host."
            ),
            category="helpers",
            permission="helper.script.execute",
            risk="critical",
            dry_run=True,
            approval_default=True,
            connector="ssh",
            parameters_model=ExecuteHelperParameters,
            handler=lambda request, context: _execute_script(request, context, resolver),
        )
    )
    registry.register(
        ToolDefinition(
            name="get_helper_script_execution",
            description=(
                "Look up a prior helper-script execution by parameters.execution_id. NOTE: "
                "execution persistence is not yet backed by a durable worker store, so this "
                "returns a 'not_persisted' status rather than live execution state."
            ),
            category="helpers",
            permission="helper.script.execution.read",
            risk="low",
            dry_run=False,
            approval_default=False,
            connector="internal",
            parameters_model=HelperExecutionLookupParameters,
            handler=_execution_not_persisted,
        )
    )
    registry.register(
        ToolDefinition(
            name="cancel_helper_script_execution",
            description=(
                "High-risk: request cancellation of a running helper-script execution by "
                "parameters.execution_id. NOTE: not yet backed by a durable execution store — "
                "currently reports 'not_persisted' and does not halt a running script."
            ),
            category="helpers",
            permission="helper.script.execution.cancel",
            risk="high",
            dry_run=True,
            approval_default=True,
            connector="internal",
            parameters_model=HelperExecutionLookupParameters,
            handler=_cancel_not_persisted,
        )
    )
    registry.register(
        ToolDefinition(
            name="run_helper_app_install",
            description=(
                "CRITICAL: high-level install of a community helper app on the target node over "
                "controlled SSH. Provide parameters.query or parameters.script_id; live runs "
                "require an exact script_id and sha256 pin. Optional mode, environment, "
                "timeout_seconds. Dry-run by default; approval required. Target: SSH host."
            ),
            category="helpers",
            permission="helper.script.execute",
            risk="critical",
            dry_run=True,
            approval_default=True,
            connector="ssh",
            parameters_model=RunHelperAppInstallParameters,
            handler=lambda request, context: _run_helper_app_install(request, context, resolver),
        )
    )


async def _sync_catalog(
    request: ToolRequest,
    context: ToolExecutionContext,
    resolver: HelperScriptCatalogProvider,
) -> dict[str, object]:
    _ = request, context
    return _catalog_payload(await _load_or_error(resolver))


async def _search_catalog(
    request: ToolRequest,
    context: ToolExecutionContext,
    resolver: HelperScriptCatalogProvider,
) -> dict[str, object]:
    _ = context
    parameters = SearchHelperParameters.model_validate(request.parameters)
    catalog = await _load_or_error(resolver)
    query = parameters.query.lower() if parameters.query else None
    category = parameters.category.lower() if parameters.category else None
    scripts = [
        script
        for script in catalog.scripts
        if (query is None or query in script.name.lower() or query in script.script_id.lower())
        and (category is None or script.category.lower() == category)
    ]
    return _catalog_payload(catalog, scripts=tuple(scripts))


async def _script_details(
    request: ToolRequest,
    context: ToolExecutionContext,
    resolver: HelperScriptCatalogProvider,
) -> dict[str, object]:
    _ = context
    parameters = ScriptIdParameters.model_validate(request.parameters)
    catalog = await _load_or_error(resolver)
    return {
        **_script_payload(_script_by_id(catalog.scripts, parameters.script_id)),
        "source_repo": catalog.source_repo,
        "source_commit": catalog.source_commit,
        "fallback_used": catalog.fallback_used,
    }


async def _preview_script(
    request: ToolRequest,
    context: ToolExecutionContext,
    resolver: HelperScriptCatalogProvider,
) -> dict[str, object]:
    _ = context
    parameters = ScriptIdParameters.model_validate(request.parameters)
    catalog, script, content = await _fetch_or_error(resolver, parameters.script_id)
    _record_helper_audit_metadata(context, catalog, script, _remote_path(script.sha256))
    return {
        **_script_payload(script),
        "source_repo": catalog.source_repo,
        "source_commit": catalog.source_commit,
        "fallback_used": catalog.fallback_used,
        "execution_status": "preview_only",
        "line_count": len(content.splitlines()),
    }


async def _stage_script(
    request: ToolRequest,
    context: ToolExecutionContext,
    resolver: HelperScriptCatalogProvider,
) -> dict[str, object]:
    parameters = StageHelperParameters.model_validate(request.parameters)
    catalog, script, content = await _fetch_or_error(resolver, parameters.script_id)
    _verify_expected_sha(parameters.sha256, script.sha256)
    remote_path = _remote_path(script.sha256)
    _record_helper_audit_metadata(context, catalog, script, remote_path)
    payload = _stage_payload(request, catalog, script, remote_path)
    if request.options.dry_run:
        return payload
    if context.ssh_client is None:
        raise ToolExecutionError(
            error_code="SSH_CONNECTION_FAILED",
            message="SSH client is not configured",
            retryable=True,
        )
    target = _ssh_target(request)
    directory = remote_path.rsplit("/", maxsplit=1)[0]
    try:
        await context.ssh_client.mkdir(target, remote_path=directory, parents=True)
        await context.ssh_client.upload(
            target,
            remote_path=remote_path,
            content=content,
            mode="0700",
            overwrite=True,
        )
    except SshClientError as exc:
        raise _tool_error_from_ssh(exc) from exc
    return payload | {"staged": True}


async def _execute_script(
    request: ToolRequest,
    context: ToolExecutionContext,
    resolver: HelperScriptCatalogProvider,
) -> dict[str, object]:
    parameters = ExecuteHelperParameters.model_validate(request.parameters)
    catalog, script, content = await _fetch_or_error(resolver, parameters.script_id)
    _ = content
    _verify_expected_sha(parameters.sha256, script.sha256)
    remote_path = _remote_path(script.sha256)
    _record_helper_audit_metadata(context, catalog, script, remote_path)
    environment = _validate_helper_environment(parameters.environment)
    command_text = _helper_command(remote_path, parameters.mode, environment)
    command = SshCommand(
        command=command_text,
        timeout_seconds=parameters.timeout_seconds,
        capture_stdout=True,
        capture_stderr=True,
    )
    policy = context.ssh_command_policy
    if policy is None:
        raise ToolExecutionError(
            error_code="POLICY_DENIED",
            message="Helper script execution requires an SSH command policy",
            retryable=False,
        )
    decision = policy.evaluate(command)
    if not decision.allowed:
        raise ToolExecutionError(
            error_code="POLICY_DENIED",
            message=decision.reason,
            retryable=False,
            details={"executable": decision.executable},
        )
    payload = _stage_payload(request, catalog, script, remote_path) | {
        "command": command_text,
        "mode": parameters.mode,
        "environment_keys": sorted(environment),
        "execution_status": "dry_run" if request.options.dry_run else "executed",
    }
    if request.options.dry_run:
        return payload
    if context.ssh_client is None:
        raise ToolExecutionError(
            error_code="SSH_CONNECTION_FAILED",
            message="SSH client is not configured",
            retryable=True,
        )
    target = _ssh_target(request)
    directory = remote_path.rsplit("/", maxsplit=1)[0]
    try:
        await context.ssh_client.mkdir(target, remote_path=directory, parents=True)
        await context.ssh_client.upload(
            target,
            remote_path=remote_path,
            content=content,
            mode="0700",
            overwrite=True,
        )
        result = await context.ssh_client.execute(target, command)
    except SshClientError as exc:
        raise _tool_error_from_ssh(exc) from exc
    return payload | {
        "exit_status": result.exit_status,
        "stdout_preview": _bounded_output(result.stdout, parameters.max_output_bytes),
        "stderr_preview": _bounded_output(result.stderr, parameters.max_output_bytes),
        "duration_ms": result.duration_ms,
    }


async def _run_helper_app_install(
    request: ToolRequest,
    context: ToolExecutionContext,
    resolver: HelperScriptCatalogProvider,
) -> dict[str, object]:
    parameters = RunHelperAppInstallParameters.model_validate(request.parameters)
    if not request.options.dry_run and (parameters.script_id is None or parameters.sha256 is None):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="Live helper app install requires exact script_id and sha256",
            retryable=False,
        )
    catalog = await _load_or_error(resolver)
    selected = _select_helper_app_script(catalog, parameters)
    catalog, selected, content = await _fetch_or_error(resolver, selected.script_id)
    _verify_expected_sha(parameters.sha256, selected.sha256)
    remote_path = _remote_path(selected.sha256)
    _record_helper_audit_metadata(context, catalog, selected, remote_path)
    if request.options.dry_run:
        return {
            **_stage_payload(request, catalog, selected, remote_path),
            "selected_script_id": selected.script_id,
            "execution_status": "preview_only",
            "line_count": len(content.splitlines()),
        }
    execute_request = request.model_copy(
        update={
            "parameters": {
                "script_id": selected.script_id,
                "sha256": selected.sha256,
                "mode": parameters.mode,
                "environment": parameters.environment,
                "timeout_seconds": parameters.timeout_seconds,
            }
        }
    )
    executed = await _execute_script(execute_request, context, resolver)
    return executed | {"selected_script_id": selected.script_id}


def _select_helper_app_script(
    catalog: HelperScriptCatalog,
    parameters: RunHelperAppInstallParameters,
) -> HelperScript:
    if parameters.script_id is not None:
        return _script_by_id(catalog.scripts, parameters.script_id)
    if parameters.query is None:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="query or script_id is required",
            retryable=False,
        )
    query = parameters.query.lower()
    matches = [
        script
        for script in catalog.scripts
        if query in script.name.lower() or query in script.script_id.lower()
    ]
    if not matches:
        raise ToolExecutionError(
            error_code="NOT_FOUND",
            message=f"No helper script matched query: {parameters.query}",
            retryable=False,
        )
    if len(matches) > 1:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="Helper query matched multiple scripts; use exact script_id",
            retryable=False,
        )
    return matches[0]


async def _execution_not_persisted(
    request: ToolRequest,
    context: ToolExecutionContext,
) -> dict[str, object]:
    parameters = HelperExecutionLookupParameters.model_validate(request.parameters)
    _ = context
    return {
        "execution_id": parameters.execution_id,
        "status": "not_persisted",
        "message": "Helper execution persistence is not yet backed by a durable worker store.",
    }


async def _cancel_not_persisted(
    request: ToolRequest,
    context: ToolExecutionContext,
) -> dict[str, object]:
    parameters = HelperExecutionLookupParameters.model_validate(request.parameters)
    _ = context
    return {
        "execution_id": parameters.execution_id,
        "dry_run": request.options.dry_run,
        "status": "not_persisted",
        "message": "Helper cancellation requires a durable execution worker store.",
    }


async def _load_or_error(resolver: HelperScriptCatalogProvider) -> HelperScriptCatalog:
    try:
        return await resolver.load_catalog()
    except HelperScriptSourceError as exc:
        raise ToolExecutionError(
            error_code="EXTERNAL_SOURCE_REQUIRED",
            message=str(exc),
            retryable=True,
        ) from exc


async def _fetch_or_error(
    resolver: HelperScriptCatalogProvider,
    script_id: str,
) -> tuple[HelperScriptCatalog, HelperScript, str]:
    _validate_script_id(script_id)
    try:
        catalog, script, content = await resolver.fetch_script_content(script_id)
    except HelperScriptSourceError as exc:
        raise ToolExecutionError(
            error_code="EXTERNAL_SOURCE_REQUIRED",
            message=str(exc),
            retryable=True,
        ) from exc
    if script.sha256 is None or not script.risk_hints:
        script = script.model_copy(
            update={
                "sha256": sha256(content.encode("utf-8")).hexdigest(),
                "risk_hints": _risk_hints_for(content),
            }
        )
    return catalog, script, content


def _catalog_payload(
    catalog: HelperScriptCatalog,
    *,
    scripts: tuple[HelperScript, ...] | None = None,
) -> dict[str, object]:
    selected = catalog.scripts if scripts is None else scripts
    return {
        "source_repo": catalog.source_repo,
        "source_commit": catalog.source_commit,
        "fallback_used": catalog.fallback_used,
        "script_count": len(selected),
        "scripts": [_script_payload(script) for script in selected],
    }


def _script_payload(script: HelperScript) -> dict[str, object]:
    return {
        "script_id": script.script_id,
        "name": script.name,
        "category": script.category,
        "path": script.path,
        "download_url": script.download_url,
        "blob_sha": script.blob_sha,
        "size": script.size,
        "sha256": script.sha256,
        "risk_hints": list(script.risk_hints),
    }


def _stage_payload(
    request: ToolRequest,
    catalog: HelperScriptCatalog,
    script: HelperScript,
    remote_path: str,
) -> dict[str, object]:
    return {
        **_script_payload(script),
        "node": request.target.node,
        "source_repo": catalog.source_repo,
        "source_commit": catalog.source_commit,
        "fallback_used": catalog.fallback_used,
        "remote_path": remote_path,
        "staged": False,
        "dry_run": request.options.dry_run,
    }


def _record_helper_audit_metadata(
    context: ToolExecutionContext,
    catalog: HelperScriptCatalog,
    script: HelperScript,
    remote_path: str,
) -> None:
    context.audit_metadata.update(
        {
            "helper_source_repo": catalog.source_repo,
            "helper_source_commit": catalog.source_commit,
            "helper_blob_sha": script.blob_sha,
            "helper_sha256": script.sha256,
            "helper_script_id": script.script_id,
            "helper_script_path": script.path,
            "helper_fallback_used": catalog.fallback_used,
            "helper_remote_path": remote_path,
        }
    )


def _helper_command(
    remote_path: str,
    mode: Literal["default", "generated"],
    environment: dict[str, str],
) -> str:
    command_parts = [f"bash {remote_path}"]
    if mode == "default":
        command = command_parts[0]
    else:
        command = f"{command_parts[0]} generated"
    command_environment = dict(environment)
    if mode != "default":
        command_environment["mode"] = mode
    if not command_environment:
        return command
    env_parts = " ".join(f"{key}={value}" for key, value in sorted(command_environment.items()))
    return f"env {env_parts} {command}"


def _validate_helper_environment(environment: dict[str, str]) -> dict[str, str]:
    validated: dict[str, str] = {}
    for key, value in environment.items():
        if not _SAFE_HELPER_ENV_KEY.fullmatch(key):
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message="Helper environment keys must be allowlisted var_* names, TERM, or mode",
                retryable=False,
            )
        if not _SAFE_HELPER_ENV_VALUE.fullmatch(value):
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message="Helper environment values contain unsupported characters",
                retryable=False,
            )
        validated[key] = value
    return validated


def _script_by_id(scripts: Sequence[HelperScript], script_id: str) -> HelperScript:
    _validate_script_id(script_id)
    for script in scripts:
        if script.script_id == script_id:
            return script
    raise HelperScriptSourceError(f"Unknown helper script: {script_id}")


def _validate_script_id(script_id: str) -> None:
    segments = script_id.split("/")
    if not _SAFE_SCRIPT_ID.fullmatch(script_id) or any(
        segment in {"", ".", ".."} for segment in segments
    ):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="script_id must reference an allowlisted helper script path",
            retryable=False,
        )


def _verify_expected_sha(expected: str | None, actual: str | None) -> None:
    if expected is not None and expected != actual:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="helper script sha256 does not match expected value",
            retryable=False,
        )


def _remote_path(script_sha: str | None) -> str:
    if script_sha is None:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="helper script must have a sha256 before staging or execution",
            retryable=False,
        )
    return f"/var/lib/proxmox-mcp/helpers/{script_sha}/script.sh"


def _risk_hints_for(content: str) -> tuple[str, ...]:
    hints: list[str] = []
    for name, pattern in _RISK_PATTERNS:
        if re.search(pattern, content, flags=re.IGNORECASE):
            hints.append(name)
    return tuple(hints)


def _bounded_output(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _ssh_target(request: ToolRequest) -> SshTarget:
    if request.target.node is None:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="Target node is required",
            retryable=False,
        )
    return SshTarget(cluster=request.target.cluster, node=request.target.node)


def _script_from_entry(entry: object, source_commit: str) -> HelperScript | None:
    if not isinstance(entry, dict):
        return None
    typed = cast(dict[str, object], entry)
    path = typed.get("path")
    name = typed.get("name")
    download_url = typed.get("download_url")
    blob_sha = typed.get("sha")
    size = typed.get("size")
    if not (
        isinstance(path, str)
        and isinstance(name, str)
        and isinstance(download_url, str)
        and isinstance(blob_sha, str)
        and isinstance(size, int)
        and path.endswith(".sh")
    ):
        return None
    category = path.split("/", maxsplit=1)[0]
    _validate_allowed_raw_url(download_url, source_commit)
    return HelperScript(
        script_id=path,
        name=name.removesuffix(".sh"),
        category=category,
        path=path,
        download_url=download_url,
        blob_sha=blob_sha,
        size=size,
    )


def _validate_allowed_raw_url(download_url: str, source_commit: str) -> None:
    parsed = urlparse(download_url)
    allowed_hosts = {"raw.githubusercontent.com"}
    if parsed.scheme != "https" or parsed.netloc not in allowed_hosts:
        raise HelperScriptSourceError("helper script download URL is not allowlisted")
    if source_commit not in parsed.path:
        raise HelperScriptSourceError("helper script download URL is not pinned to source commit")


async def _prepare_helper_artifact_content(
    content: str,
    *,
    source_repo: str,
    source_commit: str,
) -> str:
    pinned = _pin_transitive_raw_refs(content, source_repo, source_commit)
    return await _inline_remote_source_dependencies(
        pinned,
        source_repo=source_repo,
        source_commit=source_commit,
        depth=0,
    )


async def _inline_remote_source_dependencies(
    content: str,
    *,
    source_repo: str,
    source_commit: str,
    depth: int,
) -> str:
    if depth >= _MAX_HELPER_DEPENDENCY_DEPTH:
        raise HelperScriptSourceError("helper script dependency depth exceeds policy limit")

    async def replacement(match: re.Match[str]) -> str:
        dependency_url = _pin_transitive_raw_refs(match.group(1), source_repo, source_commit)
        _validate_allowed_raw_url(dependency_url, source_commit)
        if not _should_inline_dependency(dependency_url):
            return match.group(0).replace(match.group(1), dependency_url)
        dependency_content = await asyncio.to_thread(_fetch_text, dependency_url)
        prepared_dependency = await _inline_remote_source_dependencies(
            _pin_transitive_raw_refs(dependency_content, source_repo, source_commit),
            source_repo=source_repo,
            source_commit=source_commit,
            depth=depth + 1,
        )
        return (
            f"# proxmox-mcp inlined helper dependency: {dependency_url}\n"
            f"{prepared_dependency}\n"
            "# proxmox-mcp end inlined helper dependency\n"
        )

    pieces: list[str] = []
    cursor = 0
    changed = False
    for match in _REMOTE_SOURCE.finditer(content):
        changed = True
        pieces.append(content[cursor : match.start()])
        pieces.append(await replacement(match))
        cursor = match.end()
    if not changed:
        return content
    pieces.append(content[cursor:])
    return "".join(pieces)


def _should_inline_dependency(dependency_url: str) -> bool:
    return dependency_url.endswith("/misc/build.func") or dependency_url.endswith(
        "/misc/tools.func"
    )


def _pin_transitive_raw_refs(content: str, source_repo: str, source_commit: str) -> str:
    owner_repo = source_repo.removeprefix("https://github.com/")
    if owner_repo == source_repo or "/" not in owner_repo:
        raise HelperScriptSourceError("helper script source repository is not allowlisted")
    raw_main = f"https://raw.githubusercontent.com/{owner_repo}/main/"
    raw_commit = f"https://raw.githubusercontent.com/{owner_repo}/{source_commit}/"
    return content.replace(raw_main, raw_commit)


def _commit_sha(payload: object) -> str:
    if not isinstance(payload, dict):
        raise HelperScriptSourceError("GitHub commit response was invalid")
    sha = cast(dict[str, object], payload).get("sha")
    if not isinstance(sha, str) or not sha:
        raise HelperScriptSourceError("GitHub commit response did not include a commit SHA")
    return sha


def _fetch_json(url: str) -> object:
    return json.loads(_fetch_text(url))


def _fetch_text(url: str) -> str:
    request = Request(url, headers={"Accept": "application/vnd.github+json"})  # noqa: S310
    try:
        with urlopen(request, timeout=20) as response:  # noqa: S310 - allowlisted GitHub URL.
            return response.read().decode("utf-8")
    except (HTTPError, URLError, TimeoutError) as exc:
        raise HelperScriptSourceError(f"Unable to fetch helper script source: {url}") from exc


def _tool_error_from_ssh(exc: SshClientError) -> ToolExecutionError:
    return ToolExecutionError(
        error_code=exc.error_code,
        message=str(exc),
        retryable=exc.retryable,
        details=exc.details,
    )
