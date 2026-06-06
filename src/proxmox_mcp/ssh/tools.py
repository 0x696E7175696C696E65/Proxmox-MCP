from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field

from proxmox_mcp.schemas.envelope import Actor, ToolRequest
from proxmox_mcp.ssh.client import (
    SshClient,
    SshClientError,
    SshCommand,
    SshCommandResult,
    SshTarget,
)
from proxmox_mcp.ssh.policy import (
    ExecuteSshInteractiveParameters,
    ExecuteSshParameters,
    command_from_parameters,
)
from proxmox_mcp.ssh.sessions import SshSessionLimitError, SshSessionNotFoundError
from proxmox_mcp.tools.context import ToolExecutionContext
from proxmox_mcp.tools.registry import ToolDefinition, ToolExecutionError, ToolRegistry

SshToolAction = Literal[
    "execute",
    "execute_interactive",
    "open_session",
    "close_session",
    "upload",
    "download",
    "list",
    "mkdir",
    "delete",
    "copy",
]


class SshCommandExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool
    command_hash: str
    policy_allowed: bool
    exit_status: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    session_id: str | None = None
    recording_ref: str | None = None


class SshSessionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    recording_ref: str | None = None
    status: Literal["open", "closed"]


def _empty_entries() -> list[dict[str, object]]:
    return []


class SshFileTransferResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool
    operation: str
    remote_path: str | None = None
    source_path: str | None = None
    destination_path: str | None = None
    bytes_transferred: int | None = Field(default=None, ge=0)
    content: str | None = None
    entries: list[dict[str, object]] = Field(default_factory=_empty_entries)


class OpenSshSessionParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1)
    interactive: bool = True


class CloseSshSessionParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1)


class UploadFileParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remote_path: str = Field(min_length=1)
    content: str = ""
    mode: str | None = None
    overwrite: bool = False


class DownloadFileParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remote_path: str = Field(min_length=1)
    max_bytes: int = Field(default=65536, ge=1, le=1048576)


class SftpPathParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remote_path: str = Field(min_length=1)


class SftpMkdirParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remote_path: str = Field(min_length=1)
    parents: bool = False


class ScpCopyParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_path: str = Field(min_length=1)
    destination_path: str = Field(min_length=1)
    overwrite: bool = False


@dataclass(frozen=True, slots=True)
class SshToolSpec:
    name: str
    category: str
    permission: str
    risk: Literal["low", "medium", "high", "critical"]
    dry_run: bool
    approval_default: bool
    action: SshToolAction
    parameters_model: type[BaseModel]
    result_model: type[BaseModel]


SSH_TOOL_SPECS: tuple[SshToolSpec, ...] = (
    SshToolSpec(
        "execute_ssh",
        "ssh",
        "ssh.command.execute",
        "critical",
        True,
        True,
        "execute",
        ExecuteSshParameters,
        SshCommandExecutionResult,
    ),
    SshToolSpec(
        "execute_ssh_interactive",
        "ssh",
        "ssh.session.interactive",
        "critical",
        False,
        True,
        "execute_interactive",
        ExecuteSshInteractiveParameters,
        SshCommandExecutionResult,
    ),
    SshToolSpec(
        "open_ssh_session",
        "ssh",
        "ssh.session.open",
        "high",
        False,
        True,
        "open_session",
        OpenSshSessionParameters,
        SshSessionResult,
    ),
    SshToolSpec(
        "close_ssh_session",
        "ssh",
        "ssh.session.close",
        "medium",
        False,
        False,
        "close_session",
        CloseSshSessionParameters,
        SshSessionResult,
    ),
    SshToolSpec(
        "upload_file",
        "ssh",
        "ssh.file.upload",
        "high",
        True,
        False,
        "upload",
        UploadFileParameters,
        SshFileTransferResult,
    ),
    SshToolSpec(
        "download_file",
        "ssh",
        "ssh.file.download",
        "medium",
        False,
        False,
        "download",
        DownloadFileParameters,
        SshFileTransferResult,
    ),
    SshToolSpec(
        "sftp_list",
        "ssh",
        "ssh.sftp.list",
        "low",
        False,
        False,
        "list",
        SftpPathParameters,
        SshFileTransferResult,
    ),
    SshToolSpec(
        "sftp_mkdir",
        "ssh",
        "ssh.sftp.mkdir",
        "medium",
        True,
        False,
        "mkdir",
        SftpMkdirParameters,
        SshFileTransferResult,
    ),
    SshToolSpec(
        "sftp_delete",
        "ssh",
        "ssh.sftp.delete",
        "critical",
        True,
        True,
        "delete",
        SftpPathParameters,
        SshFileTransferResult,
    ),
    SshToolSpec(
        "scp_copy",
        "ssh",
        "ssh.scp.copy",
        "high",
        True,
        False,
        "copy",
        ScpCopyParameters,
        SshFileTransferResult,
    ),
)


def register_ssh_tools(registry: ToolRegistry) -> None:
    for spec in SSH_TOOL_SPECS:
        registry.register(
            ToolDefinition(
                name=spec.name,
                category=spec.category,
                permission=spec.permission,
                risk=spec.risk,
                dry_run=spec.dry_run,
                approval_default=spec.approval_default,
                connector="ssh",
                handler=_build_ssh_handler(spec),
                parameters_model=spec.parameters_model,
                result_model=spec.result_model,
            )
        )


def _build_ssh_handler(
    spec: SshToolSpec,
) -> Callable[[ToolRequest, ToolExecutionContext], Awaitable[object]]:
    async def handler(request: ToolRequest, context: ToolExecutionContext) -> object:
        if spec.action in {"execute", "execute_interactive"}:
            return await _handle_execute(
                request, context, interactive=spec.action == "execute_interactive"
            )
        if spec.action == "open_session":
            return await _handle_open_session(request, context)
        if spec.action == "close_session":
            return _handle_close_session(request, context)
        if spec.action == "upload":
            return await _handle_upload(request, context)
        if spec.action == "download":
            return await _handle_download(request, context)
        if spec.action == "list":
            return await _handle_list(request, context)
        if spec.action == "mkdir":
            return await _handle_mkdir(request, context)
        if spec.action == "delete":
            return await _handle_delete(request, context)
        return await _handle_copy(request, context)

    return handler


async def _handle_execute(
    request: ToolRequest,
    context: ToolExecutionContext,
    *,
    interactive: bool,
) -> dict[str, object]:
    client = _ssh_client(context)
    policy = _ssh_policy(context)
    parameters = ExecuteSshParameters.model_validate(request.parameters)
    command = command_from_parameters(parameters)
    command_hash = _hash_text(command.command)
    policy_decision = policy.evaluate(command)
    if not policy_decision.allowed:
        raise ToolExecutionError(
            error_code="SSH_POLICY_DENIED",
            message="SSH command denied by policy",
            details={
                "reason": policy_decision.reason,
                "executable": policy_decision.executable,
            },
            retryable=False,
        )

    session_id = parameters.session_id
    if interactive:
        if session_id is None:
            raise ToolExecutionError(
                error_code="INVALID_REQUEST",
                message="Interactive SSH execution requires an active session_id",
            )
        _active_session(context, session_id)

    context.audit_metadata.update(
        {
            "ssh_command_hash": command_hash,
            "ssh_policy_allowed": True,
            "ssh_policy_executable": policy_decision.executable,
            "ssh_session_id": session_id,
        }
    )

    if request.options.dry_run:
        return {
            "dry_run": True,
            "command_hash": command_hash,
            "policy_allowed": True,
            "session_id": session_id,
        }

    result = await _execute_client_command(client, _target_for(request), command)
    recording = await _record_command(
        request,
        context,
        command_hash=command_hash,
        result=result,
        session_id=session_id,
        redaction_profile=parameters.redaction_profile,
    )
    context.audit_metadata.update(
        {
            "ssh_recording_ref": recording.recording_ref,
            "ssh_exit_status": result.exit_status,
            "ssh_redacted": recording.redacted,
        }
    )
    return {
        "dry_run": False,
        "command_hash": command_hash,
        "policy_allowed": True,
        "exit_status": result.exit_status,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "duration_ms": result.duration_ms,
        "session_id": session_id,
        "recording_ref": recording.recording_ref,
    }


async def _handle_open_session(
    request: ToolRequest,
    context: ToolExecutionContext,
) -> dict[str, object]:
    _ = OpenSshSessionParameters.model_validate(request.parameters)
    manager = _session_manager(context)
    store = _recording_store(context)
    target = _target_for(request)
    actor = _actor_for(context, request)
    try:
        session = manager.open_session(actor=actor, target=target, interactive=True)
        recording = await store.reserve_session_recording(
            request_id=request.request_id,
            session_id=session.session_id,
        )
        session = manager.attach_recording(session.session_id, recording.recording_ref)
    except SshSessionLimitError as exc:
        raise ToolExecutionError(
            error_code="RATE_LIMITED",
            message="SSH session limit exceeded",
            retryable=True,
        ) from exc

    context.audit_metadata.update(
        {
            "ssh_session_id": session.session_id,
            "ssh_recording_ref": session.recording_ref,
        }
    )
    return {
        "session_id": session.session_id,
        "recording_ref": session.recording_ref,
        "status": "open",
    }


def _handle_close_session(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    parameters = CloseSshSessionParameters.model_validate(request.parameters)
    try:
        session = _session_manager(context).close_session(parameters.session_id)
    except SshSessionNotFoundError as exc:
        raise ToolExecutionError(
            error_code="NOT_FOUND",
            message="SSH session is not active",
        ) from exc

    context.audit_metadata.update(
        {
            "ssh_session_id": session.session_id,
            "ssh_recording_ref": session.recording_ref,
        }
    )
    return {
        "session_id": session.session_id,
        "recording_ref": session.recording_ref,
        "status": "closed",
    }


async def _handle_upload(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    parameters = UploadFileParameters.model_validate(request.parameters)
    _validate_remote_path(parameters.remote_path)
    if request.options.dry_run:
        return {
            "dry_run": True,
            "operation": "upload",
            "remote_path": parameters.remote_path,
            "bytes_transferred": len(parameters.content),
        }

    try:
        await _ssh_client(context).upload(
            _target_for(request),
            remote_path=parameters.remote_path,
            content=parameters.content,
            mode=parameters.mode,
            overwrite=parameters.overwrite,
        )
    except SshClientError as exc:
        _raise_ssh_tool_error(exc)
    return {
        "dry_run": False,
        "operation": "upload",
        "remote_path": parameters.remote_path,
        "bytes_transferred": len(parameters.content),
    }


async def _handle_download(
    request: ToolRequest, context: ToolExecutionContext
) -> dict[str, object]:
    parameters = DownloadFileParameters.model_validate(request.parameters)
    _validate_remote_path(parameters.remote_path)
    try:
        content = await _ssh_client(context).download(
            _target_for(request),
            remote_path=parameters.remote_path,
            max_bytes=parameters.max_bytes,
        )
    except SshClientError as exc:
        _raise_ssh_tool_error(exc)
    return {
        "dry_run": False,
        "operation": "download",
        "remote_path": parameters.remote_path,
        "bytes_transferred": len(content),
        "content": content,
    }


async def _handle_list(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    parameters = SftpPathParameters.model_validate(request.parameters)
    _validate_remote_path(parameters.remote_path)
    try:
        entries = await _ssh_client(context).list_dir(
            _target_for(request),
            remote_path=parameters.remote_path,
        )
    except SshClientError as exc:
        _raise_ssh_tool_error(exc)
    return {
        "dry_run": False,
        "operation": "list",
        "remote_path": parameters.remote_path,
        "entries": [entry.model_dump(mode="json") for entry in entries],
    }


async def _handle_mkdir(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    parameters = SftpMkdirParameters.model_validate(request.parameters)
    _validate_remote_path(parameters.remote_path)
    if request.options.dry_run:
        return {
            "dry_run": True,
            "operation": "mkdir",
            "remote_path": parameters.remote_path,
        }

    try:
        await _ssh_client(context).mkdir(
            _target_for(request),
            remote_path=parameters.remote_path,
            parents=parameters.parents,
        )
    except SshClientError as exc:
        _raise_ssh_tool_error(exc)
    return {
        "dry_run": False,
        "operation": "mkdir",
        "remote_path": parameters.remote_path,
    }


async def _handle_delete(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    parameters = SftpPathParameters.model_validate(request.parameters)
    _validate_remote_path(parameters.remote_path)
    if request.options.dry_run:
        return {
            "dry_run": True,
            "operation": "delete",
            "remote_path": parameters.remote_path,
        }

    try:
        await _ssh_client(context).delete_path(
            _target_for(request),
            remote_path=parameters.remote_path,
        )
    except SshClientError as exc:
        _raise_ssh_tool_error(exc)
    return {
        "dry_run": False,
        "operation": "delete",
        "remote_path": parameters.remote_path,
    }


async def _handle_copy(request: ToolRequest, context: ToolExecutionContext) -> dict[str, object]:
    parameters = ScpCopyParameters.model_validate(request.parameters)
    _validate_remote_path(parameters.source_path)
    _validate_remote_path(parameters.destination_path)
    if request.options.dry_run:
        return {
            "dry_run": True,
            "operation": "copy",
            "source_path": parameters.source_path,
            "destination_path": parameters.destination_path,
        }

    try:
        await _ssh_client(context).copy(
            _target_for(request),
            source_path=parameters.source_path,
            destination_path=parameters.destination_path,
            overwrite=parameters.overwrite,
        )
    except SshClientError as exc:
        _raise_ssh_tool_error(exc)
    return {
        "dry_run": False,
        "operation": "copy",
        "source_path": parameters.source_path,
        "destination_path": parameters.destination_path,
    }


async def _execute_client_command(
    client: SshClient,
    target: SshTarget,
    command: SshCommand,
) -> SshCommandResult:
    try:
        return await client.execute(target, command)
    except SshClientError as exc:
        _raise_ssh_tool_error(exc)


async def _record_command(
    request: ToolRequest,
    context: ToolExecutionContext,
    *,
    command_hash: str,
    result: SshCommandResult,
    session_id: str | None,
    redaction_profile: str,
):
    return await _recording_store(context).record_command(
        request_id=request.request_id,
        session_id=session_id,
        command_hash=command_hash,
        result=result,
        redaction_profile=redaction_profile,
    )


def _target_for(request: ToolRequest) -> SshTarget:
    if request.target.node is None:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="SSH target requires a node",
        )
    return SshTarget(cluster=request.target.cluster, node=request.target.node)


def _ssh_client(context: ToolExecutionContext) -> SshClient:
    if context.ssh_client is None:
        raise ToolExecutionError(
            error_code="SSH_CONNECTION_FAILED",
            message="SSH client is not configured",
            retryable=False,
        )
    return context.ssh_client


def _ssh_policy(context: ToolExecutionContext):
    if context.ssh_command_policy is None:
        raise ToolExecutionError(
            error_code="SSH_POLICY_DENIED",
            message="SSH command policy is not configured",
            retryable=False,
        )
    return context.ssh_command_policy


def _session_manager(context: ToolExecutionContext):
    if context.ssh_session_manager is None:
        raise ToolExecutionError(
            error_code="SSH_CONNECTION_FAILED",
            message="SSH session manager is not configured",
            retryable=False,
        )
    return context.ssh_session_manager


def _recording_store(context: ToolExecutionContext):
    if context.ssh_recording_store is None:
        raise ToolExecutionError(
            error_code="SSH_CONNECTION_FAILED",
            message="SSH recording store is not configured",
            retryable=False,
        )
    return context.ssh_recording_store


def _active_session(context: ToolExecutionContext, session_id: str) -> None:
    try:
        _session_manager(context).get_active_session(session_id)
    except SshSessionNotFoundError as exc:
        raise ToolExecutionError(
            error_code="NOT_FOUND",
            message="SSH session is not active",
        ) from exc


def _actor_for(context: ToolExecutionContext, request: ToolRequest) -> Actor:
    session = context.authenticated_session
    if session is None:
        return request.actor
    return Actor(
        user_id=session.identity.user_id,
        agent_id=session.identity.agent_id,
        tenant_id=session.identity.tenant_id,
    )


def _validate_remote_path(path: str) -> None:
    if "\x00" in path or "\n" in path or "\r" in path:
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="Remote path contains unsafe characters",
        )
    if not path.startswith("/"):
        raise ToolExecutionError(
            error_code="INVALID_REQUEST",
            message="Remote path must be absolute",
        )


def _hash_text(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _raise_ssh_tool_error(exc: SshClientError) -> NoReturn:
    raise ToolExecutionError(
        error_code=exc.error_code,
        message="SSH operation failed",
        details=exc.details,
        retryable=exc.retryable,
    ) from exc
