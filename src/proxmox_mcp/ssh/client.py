from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import import_module
from typing import Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field

from proxmox_mcp.schemas.envelope import ErrorCode

SshErrorCode = Literal[
    "SSH_CONNECTION_FAILED", "SSH_COMMAND_FAILED", "TIMEOUT", "NOT_FOUND", "CONFLICT"
]


class SshTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cluster: str | None = None
    node: str = Field(min_length=1)


class SshCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1)
    working_directory: str | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=30, ge=1, le=3600)
    capture_stdout: bool = True
    capture_stderr: bool = True


class SshCommandResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exit_status: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = Field(default=0, ge=0)


class SftpEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    name: str
    kind: Literal["file", "directory", "unknown"] = "unknown"
    size: int | None = Field(default=None, ge=0)


class SshClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        error_code: SshErrorCode = "SSH_COMMAND_FAILED",
        retryable: bool = False,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code: ErrorCode = error_code
        self.retryable = retryable
        self.details = {} if details is None else details


class SshClient(Protocol):
    async def execute(self, target: SshTarget, command: SshCommand) -> SshCommandResult: ...

    async def upload(
        self,
        target: SshTarget,
        *,
        remote_path: str,
        content: str,
        mode: str | None = None,
        overwrite: bool = False,
    ) -> None: ...

    async def download(self, target: SshTarget, *, remote_path: str, max_bytes: int) -> str: ...

    async def list_dir(self, target: SshTarget, *, remote_path: str) -> tuple[SftpEntry, ...]: ...

    async def mkdir(
        self, target: SshTarget, *, remote_path: str, parents: bool = False
    ) -> None: ...

    async def delete_path(self, target: SshTarget, *, remote_path: str) -> None: ...

    async def copy(
        self,
        target: SshTarget,
        *,
        source_path: str,
        destination_path: str,
        overwrite: bool = False,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class SshConnectionConfig:
    host: str
    username: str
    port: int = 22
    client_keys: tuple[str, ...] = ()
    known_hosts: str | None = None


class InMemorySshClient:
    def __init__(
        self,
        *,
        command_results: Mapping[str, SshCommandResult] | None = None,
        files: Mapping[str, str] | None = None,
    ) -> None:
        self.command_results = dict(command_results or {})
        self.files = dict(files or {})
        self.directories: set[str] = {"/"}
        self.executions: list[tuple[SshTarget, SshCommand]] = []
        self.uploads: list[tuple[SshTarget, str, str]] = []
        self.downloads: list[tuple[SshTarget, str]] = []
        self.copies: list[tuple[SshTarget, str, str]] = []

    async def execute(self, target: SshTarget, command: SshCommand) -> SshCommandResult:
        self.executions.append((target, command))
        result = self.command_results.get(command.command)
        if result is None:
            return SshCommandResult(exit_status=0, stdout="", stderr="", duration_ms=1)
        return result

    async def upload(
        self,
        target: SshTarget,
        *,
        remote_path: str,
        content: str,
        mode: str | None = None,
        overwrite: bool = False,
    ) -> None:
        _ = mode
        if remote_path in self.files and not overwrite:
            raise SshClientError("Remote file already exists", error_code="CONFLICT")
        self.files[remote_path] = content
        self.uploads.append((target, remote_path, content))

    async def download(self, target: SshTarget, *, remote_path: str, max_bytes: int) -> str:
        self.downloads.append((target, remote_path))
        content = self.files.get(remote_path)
        if content is None:
            raise SshClientError("Remote file not found", error_code="NOT_FOUND")
        return content[:max_bytes]

    async def list_dir(self, target: SshTarget, *, remote_path: str) -> tuple[SftpEntry, ...]:
        _ = target
        prefix = remote_path.rstrip("/") + "/"
        entries: list[SftpEntry] = []
        for path, content in sorted(self.files.items()):
            if path.startswith(prefix):
                name = path.removeprefix(prefix).split("/", maxsplit=1)[0]
                entries.append(
                    SftpEntry(path=f"{prefix}{name}", name=name, kind="file", size=len(content))
                )
        return tuple(entries)

    async def mkdir(self, target: SshTarget, *, remote_path: str, parents: bool = False) -> None:
        _ = target
        if not parents and _parent(remote_path) not in self.directories:
            raise SshClientError("Parent directory not found", error_code="NOT_FOUND")
        self.directories.add(remote_path.rstrip("/") or "/")

    async def delete_path(self, target: SshTarget, *, remote_path: str) -> None:
        _ = target
        if remote_path in self.files:
            del self.files[remote_path]
            return

        normalized = remote_path.rstrip("/") or "/"
        if normalized != "/" and normalized in self.directories:
            self.directories.remove(normalized)
            return

        raise SshClientError("Remote path not found", error_code="NOT_FOUND")

    async def copy(
        self,
        target: SshTarget,
        *,
        source_path: str,
        destination_path: str,
        overwrite: bool = False,
    ) -> None:
        content = self.files.get(source_path)
        if content is None:
            raise SshClientError("Remote file not found", error_code="NOT_FOUND")
        if destination_path in self.files and not overwrite:
            raise SshClientError("Remote file already exists", error_code="CONFLICT")
        self.files[destination_path] = content
        self.copies.append((target, source_path, destination_path))


class _AsyncSshRunResult(Protocol):
    exit_status: int
    stdout: str
    stderr: str


class _AsyncSshConnection(Protocol):
    async def run(
        self,
        command: str,
        *,
        check: bool = False,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
    ) -> _AsyncSshRunResult: ...


class _AsyncSshModule(Protocol):
    async def connect(
        self,
        host: str,
        *,
        port: int,
        username: str,
        client_keys: tuple[str, ...],
        known_hosts: str | None,
    ) -> _AsyncSshConnection: ...


class AsyncSshClient:
    def __init__(self, hosts: Mapping[str, SshConnectionConfig]) -> None:
        self._hosts = dict(hosts)

    async def execute(self, target: SshTarget, command: SshCommand) -> SshCommandResult:
        if command.working_directory is not None:
            raise SshClientError(
                "SSH working_directory is not supported by this adapter",
                error_code="SSH_COMMAND_FAILED",
                retryable=False,
            )

        connection_config = self._config_for(target)
        asyncssh = cast(_AsyncSshModule, import_module("asyncssh"))
        try:
            connection = await asyncssh.connect(
                connection_config.host,
                port=connection_config.port,
                username=connection_config.username,
                client_keys=connection_config.client_keys,
                known_hosts=connection_config.known_hosts,
            )
            async with asyncio.timeout(command.timeout_seconds):
                result = await connection.run(
                    command.command,
                    check=False,
                    env=command.environment,
                )
        except TimeoutError as exc:
            raise SshClientError(
                "SSH command timed out", error_code="TIMEOUT", retryable=True
            ) from exc
        except Exception as exc:
            raise SshClientError(
                "SSH command failed",
                error_code="SSH_CONNECTION_FAILED",
                retryable=True,
            ) from exc

        return SshCommandResult(
            exit_status=result.exit_status,
            stdout=result.stdout if command.capture_stdout else "",
            stderr=result.stderr if command.capture_stderr else "",
        )

    async def upload(
        self,
        target: SshTarget,
        *,
        remote_path: str,
        content: str,
        mode: str | None = None,
        overwrite: bool = False,
    ) -> None:
        _ = target, remote_path, content, mode, overwrite
        raise SshClientError("SFTP upload is not configured for this adapter")

    async def download(self, target: SshTarget, *, remote_path: str, max_bytes: int) -> str:
        _ = target, remote_path, max_bytes
        raise SshClientError("SFTP download is not configured for this adapter")

    async def list_dir(self, target: SshTarget, *, remote_path: str) -> tuple[SftpEntry, ...]:
        _ = target, remote_path
        raise SshClientError("SFTP listing is not configured for this adapter")

    async def mkdir(self, target: SshTarget, *, remote_path: str, parents: bool = False) -> None:
        _ = target, remote_path, parents
        raise SshClientError("SFTP mkdir is not configured for this adapter")

    async def delete_path(self, target: SshTarget, *, remote_path: str) -> None:
        _ = target, remote_path
        raise SshClientError("SFTP delete is not configured for this adapter")

    async def copy(
        self,
        target: SshTarget,
        *,
        source_path: str,
        destination_path: str,
        overwrite: bool = False,
    ) -> None:
        _ = target, source_path, destination_path, overwrite
        raise SshClientError("SCP copy is not configured for this adapter")

    def _config_for(self, target: SshTarget) -> SshConnectionConfig:
        config = self._hosts.get(target.node)
        if config is None:
            raise SshClientError("SSH host is not configured", error_code="SSH_CONNECTION_FAILED")
        return config


def _parent(path: str) -> str:
    normalized = path.rstrip("/")
    if not normalized or normalized == "/":
        return "/"
    parent, _, _ = normalized.rpartition("/")
    return parent or "/"
