from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from proxmox_mcp.ssh.client import SshCommand

CommandPolicyMode = Literal["allowlist", "denylist"]

_SHELL_META = re.compile(r"(?:[;&|`$<>]|\$\(|\n|\r)")
_DEFAULT_ALLOWED_EXECUTABLES = frozenset(
    {
        "ceph",
        "df",
        "free",
        "ip",
        "journalctl",
        "lsblk",
        "pct",
        "pvecm",
        "pvesh",
        "qm",
        "smartctl",
        "ss",
        "systemctl",
        "uptime",
        "zfs",
        "zpool",
    }
)
_DEFAULT_DENIED_EXECUTABLES = frozenset(
    {
        "bash",
        "curl",
        "nc",
        "netcat",
        "perl",
        "python",
        "python3",
        "rm",
        "ruby",
        "sh",
        "sudo",
        "wget",
    }
)
_DEFAULT_ALLOWED_ENVIRONMENT = frozenset({"LANG", "LC_ALL", "PATH", "TERM"})


class SshCommandPolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    executable: str | None = None


@dataclass(frozen=True, slots=True)
class SshCommandPolicy:
    mode: CommandPolicyMode = "allowlist"
    allowed_executables: frozenset[str] = _DEFAULT_ALLOWED_EXECUTABLES
    denied_executables: frozenset[str] = _DEFAULT_DENIED_EXECUTABLES
    allowed_environment: frozenset[str] = _DEFAULT_ALLOWED_ENVIRONMENT
    allow_shell_metacharacters: bool = False
    max_timeout_seconds: int = 300

    def evaluate(self, command: SshCommand) -> SshCommandPolicyDecision:
        executable = _executable_for(command.command)
        if executable is None:
            return SshCommandPolicyDecision(
                allowed=False,
                reason="Command must include an executable",
            )

        if command.timeout_seconds > self.max_timeout_seconds:
            return SshCommandPolicyDecision(
                allowed=False,
                reason="Command timeout exceeds policy maximum",
                executable=executable,
            )

        unsupported_environment = sorted(set(command.environment) - self.allowed_environment)
        if unsupported_environment:
            return SshCommandPolicyDecision(
                allowed=False,
                reason="Command environment contains unsupported variables",
                executable=executable,
            )

        if not self.allow_shell_metacharacters and _SHELL_META.search(command.command):
            return SshCommandPolicyDecision(
                allowed=False,
                reason="Shell metacharacters require explicit command policy",
                executable=executable,
            )

        if executable in self.denied_executables:
            return SshCommandPolicyDecision(
                allowed=False,
                reason="Executable is denied by SSH command policy",
                executable=executable,
            )

        if self.mode == "allowlist" and executable not in self.allowed_executables:
            return SshCommandPolicyDecision(
                allowed=False,
                reason="Executable is not in the SSH command allowlist",
                executable=executable,
            )

        return SshCommandPolicyDecision(
            allowed=True,
            reason="Command allowed by SSH command policy",
            executable=executable,
        )


class ExecuteSshParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1)
    working_directory: str | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=30, ge=1, le=3600)
    capture_stdout: bool = True
    capture_stderr: bool = True
    redaction_profile: Literal["default", "none"] = "default"
    session_id: str | None = None


def command_from_parameters(parameters: ExecuteSshParameters) -> SshCommand:
    return SshCommand(
        command=parameters.command,
        working_directory=parameters.working_directory,
        environment=parameters.environment,
        timeout_seconds=parameters.timeout_seconds,
        capture_stdout=parameters.capture_stdout,
        capture_stderr=parameters.capture_stderr,
    )


def _executable_for(command: str) -> str | None:
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return None

    if not parts:
        return None

    executable = parts[0].rsplit("/", maxsplit=1)[-1]
    return executable.lower()
