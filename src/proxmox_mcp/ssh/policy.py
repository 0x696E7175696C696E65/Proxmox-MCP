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
        "pveversion",
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
_DEFAULT_ALLOWED_ENVIRONMENT = frozenset({"LANG", "LC_ALL", "TERM"})
# Absolute paths only under these roots (blocks /tmp/qm-style planted binaries).
_ALLOWED_EXECUTABLE_ROOTS = (
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
)
_DEFAULT_ALLOWED_FILE_ROOTS = frozenset(
    {
        "/var/lib/vz",
        "/var/lib/vz/template",
        "/var/lib/vz/images",
        "/var/lib/vz/dump",
        "/var/lib/proxmox-mcp",
    }
)

# Subcommand sandboxes for powerful allowlisted binaries (post-approval still constrained).
# None => any non-shell-meta args allowed (read-only utilities).
_ALLOWED_SUBCOMMANDS: dict[str, frozenset[str] | None] = {
    "df": None,
    "free": None,
    "uptime": None,
    "pveversion": None,
    "lsblk": None,
    "smartctl": None,
    "ss": None,
    "journalctl": None,
    "ip": frozenset({"addr", "link", "route", "neigh", "rule"}),
    "pvecm": frozenset({"status", "nodes", "expected"}),
    "pvesh": frozenset({"get", "ls", "usage", "help"}),
    "qm": frozenset(
        {
            "list",
            "status",
            "config",
            "current",
            "pending",
            "cap",
            "help",
            "cloudinit",
            "guest",
            "agent",
            "wait",
            "mtunnel",
            "terminalhelp",
        }
    ),
    "pct": frozenset(
        {
            "list",
            "status",
            "config",
            "current",
            "pending",
            "cap",
            "help",
            "fstrim",
            "listsnapshot",
            "enter",
        }
    ),
    "systemctl": frozenset(
        {
            "status",
            "show",
            "is-active",
            "is-enabled",
            "is-failed",
            "list-units",
            "list-unit-files",
            "cat",
            "help",
        }
    ),
    "zfs": frozenset({"list", "get", "userspace", "holds", "mount", "version", "help"}),
    "zpool": frozenset(
        {"list", "status", "get", "iostat", "history", "help", "version", "create", "scrub"}
    ),
    "ceph": frozenset({"status", "health", "df", "versions", "osd"}),
}

# First positional token denials (defense in depth alongside allowlists).
_DENIED_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "qm": frozenset(
        {
            "destroy",
            "stop",
            "shutdown",
            "reset",
            "reboot",
            "suspend",
            "resume",
            "migrate",
            "move_disk",
            "resize",
            "set",
            "create",
            "clone",
            "snapshot",
            "rollback",
            "unlink",
            "delsnapshot",
            "del",
            "nbdstop",
            "cleanup",
        }
    ),
    "pct": frozenset(
        {
            "destroy",
            "stop",
            "shutdown",
            "reboot",
            "suspend",
            "resume",
            "migrate",
            "move_volume",
            "resize",
            "set",
            "create",
            "clone",
            "snapshot",
            "rollback",
            "unlink",
            "delsnapshot",
            "console",
        }
    ),
    "systemctl": frozenset(
        {
            "start",
            "stop",
            "restart",
            "reload",
            "enable",
            "disable",
            "mask",
            "unmask",
            "kill",
            "isolate",
            "daemon-reload",
            "edit",
            "set-property",
        }
    ),
    "zfs": frozenset({"destroy", "rollback", "send", "receive", "create", "clone", "rename", "set"}),
    "zpool": frozenset(
        {
            "destroy",
            "replace",
            "attach",
            "detach",
            "offline",
            "online",
            "clear",
            "import",
            "export",
            "labelclear",
            "remove",
            "add",
        }
    ),
    "pvesh": frozenset({"create", "set", "delete", "put", "post", "patch"}),
    "ip": frozenset({"add", "del", "change", "replace", "flush", "set"}),
    "ceph": frozenset({"mon", "mgr", "tell", "daemon"}),
}


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
    # SFTP/SCP jail: default to Proxmox-safe roots (empty override still allowed via
    # explicit frozenset() only when an operator constructs a custom policy).
    allowed_file_roots: frozenset[str] = _DEFAULT_ALLOWED_FILE_ROOTS

    def evaluate(self, command: SshCommand) -> SshCommandPolicyDecision:
        executable = _executable_for(command.command)
        if executable is None:
            return SshCommandPolicyDecision(
                allowed=False,
                reason="Command must include an executable",
            )

        raw_executable = _raw_executable(command.command)
        if raw_executable is not None and not _executable_path_allowed(raw_executable):
            return SshCommandPolicyDecision(
                allowed=False,
                reason="Executable path must be a basename or under /usr/bin|/usr/sbin|/bin|/sbin",
                executable=executable,
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

        arg_decision = _evaluate_subcommand_policy(executable, command.command)
        if arg_decision is not None:
            return arg_decision

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


class ExecuteSshInteractiveParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1)
    working_directory: str | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=30, ge=1, le=3600)
    capture_stdout: bool = True
    capture_stderr: bool = True
    redaction_profile: Literal["default", "none"] = "default"
    session_id: str = Field(min_length=1)


def command_from_parameters(
    parameters: ExecuteSshParameters | ExecuteSshInteractiveParameters,
) -> SshCommand:
    return SshCommand(
        command=parameters.command,
        working_directory=parameters.working_directory,
        environment=parameters.environment,
        timeout_seconds=parameters.timeout_seconds,
        capture_stdout=parameters.capture_stdout,
        capture_stderr=parameters.capture_stderr,
    )


def _raw_executable(command: str) -> str | None:
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return None
    if not parts:
        return None
    return parts[0]


def _command_parts(command: str) -> list[str] | None:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return None


def _positional_args(parts: list[str]) -> list[str]:
    return [part.lower() for part in parts[1:] if not part.startswith("-")]


def _first_positional_arg(parts: list[str]) -> str | None:
    args = _positional_args(parts)
    return args[0] if args else None


def _evaluate_subcommand_policy(
    executable: str,
    command: str,
) -> SshCommandPolicyDecision | None:
    parts = _command_parts(command)
    if parts is None:
        return SshCommandPolicyDecision(
            allowed=False,
            reason="Command could not be parsed for subcommand policy",
            executable=executable,
        )

    denied = _DENIED_SUBCOMMANDS.get(executable)
    has_allow = executable in _ALLOWED_SUBCOMMANDS
    if denied is None and not has_allow:
        return None

    positionals = _positional_args(parts)
    if not positionals:
        # Flag-only / bare executable — OK for read-oriented tools.
        return None

    positional = positionals[0]
    if denied is not None and positional in denied:
        return SshCommandPolicyDecision(
            allowed=False,
            reason=f"Subcommand {positional!r} is denied for {executable}",
            executable=executable,
        )

    if has_allow:
        allowed_set = _ALLOWED_SUBCOMMANDS[executable]
        if allowed_set is not None and positional not in allowed_set:
            return SshCommandPolicyDecision(
                allowed=False,
                reason=f"Subcommand {positional!r} is not permitted for {executable}",
                executable=executable,
            )

    # Ceph: only reweight-style osd ops used by domain packs (not osd out/down/rm).
    if executable == "ceph" and positional == "osd":
        if len(positionals) < 2:
            return SshCommandPolicyDecision(
                allowed=False,
                reason="ceph osd requires an explicit subcommand",
                executable=executable,
            )
        osd_op = positionals[1]
        if osd_op not in {"reweight", "reweight-by-utilization", "tree", "stat", "df", "dump"}:
            return SshCommandPolicyDecision(
                allowed=False,
                reason=f"ceph osd subcommand {osd_op!r} is not permitted",
                executable=executable,
            )

    return None


def _executable_path_allowed(raw_executable: str) -> bool:
    """Basename (resolved via secure PATH) or absolute under system bin roots."""
    if "/" not in raw_executable and "\\" not in raw_executable:
        return True
    if not raw_executable.startswith("/") or ".." in raw_executable.split("/"):
        return False
    return any(raw_executable.startswith(root) for root in _ALLOWED_EXECUTABLE_ROOTS)


def _executable_for(command: str) -> str | None:
    raw = _raw_executable(command)
    if raw is None:
        return None
    executable = raw.rsplit("/", maxsplit=1)[-1]
    return executable.lower() if executable else None
