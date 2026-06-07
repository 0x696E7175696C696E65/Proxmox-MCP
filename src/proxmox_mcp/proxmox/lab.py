from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, SecretStr

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}
LabAuthMode = Literal["api_token", "username_password"]
LabProfileName = Literal[
    "pve-9-single-node-no-ceph",
    "pve-9-storage-local-local-lvm",
    "pve-9-single-node-with-guests",
    "pve-9-ceph-enabled",
    "pve-9-ha-enabled",
    "pve-9-multi-node",
    "pve-9-pbs-enabled",
]

LAB_PROFILE_NAMES: frozenset[str] = frozenset(
    {
        "pve-9-single-node-no-ceph",
        "pve-9-storage-local-local-lvm",
        "pve-9-single-node-with-guests",
        "pve-9-ceph-enabled",
        "pve-9-ha-enabled",
        "pve-9-multi-node",
        "pve-9-pbs-enabled",
    }
)


@dataclass(frozen=True, slots=True)
class LabProfileMetadata:
    name: str
    evidence_label: str
    required_env: tuple[str, ...]
    required_tests: tuple[str, ...]
    optional_tests: tuple[str, ...]
    expected_skips: tuple[str, ...]
    topology_assertions: tuple[str, ...]
    destructive_gates: tuple[str, ...]
    promotion_eligible: bool


LAB_PROFILE_METADATA: dict[str, LabProfileMetadata] = {
    "pve-9-single-node-no-ceph": LabProfileMetadata(
        name="pve-9-single-node-no-ceph",
        evidence_label="single-node no Ceph",
        required_env=("PROXMOX_MCP_LAB_NODE", "PROXMOX_MCP_LAB_STORAGE"),
        required_tests=(
            "read-only lab smoke",
            "registered MCP read tool smoke",
            "registered disposable VM mutation smoke",
            "backup create/list smoke",
            "storage profile smoke",
        ),
        optional_tests=("LXC template lifecycle",),
        expected_skips=(
            "Ceph status when Ceph is not installed",
            "LXC lifecycle when no template exists",
        ),
        topology_assertions=("single_node", "ceph_absent", "local_storage"),
        destructive_gates=(
            "PROXMOX_MCP_LAB_MUTATIONS_ENABLED",
            "PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED",
        ),
        promotion_eligible=False,
    ),
    "pve-9-storage-local-local-lvm": LabProfileMetadata(
        name="pve-9-storage-local-local-lvm",
        evidence_label="local and local-lvm storage",
        required_env=("PROXMOX_MCP_LAB_NODE", "PROXMOX_MCP_LAB_STORAGE"),
        required_tests=("storage profile smoke",),
        optional_tests=("storage mutation smoke",),
        expected_skips=("Storage expansion and benchmarking",),
        topology_assertions=("local_dir_storage", "local_lvmthin_storage"),
        destructive_gates=(
            "PROXMOX_MCP_LAB_MUTATIONS_ENABLED",
            "PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED",
        ),
        promotion_eligible=False,
    ),
    "pve-9-single-node-with-guests": LabProfileMetadata(
        name="pve-9-single-node-with-guests",
        evidence_label="single-node guest inventory",
        required_env=("PROXMOX_MCP_LAB_NODE",),
        required_tests=("read-only lab smoke", "guest inventory smoke"),
        optional_tests=("LXC template lifecycle",),
        expected_skips=(),
        topology_assertions=("single_node", "guest_inventory_present"),
        destructive_gates=(
            "PROXMOX_MCP_LAB_MUTATIONS_ENABLED",
            "PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED",
        ),
        promotion_eligible=False,
    ),
    "pve-9-ceph-enabled": LabProfileMetadata(
        name="pve-9-ceph-enabled",
        evidence_label="Ceph topology",
        required_env=("PROXMOX_MCP_LAB_NODE",),
        required_tests=("Ceph discovery smoke",),
        optional_tests=("Ceph mutation smoke",),
        expected_skips=(),
        topology_assertions=("ceph_status", "ceph_pools", "ceph_osds"),
        destructive_gates=(
            "PROXMOX_MCP_LAB_MUTATIONS_ENABLED",
            "PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED",
        ),
        promotion_eligible=False,
    ),
    "pve-9-ha-enabled": LabProfileMetadata(
        name="pve-9-ha-enabled",
        evidence_label="HA topology",
        required_env=("PROXMOX_MCP_LAB_NODE",),
        required_tests=("HA discovery smoke",),
        optional_tests=("HA migration smoke",),
        expected_skips=(),
        topology_assertions=("ha_status", "ha_resources"),
        destructive_gates=(
            "PROXMOX_MCP_LAB_MUTATIONS_ENABLED",
            "PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED",
        ),
        promotion_eligible=False,
    ),
    "pve-9-multi-node": LabProfileMetadata(
        name="pve-9-multi-node",
        evidence_label="multi-node topology",
        required_env=("PROXMOX_MCP_LAB_EXPECTED_NODE_COUNT",),
        required_tests=("multi-node inventory smoke", "cluster quorum smoke"),
        optional_tests=("migration smoke",),
        expected_skips=(),
        topology_assertions=("expected_node_count", "cluster_quorum"),
        destructive_gates=(
            "PROXMOX_MCP_LAB_MUTATIONS_ENABLED",
            "PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED",
        ),
        promotion_eligible=False,
    ),
    "pve-9-pbs-enabled": LabProfileMetadata(
        name="pve-9-pbs-enabled",
        evidence_label="PBS backup verification",
        required_env=("PROXMOX_MCP_LAB_NODE", "PROXMOX_MCP_LAB_PBS_REPOSITORY"),
        required_tests=("PBS availability smoke", "PBS verification gate"),
        optional_tests=("backup verification smoke",),
        expected_skips=("Live PBS verification until artifact evidence is available",),
        topology_assertions=("pbs_storage_configured", "backup_artifact_addressable"),
        destructive_gates=(
            "PROXMOX_MCP_LAB_MUTATIONS_ENABLED",
            "PROXMOX_MCP_LAB_DESTRUCTIVE_ENABLED",
        ),
        promotion_eligible=False,
    ),
}


class LabEnvironmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    api_endpoint: str | None = Field(default=None, min_length=1)
    auth_mode: LabAuthMode | None = None
    token_id: str | None = Field(default=None, min_length=1)
    token_secret: SecretStr | None = None
    username: str | None = Field(default=None, min_length=1)
    password: SecretStr | None = None
    tls_verify: bool = True
    allow_insecure_transport: bool = False
    node: str | None = Field(default=None, min_length=1)
    storage_id: str | None = Field(default=None, min_length=1)
    lxc_template_storage_id: str | None = Field(default=None, min_length=1)
    lxc_template_volid: str | None = Field(default=None, min_length=1)
    expected_node_count: int | None = Field(default=None, ge=1)
    pbs_repository_id: str | None = Field(default=None, min_length=1)
    cluster_id: str = "lab"
    profile: LabProfileName = "pve-9-single-node-no-ceph"
    skip_reason: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> LabEnvironmentConfig:
        enabled = _env_bool(env.get("PROXMOX_MCP_LAB_ENABLED"), default=False)
        if not enabled:
            return cls(
                enabled=False,
                skip_reason="Set PROXMOX_MCP_LAB_ENABLED=true to run lab tests",
            )

        missing = [name for name in ("PROXMOX_MCP_LAB_API_ENDPOINT",) if not env.get(name)]
        if missing:
            return cls(
                enabled=False,
                skip_reason="Missing lab environment variables: " + ", ".join(missing),
            )

        has_token_credentials = bool(
            env.get("PROXMOX_MCP_LAB_TOKEN_ID") and env.get("PROXMOX_MCP_LAB_TOKEN_SECRET")
        )
        has_password_credentials = bool(
            env.get("PROXMOX_MCP_LAB_USERNAME") and env.get("PROXMOX_MCP_LAB_PASSWORD")
        )
        if has_token_credentials == has_password_credentials:
            return cls(
                enabled=False,
                skip_reason=(
                    "Configure exactly one token or username/password lab credentials set"
                ),
            )

        endpoint = str(env["PROXMOX_MCP_LAB_API_ENDPOINT"]).rstrip("/")
        parsed_endpoint = urlparse(endpoint)
        if parsed_endpoint.scheme != "https" or parsed_endpoint.username is not None:
            return cls(
                enabled=False,
                skip_reason=("PROXMOX_MCP_LAB_API_ENDPOINT must be an https URL without userinfo"),
            )

        tls_verify = _env_bool(env.get("PROXMOX_MCP_LAB_TLS_VERIFY"), default=True)
        allow_insecure_transport = _env_bool(
            env.get("PROXMOX_MCP_LAB_ALLOW_INSECURE_TRANSPORT"),
            default=False,
        )
        if not tls_verify and not allow_insecure_transport:
            return cls(
                enabled=False,
                skip_reason=(
                    "Set PROXMOX_MCP_LAB_ALLOW_INSECURE_TRANSPORT=true to disable TLS "
                    "verification in disposable labs"
                ),
            )

        raw_profile = env.get("PROXMOX_MCP_LAB_PROFILE", "pve-9-single-node-no-ceph")
        if raw_profile not in LAB_PROFILE_NAMES:
            return cls(
                enabled=False,
                skip_reason=f"Unknown Proxmox lab profile: {raw_profile}",
            )

        return cls(
            enabled=True,
            api_endpoint=endpoint,
            auth_mode="api_token" if has_token_credentials else "username_password",
            token_id=env.get("PROXMOX_MCP_LAB_TOKEN_ID"),
            token_secret=None
            if env.get("PROXMOX_MCP_LAB_TOKEN_SECRET") is None
            else SecretStr(env["PROXMOX_MCP_LAB_TOKEN_SECRET"]),
            username=env.get("PROXMOX_MCP_LAB_USERNAME"),
            password=None
            if env.get("PROXMOX_MCP_LAB_PASSWORD") is None
            else SecretStr(env["PROXMOX_MCP_LAB_PASSWORD"]),
            tls_verify=tls_verify,
            allow_insecure_transport=allow_insecure_transport,
            node=env.get("PROXMOX_MCP_LAB_NODE"),
            storage_id=env.get("PROXMOX_MCP_LAB_STORAGE"),
            lxc_template_storage_id=env.get("PROXMOX_MCP_LAB_LXC_TEMPLATE_STORAGE"),
            lxc_template_volid=env.get("PROXMOX_MCP_LAB_LXC_TEMPLATE_VOLID"),
            expected_node_count=_env_int(env.get("PROXMOX_MCP_LAB_EXPECTED_NODE_COUNT")),
            pbs_repository_id=env.get("PROXMOX_MCP_LAB_PBS_REPOSITORY"),
            cluster_id=env.get("PROXMOX_MCP_LAB_CLUSTER_ID", "lab"),
            profile=cast(LabProfileName, raw_profile),
        )

    def profile_missing_prerequisites(self) -> tuple[str, ...]:
        missing: list[str] = []
        metadata = self.profile_metadata()
        if "PROXMOX_MCP_LAB_NODE" in metadata.required_env and self.node is None:
            missing.append("Set PROXMOX_MCP_LAB_NODE for node-scoped lab profile tests")
        if "PROXMOX_MCP_LAB_STORAGE" in metadata.required_env and self.storage_id is None:
            missing.append("Set PROXMOX_MCP_LAB_STORAGE for local storage profile tests")
        if (
            "PROXMOX_MCP_LAB_EXPECTED_NODE_COUNT" in metadata.required_env
            and self.expected_node_count is None
        ):
            missing.append(
                "Set PROXMOX_MCP_LAB_EXPECTED_NODE_COUNT=2 or higher for multi-node profile tests"
            )
        if "PROXMOX_MCP_LAB_PBS_REPOSITORY" in metadata.required_env and (
            self.pbs_repository_id is None
        ):
            missing.append("Set PROXMOX_MCP_LAB_PBS_REPOSITORY for PBS profile tests")

        return tuple(missing)

    def profile_metadata(self) -> LabProfileMetadata:
        return LAB_PROFILE_METADATA[self.profile]


def _env_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return default


def _env_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        return int(value)
    except ValueError:
        return None
