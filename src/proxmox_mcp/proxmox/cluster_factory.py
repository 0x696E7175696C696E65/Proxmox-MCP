from __future__ import annotations

from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox.config import ProxmoxClusterConfig
from proxmox_mcp.secrets import CredentialRef


def cluster_config_from_settings(settings: Settings) -> ProxmoxClusterConfig | None:
    if settings.cluster is None:
        return None

    cluster = settings.cluster
    credential_ref = CredentialRef(
        provider=cluster.credential_ref.provider,
        path=cluster.credential_ref.path,
        purpose=cluster.credential_ref.purpose,
    )
    return ProxmoxClusterConfig(
        cluster_id=cluster.cluster_id,
        name=cluster.name,
        api_endpoint=cluster.api_endpoint,
        tls_verify=cluster.tls_verify,
        credential_ref=credential_ref,
        environment=cluster.environment,
        status=cluster.status,
    )


def normalize_proxmox_api_endpoint(api_endpoint: str) -> str:
    endpoint = api_endpoint.rstrip("/")
    suffix = "/api2/json"
    if endpoint.endswith(suffix):
        return endpoint[: -len(suffix)]
    return endpoint
