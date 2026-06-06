from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from proxmox_mcp.secrets import CredentialRef, SecretManager, SecretUnavailableError

ClusterEnvironment = Literal["development", "test", "staging", "production"]
ClusterStatus = Literal["active", "disabled"]
ProxmoxAuthType = Literal["api_token", "username_password"]


class ProxmoxClusterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cluster_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    api_endpoint: str = Field(min_length=1)
    tls_verify: bool = True
    credential_ref: CredentialRef
    environment: ClusterEnvironment = "development"
    status: ClusterStatus = "active"

    @model_validator(mode="after")
    def _validate_transport(self) -> Self:
        if not self.api_endpoint.startswith("https://"):
            raise ValueError("Proxmox clusters require https:// API endpoints")

        if self.environment == "production" and not self.tls_verify:
            raise ValueError("Production Proxmox clusters require TLS verification")

        return self


class ProxmoxApiCredential(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auth_type: ProxmoxAuthType
    token_id: str | None = None
    token_secret: SecretStr | None = None
    username: str | None = None
    password: SecretStr | None = None
    realm: str | None = None

    @model_validator(mode="after")
    def _validate_auth_variant(self) -> Self:
        if self.auth_type == "api_token":
            if self.token_id is None or self.token_secret is None:
                raise ValueError("API token credentials require token_id and token_secret")

            if self.username is not None or self.password is not None or self.realm is not None:
                raise ValueError("API token credentials cannot include username/password fields")

        if self.auth_type == "username_password":
            if self.username is None or self.password is None:
                raise ValueError("Username/password credentials require username and password")

            if self.token_id is not None or self.token_secret is not None:
                raise ValueError("Username/password credentials cannot include API token fields")

        return self

    def safe_dump(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class ResolvedProxmoxCluster(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cluster_id: str
    name: str
    api_endpoint: str
    tls_verify: bool
    credential: ProxmoxApiCredential

    def safe_dump(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class ClusterCredentialResolver:
    def __init__(self, secret_manager: SecretManager) -> None:
        self._secret_manager = secret_manager

    async def resolve(self, cluster: ProxmoxClusterConfig) -> ResolvedProxmoxCluster:
        if cluster.status != "active":
            raise ValueError(f"Cluster {cluster.cluster_id!r} is disabled")

        if cluster.credential_ref.purpose != "proxmox_api":
            raise ValueError("Cluster credential reference must have proxmox_api purpose")

        payload = await self._secret_manager.read(cluster.credential_ref)
        credential = _credential_from_payload(cluster.credential_ref, payload)
        return ResolvedProxmoxCluster(
            cluster_id=cluster.cluster_id,
            name=cluster.name,
            api_endpoint=cluster.api_endpoint,
            tls_verify=cluster.tls_verify,
            credential=credential,
        )


def _credential_from_payload(
    credential_ref: CredentialRef,
    payload: object,
) -> ProxmoxApiCredential:
    if not isinstance(payload, Mapping):
        raise SecretUnavailableError(credential_ref, "Secret payload must be an object")

    secret_payload = cast(Mapping[str, object], payload)
    auth_type = secret_payload.get("auth_type")
    if auth_type == "api_token":
        token_id = secret_payload.get("token_id")
        token_secret = secret_payload.get("token_secret")
        if not isinstance(token_id, str) or not isinstance(token_secret, str):
            raise SecretUnavailableError(
                credential_ref,
                "API token credentials require token_id and token_secret",
            )

        return ProxmoxApiCredential(
            auth_type="api_token",
            token_id=token_id,
            token_secret=SecretStr(token_secret),
        )

    if auth_type == "username_password":
        username = secret_payload.get("username")
        password = secret_payload.get("password")
        realm = secret_payload.get("realm")
        if not isinstance(username, str) or not isinstance(password, str):
            raise SecretUnavailableError(
                credential_ref,
                "Username/password credentials require username and password",
            )

        if realm is not None and not isinstance(realm, str):
            raise SecretUnavailableError(credential_ref, "Credential realm must be a string")

        return ProxmoxApiCredential(
            auth_type="username_password",
            username=username,
            password=SecretStr(password),
            realm=realm,
        )

    raise SecretUnavailableError(credential_ref, "Unsupported Proxmox credential auth_type")
