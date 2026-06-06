from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field

CredentialPurpose = Literal["proxmox_api", "ssh", "external_service"]
SecretProviderName = Literal["development", "hashicorp_vault"]


class SecretRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: SecretProviderName
    path: str = Field(min_length=1)
    version: int | None = Field(default=None, ge=1)


class CredentialRef(SecretRef):
    purpose: CredentialPurpose
    metadata: dict[str, object] = Field(default_factory=dict)

    def storage_ref(self) -> SecretRef:
        return SecretRef(provider=self.provider, path=self.path, version=self.version)


class SecretUnavailableError(RuntimeError):
    def __init__(self, credential_ref: CredentialRef, message: str = "Secret unavailable") -> None:
        super().__init__(message)
        self.credential_ref = credential_ref


class SecretStorageError(RuntimeError):
    def __init__(self, secret_ref: SecretRef, message: str = "Secret unavailable") -> None:
        super().__init__(message)
        self.secret_ref = secret_ref


class SecretProvider(Protocol):
    name: SecretProviderName

    async def read(self, secret_ref: SecretRef) -> Mapping[str, object]: ...


class DevelopmentSecretProvider:
    name: SecretProviderName = "development"

    def __init__(
        self,
        secrets: Mapping[str, Mapping[str, object]] | None = None,
        *,
        environment: str = "development",
        allow_production: bool = False,
    ) -> None:
        if environment == "production" and not allow_production:
            raise ValueError("DevelopmentSecretProvider cannot be used in production")

        self._secrets = {path: dict(value) for path, value in (secrets or {}).items()}

    def set_secret(self, path: str, payload: Mapping[str, object]) -> None:
        self._secrets[path] = dict(payload)

    async def read(self, secret_ref: SecretRef) -> Mapping[str, object]:
        payload = self._secrets.get(secret_ref.path)
        if payload is None:
            raise SecretStorageError(secret_ref)

        return dict(payload)


class VaultKvClient(Protocol):
    async def read_secret_version(
        self,
        *,
        path: str,
        version: int | None = None,
    ) -> Mapping[str, object] | None: ...


class VaultSecretProvider:
    name: SecretProviderName = "hashicorp_vault"

    def __init__(self, client: VaultKvClient) -> None:
        self._client = client

    async def read(self, secret_ref: SecretRef) -> Mapping[str, object]:
        payload = await self._client.read_secret_version(
            path=secret_ref.path,
            version=secret_ref.version,
        )
        if payload is None:
            raise SecretStorageError(secret_ref)

        return _unwrap_vault_kv2_payload(secret_ref, payload)


class SecretManager:
    def __init__(self, providers: tuple[SecretProvider, ...]) -> None:
        self._providers = {provider.name: provider for provider in providers}

    async def read(self, credential_ref: CredentialRef) -> Mapping[str, object]:
        provider = self._providers.get(credential_ref.provider)
        if provider is None:
            raise SecretUnavailableError(
                credential_ref,
                f"Secret provider {credential_ref.provider!r} is not configured",
            )

        try:
            return await provider.read(credential_ref.storage_ref())
        except SecretStorageError as exc:
            raise SecretUnavailableError(credential_ref, str(exc)) from exc


def _unwrap_vault_kv2_payload(
    secret_ref: SecretRef,
    payload: Mapping[str, object],
) -> Mapping[str, object]:
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise SecretStorageError(secret_ref, "Malformed Vault KV v2 secret envelope")

    vault_data = cast(Mapping[str, object], data)
    nested = vault_data.get("data")
    if not isinstance(nested, Mapping):
        raise SecretStorageError(secret_ref, "Malformed Vault KV v2 secret envelope")

    return dict(cast(Mapping[str, object], nested))
