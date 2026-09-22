from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field

CredentialPurpose = Literal["proxmox_api", "ssh", "external_service"]
SecretProviderName = Literal[
    "development",
    "hashicorp_vault",
    "bitwarden",
    "onepassword",
    "aws_secrets_manager",
    "azure_key_vault",
]


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


class BitwardenClient(Protocol):
    async def get_item(self, item_id: str) -> Mapping[str, object] | None: ...


class BitwardenSecretProvider:
    name: SecretProviderName = "bitwarden"

    def __init__(self, client: BitwardenClient) -> None:
        self._client = client

    async def read(self, secret_ref: SecretRef) -> Mapping[str, object]:
        item = await self._client.get_item(secret_ref.path)
        if item is None:
            raise SecretStorageError(secret_ref)

        return _fields_payload(secret_ref, item, name_key="name")


class OnePasswordClient(Protocol):
    async def get_item(self, reference: str) -> Mapping[str, object] | None: ...


class OnePasswordSecretProvider:
    name: SecretProviderName = "onepassword"

    def __init__(self, client: OnePasswordClient) -> None:
        self._client = client

    async def read(self, secret_ref: SecretRef) -> Mapping[str, object]:
        item = await self._client.get_item(secret_ref.path)
        if item is None:
            raise SecretStorageError(secret_ref)

        return _fields_payload(secret_ref, item, name_key="label")


class AwsSecretsManagerClient(Protocol):
    async def get_secret_value(
        self,
        *,
        secret_id: str,
        version_id: str | None = None,
    ) -> Mapping[str, object] | None: ...


class AwsSecretsManagerProvider:
    name: SecretProviderName = "aws_secrets_manager"

    def __init__(self, client: AwsSecretsManagerClient) -> None:
        self._client = client

    async def read(self, secret_ref: SecretRef) -> Mapping[str, object]:
        payload = await self._client.get_secret_value(
            secret_id=secret_ref.path,
            version_id=str(secret_ref.version) if secret_ref.version is not None else None,
        )
        if payload is None:
            raise SecretStorageError(secret_ref)

        secret_string = payload.get("SecretString")
        if not isinstance(secret_string, str):
            raise SecretStorageError(secret_ref, "Malformed AWS Secrets Manager payload")

        return _json_object_payload(secret_ref, secret_string, "AWS Secrets Manager")


class AzureKeyVaultClient(Protocol):
    async def get_secret(
        self,
        *,
        name: str,
        version: str | None = None,
    ) -> str | None: ...


class AzureKeyVaultProvider:
    name: SecretProviderName = "azure_key_vault"

    def __init__(self, client: AzureKeyVaultClient) -> None:
        self._client = client

    async def read(self, secret_ref: SecretRef) -> Mapping[str, object]:
        value = await self._client.get_secret(
            name=secret_ref.path,
            version=str(secret_ref.version) if secret_ref.version is not None else None,
        )
        if value is None:
            raise SecretStorageError(secret_ref)

        return _json_object_payload(secret_ref, value, "Azure Key Vault")


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


def _fields_payload(
    secret_ref: SecretRef,
    item: Mapping[str, object],
    *,
    name_key: str,
) -> Mapping[str, object]:
    fields = item.get("fields")
    if not isinstance(fields, list):
        raise SecretStorageError(secret_ref, "Malformed item fields payload")

    payload: dict[str, object] = {}
    typed_fields = cast(list[object], fields)
    for field in typed_fields:
        if not isinstance(field, Mapping):
            raise SecretStorageError(secret_ref, "Malformed item fields payload")

        typed_field = cast(Mapping[str, object], field)
        label = typed_field.get(name_key)
        value = typed_field.get("value")
        if isinstance(label, str):
            payload[label] = value

    if not payload:
        raise SecretStorageError(secret_ref, "Malformed item fields payload")

    return payload


def _json_object_payload(
    secret_ref: SecretRef,
    value: str,
    provider_name: str,
) -> Mapping[str, object]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SecretStorageError(secret_ref, f"Malformed {provider_name} JSON secret") from exc

    if not isinstance(payload, dict):
        raise SecretStorageError(secret_ref, f"Malformed {provider_name} JSON secret")

    return cast(dict[str, object], payload)
