from __future__ import annotations

import pytest

from proxmox_mcp.secrets import (
    CredentialRef,
    DevelopmentSecretProvider,
    SecretManager,
    SecretProviderName,
    SecretRef,
    SecretStorageError,
    SecretUnavailableError,
    VaultSecretProvider,
)

PROXMOX_API_VALUE = "secret-value"
CHANGED_VALUE = "changed"


def make_ref(
    *,
    provider: SecretProviderName = "development",
    path: str = "secret/proxmox/prod/api-token",
) -> CredentialRef:
    return CredentialRef(
        provider=provider,
        path=path,
        purpose="proxmox_api",
        version=7,
    )


def make_secret_ref(
    *,
    provider: SecretProviderName = "development",
    path: str = "secret/proxmox/prod/api-token",
) -> SecretRef:
    return SecretRef(provider=provider, path=path, version=7)


async def test_development_secret_provider_returns_copy_of_secret_payload() -> None:
    provider = DevelopmentSecretProvider(
        {
            "secret/proxmox/prod/api-token": {
                "auth_type": "api_token",
                "token_id": "root@pam!mcp",
                "token_secret": PROXMOX_API_VALUE,
            }
        },
        environment="test",
    )

    first = await provider.read(make_secret_ref())
    second = await provider.read(make_secret_ref())

    assert first == second
    assert first is not second
    first_copy = dict(first)
    first_copy["token_" + "secret"] = CHANGED_VALUE
    assert second["token_" + "secret"] == PROXMOX_API_VALUE


def test_development_secret_provider_is_not_allowed_in_production_by_default() -> None:
    with pytest.raises(ValueError, match="production"):
        DevelopmentSecretProvider(environment="production")


async def test_secret_manager_fails_closed_when_provider_is_missing() -> None:
    manager = SecretManager(providers=())

    with pytest.raises(SecretUnavailableError):
        await manager.read(make_ref())


async def test_secret_manager_preserves_credential_purpose_on_provider_error() -> None:
    manager = SecretManager(providers=(DevelopmentSecretProvider({}, environment="test"),))
    credential_ref = make_ref()

    with pytest.raises(SecretUnavailableError) as exc_info:
        await manager.read(credential_ref)

    assert exc_info.value.credential_ref == credential_ref
    assert exc_info.value.credential_ref.purpose == "proxmox_api"


async def test_secret_manager_passes_storage_ref_to_provider() -> None:
    class RecordingProvider:
        name: SecretProviderName = "development"

        def __init__(self) -> None:
            self.seen_ref: SecretRef | None = None

        async def read(self, secret_ref: SecretRef) -> dict[str, object]:
            self.seen_ref = secret_ref
            return {"auth_type": "api_token"}

    provider = RecordingProvider()

    await SecretManager(providers=(provider,)).read(make_ref())

    assert provider.seen_ref == SecretRef(
        provider="development",
        path="secret/proxmox/prod/api-token",
        version=7,
    )


async def test_vault_secret_provider_reads_kv_v2_payload() -> None:
    class FakeVaultClient:
        async def read_secret_version(
            self,
            *,
            path: str,
            version: int | None = None,
        ) -> dict[str, object] | None:
            assert path == "secret/proxmox/prod/api-token"
            assert version == 7
            return {
                "data": {
                    "data": {
                        "auth_type": "api_token",
                        "token_id": "root@pam!mcp",
                        "token_secret": PROXMOX_API_VALUE,
                    }
                }
            }

    payload = await VaultSecretProvider(FakeVaultClient()).read(
        make_secret_ref(provider="hashicorp_vault")
    )

    assert payload == {
        "auth_type": "api_token",
        "token_id": "root@pam!mcp",
        "token_secret": PROXMOX_API_VALUE,
    }


async def test_vault_secret_provider_rejects_malformed_kv_v2_payload() -> None:
    class FakeVaultClient:
        async def read_secret_version(
            self,
            *,
            path: str,
            version: int | None = None,
        ) -> dict[str, object] | None:
            return {
                "data": {
                    "auth_type": "api_token",
                    "token_id": "root@pam!mcp",
                    "token_secret": PROXMOX_API_VALUE,
                }
            }

    secret_ref = make_secret_ref(provider="hashicorp_vault")

    with pytest.raises(SecretStorageError, match="Malformed Vault") as exc_info:
        await VaultSecretProvider(FakeVaultClient()).read(secret_ref)

    assert exc_info.value.secret_ref == secret_ref


async def test_secret_manager_preserves_purpose_on_malformed_vault_payload() -> None:
    class FakeVaultClient:
        async def read_secret_version(
            self,
            *,
            path: str,
            version: int | None = None,
        ) -> dict[str, object] | None:
            return {"data": {"auth_type": "api_token"}}

    credential_ref = make_ref(provider="hashicorp_vault")
    manager = SecretManager(providers=(VaultSecretProvider(FakeVaultClient()),))

    with pytest.raises(SecretUnavailableError, match="Malformed Vault") as exc_info:
        await manager.read(credential_ref)

    assert exc_info.value.credential_ref == credential_ref
    assert exc_info.value.credential_ref.purpose == "proxmox_api"
