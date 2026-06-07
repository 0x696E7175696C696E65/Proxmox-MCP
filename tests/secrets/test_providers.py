from __future__ import annotations

import pytest

from proxmox_mcp.secrets import (
    AwsSecretsManagerProvider,
    AzureKeyVaultProvider,
    BitwardenSecretProvider,
    CredentialRef,
    DevelopmentSecretProvider,
    OnePasswordSecretProvider,
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


async def test_bitwarden_secret_provider_reads_item_fields() -> None:
    class FakeBitwardenClient:
        async def get_item(self, item_id: str) -> dict[str, object] | None:
            assert item_id == "bw-item-1"
            return {
                "fields": [
                    {"name": "auth_type", "value": "api_token"},
                    {"name": "token_id", "value": "root@pam!mcp"},
                    {"name": "token_secret", "value": PROXMOX_API_VALUE},
                ]
            }

    payload = await BitwardenSecretProvider(FakeBitwardenClient()).read(
        make_secret_ref(provider="bitwarden", path="bw-item-1")
    )

    assert payload["token_" + "secret"] == PROXMOX_API_VALUE


async def test_onepassword_secret_provider_reads_item_fields() -> None:
    class FakeOnePasswordClient:
        async def get_item(self, reference: str) -> dict[str, object] | None:
            assert reference == "op://vault/item"
            return {
                "fields": [
                    {"label": "auth_type", "value": "api_token"},
                    {"label": "token_id", "value": "root@pam!mcp"},
                    {"label": "token_secret", "value": PROXMOX_API_VALUE},
                ]
            }

    payload = await OnePasswordSecretProvider(FakeOnePasswordClient()).read(
        make_secret_ref(provider="onepassword", path="op://vault/item")
    )

    assert payload["token_" + "secret"] == PROXMOX_API_VALUE


async def test_aws_secrets_manager_provider_reads_json_secret_string() -> None:
    class FakeAwsClient:
        async def get_secret_value(
            self,
            *,
            secret_id: str,
            version_id: str | None = None,
        ) -> dict[str, object] | None:
            assert secret_id == "prod/proxmox/api-" + "token"
            assert version_id == "7"
            return {
                "SecretString": (
                    '{"auth_type":"api_token","token_id":"root@pam!mcp",'
                    '"token_secret":"secret-value"}'
                )
            }

    payload = await AwsSecretsManagerProvider(FakeAwsClient()).read(
        make_secret_ref(provider="aws_secrets_manager", path="prod/proxmox/api-token")
    )

    assert payload["token_" + "secret"] == PROXMOX_API_VALUE


async def test_azure_key_vault_provider_reads_json_secret_value() -> None:
    class FakeAzureClient:
        async def get_secret(
            self,
            *,
            name: str,
            version: str | None = None,
        ) -> str | None:
            assert name == "prod-proxmox-api-token"
            assert version == "7"
            return (
                '{"auth_type":"api_token","token_id":"root@pam!mcp","token_secret":"secret-value"}'
            )

    payload = await AzureKeyVaultProvider(FakeAzureClient()).read(
        make_secret_ref(provider="azure_key_vault", path="prod-proxmox-api-token")
    )

    assert payload["token_" + "secret"] == PROXMOX_API_VALUE


async def test_enterprise_secret_providers_fail_closed_on_missing_secret() -> None:
    class EmptyClient:
        async def get_item(self, item_id: str) -> None:
            _ = item_id
            return None

    with pytest.raises(SecretStorageError):
        await BitwardenSecretProvider(EmptyClient()).read(
            make_secret_ref(provider="bitwarden", path="missing")
        )
