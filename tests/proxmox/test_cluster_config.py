from __future__ import annotations

import pytest
from pydantic import SecretStr

from proxmox_mcp.proxmox import (
    ClusterCredentialResolver,
    ProxmoxApiCredential,
    ProxmoxClusterConfig,
)
from proxmox_mcp.secrets import (
    CredentialPurpose,
    CredentialRef,
    DevelopmentSecretProvider,
    SecretManager,
    SecretUnavailableError,
)

PROXMOX_API_ID = "root@pam!mcp"
PROXMOX_API_VALUE = "token-secret-value"
PROXMOX_LOGIN_VALUE = "password-value"
REDACTED = "**********"


def make_credential_ref(
    *,
    purpose: CredentialPurpose = "proxmox_api",
    path: str = "secret/proxmox/prod/api-token",
) -> CredentialRef:
    return CredentialRef(provider="development", path=path, purpose=purpose)


def make_cluster(*, credential_ref: CredentialRef | None = None) -> ProxmoxClusterConfig:
    return ProxmoxClusterConfig(
        cluster_id="prod-pve",
        name="Production PVE",
        api_endpoint="https://pve.example.test:8006/api2/json",
        tls_verify=True,
        credential_ref=make_credential_ref() if credential_ref is None else credential_ref,
        environment="production",
    )


def test_production_cluster_requires_https_endpoint() -> None:
    with pytest.raises(ValueError, match="https"):
        ProxmoxClusterConfig(
            cluster_id="prod-pve",
            name="Production PVE",
            api_endpoint="http://pve.example.test:8006/api2/json",
            credential_ref=make_credential_ref(),
            environment="production",
        )


def test_production_cluster_requires_tls_verification() -> None:
    with pytest.raises(ValueError, match="TLS"):
        ProxmoxClusterConfig(
            cluster_id="prod-pve",
            name="Production PVE",
            api_endpoint="https://pve.example.test:8006/api2/json",
            tls_verify=False,
            credential_ref=make_credential_ref(),
            environment="production",
        )


def test_proxmox_api_credential_enforces_api_token_fields() -> None:
    with pytest.raises(ValueError, match="token_id"):
        ProxmoxApiCredential(auth_type="api_token")


def test_proxmox_api_credential_enforces_username_password_fields() -> None:
    with pytest.raises(ValueError, match="username and password"):
        ProxmoxApiCredential(auth_type="username_password")


def test_proxmox_api_token_credential_rejects_password_fields() -> None:
    with pytest.raises(ValueError, match="username/password"):
        ProxmoxApiCredential(
            auth_type="api_token",
            token_id=PROXMOX_API_ID,
            token_secret=SecretStr(PROXMOX_API_VALUE),
            username="automation@pam",
        )


def test_proxmox_username_password_credential_rejects_api_token_fields() -> None:
    with pytest.raises(ValueError, match="API token"):
        ProxmoxApiCredential(
            auth_type="username_password",
            username="automation@pam",
            password=SecretStr(PROXMOX_LOGIN_VALUE),
            token_id=PROXMOX_API_ID,
        )


async def test_cluster_resolver_resolves_api_token_credentials() -> None:
    manager = SecretManager(
        providers=(
            DevelopmentSecretProvider(
                {
                    "secret/proxmox/prod/api-token": {
                        "auth_type": "api_token",
                        "token_id": PROXMOX_API_ID,
                        "token_secret": PROXMOX_API_VALUE,
                    }
                },
                environment="test",
            ),
        )
    )

    resolved = await ClusterCredentialResolver(manager).resolve(make_cluster())

    assert resolved.cluster_id == "prod-pve"
    assert resolved.credential.auth_type == "api_token"
    assert resolved.credential.token_id == PROXMOX_API_ID
    assert resolved.credential.token_secret is not None
    assert resolved.credential.token_secret.get_secret_value() == PROXMOX_API_VALUE

    dumped = resolved.safe_dump()
    assert PROXMOX_API_VALUE not in str(dumped)
    credential_dump = dumped["credential"]
    assert isinstance(credential_dump, dict)
    assert credential_dump["token_" + "secret"] == REDACTED


async def test_cluster_resolver_resolves_username_password_credentials() -> None:
    manager = SecretManager(
        providers=(
            DevelopmentSecretProvider(
                {
                    "secret/proxmox/prod/password": {
                        "auth_type": "username_password",
                        "username": "automation@pam",
                        "password": "password-value",
                        "realm": "pam",
                    }
                },
                environment="test",
            ),
        )
    )

    resolved = await ClusterCredentialResolver(manager).resolve(
        make_cluster(credential_ref=make_credential_ref(path="secret/proxmox/prod/password"))
    )

    assert resolved.credential.auth_type == "username_password"
    assert resolved.credential.username == "automation@pam"
    assert resolved.credential.password is not None
    assert resolved.credential.password.get_secret_value() == "password-value"
    assert resolved.credential.realm == "pam"
    assert "password-value" not in str(resolved.safe_dump())


async def test_cluster_resolver_rejects_non_proxmox_api_credentials() -> None:
    manager = SecretManager(
        providers=(DevelopmentSecretProvider({}, environment="test"),),
    )

    with pytest.raises(ValueError, match="proxmox_api"):
        await ClusterCredentialResolver(manager).resolve(
            make_cluster(credential_ref=make_credential_ref(purpose="ssh"))
        )


async def test_cluster_resolver_fails_closed_for_malformed_secret_payload() -> None:
    manager = SecretManager(
        providers=(
            DevelopmentSecretProvider(
                {"secret/proxmox/prod/api-token": {"auth_type": "api_token"}},
                environment="test",
            ),
        )
    )

    with pytest.raises(SecretUnavailableError, match="token_id"):
        await ClusterCredentialResolver(manager).resolve(make_cluster())
