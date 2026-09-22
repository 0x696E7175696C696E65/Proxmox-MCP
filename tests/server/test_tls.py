from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from pydantic import SecretStr

from proxmox_mcp.config import TlsSettings
from proxmox_mcp.server.tls import TlsConfigurationError, resolve_tls_config


def test_resolve_tls_config_requires_tls_material_when_generation_disabled() -> None:
    with pytest.raises(TlsConfigurationError, match="TLS certificate and key"):
        resolve_tls_config(TlsSettings(generate_self_signed=False))


def test_resolve_tls_config_requires_cert_and_key_together(tmp_path: Path) -> None:
    cert_file = tmp_path / "tls.crt"
    cert_file.write_text("not a real cert")

    with pytest.raises(TlsConfigurationError, match="both cert_file and key_file"):
        resolve_tls_config(
            TlsSettings(
                cert_file=str(cert_file),
                generate_self_signed=False,
            )
        )


def test_resolve_tls_config_generates_self_signed_certificate(tmp_path: Path) -> None:
    runtime_config = resolve_tls_config(
        TlsSettings(
            generate_self_signed=True,
            generated_cert_dir=str(tmp_path),
            common_name="mcp.example.test",
            subject_alt_names=("mcp.example.test", "127.0.0.1"),
        )
    )

    cert_file = tmp_path / "proxmox-mcp.crt"
    key_file = tmp_path / "proxmox-mcp.key"
    assert runtime_config.uvicorn_config == {
        "ssl_certfile": str(cert_file),
        "ssl_keyfile": str(key_file),
    }
    assert cert_file.exists()
    assert key_file.exists()

    certificate = x509.load_pem_x509_certificate(cert_file.read_bytes())
    assert certificate.not_valid_after_utc > datetime.now(UTC)
    san = cast(
        x509.SubjectAlternativeName,
        certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value,
    )
    assert san.get_values_for_type(x509.DNSName) == ["mcp.example.test"]
    assert "127.0.0.1" in [str(value) for value in san.get_values_for_type(x509.IPAddress)]


def test_resolve_tls_config_redacts_private_key_path(tmp_path: Path) -> None:
    runtime_config = resolve_tls_config(
        TlsSettings(
            generate_self_signed=True,
            generated_cert_dir=str(tmp_path),
        )
    )

    assert runtime_config.metadata["generated"] is True
    assert runtime_config.metadata["cert_file"] == str(tmp_path / "proxmox-mcp.crt")
    assert runtime_config.metadata["key_file"] == "**********"
    assert "proxmox-mcp.key" not in str(runtime_config.metadata)


def test_resolve_tls_config_accepts_user_provided_cert_chain(tmp_path: Path) -> None:
    generated = resolve_tls_config(
        TlsSettings(generate_self_signed=True, generated_cert_dir=str(tmp_path / "generated"))
    )
    cert_file = generated.uvicorn_config["ssl_certfile"]
    key_file = generated.uvicorn_config["ssl_keyfile"]

    runtime_config = resolve_tls_config(
        TlsSettings(
            cert_file=cert_file,
            key_file=SecretStr(key_file),
            generate_self_signed=False,
        )
    )

    assert runtime_config.uvicorn_config == {
        "ssl_certfile": cert_file,
        "ssl_keyfile": key_file,
    }
    assert runtime_config.metadata["generated"] is False
    assert runtime_config.metadata["key_file"] == "**********"
