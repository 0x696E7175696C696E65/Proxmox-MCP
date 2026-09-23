from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID
from pydantic import SecretStr, ValidationError

from proxmox_mcp.config import Settings, TlsSettings
from proxmox_mcp.server.tls import (
    TlsConfigurationError,
    generate_tls_material,
    resolve_tls_config,
    resolve_tls_mode,
)


def test_resolve_tls_config_requires_tls_material_when_generation_disabled() -> None:
    with pytest.raises(TlsConfigurationError, match="TLS mode unresolved|certificate and key"):
        resolve_tls_config(TlsSettings(generate_self_signed=False, mode=None))


def test_resolve_tls_config_requires_cert_and_key_together(tmp_path: Path) -> None:
    cert_file = tmp_path / "tls.crt"
    cert_file.write_text("not a real cert")

    with pytest.raises(ValidationError, match="cert_file and key_file"):
        TlsSettings(
            mode="byoc",
            cert_file=str(cert_file),
            generate_self_signed=False,
        )


def test_resolve_tls_config_generates_self_signed_certificate(tmp_path: Path) -> None:
    runtime_config = resolve_tls_config(
        TlsSettings(
            mode="generate",
            generate_self_signed=True,
            generated_cert_dir=str(tmp_path),
            common_name="mcp.example.test",
            subject_alt_names=("mcp.example.test", "127.0.0.1"),
        )
    )

    cert_file = tmp_path / "proxmox-mcp.crt"
    key_file = tmp_path / "proxmox-mcp.key"
    ca_file = tmp_path / "ca.crt"
    assert runtime_config.uvicorn_config == {
        "ssl_certfile": str(cert_file),
        "ssl_keyfile": str(key_file),
    }
    assert cert_file.exists()
    assert key_file.exists()
    assert ca_file.exists()
    assert runtime_config.metadata["mode"] == "generate"
    assert runtime_config.metadata["ca_file"] == str(ca_file)

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
    ca_file = generated.metadata["ca_file"]
    assert isinstance(ca_file, str)

    runtime_config = resolve_tls_config(
        TlsSettings(
            mode="byoc",
            cert_file=cert_file,
            key_file=SecretStr(key_file),
            ca_file=ca_file,
            generate_self_signed=False,
        )
    )

    assert runtime_config.uvicorn_config == {
        "ssl_certfile": cert_file,
        "ssl_keyfile": key_file,
    }
    assert runtime_config.metadata["generated"] is False
    assert runtime_config.metadata["mode"] == "byoc"
    assert runtime_config.metadata["key_file"] == "**********"


def test_generate_leaf_signed_by_operator_ca(tmp_path: Path) -> None:
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Homelab CA")])
    now = datetime.now(UTC)
    from datetime import timedelta

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_path = ca_dir / "ca.crt"
    ca_key_path = ca_dir / "ca.key"
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_key_path.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    out = tmp_path / "server"
    runtime = generate_tls_material(
        TlsSettings(
            mode="generate",
            generate_self_signed=True,
            generated_cert_dir=str(out),
            common_name="mcp.home.arpa",
            subject_alt_names=("mcp.home.arpa", "127.0.0.1"),
            ca_file=str(ca_cert_path),
            ca_key_file=SecretStr(str(ca_key_path)),
        )
    )
    assert runtime.metadata["signed_by_operator_ca"] is True
    leaf = x509.load_pem_x509_certificate(Path(str(runtime.metadata["cert_file"])).read_bytes())
    assert leaf.issuer == ca_cert.subject
    trust = Path(str(runtime.metadata["ca_file"])).read_bytes()
    assert trust == ca_cert.public_bytes(serialization.Encoding.PEM)


def test_byoc_rejects_leaf_not_signed_by_configured_ca(tmp_path: Path) -> None:
    a = resolve_tls_config(
        TlsSettings(generate_self_signed=True, generated_cert_dir=str(tmp_path / "a"))
    )
    b = resolve_tls_config(
        TlsSettings(generate_self_signed=True, generated_cert_dir=str(tmp_path / "b"))
    )
    with pytest.raises(TlsConfigurationError, match="not signed by"):
        resolve_tls_config(
            TlsSettings(
                mode="byoc",
                cert_file=a.uvicorn_config["ssl_certfile"],
                key_file=SecretStr(a.uvicorn_config["ssl_keyfile"]),
                ca_file=str(b.metadata["ca_file"]),
                generate_self_signed=False,
            )
        )


def test_production_rejects_generated_tls_without_break_glass() -> None:
    with pytest.raises(ValidationError, match="BYOC TLS|ALLOW_GENERATED_TLS"):
        Settings(
            environment="production",
            auth_mode="service_token",
            service_token="x" * 32,
            allow_shared_service_token_actor=True,
            tls=TlsSettings(mode="generate", generate_self_signed=True),
        )


def test_production_accepts_byoc_tls(tmp_path: Path) -> None:
    generated = resolve_tls_config(
        TlsSettings(generate_self_signed=True, generated_cert_dir=str(tmp_path))
    )
    settings = Settings(
        environment="production",
        auth_mode="service_token",
        service_token="x" * 32,
        allow_shared_service_token_actor=True,
        tls=TlsSettings(
            mode="byoc",
            cert_file=generated.uvicorn_config["ssl_certfile"],
            key_file=SecretStr(generated.uvicorn_config["ssl_keyfile"]),
            ca_file=str(generated.metadata["ca_file"]),
            generate_self_signed=False,
        ),
    )
    assert resolve_tls_mode(settings.tls) == "byoc"
