from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from proxmox_mcp.config import TlsSettings

_REDACTED = "**********"
_GENERATED_CERT_NAME = "proxmox-mcp.crt"
_GENERATED_KEY_NAME = "proxmox-mcp.key"


class TlsConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TlsRuntimeConfig:
    uvicorn_config: dict[str, str]
    metadata: dict[str, object]


def resolve_tls_config(settings: TlsSettings) -> TlsRuntimeConfig:
    if settings.cert_file is not None or settings.key_file is not None:
        if settings.cert_file is None or settings.key_file is None:
            raise TlsConfigurationError("TLS requires both cert_file and key_file")

        cert_file = Path(settings.cert_file)
        key_file = Path(settings.key_file.get_secret_value())
        _validate_cert_chain(cert_file, key_file)
        return _runtime_config(cert_file=cert_file, key_file=key_file, generated=False)

    if not settings.generate_self_signed:
        raise TlsConfigurationError(
            "TLS certificate and key are required when self-signed generation is disabled"
        )

    cert_file, key_file = _generate_self_signed_certificate(settings)
    _validate_cert_chain(cert_file, key_file)
    return _runtime_config(cert_file=cert_file, key_file=key_file, generated=True)


def _runtime_config(*, cert_file: Path, key_file: Path, generated: bool) -> TlsRuntimeConfig:
    cert_file_text = str(cert_file)
    key_file_text = str(key_file)
    return TlsRuntimeConfig(
        uvicorn_config={
            "ssl_certfile": cert_file_text,
            "ssl_keyfile": key_file_text,
        },
        metadata={
            "enabled": True,
            "generated": generated,
            "cert_file": cert_file_text,
            "key_file": _REDACTED,
        },
    )


def _validate_cert_chain(cert_file: Path, key_file: Path) -> None:
    if not cert_file.is_file():
        raise TlsConfigurationError(f"TLS certificate file does not exist: {cert_file}")
    if not key_file.is_file():
        raise TlsConfigurationError(f"TLS private key file does not exist: {key_file}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    except ssl.SSLError as exc:
        raise TlsConfigurationError(
            "TLS certificate and private key do not form a valid chain"
        ) from exc
    except OSError as exc:
        raise TlsConfigurationError("TLS certificate and private key could not be loaded") from exc


def _generate_self_signed_certificate(settings: TlsSettings) -> tuple[Path, Path]:
    generated_dir = Path(settings.generated_cert_dir)
    generated_dir.mkdir(parents=True, exist_ok=True)
    cert_file = generated_dir / _GENERATED_CERT_NAME
    key_file = generated_dir / _GENERATED_KEY_NAME

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, settings.common_name),
        ]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(_subject_alt_names(settings)),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_file.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    _best_effort_chmod(key_file, 0o600)
    _best_effort_chmod(cert_file, 0o644)
    return cert_file, key_file


def _subject_alt_names(settings: TlsSettings) -> list[x509.GeneralName]:
    names = _unique_names((settings.common_name, *settings.subject_alt_names))
    return [_general_name_for(name) for name in names]


def _unique_names(names: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        normalized = name.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return tuple(result)


def _general_name_for(name: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ip_address(name))
    except ValueError:
        return x509.DNSName(name)


def _best_effort_chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        return
