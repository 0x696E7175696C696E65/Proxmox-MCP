from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from proxmox_mcp.config import TlsSettings

_REDACTED = "**********"
_GENERATED_CERT_NAME = "proxmox-mcp.crt"
_GENERATED_KEY_NAME = "proxmox-mcp.key"
_GENERATED_CA_NAME = "ca.crt"
_GENERATED_CA_KEY_NAME = "ca.key"

TlsMode = Literal["generate", "byoc"]


class TlsConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TlsRuntimeConfig:
    uvicorn_config: dict[str, str]
    metadata: dict[str, object]


def resolve_tls_mode(settings: TlsSettings) -> TlsMode:
    """Resolve effective TLS mode: generate local material or bring-your-own-cert."""
    if settings.mode is not None:
        return settings.mode
    if settings.cert_file is not None or settings.key_file is not None:
        return "byoc"
    if settings.generate_self_signed:
        return "generate"
    raise TlsConfigurationError(
        "TLS mode unresolved: set PROXMOX_MCP_TLS__MODE=generate|byoc, "
        "or provide cert_file+key_file (BYOC), or enable generate_self_signed"
    )


def resolve_tls_config(settings: TlsSettings) -> TlsRuntimeConfig:
    mode = resolve_tls_mode(settings)
    if mode == "byoc":
        return _resolve_byoc(settings)
    return _resolve_generate(settings)


def generate_tls_material(
    settings: TlsSettings,
    *,
    output_dir: Path | None = None,
) -> TlsRuntimeConfig:
    """Generate HTTPS material without starting the server (CLI / bootstrap)."""
    target = settings
    if output_dir is not None:
        target = settings.model_copy(update={"generated_cert_dir": str(output_dir)})
    if resolve_tls_mode(target) != "generate" and target.ca_file is None:
        target = target.model_copy(update={"mode": "generate", "generate_self_signed": True})
    return _resolve_generate(target, force_regenerate=True)


def _resolve_byoc(settings: TlsSettings) -> TlsRuntimeConfig:
    if settings.cert_file is None or settings.key_file is None:
        raise TlsConfigurationError(
            "BYOC mode requires PROXMOX_MCP_TLS__CERT_FILE and PROXMOX_MCP_TLS__KEY_FILE"
        )

    cert_file = Path(settings.cert_file)
    key_file = Path(settings.key_file.get_secret_value())
    ca_file = Path(settings.ca_file) if settings.ca_file else None

    _validate_cert_chain(cert_file, key_file)
    if ca_file is not None:
        _validate_leaf_against_ca(cert_file, ca_file)

    return _runtime_config(
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_file,
        mode="byoc",
        generated=False,
        signed_by_operator_ca=ca_file is not None,
    )


def _resolve_generate(
    settings: TlsSettings,
    *,
    force_regenerate: bool = False,
) -> TlsRuntimeConfig:
    generated_dir = Path(settings.generated_cert_dir)
    generated_dir.mkdir(parents=True, exist_ok=True)
    cert_file = generated_dir / _GENERATED_CERT_NAME
    key_file = generated_dir / _GENERATED_KEY_NAME
    ca_out = generated_dir / _GENERATED_CA_NAME

    reuse = (
        not force_regenerate
        and cert_file.is_file()
        and key_file.is_file()
        and ca_out.is_file()
        and _cert_key_pair_valid(cert_file, key_file)
    )
    if reuse:
        return _runtime_config(
            cert_file=cert_file,
            key_file=key_file,
            ca_file=ca_out,
            mode="generate",
            generated=True,
            signed_by_operator_ca=_leaf_signed_by_file(cert_file, ca_out),
        )

    if settings.ca_file is not None and settings.ca_key_file is not None:
        cert_file, key_file, ca_out = _generate_leaf_signed_by_operator_ca(
            settings,
            cert_file=cert_file,
            key_file=key_file,
            ca_out=ca_out,
        )
        signed_by_ca = True
    else:
        cert_file, key_file, ca_out = _generate_self_signed_certificate(
            settings,
            cert_file=cert_file,
            key_file=key_file,
            ca_out=ca_out,
        )
        signed_by_ca = False

    _validate_cert_chain(cert_file, key_file)
    return _runtime_config(
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_out,
        mode="generate",
        generated=True,
        signed_by_operator_ca=signed_by_ca,
    )


def _runtime_config(
    *,
    cert_file: Path,
    key_file: Path,
    ca_file: Path | None,
    mode: TlsMode,
    generated: bool,
    signed_by_operator_ca: bool,
) -> TlsRuntimeConfig:
    uvicorn: dict[str, str] = {
        "ssl_certfile": str(cert_file),
        "ssl_keyfile": str(key_file),
    }
    metadata: dict[str, object] = {
        "enabled": True,
        "mode": mode,
        "generated": generated,
        "signed_by_operator_ca": signed_by_operator_ca,
        "cert_file": str(cert_file),
        "key_file": _REDACTED,
        "ca_file": str(ca_file) if ca_file is not None else None,
        "trust_hint": (
            "Import ca_file into MCP/browser trust stores for local HTTPS verification"
            if ca_file is not None
            else "Provide PROXMOX_MCP_TLS__CA_FILE so clients can verify the server certificate"
        ),
    }
    return TlsRuntimeConfig(uvicorn_config=uvicorn, metadata=metadata)


def _validate_cert_chain(cert_file: Path, key_file: Path) -> None:
    if not cert_file.is_file():
        raise TlsConfigurationError(f"TLS certificate file does not exist: {cert_file}")
    if not key_file.is_file():
        raise TlsConfigurationError(f"TLS private key file does not exist: {key_file}")
    if not _cert_key_pair_valid(cert_file, key_file):
        raise TlsConfigurationError(
            "TLS certificate and private key do not form a valid chain"
        )


def _cert_key_pair_valid(cert_file: Path, key_file: Path) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    except (ssl.SSLError, OSError):
        return False
    return True


def _validate_leaf_against_ca(cert_file: Path, ca_file: Path) -> None:
    if not ca_file.is_file():
        raise TlsConfigurationError(f"TLS CA file does not exist: {ca_file}")
    try:
        leaf = _load_first_certificate(cert_file)
        anchors = _load_certificates(ca_file)
        extras = _load_certificates(cert_file)[1:]
    except ValueError as exc:
        raise TlsConfigurationError(f"Unable to parse TLS certificate material: {exc}") from exc

    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    # Self-signed BYOC: leaf is the trust root itself.
    if any(leaf_der == a.public_bytes(serialization.Encoding.DER) for a in anchors):
        return

    for anchor in anchors:
        if _issued_by(leaf, anchor):
            return

    # Fullchain in cert_file: leaf ← intermediate ← configured CA.
    for intermediate in extras:
        if not _issued_by(leaf, intermediate):
            continue
        for anchor in anchors:
            if _issued_by(intermediate, anchor) or intermediate.public_bytes(
                serialization.Encoding.DER
            ) == anchor.public_bytes(serialization.Encoding.DER):
                return

    raise TlsConfigurationError(
        "BYOC leaf certificate is not signed by PROXMOX_MCP_TLS__CA_FILE "
        "(bring your own CA chain or omit ca_file)"
    )


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
    except Exception:  # noqa: BLE001 - cryptography raises several types
        return False
    return True


def _leaf_signed_by_file(cert_file: Path, ca_file: Path) -> bool:
    try:
        _validate_leaf_against_ca(cert_file, ca_file)
    except TlsConfigurationError:
        return False
    leaf = _load_first_certificate(cert_file)
    ca = _load_first_certificate(ca_file)
    return leaf.public_bytes(serialization.Encoding.DER) != ca.public_bytes(
        serialization.Encoding.DER
    )


def _generate_self_signed_certificate(
    settings: TlsSettings,
    *,
    cert_file: Path,
    key_file: Path,
    ca_out: Path,
) -> tuple[Path, Path, Path]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=settings.key_size)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, settings.common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proxmox MCP (generated)"),
        ]
    )
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=settings.validity_days))
        .add_extension(
            x509.SubjectAlternativeName(_subject_alt_names(settings)),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )
    certificate = builder.sign(private_key, hashes.SHA256())
    _write_key(key_file, private_key)
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    cert_file.write_bytes(pem)
    ca_out.write_bytes(pem)  # trust root == self-signed server cert
    _best_effort_chmod(key_file, 0o600)
    _best_effort_chmod(cert_file, 0o644)
    _best_effort_chmod(ca_out, 0o644)
    return cert_file, key_file, ca_out


def _generate_leaf_signed_by_operator_ca(
    settings: TlsSettings,
    *,
    cert_file: Path,
    key_file: Path,
    ca_out: Path,
) -> tuple[Path, Path, Path]:
    assert settings.ca_file is not None
    assert settings.ca_key_file is not None
    ca_path = Path(settings.ca_file)
    ca_key_path = Path(settings.ca_key_file.get_secret_value())
    if not ca_path.is_file():
        raise TlsConfigurationError(f"Operator CA certificate does not exist: {ca_path}")
    if not ca_key_path.is_file():
        raise TlsConfigurationError(f"Operator CA private key does not exist: {ca_key_path}")

    ca_cert = _load_first_certificate(ca_path)
    ca_key = _load_private_key(ca_key_path)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=settings.key_size)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, settings.common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proxmox MCP"),
        ]
    )
    now = datetime.now(UTC)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=settings.validity_days))
        .add_extension(
            x509.SubjectAlternativeName(_subject_alt_names(settings)),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(key_file, leaf_key)
    # Prefer fullchain (leaf + CA) so clients that don't have the CA yet still see intermediates.
    cert_file.write_bytes(
        leaf.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    ca_out.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    _best_effort_chmod(key_file, 0o600)
    _best_effort_chmod(cert_file, 0o644)
    _best_effort_chmod(ca_out, 0o644)
    return cert_file, key_file, ca_out


def _write_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _load_private_key(path: Path) -> CertificateIssuerPrivateKeyTypes:
    loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(loaded, rsa.RSAPrivateKey):
        # cryptography accepts several key types for signing; keep RSA for generated material.
        return loaded  # type: ignore[return-value]
    return loaded


def _load_first_certificate(path: Path) -> x509.Certificate:
    certs = _load_certificates(path)
    if not certs:
        raise ValueError(f"no certificates found in {path}")
    return certs[0]


def _load_certificates(path: Path) -> list[x509.Certificate]:
    data = path.read_bytes()
    certs: list[x509.Certificate] = []
    # Split PEM blocks; also accept a single DER blob.
    text = data.decode("ascii", errors="ignore")
    if "BEGIN CERTIFICATE" in text:
        chunks = text.split("-----BEGIN CERTIFICATE-----")
        for chunk in chunks[1:]:
            pem = "-----BEGIN CERTIFICATE-----" + chunk.split("-----END CERTIFICATE-----")[0]
            pem += "-----END CERTIFICATE-----\n"
            certs.append(x509.load_pem_x509_certificate(pem.encode()))
        return certs
    return [x509.load_der_x509_certificate(data)]


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
