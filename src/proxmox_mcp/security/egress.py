"""Secure-by-design egress helpers: HTTPS-only, DNS pin, no redirects."""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from typing import Mapping
from urllib.error import URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import (
    HTTPErrorProcessor,
    HTTPSHandler,
    Request,
    build_opener,
)

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "metadata.google",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa")

# Prefer IPv4 when both families resolve — simpler TLS/Host handling for pin.
_SECURE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass(frozen=True, slots=True)
class ResolvedHttpsEndpoint:
    url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


class NoRedirectProcessor(HTTPErrorProcessor):
    """Refuse to follow redirects (credential-bearing requests must not hop)."""

    def http_response(self, request: Request, response: object) -> object:  # type: ignore[override]
        code = int(getattr(response, "code", 0) or getattr(response, "status", 0) or 0)
        if 300 <= code < 400:
            raise URLError(f"HTTP redirect {code} refused for secure egress")
        return response

    https_response = http_response  # type: ignore[assignment]


def _hostname_from_netloc(hostname: str | None) -> str:
    host = (hostname or "").lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _ip_is_metadata_or_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return True
    if ip == ipaddress.ip_address("169.254.169.254"):
        return True
    if ip == ipaddress.ip_address("fd00:ec2::254"):
        return True
    # CGNAT / shared address space — cloud IMDS endpoints often live here
    # (e.g. Alibaba 100.100.100.200). Never treat as "public" egress.
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return False


def _ip_is_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(ip.is_private)


def validate_https_url_host(
    url: str,
    *,
    allow_private: bool,
    allow_public: bool,
    resolve: bool = True,
) -> ResolvedHttpsEndpoint:
    """Validate https URL and optionally resolve DNS with destination policy."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("URL must use https://")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must not contain userinfo")
    hostname = _hostname_from_netloc(parsed.hostname)
    if not hostname:
        raise ValueError("URL must include a host")
    if hostname in _BLOCKED_HOSTNAMES or any(hostname.endswith(s) for s in _BLOCKED_SUFFIXES):
        raise ValueError("URL host is forbidden")

    port = parsed.port or 443
    addresses: list[str] = []

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        addresses = [str(literal)]
        _assert_address_policy(literal, allow_private=allow_private, allow_public=allow_public)
    elif resolve:
        try:
            infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"DNS resolution failed for host {hostname}") from exc
        seen: set[str] = set()
        for info in infos:
            sockaddr = info[4]
            ip_text = str(sockaddr[0])
            if ip_text in seen:
                continue
            seen.add(ip_text)
            addresses.append(ip_text)
            _assert_address_policy(
                ipaddress.ip_address(ip_text),
                allow_private=allow_private,
                allow_public=allow_public,
            )
        if not addresses:
            raise ValueError(f"DNS resolution returned no addresses for {hostname}")
    else:
        if not allow_public and not allow_private:
            raise ValueError("URL host policy rejects all destinations")

    return ResolvedHttpsEndpoint(
        url=url.rstrip("/"),
        hostname=hostname,
        port=port,
        addresses=tuple(addresses),
    )


def _assert_address_policy(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool,
    allow_public: bool,
) -> None:
    if _ip_is_metadata_or_forbidden(ip):
        raise ValueError("URL must not target loopback, link-local, metadata, or reserved addresses")
    private = _ip_is_private(ip)
    if private and not allow_private:
        raise ValueError("URL must not target private addresses")
    if not private and not allow_public:
        raise ValueError("URL must not target public addresses")


def _prefer_pinned_address(addresses: tuple[str, ...]) -> str:
    for address in addresses:
        try:
            if isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address):
                return address
        except ValueError:
            continue
    return addresses[0]


def _host_header(hostname: str, port: int) -> str:
    if port == 443:
        return hostname
    # IPv6 literals in Host need brackets when port is present.
    try:
        ip = ipaddress.ip_address(hostname)
        if isinstance(ip, ipaddress.IPv6Address):
            return f"[{hostname}]:{port}"
    except ValueError:
        pass
    return f"{hostname}:{port}"


def https_request_no_redirect(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    data: bytes | None = None,
    timeout_seconds: float = 5.0,
    ssl_context: object | None = None,
    allow_private: bool,
    allow_public: bool,
) -> tuple[int, bytes]:
    """HTTPS request pinned to a validated IP (no DNS rebinding TOCTOU, no redirects)."""
    endpoint = validate_https_url_host(
        url,
        allow_private=allow_private,
        allow_public=allow_public,
        resolve=True,
    )
    if not endpoint.addresses:
        raise ValueError("URL host has no resolved addresses to pin")

    pinned_ip = _prefer_pinned_address(endpoint.addresses)
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    context: ssl.SSLContext
    if ssl_context is None:
        context = ssl.create_default_context()
    elif isinstance(ssl_context, ssl.SSLContext):
        context = ssl_context
    else:
        raise TypeError("ssl_context must be an ssl.SSLContext or None")

    # Connect by IP; present original hostname for SNI + cert verification.
    verify_hostname = bool(getattr(context, "check_hostname", True)) and (
        context.verify_mode != ssl.CERT_NONE
    )

    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:  # noqa: ANN201
            sock = socket.create_connection((pinned_ip, endpoint.port), self.timeout)
            try:
                self.sock = context.wrap_socket(
                    sock,
                    server_hostname=endpoint.hostname if verify_hostname else None,
                )
            except Exception:
                sock.close()
                raise

    request_headers = {str(k): str(v) for k, v in dict(headers or {}).items()}
    # Always pin Host to the validated hostname — never allow caller override.
    request_headers["Host"] = _host_header(endpoint.hostname, endpoint.port)
    request_headers.setdefault("Connection", "close")

    conn = _PinnedHTTPSConnection(
        pinned_ip,
        endpoint.port,
        timeout=timeout_seconds,
        context=context,
    )
    try:
        conn.request(method.upper(), path, body=data, headers=request_headers)
        response = conn.getresponse()
        status = int(response.status)
        body = response.read()
        # Never follow redirects — credential-bearing hops are forbidden.
        if 300 <= status < 400:
            raise URLError(f"HTTP redirect {status} refused for secure egress")
        return status, body
    finally:
        conn.close()


def https_json_get_no_redirect(
    url: str,
    *,
    timeout_seconds: float = 10.0,
    allow_private: bool,
    allow_public: bool,
    headers: Mapping[str, str] | None = None,
) -> object:
    """GET JSON via pinned HTTPS egress (no redirects)."""
    merged = {"Accept": "application/json", **dict(headers or {})}
    status, body = https_request_no_redirect(
        url,
        method="GET",
        headers=merged,
        timeout_seconds=timeout_seconds,
        allow_private=allow_private,
        allow_public=allow_public,
    )
    if status >= 400:
        raise URLError(f"HTTP {status}")
    return json.loads(body.decode("utf-8"))


def https_json_post_no_redirect(
    url: str,
    payload: dict[str, object],
    *,
    timeout_seconds: float = 10.0,
    allow_private: bool,
    allow_public: bool,
    headers: Mapping[str, str] | None = None,
) -> int:
    """POST JSON via pinned HTTPS egress (no redirects). Returns HTTP status."""
    merged = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        **dict(headers or {}),
    }
    status, _body = https_request_no_redirect(
        url,
        method="POST",
        headers=merged,
        data=json.dumps(payload).encode("utf-8"),
        timeout_seconds=timeout_seconds,
        allow_private=allow_private,
        allow_public=allow_public,
    )
    return status


# Kept for tests that assert NoRedirectProcessor wiring with urllib openers.
def _legacy_urllib_opener(*, ssl_context: object | None = None) -> object:
    handlers: list[object] = [NoRedirectProcessor()]
    if ssl_context is not None:
        handlers.insert(0, HTTPSHandler(context=ssl_context))  # type: ignore[arg-type]
    return build_opener(*handlers)  # type: ignore[arg-type]


def pinned_url_for_tests(url: str, pinned_ip: str) -> str:
    """Rewrite a URL host to a pinned IP (test helper)."""
    parsed = urlparse(url)
    try:
        ip = ipaddress.ip_address(pinned_ip)
        host = f"[{pinned_ip}]" if isinstance(ip, ipaddress.IPv6Address) else pinned_ip
    except ValueError:
        host = pinned_ip
    port = parsed.port
    netloc = host if port is None else f"{host}:{port}"
    return urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )


SECURE_SSH_PATH = _SECURE_PATH
