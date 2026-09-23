"""Admin inventory summary facade over active-host Proxmox reads."""

from __future__ import annotations

from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxmox_mcp.admin.app import _state
from proxmox_mcp.security.redaction import sanitize_for_security_boundary


async def _safe_get(client: Any, path: str) -> list[dict[str, object]] | dict[str, object] | None:
    try:
        data = await client.get(path)
    except Exception:  # noqa: BLE001 - fail closed per section
        return None
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return data
    return None


def _as_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _as_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _pct(used: float | None, total: float | None) -> float | None:
    if used is None or total is None or total <= 0:
        return None
    return round(min(100.0, max(0.0, (used / total) * 100.0)), 1)


def _enrich_node(raw: dict[str, object], status: dict[str, object] | None) -> dict[str, object]:
    row = dict(raw)
    st = status or {}
    cpu = _as_float(st.get("cpu") if st else raw.get("cpu"))
    maxcpu = _as_int(st.get("maxcpu") if st else raw.get("maxcpu"))
    mem = _as_float(st.get("mem") if st else raw.get("mem"))
    maxmem = _as_float(st.get("maxmem") if st else raw.get("maxmem"))
    # Some PVE builds nest memory under status.memory.{used,total,free}.
    nested = st.get("memory") if isinstance(st.get("memory"), dict) else None
    if nested and isinstance(nested, dict):
        mem = mem if mem is not None else _as_float(nested.get("used") or nested.get("mem"))
        maxmem = (
            maxmem
            if maxmem is not None
            else _as_float(nested.get("total") or nested.get("maxmem"))
        )
    uptime = _as_int(st.get("uptime") if st else raw.get("uptime"))
    version = st.get("pveversion") or st.get("version") or raw.get("pveversion")
    row.update(
        {
            "cpu_ratio": cpu,
            "cpu_percent": round(cpu * 100.0, 1) if cpu is not None else None,
            "maxcpu": maxcpu,
            "mem_used": mem,
            "mem_total": maxmem,
            "mem_percent": _pct(mem, maxmem),
            "uptime_seconds": uptime,
            "version": version,
            "status": row.get("status") or st.get("status") or "unknown",
        }
    )
    return row


def _enrich_guest(raw: dict[str, object], *, guest_type: str, node_name: str) -> dict[str, object]:
    row = dict(raw)
    mem = _as_float(row.get("mem"))
    maxmem = _as_float(row.get("maxmem"))
    disk = _as_float(row.get("disk"))
    maxdisk = _as_float(row.get("maxdisk"))
    cpu = _as_float(row.get("cpu"))
    tags = row.get("tags")
    row.update(
        {
            "node": node_name,
            "guest_type": guest_type,
            "cpu_ratio": cpu,
            "cpu_percent": round(cpu * 100.0, 1) if cpu is not None else None,
            "mem_used": mem,
            "mem_total": maxmem,
            "mem_percent": _pct(mem, maxmem),
            "disk_used": disk,
            "disk_total": maxdisk,
            "disk_percent": _pct(disk, maxdisk),
            "uptime_seconds": _as_int(row.get("uptime")),
            "tags": str(tags).split(";") if isinstance(tags, str) and tags else [],
            "status": row.get("status") or "unknown",
        }
    )
    return row


def _enrich_storage(raw: dict[str, object], *, node_name: str) -> dict[str, object]:
    row = dict(raw)
    used = _as_float(row.get("used") or row.get("disk"))
    total = _as_float(row.get("total") or row.get("maxdisk"))
    content = row.get("content")
    content_types = (
        [part for part in str(content).split(",") if part]
        if content is not None
        else []
    )
    row.update(
        {
            "node": node_name,
            "used_bytes": used,
            "total_bytes": total,
            "used_percent": _pct(used, total),
            "content_types": content_types,
            "status": row.get("status") or ("available" if row.get("active") else "unknown"),
        }
    )
    return row


def _redact_guest_config(config: dict[str, object]) -> dict[str, object]:
    sensitive = {
        "sshkeys",
        "cipassword",
        "password",
        "secret",
        "token",
        "key",
        "private",
        "webhook",
    }
    out: dict[str, object] = {}
    for key, value in config.items():
        lowered = key.lower()
        if any(token in lowered for token in sensitive):
            out[key] = "[redacted]"
            continue
        if isinstance(value, str) and len(value) > 512:
            out[key] = value[:512] + "…"
        else:
            out[key] = value
    return out


async def inventory_summary(request: Request) -> Response:
    state = _state(request)
    client = getattr(state, "proxmox_client", None)
    if client is None:
        return JSONResponse(
            {
                "configured": False,
                "detail": "Proxmox client unavailable — activate a host with secrets ready",
                "nodes": [],
                "vms": [],
                "lxc": [],
                "storage": [],
            },
            status_code=200,
        )

    nodes_raw = await _safe_get(client, "/nodes")
    if nodes_raw is None:
        return JSONResponse(
            {
                "configured": False,
                "detail": "Failed to read cluster inventory",
                "nodes": [],
                "vms": [],
                "lxc": [],
                "storage": [],
            },
            status_code=200,
        )

    nodes_list = nodes_raw if isinstance(nodes_raw, list) else []
    nodes: list[dict[str, object]] = []
    vms: list[dict[str, object]] = []
    lxc: list[dict[str, object]] = []
    storage: list[dict[str, object]] = []

    for node in nodes_list:
        node_name = str(node.get("node") or node.get("name") or "")
        if not node_name:
            continue
        status_raw = await _safe_get(client, f"/nodes/{node_name}/status")
        status = status_raw if isinstance(status_raw, dict) else None
        nodes.append(_enrich_node(node, status))

        qemu = await _safe_get(client, f"/nodes/{node_name}/qemu")
        if isinstance(qemu, list):
            for item in qemu:
                vms.append(_enrich_guest(item, guest_type="vm", node_name=node_name))
        containers = await _safe_get(client, f"/nodes/{node_name}/lxc")
        if isinstance(containers, list):
            for item in containers:
                lxc.append(_enrich_guest(item, guest_type="lxc", node_name=node_name))
        stores = await _safe_get(client, f"/nodes/{node_name}/storage")
        if isinstance(stores, list):
            for item in stores:
                storage.append(_enrich_storage(item, node_name=node_name))

    payload = {
        "configured": True,
        "nodes": nodes,
        "vms": vms,
        "lxc": lxc,
        "storage": storage,
        "counts": {
            "nodes": len(nodes),
            "vms": len(vms),
            "lxc": len(lxc),
            "storage": len(storage),
        },
    }
    sanitized = sanitize_for_security_boundary(payload)
    return JSONResponse(sanitized if isinstance(sanitized, dict) else payload)


async def inventory_guest_detail(request: Request) -> Response:
    """Read-only guest drill-down: status + redacted config summary."""
    state = _state(request)
    client = getattr(state, "proxmox_client", None)
    if client is None:
        return JSONResponse(
            {"configured": False, "detail": "Proxmox client unavailable"},
            status_code=200,
        )

    guest_type = str(request.path_params.get("guest_type") or "").lower()
    guest_id = str(request.path_params.get("guest_id") or "")
    if guest_type not in {"vm", "qemu", "lxc"} or not guest_id.isdigit():
        return JSONResponse({"detail": "Invalid guest type or id"}, status_code=400)

    api_kind = "qemu" if guest_type in {"vm", "qemu"} else "lxc"
    node = request.query_params.get("node")
    if not node:
        # Resolve node by scanning inventory when not provided.
        nodes_raw = await _safe_get(client, "/nodes")
        nodes_list = nodes_raw if isinstance(nodes_raw, list) else []
        for n in nodes_list:
            node_name = str(n.get("node") or "")
            if not node_name:
                continue
            listing = await _safe_get(client, f"/nodes/{node_name}/{api_kind}")
            if isinstance(listing, list):
                for item in listing:
                    if str(item.get("vmid")) == guest_id:
                        node = node_name
                        break
            if node:
                break
    if not node:
        return JSONResponse({"detail": "Guest not found"}, status_code=404)

    status = await _safe_get(client, f"/nodes/{node}/{api_kind}/{guest_id}/status/current")
    config = await _safe_get(client, f"/nodes/{node}/{api_kind}/{guest_id}/config")
    status_dict = status if isinstance(status, dict) else {}
    config_dict = config if isinstance(config, dict) else {}
    enriched = _enrich_guest(
        {**status_dict, "vmid": int(guest_id), "name": config_dict.get("name") or status_dict.get("name")},
        guest_type="lxc" if api_kind == "lxc" else "vm",
        node_name=node,
    )
    payload = {
        "configured": True,
        "guest": enriched,
        "config_summary": _redact_guest_config(config_dict),
        "node": node,
        "guest_type": enriched["guest_type"],
        "guest_id": guest_id,
    }
    sanitized = sanitize_for_security_boundary(payload)
    return JSONResponse(sanitized if isinstance(sanitized, dict) else payload)
