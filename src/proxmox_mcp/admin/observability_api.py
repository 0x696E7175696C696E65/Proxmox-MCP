"""Admin observability overview API."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from proxmox_mcp.admin.app import _state
from proxmox_mcp.observability import AlertmanagerAlertBackend, PrometheusTrendBackend
from proxmox_mcp.security.redaction import sanitize_for_security_boundary


async def observability_overview(request: Request) -> Response:
    state = _state(request)
    obs = state.settings.observability
    alertmanager_url = obs.alertmanager_url
    prometheus_url = obs.prometheus_url

    alerts: list[dict[str, object]] = []
    trends: list[dict[str, object]] = []
    alertmanager_configured = bool(alertmanager_url)
    prometheus_configured = bool(prometheus_url)
    errors: list[str] = []

    if alertmanager_url:
        try:
            backend = AlertmanagerAlertBackend(
                base_url=alertmanager_url,
                allow_private_hosts=obs.allow_private_hosts,
            )
            records = await backend.get_recent_alerts(
                limit=25,
                tenant_id=None,
                cluster_id=None,
                node_id=None,
            )
            alerts = [
                {
                    "name": r.name,
                    "status": r.status,
                    "severity": r.severity,
                    "starts_at": r.starts_at,
                    "fingerprint": r.fingerprint,
                }
                for r in records
            ]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"alertmanager: {type(exc).__name__}")

    if prometheus_url:
        try:
            backend = PrometheusTrendBackend(
                base_url=prometheus_url,
                allow_private_hosts=obs.allow_private_hosts,
            )
            records = await backend.get_resource_trends(
                resource_type="cluster",
                resource_id="default",
                metric="up",
                range_seconds=3600,
                step_seconds=300,
                limit=1,
            )
            for trend in records:
                trends.append(
                    {
                        "metric": trend.metric,
                        "resource_type": trend.resource_type,
                        "resource_id": trend.resource_id,
                        "samples": trend.samples[-24:],
                    }
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"prometheus: {type(exc).__name__}")

    payload = {
        "configured": alertmanager_configured or prometheus_configured,
        "alertmanager": {
            "configured": alertmanager_configured,
            "url_configured": alertmanager_configured,
        },
        "prometheus": {
            "configured": prometheus_configured,
            "url_configured": prometheus_configured,
        },
        "alerts": alerts,
        "trends": trends,
        "errors": errors,
    }
    sanitized = sanitize_for_security_boundary(payload)
    return JSONResponse(sanitized if isinstance(sanitized, dict) else payload)
