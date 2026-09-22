"""Admin control plane package."""

from __future__ import annotations

__all__ = [
    "AdminAppState",
    "AdminEventHub",
    "AdminPathMiddleware",
    "ConfigStore",
    "RuntimeController",
    "create_admin_starlette_app",
]


def __getattr__(name: str):  # noqa: ANN201
    if name in {
        "AdminAppState",
        "AdminPathMiddleware",
        "create_admin_starlette_app",
    }:
        from proxmox_mcp.admin.app import (
            AdminAppState,
            AdminPathMiddleware,
            create_admin_starlette_app,
        )

        mapping = {
            "AdminAppState": AdminAppState,
            "AdminPathMiddleware": AdminPathMiddleware,
            "create_admin_starlette_app": create_admin_starlette_app,
        }
        return mapping[name]
    if name == "AdminEventHub":
        from proxmox_mcp.admin.events import AdminEventHub

        return AdminEventHub
    if name in {"ConfigStore", "RuntimeController"}:
        from proxmox_mcp.admin.config_store import ConfigStore, RuntimeController

        mapping = {"ConfigStore": ConfigStore, "RuntimeController": RuntimeController}
        return mapping[name]
    raise AttributeError(name)
