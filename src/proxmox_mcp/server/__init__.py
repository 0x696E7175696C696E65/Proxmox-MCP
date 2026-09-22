"""Server package."""

__all__ = ["build_server"]


def __getattr__(name: str):  # noqa: ANN201
    if name == "build_server":
        from proxmox_mcp.server.app import build_server

        return build_server
    raise AttributeError(name)
