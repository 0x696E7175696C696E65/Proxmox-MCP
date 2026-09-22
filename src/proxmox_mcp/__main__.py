from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from proxmox_mcp import __version__
from proxmox_mcp.config import Settings
from proxmox_mcp.proxmox import (
    DANGEROUS_TOOL_SPECS,
    DOMAIN_COMPLETION_TOOL_SPECS,
    READ_ONLY_TOOL_SPECS,
    SAFE_MUTATION_TOOL_SPECS,
    domain_tool_promotion_records,
)
from proxmox_mcp.server.config_validation import ValidationIssue, doctor, validate_settings
from proxmox_mcp.ssh.tools import SSH_TOOL_SPECS
from proxmox_mcp.tools.internal import HEALTH_CHECK_DEFINITION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxmox-mcp")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser("serve", help="Start the MCP server")
    serve.add_argument(
        "--mode",
        choices=("dev", "homelab"),
        default=None,
        help="Runtime mode (default: homelab when durable state enabled, else dev)",
    )

    subparsers.add_parser("validate-config", help="Validate environment configuration")
    subparsers.add_parser("doctor", help="Validate configuration and probe dependencies")
    subparsers.add_parser("migrate", help="Apply Alembic migrations")

    tools = subparsers.add_parser("tools", help="Tool catalog commands")
    tools_sub = tools.add_subparsers(dest="tools_command", required=True)
    list_parser = tools_sub.add_parser("list", help="List registered tools")
    list_parser.add_argument(
        "--status",
        choices=("live", "guarded", "all"),
        default="all",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.version:
        print(f"proxmox-mcp {__version__}")
        return 0

    command = args.command
    if command is None:
        from proxmox_mcp.server.app import run

        run()
        return 0

    if command == "serve":
        from proxmox_mcp.server.app import run

        run(mode=args.mode)
        return 0

    if command == "validate-config":
        return _report_issues(validate_settings(Settings()))

    if command == "doctor":
        return _report_issues(doctor(Settings()))

    if command == "migrate":
        return _migrate()

    if command == "tools" and args.tools_command == "list":
        _print_tools(status_filter=args.status)
        return 0

    print(f"Unknown command: {command}", file=sys.stderr)
    return 2


def _report_issues(issues: Sequence[ValidationIssue]) -> int:
    if not issues:
        print("ok")
        return 0

    for issue in issues:
        name = getattr(issue, "name", "unknown")
        detail = getattr(issue, "detail", str(issue))
        print(f"{name}: {detail}", file=sys.stderr)
    return 1


def _migrate() -> int:
    from alembic import command
    from alembic.config import Config

    settings = Settings()
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", settings.database_url.get_secret_value())
    command.upgrade(config, "head")
    print("migrations applied")
    return 0


def _print_tools(*, status_filter: str) -> None:
    promotion = {record.name: record.promotion_status for record in domain_tool_promotion_records()}
    specs: list[tuple[str, str]] = [
        (HEALTH_CHECK_DEFINITION.name, "live"),
        *((spec.name, "live") for spec in READ_ONLY_TOOL_SPECS),
        *((spec.name, "live") for spec in SAFE_MUTATION_TOOL_SPECS),
        *((spec.name, "live") for spec in DANGEROUS_TOOL_SPECS),
        *((spec.name, promotion.get(spec.name, "live")) for spec in DOMAIN_COMPLETION_TOOL_SPECS),
        *((spec.name, "live") for spec in SSH_TOOL_SPECS),
    ]
    for name, status in sorted(specs, key=lambda item: item[0]):
        normalized = "guarded" if status != "live" else "live"
        if status_filter != "all" and normalized != status_filter:
            continue
        print(f"{name}\t{normalized}")


if __name__ == "__main__":
    raise SystemExit(main())
