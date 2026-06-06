from __future__ import annotations

import argparse

from proxmox_mcp import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxmox-mcp")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.version:
        print(f"proxmox-mcp {__version__}")
        return 0

    from proxmox_mcp.server.app import run

    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
