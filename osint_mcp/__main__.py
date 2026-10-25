"""``python -m osint_mcp`` / ``osint-mcp`` entrypoint (stdio transport)."""

from __future__ import annotations


def main() -> None:
    from .app import mcp

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
