"""
Entry point.

    itom-mcp                      # stdio (Claude Desktop / Claude Code / local clients)
    itom-mcp --transport http     # streamable HTTP on MCP_HTTP_HOST:MCP_HTTP_PORT, path /mcp

Secrets are read from the environment (or *_FILE), never from command-line flags.
"""

from __future__ import annotations

import argparse
import logging
import sys

from dotenv import load_dotenv

from itom_mcp.config import ConfigError, load_settings
from itom_mcp.server import build_http_app, build_server, configure_logging

logger = logging.getLogger("itom_mcp")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="ServiceNow ITOM MCP server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--env-file", help="Optional .env file to load (never committed)")
    args = parser.parse_args(argv)

    load_dotenv(args.env_file) if args.env_file else load_dotenv()

    try:
        settings = load_settings()
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(2)

    configure_logging(settings.log_level)
    try:
        mcp, _ctx = build_server(settings)
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            import uvicorn

            app = build_http_app(mcp, settings)
            uvicorn.run(
                app,
                host=settings.http_host,
                port=settings.http_port,
                log_level=settings.log_level.lower(),
                server_header=False,
                proxy_headers=True,
                forwarded_allow_ips="*",
                timeout_keep_alive=30,
            )
    except ConfigError as e:
        logger.error("Configuration error: %s", e)
        sys.exit(2)


if __name__ == "__main__":
    main()
