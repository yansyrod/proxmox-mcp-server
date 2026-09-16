#!/usr/bin/env python3
"""
Proxmox VE MCP Server — full API coverage

Configuration (environment variables):
    PROXMOX_HOST        Proxmox hostname or IP (required)
    PROXMOX_PORT        API port (default: 8006)
    PROXMOX_USER        Username (e.g. root@pam) (required)
    PROXMOX_TOKEN_NAME  API token name (required if no password)
    PROXMOX_TOKEN_VALUE API token value (required if no password)
    PROXMOX_PASSWORD    Password (alternative to token auth)
    PROXMOX_VERIFY_SSL  Verify SSL certs (default: false)

MCP transport configuration:
    MCP_TRANSPORT               stdio (default) or streamable-http
    MCP_HTTP_HOST               HTTP bind address (default: 127.0.0.1)
    MCP_HTTP_PORT               HTTP bind port (default: 8000)
    MCP_HTTP_PATH               Streamable HTTP mount path (default: /mcp)
    MCP_HTTP_ALLOWED_HOSTS      Comma-separated Host header allowlist
    MCP_HTTP_ALLOWED_ORIGINS    Comma-separated Origin allowlist

Guest SSH operations are disabled by default. See .env.example and
LAB_GUEST_OPS.md before enabling them.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import mcp.server.stdio
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import TextContent, Tool
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
import uvicorn

# Load .env before importing modules which read feature flags at import time.
load_dotenv()

from .client import ProxmoxClient, _validate_config  # noqa: E402
from .safety import augment_schema, enforce  # noqa: E402
from .tools import (  # noqa: E402
    acme,
    access,
    ceph,
    cluster,
    disks,
    firewall,
    guest,
    lxc,
    nodes,
    notifications,
    pools,
    qemu,
    sdn,
    storage,
)

# --- Build unified tool registry ---

MODULES = [
    nodes,
    qemu,
    lxc,
    storage,
    cluster,
    access,
    firewall,
    disks,
    ceph,
    acme,
    sdn,
    notifications,
    pools,
    guest,
]

ALL_TOOLS: list[Tool] = []
TOOL_MODULE: dict[str, Any] = {}

for mod in MODULES:
    for tool_def in mod.TOOLS:
        name = tool_def["name"]
        t = Tool(
            name=name,
            description=tool_def["description"],
            inputSchema=augment_schema(name, tool_def["inputSchema"]),
        )
        ALL_TOOLS.append(t)
        TOOL_MODULE[name] = mod

# --- MCP server setup ---

proxmox = ProxmoxClient()
app = Server("proxmox-mcp-server")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return ALL_TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    try:
        mod = TOOL_MODULE.get(name)
        if mod is None:
            raise ValueError(f"Unknown tool: {name}")
        safe_arguments = enforce(name, dict(arguments or {}))
        result = await mod.handle(name, safe_arguments, proxmox)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        error = {"error": str(e), "tool": name}
        return [TextContent(type="text", text=json.dumps(error, indent=2))]


def _csv_env(name: str, default: str = "") -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _print_banner(transport: str) -> None:
    print("=" * 60, file=sys.stderr)
    print("Proxmox VE MCP Server", file=sys.stderr)
    print(f"Tools: {len(ALL_TOOLS)}", file=sys.stderr)
    print(f"Transport: {transport}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)


async def _prepare() -> None:
    _validate_config()
    await proxmox.authenticate()


async def main_stdio() -> None:
    _print_banner("stdio")
    await _prepare()
    print(f"✓ Ready — {len(ALL_TOOLS)} tools available", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


async def main_streamable_http() -> None:
    host = os.getenv("MCP_HTTP_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_HTTP_PORT", "8000"))
    path = os.getenv("MCP_HTTP_PATH", "/mcp").strip() or "/mcp"
    if not path.startswith("/"):
        path = f"/{path}"
    path = path.rstrip("/") or "/mcp"

    allowed_hosts = _csv_env(
        "MCP_HTTP_ALLOWED_HOSTS",
        "127.0.0.1:*,localhost:*",
    )
    allowed_origins = _csv_env("MCP_HTTP_ALLOWED_ORIGINS")

    security_settings = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )

    session_manager = StreamableHTTPSessionManager(
        app=app,
        json_response=False,
        stateless=False,
        security_settings=security_settings,
        max_sessions=256,
    )

    async def health(_request: Any) -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "proxmox-mcp-server"})

    @asynccontextmanager
    async def lifespan(_starlette_app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    http_app = Starlette(
        routes=[
            Route("/health", endpoint=health, methods=["GET"]),
            Mount(path, app=session_manager.handle_request),
        ],
        lifespan=lifespan,
    )

    _print_banner("streamable-http")
    print(f"HTTP endpoint: http://{host}:{port}{path}/", file=sys.stderr)
    print(f"Allowed Host headers: {', '.join(allowed_hosts) or '(none)'}", file=sys.stderr)

    await _prepare()
    print(f"✓ Ready — {len(ALL_TOOLS)} tools available", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    config = uvicorn.Config(
        http_app,
        host=host,
        port=port,
        log_level=os.getenv("MCP_HTTP_LOG_LEVEL", "info"),
        access_log=False,
        proxy_headers=True,
        forwarded_allow_ips=os.getenv("MCP_HTTP_FORWARDED_ALLOW_IPS", "127.0.0.1"),
    )
    server = uvicorn.Server(config)
    await server.serve()


async def main() -> None:
    transport = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()
    if transport == "stdio":
        await main_stdio()
        return
    if transport in {"streamable-http", "streamable_http", "http"}:
        await main_streamable_http()
        return
    raise ValueError(
        f"Unsupported MCP_TRANSPORT={transport!r}; use 'stdio' or 'streamable-http'"
    )


def run() -> None:
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n✓ Server stopped", file=sys.stderr)
    except Exception as e:
        print(f"\n✗ Fatal: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        asyncio.run(proxmox.close())


if __name__ == "__main__":
    run()
