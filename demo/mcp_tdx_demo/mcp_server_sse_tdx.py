"""MCP SSE server for TDX helpers.

This server is a thin adapter over :mod:`bytedance.tdx_api.tdx_api` so the
MCP tools reuse the shared implementation directly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Sequence

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Mount, Route

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bytedance.tdx_api.tdx_api import fetch_td_eventlog, get_raw_tdx_quote, get_tee_status


TOOL_HANDLERS: Dict[str, Callable[[], Dict[str, Any]]] = {
    "fetchTDEventlog": fetch_td_eventlog,
    "getRawTDXQuote": get_raw_tdx_quote,
    "getTEEStatus": get_tee_status,
}

TOOL_DESCRIPTIONS = {
    "fetchTDEventlog": "Retrieve TD event log data using the shared TDX API bundle.",
    "getRawTDXQuote": "Retrieve raw TDX quote data using the shared TDX API bundle.",
    "getTEEStatus": "Check whether the current host is running as a TDX guest using the shared TDX API bundle.",
}

sse = SseServerTransport("/messages/")
app = Server("tdx-mcp-sse-server")


async def _invoke_tool(name: str) -> Sequence[types.TextContent]:
    result = TOOL_HANDLERS[name]()
    return [types.TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> Sequence[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    if name not in TOOL_HANDLERS:
        raise ValueError(f"Unsupported tool: {name}")
    return await _invoke_tool(name)


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name=name,
            description=description,
            inputSchema={
                "type": "object",
                "required": [],
                "properties": {},
            },
        )
        for name, description in TOOL_DESCRIPTIONS.items()
    ]


async def handle_sse(request):
    async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
        await app.run(streams[0], streams[1], app.create_initialization_options())
    return Response()


starlette_app = Starlette(
    debug=True,
    routes=[
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
    ],
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(starlette_app, host="0.0.0.0", port=8800)
