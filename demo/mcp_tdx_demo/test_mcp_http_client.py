#!/usr/bin/env python3
"""End-to-end HTTP client test for mcp_http.py.

This script validates that the HTTP server exposes the same three TDX helper
functions as ``mcp_server_sse_tdx.py`` and that each endpoint returns the JSON
shape defined by ``bytedance.tdx_api.tdx_api``.

By default the script starts ``mcp_http.app`` in-process on an ephemeral port.
Use ``--url`` to connect to an already running server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
from contextlib import asynccontextmanager

import httpx
import uvicorn

import mcp_http as server


EXPECTED_TOOL_NAMES = ["fetchTDEventlog", "getRawTDXQuote", "getTEEStatus"]


def _assert_default_tool_wiring() -> None:
    assert server.TOOL_HANDLERS["fetchTDEventlog"] is server.fetch_td_eventlog
    assert server.TOOL_HANDLERS["getRawTDXQuote"] is server.get_raw_tdx_quote
    assert server.TOOL_HANDLERS["getTEEStatus"] is server.get_tee_status


def _pick_free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _validate_payload(tool_name: str, payload: dict) -> None:
    assert isinstance(payload, dict), f"{tool_name} should return a JSON object"
    assert isinstance(payload.get("status"), int), f"{tool_name} should return integer status"

    if tool_name == "fetchTDEventlog":
        if payload["status"] == 200:
            assert isinstance(payload.get("message"), str), payload
            assert isinstance(payload.get("td_eventlog"), str), payload
        else:
            assert isinstance(payload.get("error"), str), payload
        return

    if tool_name == "getRawTDXQuote":
        if payload["status"] == 200:
            assert isinstance(payload.get("quote_data"), str), payload
            assert "parse_result" in payload, payload
        else:
            assert isinstance(payload.get("error"), str), payload
        return

    if tool_name == "getTEEStatus":
        if payload["status"] == 200:
            assert isinstance(payload.get("message"), str), payload
        else:
            assert isinstance(payload.get("error"), str), payload
        return

    raise AssertionError(f"Unexpected tool name: {tool_name}")


def _summarize_payload(tool_name: str, payload: dict) -> str:
    if tool_name == "fetchTDEventlog":
        if payload["status"] == 200:
            return json.dumps(
                {
                    "status": payload["status"],
                    "message": payload.get("message"),
                    "td_eventlog_len": len(payload.get("td_eventlog", "")),
                },
                ensure_ascii=False,
            )
        return json.dumps({"status": payload["status"], "error": payload.get("error")}, ensure_ascii=False)

    if tool_name == "getRawTDXQuote":
        if payload["status"] == 200:
            parse_result = payload.get("parse_result") or {}
            return json.dumps(
                {
                    "status": payload["status"],
                    "quote_data_len": len(payload.get("quote_data", "")),
                    "parse_result_keys": sorted(parse_result.keys()),
                },
                ensure_ascii=False,
            )
        return json.dumps({"status": payload["status"], "error": payload.get("error")}, ensure_ascii=False)

    if tool_name == "getTEEStatus":
        if payload["status"] == 200:
            return json.dumps({"status": payload["status"], "message": payload.get("message")}, ensure_ascii=False)
        return json.dumps({"status": payload["status"], "error": payload.get("error")}, ensure_ascii=False)

    return json.dumps(payload, ensure_ascii=False)


async def _run_client(base_url: str) -> None:
    async with httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=120) as client:
        health = (await client.get("/health")).json()
        assert health["status"] == "healthy", health

        tools = (await client.get("/api/tools")).json()
        tool_names = [tool["name"] for tool in tools]
        assert tool_names == EXPECTED_TOOL_NAMES, tool_names

        for tool_name in EXPECTED_TOOL_NAMES:
            response = await client.post(server.TOOL_ENDPOINTS[tool_name])
            response.raise_for_status()
            payload = response.json()
            _validate_payload(tool_name, payload)
            print(f"{tool_name}: {_summarize_payload(tool_name, payload)}")


@asynccontextmanager
async def _embedded_server(base_url: str | None):
    if base_url is not None:
        yield base_url.rstrip("/")
        return

    host = "127.0.0.1"
    port = _pick_free_port(host)
    config = uvicorn.Config(
        server.app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    uvicorn_server = uvicorn.Server(config)
    server_task = asyncio.create_task(uvicorn_server.serve())

    try:
        deadline = asyncio.get_running_loop().time() + 5
        while not uvicorn_server.started:
            if server_task.done():
                raise RuntimeError("Embedded mcp_http.py stopped before startup")
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("Timed out waiting for embedded mcp_http.py to start")
            await asyncio.sleep(0.05)

        yield f"http://{host}:{port}"
    finally:
        uvicorn_server.should_exit = True
        await asyncio.wait_for(server_task, timeout=5)


async def main(url: str | None) -> int:
    _assert_default_tool_wiring()

    async with _embedded_server(url) as base_url:
        await _run_client(base_url)

    print("mcp_http client test: PASS")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP client test for mcp_http.py")
    parser.add_argument(
        "--url",
        help="Connect to an existing server base URL instead of starting an embedded one, for example http://127.0.0.1:8800",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.url)))