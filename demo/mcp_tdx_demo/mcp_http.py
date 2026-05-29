"""HTTP API wrapper for the shared TDX helpers.

This server mirrors ``mcp_server_sse_tdx.py`` but exposes plain HTTP endpoints
for the same three tools backed by ``bytedance.tdx_api.tdx_api``.
"""

from __future__ import annotations

import base64
import datetime
import sys
from pathlib import Path
from typing import Any, Callable, Dict

from fastapi import FastAPI
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bytedance.tdx_api.tdx_api import (
    appraise_quote_from_raw,
    fetch_td_eventlog,
    get_raw_tdx_quote,
    get_tee_status,
)


TOOL_HANDLERS: Dict[str, Callable[[], Dict[str, Any]]] = {
    "fetchTDEventlog": fetch_td_eventlog,
    "getRawTDXQuote": get_raw_tdx_quote,
    "getTEEStatus": get_tee_status,
}

TOOL_DESCRIPTIONS = {
    "fetchTDEventlog": "Retrieve TD event log data using the shared TDX API bundle.",
    "getRawTDXQuote": "Retrieve raw TDX quote data using the shared TDX API bundle.",
    "getTEEStatus": "Check whether the current host is running as a TDX guest using the shared TDX API bundle.",
    "quoteVerify": "Run quote appraisal via appraise_quote_from_raw using a base64-encoded quote.",
}

TOOL_ENDPOINTS = {
    "fetchTDEventlog": "/api/fetchTDEventlog",
    "getRawTDXQuote": "/api/getRawTDXQuote",
    "getTEEStatus": "/api/getTEEStatus",
    "quoteVerify": "/api/quoteVerify",
}

app = FastAPI(
    title="TDX Tools HTTP API",
    description="HTTP API for the shared TDX helper tools",
)


def _invoke_tool(name: str) -> Dict[str, Any]:
    return TOOL_HANDLERS[name]()


def _decode_base64_payload(payload: str) -> bytes:
    payload = payload.strip()
    padding_needed = (-len(payload)) % 4
    if padding_needed:
        payload += "=" * padding_needed
    return base64.b64decode(payload, validate=True)


class QuoteVerifyRequest(BaseModel):
    quote: str
    tenant_policy: str
    platform_policy: str | None = None
    policy_pubkeys: list[str] | None = None
    verbose: bool = False


@app.post("/api/fetchTDEventlog")
async def http_fetch_td_eventlog() -> Dict[str, Any]:
    return _invoke_tool("fetchTDEventlog")


@app.post("/api/getRawTDXQuote")
async def http_get_raw_tdx_quote() -> Dict[str, Any]:
    return _invoke_tool("getRawTDXQuote")


@app.post("/api/getTEEStatus")
async def http_get_tee_status() -> Dict[str, Any]:
    return _invoke_tool("getTEEStatus")


@app.post("/api/quoteVerify")
async def http_quote_verify(request: QuoteVerifyRequest) -> Dict[str, Any]:
    default_result: Dict[str, Any] = {
        "verify_success": False,
        "appraisal_success": False,
        "auth_success": None,
        "owner_auth_success": None,
        "overall_success": False,
        "warning": "Skipped policy owner authentication because policy_pubkeys were not provided.",
    }

    try:
        quote_data = _decode_base64_payload(request.quote)
    except Exception as exc:
        return {
            "status": 400,
            "error": f"Invalid base64 quote payload: {str(exc)}",
            "result": default_result,
        }

    policy_pubkeys = None
    if request.policy_pubkeys:
        try:
            policy_pubkeys = [
                _decode_base64_payload(pubkey_b64) for pubkey_b64 in request.policy_pubkeys
            ]
        except Exception as exc:
            return {
                "status": 400,
                "error": f"Invalid base64 policy_pubkeys payload: {str(exc)}",
                "result": {
                    **default_result,
                    "warning": None,
                },
            }

    return appraise_quote_from_raw(
        quote_data=quote_data,
        tenant_policy=request.tenant_policy.encode("utf-8"),
        platform_policy=(
            request.platform_policy.encode("utf-8") if request.platform_policy is not None else None
        ),
        policy_pubkeys=policy_pubkeys,
        verbose=request.verbose,
    )


@app.get("/api/tools")
async def list_available_tools() -> list[dict[str, Any]]:
    tools = [
        {
            "name": name,
            "description": TOOL_DESCRIPTIONS[name],
            "endpoint": TOOL_ENDPOINTS[name],
            "method": "POST",
            "required_params": [],
            "example_request": {},
        }
        for name in TOOL_HANDLERS
    ]

    tools.append(
        {
            "name": "quoteVerify",
            "description": TOOL_DESCRIPTIONS["quoteVerify"],
            "endpoint": TOOL_ENDPOINTS["quoteVerify"],
            "method": "POST",
            "required_params": ["quote", "tenant_policy"],
            "example_request": {
                "quote": "<base64-encoded-quote>",
                "tenant_policy": "<tenant-policy-jwt-text>",
                "platform_policy": "<optional-platform-policy-jwt-text>",
                "policy_pubkeys": ["<optional-base64-pubkey>"],
                "verbose": False,
            },
        }
    )
    return tools


@app.get("/health")
async def health_check() -> Dict[str, str]:
    return {"status": "healthy", "timestamp": datetime.datetime.now().isoformat()}


@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "name": "TDX Tools HTTP API",
        "version": "1.0.0",
        "description": "HTTP API for the shared TDX helper tools",
        "endpoints": {
            "tools": "/api/tools",
            "health": "/health",
            **{name: endpoint for name, endpoint in TOOL_ENDPOINTS.items()},
        },
    }


if __name__ == "__main__":
    import uvicorn

    print("Starting TDX Tools HTTP API server...")
    print("Available endpoints:")
    print("  GET  /                 - API information")
    print("  GET  /health           - Health check")
    print("  GET  /api/tools        - List available tools")
    print("  POST /api/fetchTDEventlog - Retrieve TD Eventlog")
    print("  POST /api/getRawTDXQuote  - Get raw TDX Quote")
    print("  POST /api/getTEEStatus    - Check TEE status")
    print("  POST /api/quoteVerify     - Quote appraisal with base64 quote")
    print("\nServer starting on http://0.0.0.0:8800")
    uvicorn.run(app, host="0.0.0.0", port=8800)
