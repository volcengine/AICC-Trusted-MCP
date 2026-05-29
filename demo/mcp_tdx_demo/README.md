# MCP TDX Demo

This directory contains the HTTP and MCP/Server-Sent Events demo for the shared
TDX helpers. It wraps the reusable API bundle in `../../bytedance/tdx_api`
with server routing and tool registration.

## Overview

The server implementations provide the same four TDX-oriented tools:

- `fetchTDEventlog`: read the TD event log from the current environment
- `getRawTDXQuote`: generate a TDX quote and return JSON-serializable data
- `getTEEStatus`: detect whether the host is running as a TDX guest
- `quoteVerify`: run quote appraisal with a base64-encoded quote and policies

The HTTP and SSE entry points are implemented in `mcp_http.py` and
`mcp_server_sse_tdx.py`.

## Relationship to the API bundle

This demo depends on the reusable TDX API bundle in
`../../bytedance/tdx_api`. That bundle provides the lower-level quote
generation, guest detection, and event-log logic. The demo layer adds the HTTP
and MCP SSE server interfaces.

## Requirements

- Python 3.11
- The Python dependencies listed in `requirement.txt`
- Access to the native `quote_generator` extension from the API bundle
- The runtime libraries used by the event-log path, including `cctrusted_base`
  and `cctrusted_vm`

## Local Setup

Use a project-local virtual environment so the demo server runs with the same
packages every time:

```bash
cd /home/AICC-Trusted-MCP/demo/mcp_tdx_demo
/usr/bin/python3 -m venv .venv
.venv/bin/python -m pip install -r requirement.txt
.venv/bin/python -m pip install fastapi
```

Notes:

- `requirement.txt` covers the shared MCP/TDX runtime dependencies.
- `fastapi` is needed by `mcp_http.py`, even though it is not listed in
  `requirement.txt`.
- Run the servers with `.venv/bin/python` so the installed packages are used.

## Installation

1. Prepare a Python 3.11 environment.
2. Create `.venv` and install the requirements as shown above.
3. If you need to import the reusable API bundle outside these entry points,
   add the repository root to `PYTHONPATH`, for example:

```bash
export PYTHONPATH=/home/AICC-Trusted-MCP:$PYTHONPATH
```

4. Start the server entry point you need.

## Start HTTP Server

Run the HTTP API with the project-local environment:

```bash
cd /home/AICC-Trusted-MCP/demo/mcp_tdx_demo
.venv/bin/python mcp_http.py
```

The HTTP server listens on `http://127.0.0.1:8800`.

## Start SSE Server

Run the SSE MCP server with the project-local environment:

```bash
cd /home/AICC-Trusted-MCP/demo/mcp_tdx_demo
.venv/bin/python mcp_server_sse_tdx.py
```

The SSE server also listens on `http://127.0.0.1:8800`.

## Running the demo

Each demo server listens on `0.0.0.0:8800` by default. Start one at a time, or
override the port when running them side by side.

## HTTP Verification

Use these commands to verify the HTTP server:

```bash
curl -s http://127.0.0.1:8800/
curl -s http://127.0.0.1:8800/health
curl -s http://127.0.0.1:8800/api/tools
curl -s -X POST http://127.0.0.1:8800/api/fetchTDEventlog
curl -s -X POST http://127.0.0.1:8800/api/getTEEStatus
curl -s -X POST http://127.0.0.1:8800/api/getRawTDXQuote
curl -s -X POST http://127.0.0.1:8800/api/quoteVerify -H "Content-Type: application/json" -d '{"quote": "<base64-quote>", "tenant_policy": "<tenant-policy-jwt-text>", "platform_policy": "<optional-platform-policy-jwt-text>", "policy_pubkeys": ["<optional-base64-pubkey>"]}'
```

Expected behavior:

- `/` returns server metadata
- `/health` returns a healthy status
- `/api/tools` lists the available HTTP endpoints
- `/api/fetchTDEventlog` returns the event log output when the environment
  supports it
- `/api/getTEEStatus` returns the TEE detection result from `tdx_api.py`
- `/api/getRawTDXQuote` returns the raw quote payload from `tdx_api.py`
- `/api/quoteVerify` returns the appraisal result for a given base64 quote and policy

To run the automated HTTP client test:

```bash
cd /home/AICC-Trusted-MCP/demo/mcp_tdx_demo
.venv/bin/python test_mcp_http_client.py
```

## SSE Verification

The SSE server uses the MCP message flow. First open the SSE stream and copy
the `session_id` from the returned endpoint line:

```bash
curl -N http://127.0.0.1:8800/sse
```

Example response:

```text
data: /messages/?session_id=YOUR_SESSION_ID
```

Then use that `session_id` to send JSON-RPC requests to `/messages/`.

Initialize the session:

```bash
curl -s -X POST "http://127.0.0.1:8800/messages/?session_id=YOUR_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2025-11-25",
      "capabilities":{},
      "clientInfo":{"name":"curl","version":"0.1"}
    }
  }'
```

Notify initialization completion:

```bash
curl -s -X POST "http://127.0.0.1:8800/messages/?session_id=YOUR_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"notifications/initialized"
  }'
```

List tools:

```bash
curl -s -X POST "http://127.0.0.1:8800/messages/?session_id=YOUR_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":2,
    "method":"tools/list",
    "params":{}
  }'
```

Call `fetchTDEventlog`:

```bash
curl -s -X POST "http://127.0.0.1:8800/messages/?session_id=YOUR_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":3,
    "method":"tools/call",
    "params":{
      "name":"fetchTDEventlog",
      "arguments":{}
    }
  }'
```

Call `getTEEStatus`:

```bash
curl -s -X POST "http://127.0.0.1:8800/messages/?session_id=YOUR_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":4,
    "method":"tools/call",
    "params":{
      "name":"getTEEStatus",
      "arguments":{}
    }
  }'
```

Call `getRawTDXQuote`:

```bash
curl -s -X POST "http://127.0.0.1:8800/messages/?session_id=YOUR_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":5,
    "method":"tools/call",
    "params":{
      "name":"getRawTDXQuote",
      "arguments":{}
    }
  }'
```

Call `quoteVerify`:

```bash
curl -s -X POST "http://127.0.0.1:8800/messages/?session_id=YOUR_SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":6,
    "method":"tools/call",
    "params":{
      "name":"quoteVerify",
      "arguments":{
        "quote": "<base64-encoded-quote>",
        "tenant_policy": "<tenant-policy-jwt-text>",
        "platform_policy": "<optional-platform-policy-jwt-text>",
        "policy_pubkeys": ["<optional-base64-pubkey>"]
      }
    }
  }'
```

To run the automated SSE client test:

```bash
cd /home/AICC-Trusted-MCP/demo/mcp_tdx_demo
.venv/bin/python test_mcp_server_sse_tdx_client.py
```

## Example curl checks

```bash
curl -s http://localhost:8800/
curl -s http://localhost:8800/health
curl -s http://localhost:8800/api/tools
curl -s -X POST -H "Content-Type: application/json" http://localhost:8800/api/fetchTDEventlog
curl -s -X POST -H "Content-Type: application/json" http://localhost:8800/api/getRawTDXQuote
curl -s -X POST -H "Content-Type: application/json" http://localhost:8800/api/getTEEStatus
curl -s -X POST -H "Content-Type: application/json" -d '{"quote": "<base64-quote>", "tenant_policy": "<tenant-policy-jwt-text>", "platform_policy": "<optional-platform-policy-jwt-text>", "policy_pubkeys": ["<optional-base64-pubkey>"]}' http://localhost:8800/api/quoteVerify
```

## Error handling

- Import failures for the native quote module are surfaced immediately
- Tool failures are returned as JSON responses with an error message