# TDX API Bundle

This directory contains the reusable TDX helper library used by the demo
server. It is meant to be imported from your own Python scripts or validated
with the bundled smoke test.

## What is included

- `tdx_api.py`: reusable helper functions for quote generation, attestation,
  guest detection, and TD event log retrieval
- `test_tdx_api.py`: smoke test for the public API
- `requirements.txt`: runtime Python dependencies
- `lib/quote_generator.cpython-311-x86_64-linux-gnu.so`: native quote generator
  built for Python 3.11

## What is not included

- The legacy `appraisal/` sources from the original repository
- The MCP HTTP/SSE server entry points
- A full standalone Python environment

## Installation

1. Create and activate a Python 3.11 environment.
2. Install the Python dependencies:

```bash
pip install -r requirements.txt
```

3. If you want to import `tdx_api` from another folder, either:

  - add this directory to `PYTHONPATH` and use `from tdx_api import ...`, or
  - add the repository root to `PYTHONPATH` and use
    `from bytedance.tdx_api.tdx_api import ...`

## Smoke test

Run the bundled test from this directory:

```bash
python3 test_tdx_api.py --skip-attest
```

## Using the API from your own script

The most common import pattern is:

```python
from tdx_api import (
    DEFAULT_ATTEST_SERVICE_ENDPOINT,
    attest_tdx_quote,
    fetch_td_eventlog,
    get_raw_tdx_quote,
    get_tee_status,
)
```

Then call the functions directly, for example:

```python
result = get_raw_tdx_quote()
print(result)
```

## Relationship to the demo server

The MCP demo in `../../demo/mcp_tdx_demo/README.md` builds on the same quote
generation, guest detection, and event-log flow. This bundle is the
lower-level reusable API layer; the demo adds HTTP and MCP SSE server wiring
around it.
