# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

__all__ = [
    "trusted_mcp_client",
]

from datetime import timedelta
import json
import logging
import os
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager

from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import GetSessionIdCallback, streamablehttp_client
from mcp.shared._httpx_utils import McpHttpClientFactory
from mcp.shared.message import SessionMessage
from typing_extensions import override

import bytedance.jeddak_secure_channel as jsc

from .common import (
    TRUSTED_HEADER_NAME,
    extend_trust_capabilities,
    get_trust_capabilities,
)

logger = logging.getLogger(__name__)


class JscResponse(httpx.Response):
    jsc_response_key: jsc.ResponseKey

    def __init__(self, original: httpx.Response, key: jsc.ResponseKey):
        super().__init__(
            status_code=original.status_code,
            headers=original.headers,
            stream=original.stream,
            extensions=original.extensions,
        )
        self.jsc_response_key = key

    @override
    async def aread(self) -> bytes:
        content = await super().aread()
        return self.jsc_response_key.decrypt(content)

    @override
    async def aiter_lines(self) -> AsyncIterator[str]:
        async for line in super().aiter_lines():
            if line.startswith("data:"):
                data = line.removeprefix("data:").removeprefix(" ")
                decrypted = self.jsc_response_key.decrypt(data).decode()
                yield "data: " + decrypted
            else:
                yield line

    @override
    async def aiter_raw(
            self, chunk_size: int | None = None
    ) -> AsyncIterator[bytes]:
        async for chunk in super().aiter_raw(chunk_size):
            datas = chunk.decode().split('\r\n')
            for i in range(len(datas)):
                if datas[i].startswith("data:"):
                    data = datas[i].removeprefix("data:").removeprefix(" ")
                    decrypted = self.jsc_response_key.decrypt(data).decode()
                    datas[i] = "data: " + decrypted
            yield "\r\n".join(datas).encode()


class AsyncTrustedTransport(httpx.AsyncHTTPTransport):
    jsc_client: jsc.Client | None

    """
    None: not yet initialized
    True: server supports AICC, encrypt following requests
    False: server does not support AICC
    """
    server_support: bool | None

    def __init__(self, client: jsc.Client | None) -> None:
        super().__init__()
        self.jsc_client = client
        self.server_support = None

    async def _try_handle_initialize_request(
        self, req: httpx.Request
    ) -> httpx.Response | None:
        if not req.headers.get("content-type", "").startswith("application/json"):
            return

        try:
            body = await req.aread()
            if not body:
                logger.warning("Someone is sending suspicious content-type")
                return

            body_obj = json.loads(body)
        except Exception:
            logger.exception("Try handle initialize request")
            return

        if body_obj.get("method") != "initialize":
            return

        params = body_obj["params"] = body_obj.get("params", {})
        extend_trust_capabilities(params)

        logger.info(f"Rewrote initialize request {body_obj}")

        new_body = json.dumps(
            body_obj, separators=(",", ":"), ensure_ascii=False
        ).encode()
        req._content = new_body
        req.stream = httpx.ByteStream(req._content)
        req.headers["content-length"] = str(len(req._content))

        resp = await super().handle_async_request(req)

        self.server_support = True

        return resp

    async def _handle_initialize_response(self, resp: httpx.Response) -> None:
        content_type = resp.headers.get("content-type", "")

        try:
            if content_type.startswith("application/json"):
                body = await resp.aread()
                body_obj = json.loads(body)
                resp._content = body
                resp.stream = httpx.ByteStream(resp._content)

            elif content_type.startswith("text/event-stream"):
                body = await resp.aread()
                parsed_result = None
                for line in body.split(b"\r\n"):
                    if line.startswith(b"data:"):
                        data = line.removeprefix(b"data:").removeprefix(b" ")
                        parsed_result = json.loads(data).get("result", {})
                        break
                if parsed_result is None:
                    logger.warning("No data in initialize response")
                    return
                body_obj = {"result": parsed_result}
                resp._content = body
                resp.stream = httpx.ByteStream(resp._content)

            else:
                logger.warning(f"Cannot handle initialize response {content_type}")
                return

        except Exception:
            logger.exception("Try handle initialize response")
            return

        if trust_capabilities := get_trust_capabilities(body_obj.get("result", {})):
            logger.info(f"Server supports AICC {trust_capabilities}")
            self.server_support = True
        else:
            logger.info("Server does NOT support AICC")
            self.server_support = False

    async def _handle_encrypted_request(self, req: httpx.Request) -> httpx.Response:
        assert self.jsc_client

        # Read full request body and encrypt
        content = await req.aread()
        encrypted, resp_key = self.jsc_client.encrypt_with_response(content)
        req._content = encrypted.encode()
        req.stream = httpx.ByteStream(req._content)
        req.headers["content-length"] = str(len(req._content))
        req.headers["content-type"] = "application/json"

        req.headers[TRUSTED_HEADER_NAME] = "1"

        resp = await super().handle_async_request(req)

        if resp.headers.get(TRUSTED_HEADER_NAME):
            return JscResponse(resp, resp_key)
        else:
            if 200 <= resp.status_code <= 299:
                logger.warning("Encrypted request but plaintext response")
            return resp

    @override
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not self.jsc_client:
            # Client does not support AICC
            return await super().handle_async_request(request)

        if self.server_support is None:
            # Try to intercept initialize request
            if resp := await self._try_handle_initialize_request(request):
                return resp

        elif self.server_support:
            # Already negotiated; encrypt request and decrypt response
            return await self._handle_encrypted_request(request)

        # Server does not support AICC
        return await super().handle_async_request(request)


def _create_trusted_http_client(jsc_client: jsc.Client | None) -> McpHttpClientFactory:
    def f(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout if timeout is not None else httpx.Timeout(30),
            headers=headers,
            auth=auth,
            transport=AsyncTrustedTransport(jsc_client),
        )

    return f


@asynccontextmanager
async def trusted_mcp_client(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float | timedelta = 30,
    sse_read_timeout: float | timedelta = 60 * 5,
    terminate_on_close: bool = True,
    auth: httpx.Auth | None = None,
) -> AsyncGenerator[ClientSession, None]:
    jsc_client = None
    filtered_headers = headers.copy() if headers else None
    aicc_config_path = filtered_headers.pop("aicc-config", None) if filtered_headers else None
    if aicc_config_path:
        jsc_config = jsc.ClientConfig.from_file(aicc_config_path)
    else:
        jsc_config = jsc.ClientConfig.from_dict({"pub_key_path": "./myPublicKey.pem"})

    try:
        jsc_client = jsc.Client(jsc_config)
    except Exception:
        logger.exception("Create AICC client")

    try:
        async with streamablehttp_client(
            url=url,
            headers=filtered_headers,
            timeout=timeout,
            sse_read_timeout=sse_read_timeout,
            terminate_on_close=terminate_on_close,
            httpx_client_factory=_create_trusted_http_client(jsc_client),
            auth=auth,
        ) as (recv_stream, send_stream, _id_callback):
            async with ClientSession(recv_stream, send_stream) as mcp_session:
                await mcp_session.initialize()
                yield mcp_session
    except RuntimeError as e:
        if 'asynchronous generator is already running' in str(e):
            logger.debug('Suppress generator closing race: %s', e)
        else:
            raise


@asynccontextmanager
async def trusted_mcp_client_context(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float | timedelta = 30,
    sse_read_timeout: float | timedelta = 60 * 5,
    terminate_on_close: bool = True,
    auth: httpx.Auth | None = None,
) -> AsyncGenerator[
    tuple[
        MemoryObjectReceiveStream[SessionMessage | Exception],
        MemoryObjectSendStream[SessionMessage],
        GetSessionIdCallback,
    ],
    None,
]:
    jsc_client = None
    filtered_headers = headers.copy() if headers else None
    aicc_config_path = filtered_headers.pop("aicc-config", None) if filtered_headers else None
    if aicc_config_path:
        jsc_config = jsc.ClientConfig.from_file(aicc_config_path)
    else:
        jsc_config = jsc.ClientConfig.from_dict({"pub_key_path": "./myPublicKey.pem"})

    try:
        jsc_client = jsc.Client(jsc_config)
    except Exception:
        logger.exception("Create AICC client")

    async with streamablehttp_client(
        url=url,
        headers=filtered_headers,
        timeout=timeout,
        sse_read_timeout=sse_read_timeout,
        terminate_on_close=terminate_on_close,
        httpx_client_factory=_create_trusted_http_client(jsc_client),
        auth=auth,
    ) as (recv_stream, send_stream, id_callback):
        yield (
            recv_stream,
            send_stream,
            id_callback,
        )
