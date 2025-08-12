from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared._httpx_utils import McpHttpClientFactory
from typing_extensions import override

import bytedance.jeddak_secure_channel as jsc


class JscResponse(httpx.Response):
    jsc_response_key: jsc.ResponseKey

    def __init__(self, upstream: httpx.Response, key: jsc.ResponseKey):
        super().__init__(
            status_code=upstream.status_code,
            headers=upstream.headers,
            stream=upstream.stream,
            extensions=upstream.extensions,
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


class AsyncTrustedTransport(httpx.AsyncHTTPTransport):
    jsc_client: jsc.Client

    def __init__(self, client: jsc.Client) -> None:
        super().__init__()
        self.jsc_client = client

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Read full request body and encrypt
        should_encrypt = True
        resp_key = None
        if should_encrypt:
            content = await request.aread()
            encrypted, resp_key = self.jsc_client.encrypt_with_response(content)
            request._content = encrypted.encode()
            request.stream = httpx.ByteStream(request._content)
            request.headers["content-length"] = str(len(request._content))
            request.headers["content-type"] = "application/json"

            request.headers["x-jeddak-trusted-mcp"] = "1"

        upstream_resp = await super().handle_async_request(request)

        if upstream_resp.headers.get("x-jeddak-trusted-mcp"):
            assert resp_key is not None
            return JscResponse(upstream_resp, resp_key)
        else:
            return upstream_resp


def _create_trusted_http_client(jsc_client: jsc.Client) -> McpHttpClientFactory:
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
    url: str, jsc_config: jsc.ClientConfig
) -> AsyncGenerator[ClientSession, None]:
    jsc_client = jsc.Client(jsc_config)

    async with streamablehttp_client(
        url,
        httpx_client_factory=_create_trusted_http_client(jsc_client),
    ) as (recv_stream, send_stream, _id_callback):
        async with ClientSession(recv_stream, send_stream) as mcp_session:
            yield mcp_session
