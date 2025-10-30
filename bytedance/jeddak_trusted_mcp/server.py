# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

__all__ = [
    "TrustedMCP",
    "TrustedSessionManager",
]

import json
import logging
import os

from mcp.server.fastmcp.server import FastMCP
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import Receive, Scope, Send
from typing_extensions import override

import bytedance.jeddak_secure_channel as jsc

from .async_transformer import (
    RequestTransformer,
    ResponseTransformer,
    ResponseTransformerInterface,
    TransformAction,
)
from .common import (
    TRUSTED_HEADER_NAME,
    extend_trust_capabilities,
    get_trust_capabilities,
)

logger = logging.getLogger(__name__)


class InitializeTransformer(ResponseTransformerInterface):
    @override
    def headers(self, status: int, headers: MutableHeaders) -> TransformAction:
        if not (200 <= status <= 299):
            return "pass"

        content_type = headers.get("content-type", "")
        if content_type.startswith("application/json"):
            return "transform_full"
        elif content_type.startswith("text/event-stream"):
            return "transform_line"
        else:
            logger.warning(f"Cannot rewrite initialize response {content_type}")
            return "pass"

    def _rewrite_resp(self, body_obj: dict):
        result = body_obj["result"] = body_obj.get("result", {})
        extend_trust_capabilities(result)

        logger.info(f"Rewrote initialize response {result}")

    def transform_full(self, body: bytes) -> bytes:
        try:
            body_obj = json.loads(body)
        except Exception:
            logger.exception("Initialize response")
            return body

        self._rewrite_resp(body_obj)

        return json.dumps(body_obj, separators=(",", ":"), ensure_ascii=False).encode()

    def transform_line(self, line: bytes) -> bytes:
        if not line.startswith(b"data:"):
            return line

        data = line.removeprefix(b"data:").removeprefix(b" ")
        try:
            body_obj = json.loads(data)

        except Exception:
            logger.exception("Initialize response")
            return line

        self._rewrite_resp(body_obj["result"])

        return (
            b"data: "
            + json.dumps(body_obj, separators=(",", ":"), ensure_ascii=False).encode()
        )


class EncryptingTransformer(ResponseTransformerInterface):
    resp_key: jsc.ResponseKey

    def __init__(self, resp_key: jsc.ResponseKey):
        self.resp_key = resp_key

    @override
    def headers(self, status: int, headers: MutableHeaders) -> TransformAction:
        if not (200 <= status <= 299):
            return "pass"

        content_type = headers.get("content-type", "")
        if content_type.startswith("application/json"):
            headers[TRUSTED_HEADER_NAME] = "1"
            return "transform_full"
        elif content_type.startswith("text/event-stream"):
            headers[TRUSTED_HEADER_NAME] = "1"
            return "transform_line"
        else:
            logger.warning(f"Cannot encrypt content-type {content_type}")
            return "pass"

    @override
    def transform_full(self, body: bytes) -> bytes:
        return self.resp_key.encrypt(body).encode()

    @override
    def transform_line(self, line: bytes) -> bytes:
        if not line.startswith(b"data:"):
            return line

        data = line.removeprefix(b"data:").removeprefix(b" ")
        encrypted_resp = self.resp_key.encrypt(data).encode()
        return b"data: " + encrypted_resp


class TrustedSessionManager(StreamableHTTPSessionManager):
    jsc_server: jsc.Server | None

    def __init__(self, jsc_server: jsc.Server | None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.jsc_server = jsc_server

    def _handle_request_impl(
        self, headers: Headers, req: RequestTransformer, send: Send
    ) -> Send | None:
        if not req.body:
            logger.info("Request body empty")
            return

        if headers.get(TRUSTED_HEADER_NAME):
            # Already negotiated; decrypt request and encrypt response
            if self.jsc_server is None:
                logger.error("Encrypted request but no server does not support AICC")
                return

            decrypted_req, resp_key = self.jsc_server.decrypt_with_response(req.body)
            req.body = decrypted_req

            resp = ResponseTransformer(send, EncryptingTransformer(resp_key))
            return resp.send

        if headers.get("content-type", "").startswith("application/json"):
            # Try to intercept initialize request
            try:
                body_obj = json.loads(req.body)
            except Exception:
                logger.exception("Try handle initialize request")
                return

            if body_obj.get("method") != "initialize":
                return

            if trust_capabilities := get_trust_capabilities(body_obj.get("params", {})):
                logger.info(f"Client supports AICC {trust_capabilities}")
            else:
                logger.info("Client does NOT support AICC")

            resp = ResponseTransformer(send, InitializeTransformer())
            return resp.send

        logger.warning(f"Unhandled request {headers}")

    @override
    async def handle_request(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await super().handle_request(scope, receive, send)
            return

        req = RequestTransformer(receive)
        await req.collect_body()
        new_receive = req.receive

        headers = Headers(scope=scope)
        new_send = self._handle_request_impl(headers, req, send) or send

        await super().handle_request(scope, new_receive, new_send)


class TrustedMCP(FastMCP):
    def __init__(self, aicc_config_path: str | os.PathLike = None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        jsc_server = None
        if aicc_config_path:
            jsc_config = jsc.ServerConfig.from_file(aicc_config_path)
        else:
            jsc_config = jsc.ServerConfig.from_dict({"key_file": "./myPrivateKey.pem"})

        try:
            jsc_server = jsc.Server(jsc_config)
        except Exception:
            logger.exception("Create AICC server")

        self._session_manager = TrustedSessionManager(
            jsc_server,
            app=self._mcp_server,
            event_store=self._event_store,
            json_response=self.settings.json_response,
            stateless=False,
            security_settings=self.settings.transport_security,
        )
