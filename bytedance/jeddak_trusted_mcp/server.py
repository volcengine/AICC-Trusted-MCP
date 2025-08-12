import logging
from collections.abc import MutableMapping
from typing import Any, Literal

from mcp.server.fastmcp.server import FastMCP
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import Receive, Scope, Send
from typing_extensions import override

import bytedance.jeddak_secure_channel as jsc


class TrustedSessionManager(StreamableHTTPSessionManager):
    jsc_server: jsc.Server

    def __init__(self, jsc_server: jsc.Server, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.jsc_server = jsc_server

    @override
    async def handle_request(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not Headers(scope=scope).get(
            "x-jeddak-trusted-mcp"
        ):
            await super().handle_request(scope, receive, send)
            return

        # Collect request body
        req_messages: list[MutableMapping[str, Any]] = []
        req_body = b""
        while True:
            message = await receive()
            if message["type"] == "http.request":
                req_body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                return
            else:
                req_messages.append(message)

        if not req_body:
            logging.warning("Request body empty")
            await super().handle_request(scope, receive, send)
            return

        # Decrypt request body
        decrypted_req, resp_key = self.jsc_server.decrypt_with_response(req_body)

        # Replay received messages
        req_messages.append(
            {"type": "http.request", "body": decrypted_req, "more_body": False}
        )
        req_messages.reverse()

        async def new_receive() -> MutableMapping[str, Any]:
            if req_messages:
                return req_messages.pop()
            return await receive()

        # Encrypt response

        resp_mode: Literal["waiting", "none", "full", "event-stream", "finished"] = (
            "waiting"
        )
        resp_start_message: MutableMapping[str, Any] | None = None
        resp_headers: MutableHeaders | None = None
        resp_body = b""

        async def new_send(message: MutableMapping[str, Any]) -> None:
            nonlocal resp_mode, resp_start_message, resp_headers, resp_body

            if message["type"] == "http.response.start":
                # Transform response headers
                if resp_mode != "waiting":
                    logging.error("Response headers sent again")

                resp_start_message = message
                resp_headers = MutableHeaders(raw=message.get("headers", {}))
                content_type = resp_headers.get("content-type", "")
                if content_type.startswith("application/json"):
                    resp_mode = "full"
                    resp_headers["x-jeddak-trusted-mcp"] = "1"
                    # Defer sending response header to update Content-Length
                    return
                elif content_type.startswith("text/event-stream"):
                    resp_mode = "event-stream"
                    resp_headers["x-jeddak-trusted-mcp"] = "1"
                    message["headers"] = resp_headers.raw
                    await send(message)
                    return
                else:
                    resp_mode = "none"
                    await send(message)
                    return
            elif message["type"] == "http.response.body":
                # Transform response body
                if resp_mode == "none":
                    await send(message)
                    return
                elif resp_mode == "full":
                    resp_body += message.get("body", b"")
                    if not message.get("more_body", False):
                        assert resp_start_message is not None
                        assert resp_headers is not None
                        resp_mode = "finished"
                        encrypted_resp = resp_key.encrypt(resp_body).encode()
                        resp_headers["content-length"] = str(len(encrypted_resp))
                        resp_start_message["headers"] = resp_headers.raw
                        await send(resp_start_message)
                        message["body"] = encrypted_resp
                        await send(message)
                        return
                    else:
                        # Defer sending response headers
                        return
                elif resp_mode == "event-stream":
                    resp_body += message.get("body", b"")
                    transformed_body = b""
                    while True:
                        line, sep, rest = resp_body.partition(b"\r\n")
                        if not sep:
                            break
                        resp_body = rest
                        if line.startswith(b"data:"):
                            data = line.removeprefix(b"data:").removeprefix(b" ")
                            encrypted_resp = resp_key.encrypt(data).encode()
                            transformed_body += b"data: " + encrypted_resp + sep
                        else:
                            transformed_body += line + sep
                    is_end = not message.get("more_body", False)
                    if is_end:
                        resp_mode = "finished"
                        if resp_body:
                            logging.error("Response body not ending in newline")
                    if is_end or transformed_body:
                        message["body"] = transformed_body
                        await send(message)
                    return
                else:
                    logging.error(
                        "Response body sent before headers, or after more_body=False"
                    )
                    await send(message)
            else:
                await send(message)

        # Pass to upstream
        await super().handle_request(scope, new_receive, new_send)


class TrustedMcp(FastMCP):
    def __init__(self, jsc_config: jsc.ServerConfig, *args, **kwargs):
        super().__init__(*args, **kwargs)

        jsc_server = jsc.Server(jsc_config)

        self._session_manager = TrustedSessionManager(
            jsc_server,
            app=self._mcp_server,
            event_store=self._event_store,
            json_response=self.settings.json_response,
            stateless=False,
            security_settings=self.settings.transport_security,
        )
