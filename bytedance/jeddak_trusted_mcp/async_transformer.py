# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

__all__ = [
    "RequestTransformer",
    "ResponseTransformer",
    "ResponseTransformerInterface",
    "TransformAction",
]

import logging
from typing import AsyncGenerator, Awaitable, Literal, Protocol

from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Send

logger = logging.getLogger(__name__)


class RequestTransformer:
    upstream: Receive

    messages: list[Message]
    body: bytes

    _channel: AsyncGenerator[Message, None]

    def __init__(self, upstream: Receive):
        self.upstream = upstream
        self.messages = []
        self.body = b""
        self._channel = self._loop()

    async def collect_body(self) -> None:
        while True:
            message = await self.upstream()
            if message["type"] == "http.request":
                self.body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            else:
                self.messages.append(message)
                if message["type"] == "http.disconnect":
                    break

    async def _loop(self) -> AsyncGenerator[Message, None]:
        # Replay received messages
        for message in self.messages:
            yield message
        yield {"type": "http.request", "body": self.body, "more_body": False}

        # Forward to upstream
        while True:
            yield await self.upstream()

    def receive(self) -> Awaitable[Message]:
        return anext(self._channel)


TransformAction = Literal["pass", "transform_full", "transform_line"]


class ResponseTransformerInterface(Protocol):
    def headers(self, status: int, headers: MutableHeaders) -> TransformAction:
        return "pass"

    def transform_full(self, body: bytes) -> bytes:
        return body

    def transform_line(self, line: bytes) -> bytes:
        return line


class ResponseTransformer:
    downstream: Send

    transformer: ResponseTransformerInterface

    _channel: AsyncGenerator[None, Message] | None

    def __init__(self, downstream: Send, transformer: ResponseTransformerInterface):
        self.downstream = downstream
        self.transformer = transformer

        # We need to call anext() to start the generator before it produces values
        # But __init__ is not async, so we defer creating the generator
        self._channel = None

    async def _loop(self) -> AsyncGenerator[None, Message]:
        while True:
            # Start of a response
            message = yield

            # Expect response headers
            if message["type"] != "http.response.start":
                logger.warning(f"Expecting headers message, but got {message}")
                await self.downstream(message)
                continue

            # Determine the action by (subclass) handler
            status = message.get("status", 0)
            headers = MutableHeaders(raw=message.get("headers", {}))

            action = self.transformer.headers(status, headers)

            # Handler may have changed the headers
            message["headers"] = headers.raw

            if action == "pass":
                # Passthrough the body
                await self.downstream(message)
                more_body = True
                while more_body:
                    message = yield
                    if message["type"] != "http.response.body":
                        logger.warning(f"Expecting body message, but got {message}")
                        await self.downstream(message)
                        break
                    await self.downstream(message)
                    more_body = message.get("more_body", False)

            elif action == "transform_full":
                # Collect the full body and transform
                # Defer sending headers
                headers_message = message
                body = b""
                more_body = True
                while more_body:
                    message = yield
                    if message["type"] != "http.response.body":
                        logger.warning(f"Expecting body message, but got {message}")
                        await self.downstream(message)
                        break
                    body += message.get("body", b"")
                    more_body = message.get("more_body", False)

                body = self.transformer.transform_full(body)

                # Send the updated headers
                headers["content-length"] = str(len(body))
                headers_message["headers"] = headers.raw
                await self.downstream(headers_message)

                # Send the transformed body
                await self.downstream(
                    {"type": "http.response.body", "body": body, "more_body": False}
                )

            elif action == "transform_line":
                # Transform the body stream line by line
                await self.downstream(message)
                body = b""
                more_body = True
                while more_body:
                    message = yield
                    if message["type"] != "http.response.body":
                        logger.warning(f"Expecting body message, but got {message}")
                        await self.downstream(message)
                        break
                    body += message.get("body", b"")
                    more_body = message.get("more_body", False)

                    lines = b""
                    while True:
                        line, sep, rest = body.partition(b"\r\n")
                        if not sep:
                            break
                        body = rest
                        lines += self.transformer.transform_line(line)
                        lines += sep

                    if not more_body or lines:
                        message["body"] = lines
                        await self.downstream(message)
                if body:
                    logger.warning("Response body not ending in newline")

    async def send(self, message: Message) -> None:
        if self._channel is None:
            self._channel = self._loop()
            await anext(self._channel)  # Run the generator until first yield point
        return await self._channel.asend(message)
