# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

import base64
import json
import random
import secrets
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest
import requests
import responses
from pytest_mock import MockerFixture
from typing import Dict, Tuple

from bytedance.jeddak_secure_channel import Client, ClientConfig, Server, ServerConfig

INACCESSIBLE_HOST = "no-such-host.local"
INACCESSIBLE_URL = f"http://{INACCESSIBLE_HOST}"


@pytest.fixture
def offline_client() -> Client:
    """未配置服务端 URL 的数据发送方对象."""
    client_config = ClientConfig(ra_url=INACCESSIBLE_URL, ra_attested_pods=[])

    return Client(client_config)


@pytest.fixture
def offline_server() -> Server:
    """未配置服务端 URL 的数据接收方对象."""
    server_config = ServerConfig(
        tks_url=INACCESSIBLE_URL,
        eps_url=INACCESSIBLE_URL,
        ras_address=INACCESSIBLE_HOST,
    )

    return Server(server_config)


@dataclass
class MockServices:
    """对证明生成服务 (EPS) 和远程证明服务 (RAS) 的 mock 对象."""

    get_quote: MagicMock
    get_attestaion_evaluation: MagicMock


@pytest.fixture
def mock_services(mocker: MockerFixture) -> MockServices:
    """对证明生成服务 (EPS) 和远程证明服务 (RAS) 的 mock 对象."""

    mock_eps = mocker.patch("bytedance.jeddak_secure_channel.server.EpsClient", autospec=True)
    get_quote = mock_eps.return_value.get_quote
    get_quote.return_value = base64.b64encode(secrets.token_bytes(10)).decode()

    mock_ras = mocker.patch("bytedance.jeddak_secure_channel.server.RasClient", autospec=True)
    get_attestaion_evaluation = mock_ras.return_value.get_attestation_evaluation
    get_attestaion_evaluation.returl_value = base64.b64encode(secrets.token_bytes(10)).decode()

    return MockServices(get_quote, get_attestaion_evaluation)


@pytest.fixture
def mock_server(mock_services: MockServices, offline_server: Server) -> Server:
    """对远程证明功能进行 mock 的数据接收方对象."""
    return offline_server


def mock_attest(client: Client, server: Server) -> None:
    def mock_callback(req: requests.PreparedRequest) -> Tuple[int, Dict[str, str], str]:
        assert req.body is not None
        return 200, {}, json.dumps(server.handle_ra_request(json.loads(req.body)))

    with responses.RequestsMock() as rsps:
        rsps.add_callback("POST", client.config.ra_url, callback=mock_callback)

        client.attest_server(None)


@pytest.fixture
def mock_channel(offline_client: Client, mock_server: Server) -> Tuple[Client, Server]:
    """对远程证明功能进行 mock, 并已完成远程证明的数据发送方和接收方对象."""

    mock_server.generate_key()

    mock_attest(offline_client, mock_server)

    return offline_client, mock_server


def tweak_bytes(b: bytes) -> bytes:
    """随机修改 bytes 内容."""

    if len(b) == 0:
        return b"123"

    a = bytearray(b)
    a[random.randrange(len(b))] ^= 1
    return bytes(a)
