# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

import secrets
from pathlib import Path

import pytest

from bytedance.jeddak_secure_channel import error
from bytedance.jeddak_secure_channel.crypto.aes import AES_MAC_LEN, AES_NONCE_LEN, AesKey

from .conftest import tweak_bytes

MESSAGES_BINARY = [
    pytest.param(b"i am bytes", id="short_bytes"),
    pytest.param(secrets.token_bytes(5000), id="long_bytes"),
    pytest.param(b"", id="empty_bytes"),
]
"""二进制消息测试数据."""

MESSAGES_TEXT = [
    pytest.param("i am str", id="short_str"),
    pytest.param(secrets.token_hex(5000).replace("a", "\n"), id="long_str"),
    pytest.param("", id="empty_str"),
]
"""文本消息测试数据."""


@pytest.mark.parametrize("message", MESSAGES_BINARY)
def test_encrypt(message: bytes):
    """测试 AES 加解密."""

    key = AesKey.generate()

    nonce, ciphertext, mac = encrypted = key.encrypt(message)

    assert len(nonce) == AES_NONCE_LEN
    assert len(ciphertext) == len(message)
    assert len(mac) == AES_MAC_LEN

    decrypted = key.decrypt(*encrypted)

    assert decrypted == message


@pytest.mark.parametrize("message", MESSAGES_BINARY)
def test_encrypt_stream_binary(tmp_path: Path, message: bytes):
    """测试 AES 对二进制数据流加解密."""

    key = AesKey.generate()

    input_path = tmp_path / "input"
    input_path.write_bytes(message)

    encrypted_path = tmp_path / "encrypted"
    with input_path.open("rb") as source, encrypted_path.open("wb") as dest:
        nonce, mac = key.encrypt_stream(source, dest, "b")

    output_path = tmp_path / "output"
    with encrypted_path.open("rb") as source, output_path.open("wb") as dest:
        key.decrypt_stream(source, dest, nonce, mac, "b")

    decrypted = output_path.read_bytes()
    assert decrypted == message


@pytest.mark.parametrize("message", MESSAGES_TEXT)
def test_encrypt_stream_text(tmp_path: Path, message: str):
    """测试 AES 对文本数据流按行加解密."""

    key = AesKey.generate()

    input_path = tmp_path / "input"
    input_path.write_text(message)

    # 加密
    encrypted_path = tmp_path / "encrypted"
    with input_path.open("rt") as source, encrypted_path.open("wt") as dest:
        nonce, mac = key.encrypt_stream(source, dest, "t")

    # 测试按行加密
    encryped = encrypted_path.read_text()
    assert encryped.rstrip("\n").count("\n") == message.rstrip("\n").count("\n")

    # 解密
    output_path = tmp_path / "output"
    with encrypted_path.open("rt") as source, output_path.open("wt") as dest:
        key.decrypt_stream(source, dest, nonce, mac, "t")

    # 测试解密内容
    decrypted = output_path.read_text()
    assert decrypted.rstrip("\n") == message.rstrip("\n")


@pytest.mark.parametrize("message", MESSAGES_BINARY)
def test_decrypt_error(message: bytes):
    """测试 AES 解密错误处理."""

    key = AesKey.generate()

    nonce, ciphertext, mac = key.encrypt(message)

    with pytest.raises(error.DecryptionError):
        key.decrypt(tweak_bytes(nonce), ciphertext, mac)

    with pytest.raises(error.DecryptionError):
        key.decrypt(nonce, tweak_bytes(ciphertext), mac)

    with pytest.raises(error.DecryptionError):
        key.decrypt(nonce, ciphertext, tweak_bytes(mac))
