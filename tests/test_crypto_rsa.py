# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

from bytedance.jeddak_secure_channel.crypto import PrivateKey


def test_encrypt():
    """测试 RSA 加解密."""

    message = b"Hello, World!"

    key = PrivateKey.generate()

    encrypted = key.encrypt(message)

    decrypted = key.decrypt(encrypted)
    assert decrypted == message


def test_sign():
    """测试 RSA 签名."""

    message = "Hello, World!"

    key = PrivateKey.generate()

    signature = key.sign(message)
    print(signature)

    verified = key.verify(signature, message)
    assert verified

    verified = key.verify(signature, "Hell0, W0rld!")
    assert not verified
