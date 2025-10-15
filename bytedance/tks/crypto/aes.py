# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

__all__ = [
    "gcm_encrypt",
    "gcm_decrypt",
]

import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..consts import conf


def gcm_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv, ciphertext = ciphertext[:12], ciphertext[12:]
    ciphertext, tag = ciphertext[:-16], ciphertext[-16:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = secrets.token_bytes(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag


def generate_key_from_string(seed_string: str) -> bytes:
    backend = default_backend()
    # 将字符串种子转换为字节
    password = seed_string.encode()
    salt = conf.SALT.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend
    )
    key = kdf.derive(password)
    return key
