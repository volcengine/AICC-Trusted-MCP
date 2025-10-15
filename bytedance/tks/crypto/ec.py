# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = [
    "diffie_hellman_key_exchange",
    "generate_key_pair",
]


def diffie_hellman_key_exchange(local_sk: bytes, peer_pk: bytes) -> bytes:
    local_sk_key = serialization.load_pem_private_key(local_sk, password=None)
    peer_pk_key = serialization.load_pem_public_key(peer_pk)
    assert isinstance(local_sk_key, ec.EllipticCurvePrivateKey)
    assert isinstance(peer_pk_key, ec.EllipticCurvePublicKey)
    shared_key = local_sk_key.exchange(ec.ECDH(), peer_pk_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None).derive(
        shared_key
    )
    return derived_key


def generate_key_pair() -> Tuple[bytes, bytes]:
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem
