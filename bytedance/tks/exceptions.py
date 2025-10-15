# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

__all__ = [
    "TKSError",
    "RAError",
]


class TKSError(Exception): ...  # noqa: E701


class RAError(TKSError): ...  # noqa: E701
