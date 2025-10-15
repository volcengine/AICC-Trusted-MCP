# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

__all__ = [
    "TRUSTED_HEADER_NAME",
    "extend_trust_capabilities",
    "get_trust_capabilities",
]

TRUSTED_HEADER_NAME = "x-trusted-mcp"


def extend_trust_capabilities(params: dict) -> None:
    capabilities = params["capabilities"] = params.get("capabilities", {})
    experimental = capabilities["experimental"] = capabilities.get("experimental", {})
    experimental["trustProtocol"] = {"name": "AICC", "version": "0.1"}


def get_trust_capabilities(params: dict) -> dict | None:
    capabilities = params.get("capabilities", {}).get("experimental", {})
    trust_protocol = capabilities.get("trustProtocol", {})
    if trust_protocol.get("name") == "AICC":
        return trust_protocol
    return None
