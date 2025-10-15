# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

from pkgutil import extend_path

# Make "bytedance" a namespace package
__path__ = extend_path(__path__, __name__)
