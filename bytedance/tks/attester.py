# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

__all__ = [
    "Attester",
    "EPSAttester",
]

import os
from abc import ABC, abstractmethod

import requests

from . import exceptions as exp


class Attester(ABC):
    @abstractmethod
    def get_evidence(self, report_data: str) -> bytes:
        raise NotImplementedError


class EPSAttester(Attester):
    def __init__(self) -> None:
        pass

    def get_evidence(self, report_data: str, pod_name: str = "", attest_gpu: bool = True) -> bytes:
        host_ip = os.environ.get("JPCC_HOST_IP", "localhost")
        eps_addr = f"{host_ip}:8006"
        if not pod_name:
            pod_name = os.environ.get("HOSTNAME", "")

        url = "http://{}/aa/evidence?runtime_data={}&pod_name={}&attest_gpu={}".format(
            eps_addr, report_data, pod_name, str(attest_gpu).lower())

        try:
            resp = requests.get(url=url)
            resp.raise_for_status()
        except requests.RequestException as e:
            raise exp.RAError("Bad connection to EPS '{}': {}".format(url, e)) from e

        return resp.content
