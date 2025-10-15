# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

import base64
import dataclasses
import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import requests
from typing import IO, TYPE_CHECKING, Any, Dict, Optional, Union
from volcenginesdkcore.rest import ApiException
from bytedance.jeddak_secure_channel.ra import RaConfig, attest_server, generate_nonce

from . import exceptions as exp
from .attester import EPSAttester
from .crypto import aes, ec

if TYPE_CHECKING:
    from _typeshed import GenericPath
else:
    GenericPath = str

__all__ = [
    "TKSClient",
    "TKSConfig",
]

PATH_ATTEST = "/api/tks/v1/security/attest"
PATH_RING_CREATE = "/api/tks/v1/ring/create"
PATH_KEY_EXPORT = "/api/tks/v1/key/export"
PATH_KEY_CREATE = "/api/tks/v1/key/create"
PATH_KEY_IMPORT = "/api/tks/v1/key/import"
PATH_POLICY_SET = "/api/tks/v1/policy/set"
PATH_KEY_LIST = "/api/tks/v1/key/list"
PATH_RING_LIST = "/api/tks/v1/ring/list"
PATH_KEY_INFO = "/api/tks/v1/key/getinfo"


def utc8_timestamp() -> int:
    return int(datetime.now(timezone(timedelta(hours=8))).timestamp())


@dataclass
class TKSConfig:
    addr: str = "jeddakchain.bytedance.com"
    pod_name: str = ""
    enable_tls: bool = False
    pcc_config: dict = dataclasses.field(default_factory=dict)
    top_config: dict = dataclasses.field(default_factory=dict)


class TKSClient:
    def __init__(self, app_id: str, config: TKSConfig) -> None:
        self._app_id = app_id
        self._config = config
        self.attester = EPSAttester()
        self.CHUNK_SIZE = 1024

    def _request_tks(
            self,
            url: str,
            body: Any,
            headers: Optional[Dict[str, str]] = None,
            cookies: Optional[Dict[str, str]] = None,
    ) -> dict:
        try:
            if self._config.top_config:
                if self._config.top_config.get("url_rewrite", ""):
                    from bytedance.jeddak_secure_channel.utils import (
                        request_bytedance_gateway,
                    )

                    resp = request_bytedance_gateway(
                        url, body, headers, self._config.top_config
                    )
                else:
                    from bytedance.jeddak_secure_channel.utils import top_request

                    resp = top_request(url, body, headers, self._config.top_config)
            else:
                resp = requests.post(
                    url=url, json=body, headers=headers, cookies=cookies
                )
        except ApiException as e:
            raise exp.TKSError(
                "Status '{}' from TKS, URL: '{}', Content: {}".format(
                    e.status, url, e.body
                )
            ) from e
        except Exception as e:
            raise exp.TKSError("Network error") from e
        try:
            if isinstance(resp, requests.Response):
                resp.raise_for_status()
                resp = resp.json()
        except requests.HTTPError as e:
            raise exp.TKSError(
                "Status '{}' from TKS, URL: '{}', Content: {}".format(
                    resp.status_code, url, resp.text
                )
            ) from e
        except requests.RequestException as e:
            raise exp.TKSError("Bad connection to TKS: {}".format(e)) from e

        # if "Result" not in resp:
        #     raise exp.TKSError("Unexpected response: {}".format(resp))
        res = resp["Result"] if "Result" in resp else resp

        return res

    def challenge_server(self, nonce: str) -> str:
        return self._do_server_ra(nonce)["Report"]

    def create_ring(self, ring_name: str, desc: str = "", **kwargs) -> dict:
        try:
            if self._config.top_config:
                url = self._config.addr
                self._config.top_config["action"] = "CreateTksRing"
            else:
                url = self._get_tks_url(PATH_RING_CREATE)

            result = self._request_tks(
                url=url,
                body={"RingName": ring_name, "Description": desc},
                headers=self._get_headers(),
                **kwargs,
            )
            return result
        except requests.RequestException as e:
            raise exp.TKSError("create_ring to TKS: {}".format(e)) from e

    def create_key(
            self,
            ring_id: str,
            algo: str,
            key_name: str = "",
            desc: str = "",
            **kwargs,
    ) -> dict:
        key_meta = self._do_key_creation(
            ring_id, algo=algo, key_name=key_name, src="internal", desc=desc, **kwargs
        )
        return key_meta

    def import_key(
            self,
            ring_id: str,
            algo: str,
            key: bytes,
            key_name: str = "",
            desc: str = "",
            usage_scenario="ModelEncryption",
            **kwargs,
    ) -> dict:
        # Create an empty key record
        key_meta = self._do_key_creation(
            ring_id,
            algo=algo,
            key_name=key_name,
            src="external",
            desc=desc,
            usage_scenario=usage_scenario,
            **kwargs,
        )

        # Locally generate key pair
        sk_local, pk_local = ec.generate_key_pair()

        # Challenge server
        ra_result = self._do_server_ra(bi_auth=False)
        pk_server = base64.b64decode(ra_result["DHParam"].encode())

        # Encrypt key
        ek = ec.diffie_hellman_key_exchange(sk_local, pk_server)
        encrypted_key = aes.gcm_encrypt(ek, key)

        if self._config.top_config:
            url = self._config.addr
            self._config.top_config["action"] = "ImportTksKey"
        else:
            url = self._get_tks_url(PATH_KEY_IMPORT)

        _ = self._request_tks(
            url=url,
            body={
                "RingID": ring_id,
                "KeyID": key_meta["KeyID"],
                "Key": base64.b64encode(encrypted_key).decode(),
                "DHParam": base64.b64encode(pk_local).decode(),
            },
            headers=self._get_headers(),
            **kwargs,
        )

        return key_meta

    def get_key_info(
            self,
            ring_id: str,
            key_id: str,
    ) -> dict:
        if self._config.top_config:
            url = self._config.addr
            self._config.top_config["action"] = "GetTksKeyinfo"
        else:
            url = self._get_tks_url(PATH_KEY_INFO)
        result = self._request_tks(
            url=url,
            body={
                "RingID": ring_id,
                "KeyID": key_id,
            },
            headers=self._get_headers(),
        )

        return result

    def get_key(
            self,
            ring_id: str,
            key_id: str,
            need_evidence: bool = True,
            attest_gpu: bool = True,
            policy_id='',
            tks_url='',
            tks_uid='',
            tks_service_name='',
            **kwargs,
    ) -> bytes:
        print(f'tks get_key: policy_id={policy_id}, url={tks_url}, uid={tks_uid}, ra_service_name={tks_service_name}')

        if policy_id:
            ra_config = RaConfig()
            self._config.top_config["action"] = "GetAttestationBackend"
            ra_config.bytedance_top_info = self._config.top_config
            ra_config.ra_url = tks_url
            ra_config.ra_service_name = tks_service_name
            if not ra_config.ra_service_name:
                ra_config.ra_service_name = "PCC.TKS"
            ra_config.ra_policy_id = policy_id
            ra_config.ra_uid = tks_uid
            ra_config.ra_key_negotiation = False

            nonce = generate_nonce()
            verify_res, public_key_info = attest_server("", ra_config, nonce)
            if not verify_res:
                raise Exception("verify tks failed!!!")
            print("verify tks success!!!")

        ra_result = self._do_server_ra(bi_auth=True)
        # get pub_key from server
        pk_server = base64.b64decode(ra_result["DHParam"].encode())

        sk_local, pk_local = ec.generate_key_pair()
        req_body = {
            "AppID": self._app_id,
            "RingID": ring_id,
            "KeyID": key_id,
            "DHParam": base64.b64encode(pk_local).decode(),
            "ClientChall": ra_result["Challenge"],
            # "RAEvidence": {"TEEType": "coco", "Report": base64.b64encode(evidence).decode()},
        }

        if need_evidence:
            evidence = self.attester.get_evidence(
                ra_result["Challenge"]["NonceDown"][:64],
                self._config.pod_name,
                attest_gpu,
            )

            req_body["RAEvidence"] = {
                "TEEType": "coco",
                "Report": base64.b64encode(evidence).decode(),
            }
        if self._config.top_config:
            url = self._config.addr
            self._config.top_config["action"] = "ExportTksKey"
        else:
            url = self._get_tks_url(PATH_KEY_EXPORT)

        res = self._request_tks(
            url=url, body=req_body, headers=self._get_headers(), **kwargs
        )

        encrypted_key = res["Key"]

        ek = ec.diffie_hellman_key_exchange(local_sk=sk_local, peer_pk=pk_server)

        data_key = aes.gcm_decrypt(ek, base64.b64decode(encrypted_key))

        return data_key

    def set_key_policy(self, ring_id: str, key_id: str, policy: str, **kwargs) -> dict:
        if self._config.top_config:
            url = self._config.addr
            self._config.top_config["action"] = "ImportTksKey"
        else:
            url = self._get_tks_url(PATH_POLICY_SET)

        result = self._request_tks(
            url=url,
            headers=self._get_headers(),
            body={
                "ID": key_id,
                "Range": "key",
                "Rules": policy,
            },
            **kwargs,
        )
        return result

    def _do_key_creation(
            self,
            ring_id: str,
            algo: str,
            key_name: str = "",
            src: str = "internal",
            desc: str = "",
            usage_scenario: str = "ModelEncryption",
            **kwargs,
    ) -> dict:
        if self._config.top_config:
            url = self._config.addr
            self._config.top_config["action"] = "CreateTksKey"
        else:
            url = self._get_tks_url(PATH_KEY_CREATE)
        result = self._request_tks(
            url=url,
            body={
                "RingID": ring_id,
                "KeyName": key_name,
                "Algo": algo,
                "Source": src,
                "Description": desc,
                "UsageScenario": usage_scenario,
            },
            headers=self._get_headers(),
            **kwargs,
        )

        return result

    def list_ring_id(
            self,
            page_number: int = 0,
            page_size: int = 10,
            show_invisible: bool = False,
            **kwargs,
    ):
        """
        :param page_size:
        :param page_number:
        :param show_invisible:
        :param kwargs:
        :return:
        """
        try:
            if self._config.top_config:
                url = self._config.addr
                self._config.top_config["action"] = "ListTksRing"
            else:
                url = self._get_tks_url(PATH_RING_LIST)

            body = {
                "PageSize": page_size,
                "PageNumber": page_number,
                "ShowInvisible": show_invisible,
            }

            result = self._request_tks(
                url=url, body=body, headers=self._get_headers(), **kwargs
            )
            return result
        except requests.RequestException as e:
            raise exp.TKSError("list ring id error: {}".format(e)) from e

    def list_key(
            self,
            ring_id: Optional[str] = None,
            page_number: int = 0,
            page_size: int = 10,
            status: Optional[str] = None,
            **kwargs,
    ):
        """
        :param ring_id:
        :param page_size:
        :param page_number:
        :param status:
        :param kwargs:
        :return:
        """
        try:
            if self._config.top_config:
                url = self._config.addr
                self._config.top_config["action"] = "ListTksKey"
            else:
                url = self._get_tks_url(PATH_KEY_LIST)

            body: dict = {"PageSize": page_size, "PageNumber": page_number}
            if ring_id:
                body["RingID"] = ring_id
            if status:
                body["Status"] = status

            result = self._request_tks(
                url=url, body=body, headers=self._get_headers(), **kwargs
            )
            return result
        except requests.RequestException as e:
            raise exp.TKSError("list key error: {}".format(e)) from e

    def _do_server_ra(
            self, nonce: Optional[str] = None, bi_auth: bool = True, **kwargs
    ) -> dict:
        if nonce is None:
            nonce = secrets.token_hex(32)

        if self._config.top_config:
            url = self._config.addr
            self._config.top_config["action"] = "AttestTksSecurity"
        else:
            url = self._get_tks_url(PATH_ATTEST)

        resp = self._request_tks(
            url=url,
            body={"NonceUp": nonce, "BiAuth": bi_auth},
            headers=self._get_headers(),
            **kwargs,
        )

        return resp

    def _get_tks_url(self, path: str) -> str:
        if self._config.addr.startswith("http"):
            return "{}{}".format(self._config.addr, path)
        else:
            scheme = "https" if self._config.enable_tls else "http"
            return "{}://{}{}".format(scheme, self._config.addr, path)

    def _generate_pcc_token(self, timestamp: str) -> str:
        """
        生成访问bytedance pcc_controller的token
        :param timestamp:
        :return:
        """
        ak = self._config.pcc_config["ak"]
        sk = self._config.pcc_config["sk"]

        h = hashlib.sha256()
        h.update(sk.encode())
        sk = h.hexdigest()
        h = hashlib.sha256()
        h.update((ak + sk + str(timestamp)).encode())
        token = h.hexdigest()
        return token

    def _get_headers(self) -> dict:
        timestamp = str(int(datetime.now(timezone.utc).timestamp()))
        headers = {
            "AppID": self._app_id,
            # "Timestamp": str(utc8_timestamp()),
            "Timestamp": timestamp,
            # "nonce": "a314b43502077cd89d21378b29954207aaf5b3848d4d7fa9f16682ba1f6f3317"
        }

        if self._config.pcc_config:
            headers["Content-Type"] = "application/json"
            headers["J-Internal-Ak"] = self._config.pcc_config["ak"]
            headers["J-Internal-Token"] = self._generate_pcc_token(timestamp)

        return headers

    def aes_encrypt(self, aes_key: Union[bytes, str], data: Union[bytes, str]) -> bytes:
        if isinstance(aes_key, str):
            aes_key = aes_key.encode()
        if isinstance(data, str):
            data = data.encode()
        return aes.gcm_encrypt(aes_key, data)

    def aes_decrypt(self, aes_key: Union[bytes, str], data: Union[bytes, str]) -> bytes:
        if isinstance(aes_key, str):
            aes_key = aes_key.encode()
        if isinstance(data, str):
            data = data.encode()
        return aes.gcm_decrypt(aes_key, data)

    def encrypt_file(
            self,
            aes_key: Union[bytes, str],
            source_path: str,
            dest_path: str,
            mode: str = "b",
    ) -> bool:
        if mode not in ["b", "t"]:
            raise Exception("mode argument error")

        if isinstance(aes_key, str):
            aes_key = aes_key.encode()

        with open(source_path, f"r{mode}") as source, open(
                dest_path, f"w{mode}"
        ) as dest:
            if mode == "b":
                source_b: IO[bytes] = source
                dest_b: IO[bytes] = dest
                plaintext = source_b.read()
                ciphertext = self.aes_encrypt(aes_key, plaintext)
                dest_b.write(ciphertext)
            else:
                source_t: IO[str] = source
                dest_t: IO[str] = dest
                for plaintext in source_t:
                    plaintext = plaintext.rstrip("\n")
                    ciphertext = self.aes_encrypt(aes_key, plaintext)
                    dest_t.write(base64.b64encode(ciphertext).decode() + "\n")

        return True

    def decrypt_file(
            self,
            aes_key: Union[bytes, str],
            source_path: str,
            dest_path: str,
            mode: str = "b",
    ) -> bool:
        if mode not in ["b", "t"]:
            raise Exception("mode argument error")

        if isinstance(aes_key, str):
            aes_key = aes_key.encode()

        with open(source_path, f"r{mode}") as source, open(
                dest_path, f"w{mode}"
        ) as dest:
            if mode == "b":
                source_b: IO[bytes] = source
                dest_b: IO[bytes] = dest
                ciphertext = source_b.read()
                plaintext = self.aes_decrypt(aes_key, ciphertext)
                dest_b.write(plaintext)
            else:
                source_t: IO[str] = source
                dest_t: IO[str] = dest
                for ciphertext in source_t:
                    ciphertext = ciphertext.rstrip("\n")
                    ciphertext = base64.b64decode(ciphertext.encode())
                    plaintext = self.aes_decrypt(aes_key, ciphertext)
                    dest_t.write(plaintext.decode() + "\n")
                    # dest_t.write(base64.b64encode(plaintext).decode() + "\n")
        return True


default_config = TKSConfig()
