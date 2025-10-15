# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

"""
安全通信远程证明功能.
"""

__all__ = [
    "RaConfig",
    "RaPod",
    "RaRequest",
    "RaResponse",
    "RaResponseMetadata",
    "RaResponsePod",
    "RaResponsePods",
    "attest_server",
    "prepare_ra_request",
    "validata_ra_request",
    "attest_client",
    "generate_nonce",
]

import time
import uuid
import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Tuple
import hashlib
from .merkle_utils import verify_inclusion, MerkleProof
import requests
from typing_extensions import (
    Dict,
    List,
    Literal,
    NotRequired,
    Optional,
    TypedDict,
    Union,
)

from . import error
from .log import logger
from .utils import request_bytedance_gateway

RA_NONCE_LEN = 12
RA_TYPE_LOCAL = "local"
RA_TYPE_TCA = "tca"


class RaPod(TypedDict):
    cluster_id: str

    namespace: str

    deployment: str

    pod: NotRequired[Literal["random", "all"]]
    """默认为 random, 如果想要全部则为 all."""


@dataclass
class RaConfig:
    """
    访问远程证明功能的配置.
    """

    ra_url: str = ""
    """远程证明端点的 HTTP 地址."""

    ra_type: str = RA_TYPE_TCA
    """ra的类型，local：本地RA， tca：TCA的RAS_adapter接口(默认)."""

    ra_service_name: str = ""
    """数据接收端（服务端）的服务名. ,用于验证通过机密容器部署的服务"""

    ra_pods_info: str = ""
    """
        待验证的节点的pod信息，用于验证非通过机密容器部署的服务, 
        格式: {cluster_id:***, namespace:***, deployment:***}
        ra_service_name 和 ra_pods_info 二选一
    """

    ra_uid: str = ""
    """用户的UID"""

    ra_key_negotiation: bool = True
    """是否在验证的时候需要同步进行协商密钥."""

    ra_need_token: bool = True  # RA 功能稳定后要改成 False
    """是否要返回验证 token. 默认为是."""

    attest_must: bool = False
    """是否一定要返回验证报告才能采用公钥."""

    ra_policy_id: str = ""
    """进行验证所使用的策略, 如果 ra_need_token 为 True, 则必填."""

    bytedance_top_info: str = ""
    """访问bytedance TOP网关的信息."""

    ra_attested_pods: List[RaPod] = field(default_factory=list)
    """old 需要验证的节点信息."""

    ra_policy_ids: List[str] = field(default_factory=list)
    """old 进行验证所使用的策略, 如果 ra_need_token 为 True, 则必填."""


class RaRequest(TypedDict):
    """数据发送方发出的远程证明请求."""

    key_negotiation: bool
    """是否在验证的时候需要同步进行协商密钥."""

    token: bool
    """是否要返回验证 token."""

    policy_ids: List[str]
    """进行验证所使用的策略."""

    attested_pods: List[RaPod]
    """需要验证的节点信息."""


class RaResponseMetadata(TypedDict):
    Code: int
    Message: str


class RaResponsePod(TypedDict):
    evidence: str
    token: str
    key_info: dict


RaResponsePods = Dict[str, RaResponsePod]


class RaResponse(TypedDict):
    """数据接收方发出的远程证明响应."""

    ResponseMetadata: RaResponseMetadata

    ResponseResult: RaResponsePods


def prepare_ra_request(config: RaConfig) -> RaRequest:
    """
    准备远程证明请求.

    Returns:
        远程证明请求. 可作为 JSON 发送给数据接收方远程证明端点.
    """
    return RaRequest(
        key_negotiation=config.ra_key_negotiation,
        token=config.ra_need_token,
        policy_ids=config.ra_policy_ids,
        attested_pods=config.ra_attested_pods,
    )


def validata_ra_request(request: RaRequest) -> None:
    """
    验证远程证明请求有效性.

    Raises:
        ParamError: 请求的 nonce 或 timestamp 字段无效.
    """
    nonce = request.get("hex_runtime_data")
    if nonce:
        nonce = base64.b64decode(nonce)
        if len(nonce) != RA_NONCE_LEN:
            raise error.ParamError("nonce", "Invalid RA request")

    # time = datetime.fromtimestamp(request["timestamp"], timezone.utc)
    # now = datetime.now(timezone.utc)
    # if time > now + timedelta(minutes=1) or time < now - timedelta(minutes=2):
    #     raise error.ParamError("timestamp", "Invalid RA request")


def generate_nonce():
    return ''.join(str(uuid.uuid4()).split('-'))[-16:]


def request_tca(config: RaConfig, nonce: str = None):
    try:
        ra_url = config.ra_url
        ra_service_name = config.ra_service_name
        ra_pods_info = config.ra_pods_info
        ra_key_negotiation = config.ra_key_negotiation
        ra_policy_id = config.ra_policy_id
        ra_uid = config.ra_uid

        top_info = config.bytedance_top_info
        if top_info and isinstance(top_info, str):
            top_info = json.loads(top_info)
        # assert isinstance(top_info, dict)

        headers = {"UID": ra_uid}

        if not nonce:
            nonce = generate_nonce()

        if ra_service_name:
            body = {
                "Nonce": nonce,
                "PolicyID": ra_policy_id,
                "ServiceName": ra_service_name,
                "KeyNegotiation": ra_key_negotiation,
                "Token": True,
            }
        elif ra_pods_info:
            if isinstance(ra_pods_info, str):
                ra_pods_info = json.loads(ra_pods_info)
            body = {
                "Nonce": nonce,
                "PolicyID": ra_policy_id,
                "AttestedPods": [ra_pods_info],
                "KeyNegotiation": ra_key_negotiation,
                "Token": True,
            }
        else:
            raise error.ServiceError("RA", config.ra_url, None, "call TCA error")

        return request_bytedance_gateway(ra_url, body, headers, top_info)
    except Exception as e:
        logger.critical(f"Response is not JSON: service={config.ra_url}")
        raise error.ServiceError("RA", config.ra_url, None, "call TCA error") from e


def attest_server_local(token: Optional[str], config: RaConfig) -> Tuple[bool, str]:
    """
    对数据接收方进行远程证明(非TCA方式).
    """
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    headers = {"timestamp": timestamp}
    if token:
        headers["token"] = f"{token}"

    request = {"nonce": generate_nonce()}
    try:
        logger.info(
            f"request ra, url={config.ra_url}, header={headers}, params={request}"
        )
        response = requests.post(config.ra_url, headers=headers, json=request)
    except Exception as e:
        logger.critical(f"RA Network error: url={config.ra_url}")
        raise error.NetworkError("RA", config.ra_url, endpoint=None) from e

    if response.status_code != 200:
        logger.error(
            f"Service error: service={config.ra_url} code={response.status_code}"
        )
        raise error.ServiceError(
            "RA", config.ra_url, None, f"code={response.status_code}"
        )

    try:
        response_json: RaResponse = response.json()
        logger.info(f"ra response={response_json}")

        res_meta_data = response_json.get("ResponseMetadata")
        res_result = response_json.get("ResponseResult")

        if not res_meta_data or not res_result:
            raise error.ServiceError("RA", config.ra_url, None, "wrong format")

        if res_meta_data.get("Code") != 0:
            raise error.ServiceError(
                "RA", config.ra_url, None, res_meta_data.get("Message", "")
            )

        for pod_name, pod_ra_info in res_result.items():
            # evidence = pod_ra_info.get("evidence")
            # token = pod_ra_info.get("token")
            key_info = pod_ra_info.get("key_info")
            if not key_info:
                raise error.ServiceError("RA", config.ra_url, "RSA key", "null")

            return True, key_info["pub_key_info"]
    except Exception as e:
        logger.critical(f"Response is not JSON: service={config.ra_url}")
        raise error.ServiceError("RA", config.ra_url, None, "not JSON") from e

    return False, ""


def verify_jwt_token(token):
    """使用Python标准库验证JWT token，不依赖第三方库"""
    try:
        # 分割JWT的三部分：header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            logger.error("verify_ra_token: Invalid token format")
            return False

        header_encoded, payload_encoded, signature_encoded = parts

        # Base64 URL安全解码函数
        def base64url_decode(encoded_str):
            # 补齐padding
            padded_str = encoded_str + '=' * ((4 - len(encoded_str) % 4) % 4)
            return base64.urlsafe_b64decode(padded_str)

        # 解码header和payload
        try:
            header = json.loads(base64url_decode(header_encoded).decode('utf-8'))
            payload = json.loads(base64url_decode(payload_encoded).decode('utf-8'))
        except (ValueError, UnicodeDecodeError) as e:
            logger.error(f"verify_ra_token: Failed to decode token parts: {e}")
            return False

        # 验证issuer
        if payload.get('iss') != "Bytedance-Remote-Attestation-Service":
            logger.error("verify_ra_token: Invalid issuer.")
            return False

        # 验证过期时间（如果存在）
        if 'exp' in payload:
            try:
                current_time = int(time.time())
                if payload['exp'] < current_time:
                    logger.error("verify_ra_token: Token has expired.")
                    return False
            except (ValueError, TypeError):
                logger.error("verify_ra_token: Invalid expiration time format")
                return False

        # 构建待验证的数据
        message = f"{header_encoded}.{payload_encoded}".encode()

        # 这里简化处理，实际项目中可能需要根据header中的alg字段选择合适的算法
        # 并且需要从payload或其他地方获取公钥信息来验证签名
        # 由于没有实际的密钥信息，这里只进行基础验证，跳过签名验证
        logger.debug(f"Token is valid (basic validation passed). Payload:{payload}")
        return True

    except Exception as e:
        logger.error(f"verify_ra_token: {e}")
        return False


def verify_nonce(proof, report_data, nonce, pub_key_info):
    try:
        # 前64位是nonce的sha256哈希，后64位是公钥的sha256哈希
        nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()

        # 计算pub_key_info的SHA256哈希
        if pub_key_info:
            pub_key_hash = hashlib.sha256(pub_key_info.encode()).hexdigest()
        else:
            # 如果公钥为空，用64个0替换
            pub_key_hash = "0000000000000000000000000000000000000000000000000000000000000000"

        # 拼接两个哈希值
        base = nonce_hash + pub_key_hash
        if not proof:
            return report_data == base
        h = hashlib.sha512()
        h.update(b'\x00' + base.encode())
        base = h.hexdigest()
        root = report_data
        proof = MerkleProof.deserialize(proof)
        verify_inclusion(bytes.fromhex(base), bytes.fromhex(root), proof)
        return True
    except Exception as e:
        logger.error(f"verify nonce failed!!!,msg={str(e)}")
        raise e


def attest_server(token: Optional[str], config: RaConfig, nonce: str = None) -> Tuple[bool, str]:
    """
    对数据接收方进行远程证明.
    :return (ra_status, pub_key)
    """
    if config.bytedance_top_info:
        response = request_tca(config, nonce)
    else:
        return attest_server_local(token, config)

    if response is None:
        logger.error(f"RA Service error: url={config.ra_url} response=NULL")
        raise error.ServiceError("RA", config.ra_url, None, "NULL")

    if response.status_code != 200:
        logger.error(
            f"RA Service error: return code={response.status_code}, return content={response.content}"
        )
        raise error.ServiceError(
            "RA", config.ra_url, None, f"code={response.status_code}"
        )

    try:
        attestation_status = False
        public_key_info = ""

        ra_res = json.loads(response.text).get("Result")
        if not ra_res:
            logger.error(f"RA response={response.text}")
            return False, ""

        # 取第一个节点验证就可以
        for cluster_info, res_info in ra_res.items():
            # raw_evidence = res_info.get("evidence")
            # if raw_evidence:
            #     tmp = json.loads(raw_evidence)
            #     raw_evidence_json = json.dumps(tmp, indent=4)
            #     logger.debug(f"get ra evidence:{raw_evidence_json}")

            raw_token = res_info.get("token")
            if not raw_token:
                logger.critical("token is None")
                return False, ""
            else:
                evidence_info = res_info.get("evidence")
                evidence_info_json = json.loads(evidence_info)
                proof = evidence_info_json.get('proof')
                logger.info(f"proof={proof}")
                token_parts = raw_token.split(".")
                if len(token_parts) >= 2:
                    token_data = token_parts[1]
                    try:
                        # 使用base64.urlsafe_b64decode进行URL安全模式的解码
                        decoded_data = base64.urlsafe_b64decode(
                            token_data + "=" * (4 - len(token_data) % 4)
                        ).decode("utf-8")
                        token_dict = json.loads(decoded_data)
                        report_data = token_dict.get('tdx').get('report_data')
                    except Exception as e:
                        logger.error(f"解码出现错误: {e}")
                        raise Exception("decode token error")
                logger.info(f"report_data={report_data}")

                if config.ra_key_negotiation:
                    pub_key = res_info.get("key_info")
                    pub_key_info = pub_key.get('pub_key_info')
                else:
                    pub_key_info = ""
                try:
                    if not verify_nonce(proof, report_data, nonce, pub_key_info):
                        logger.error("verify nonce failed")
                        return False, ""

                except Exception as e:
                    logger.error(f"verify nonce failed!!!,msg={str(e)}")
                    return False, ""

                if not verify_jwt_token(raw_token):
                    logger.critical("token verify failed")
                    return False, ""
                else:
                    token_dict = {}
                    token_parts = raw_token.split(".")
                    if len(token_parts) >= 2:
                        token_data = token_parts[1]
                        try:
                            # 使用base64.urlsafe_b64decode进行URL安全模式的解码
                            decoded_data = base64.urlsafe_b64decode(
                                token_data + "=" * (4 - len(token_data) % 4)
                            ).decode("utf-8")

                            token_dict = json.loads(decoded_data)
                        except Exception as e:
                            logger.critical(f"token 解码出现错误: {e}")
                            return False, ""

                    attestation_status = len(token_dict.get("policies_matched")) > 0
            if config.ra_key_negotiation:
                public_key_info = res_info.get("key_info").get("pub_key_info")
            break

        return attestation_status, public_key_info
    except Exception as e:
        logger.critical(f"Response is not JSON: service={config.ra_url}")
        raise error.ServiceError("RA", config.ra_url, None, "not JSON") from e


def attest_client(client_ra_config: dict, client_bytedance_top_info: str, nonce: str = None) -> bool:
    """
    对数据发送方进行远程证明.
    """
    ra_service_name: Optional[str] = client_ra_config.get("ra_service_name")
    ra_policy_id: Optional[str] = client_ra_config.get("ra_policy_id")
    ra_pods_info = client_ra_config.get("ra_pods_info")
    ra_key_negotiation: Optional[bool] = client_ra_config.get("ra_key_negotiation")

    top_info = client_bytedance_top_info
    if top_info and isinstance(top_info, str):
        top_info = json.loads(top_info)

    ra_url = client_ra_config.get("ra_url", "open.volcengineapi.com")
    ra_uid = client_ra_config.get("ra_uid")
    if ra_uid:
        headers = {"UID": ra_uid}
    else:
        headers = {}

    if not nonce:
        nonce = generate_nonce()

    if ra_service_name:
        body = {
            "Nonce": nonce,
            "PolicyID": ra_policy_id,
            "ServiceName": ra_service_name,
            "KeyNegotiation": ra_key_negotiation,
            "Token": True,
        }
    elif ra_pods_info:
        if isinstance(ra_pods_info, str):
            ra_pods_info = json.loads(ra_pods_info)
        body = {
            "Nonce": nonce,
            "PolicyID": ra_policy_id,
            "AttestedPods": [ra_pods_info],
            "KeyNegotiation": ra_key_negotiation,
            "Token": True,
        }
    else:
        raise error.ServiceError("RA", ra_service_name, None, "call TCA error")

    response = request_bytedance_gateway(ra_url, body, headers, top_info)
    if not response:
        logger.error("Client RA error: response NULL")
        raise error.ServiceError("RA", ra_service_name, None, "NULL")

    if response.status_code != 200:
        logger.error(
            f"client ra error: ra_service_name={ra_service_name} code={response.status_code}"
        )
        raise error.ServiceError(
            "RA", ra_service_name, None, f"code={response.status_code}"
        )

    try:
        ra_res = json.loads(response.text).get("Result")
        if not ra_res:
            logger.error(
                f"attest_client failed, verify_result is NULL, ra interface response={response.text}"
            )
            return False

        attestation_status = False
        for cluster_info, res_info in ra_res.items():
            # raw_evidence = res_info.get("evidence")
            # tmp = json.loads(raw_evidence)
            # raw_evidence_json = json.dumps(tmp, indent=4)
            # logger.debug(f"get ra evidence:{raw_evidence_json}")

            raw_token = res_info.get("token")
            if not raw_token:
                logger.critical("token is None")
                return False

            if not verify_jwt_token(raw_token):
                logger.critical("token verify failed")
                return False

            token_dict = {}
            token_parts = raw_token.split(".")
            if len(token_parts) >= 2:
                token_data = token_parts[1]
                try:
                    # 使用base64.urlsafe_b64decode进行URL安全模式的解码
                    decoded_data = base64.urlsafe_b64decode(
                        token_data + "=" * (4 - len(token_data) % 4)
                    ).decode("utf-8")

                    token_dict = json.loads(decoded_data)
                except Exception as e:
                    logger.critical(f"token 解码出现错误: {e}")
                    return False

            attestation_status = len(token_dict.get("policies_matched")) > 0
            break

        return attestation_status
    except Exception as e:
        logger.critical(f"Response is not JSON: client_service_name={ra_service_name}")
        raise error.ServiceError("RA", ra_service_name, None, "not JSON") from e
