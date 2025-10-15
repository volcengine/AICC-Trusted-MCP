# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

import base64
import json
import requests
from unittest.mock import MagicMock, patch
import pytest

from bytedance.jeddak_secure_channel import error
from bytedance.jeddak_secure_channel.ra import (
    RaConfig,
    RA_NONCE_LEN,
    RA_TYPE_LOCAL,
    RA_TYPE_TCA,
    generate_nonce,
    prepare_ra_request,
    validata_ra_request,
    attest_server,
    attest_client,
    verify_nonce,
)


def test_ra_config_defaults():
    """测试RaConfig默认值"""
    config = RaConfig()
    assert config.ra_url == ""
    assert config.ra_type == RA_TYPE_TCA
    assert config.ra_service_name == ""
    assert config.ra_pods_info == ""
    assert config.ra_uid == ""
    assert config.ra_key_negotiation is True
    assert config.ra_need_token is True
    assert config.attest_must is False
    assert config.ra_policy_id == ""
    assert config.bytedance_top_info == ""
    assert config.ra_attested_pods == []
    assert config.ra_policy_ids == []


def test_ra_config_custom_values():
    """测试RaConfig自定义值"""
    config = RaConfig(
        ra_url="https://example.com/ra",
        ra_type=RA_TYPE_LOCAL,
        ra_service_name="test-service",
        ra_pods_info=json.dumps({"cluster_id": "test", "namespace": "test", "deployment": "test"}),
        ra_uid="test-uid",
        ra_key_negotiation=False,
        ra_need_token=False,
        attest_must=True,
        ra_policy_id="test-policy",
        bytedance_top_info=json.dumps({"app_key": "test", "app_secret": "test"}),
        ra_attested_pods=[{"cluster_id": "test", "namespace": "test", "deployment": "test"}],
        ra_policy_ids=["test-policy-1", "test-policy-2"],
    )
    assert config.ra_url == "https://example.com/ra"
    assert config.ra_type == RA_TYPE_LOCAL
    assert config.ra_service_name == "test-service"
    assert config.ra_pods_info == json.dumps({"cluster_id": "test", "namespace": "test", "deployment": "test"})
    assert config.ra_uid == "test-uid"
    assert config.ra_key_negotiation is False
    assert config.ra_need_token is False
    assert config.attest_must is True
    assert config.ra_policy_id == "test-policy"
    assert config.bytedance_top_info == json.dumps({"app_key": "test", "app_secret": "test"})
    assert config.ra_attested_pods == [{"cluster_id": "test", "namespace": "test", "deployment": "test"}]
    assert config.ra_policy_ids == ["test-policy-1", "test-policy-2"]


def test_generate_nonce():
    """测试生成nonce"""
    nonce = generate_nonce()
    assert isinstance(nonce, str)
    assert len(nonce) == 16

    # 测试多次生成的nonce不同
    nonce2 = generate_nonce()
    assert nonce != nonce2


def test_prepare_ra_request():
    """测试准备远程证明请求"""
    config = RaConfig(
        ra_key_negotiation=True,
        ra_need_token=True,
        ra_policy_ids=["test-policy"],
        ra_attested_pods=[{"cluster_id": "test", "namespace": "test", "deployment": "test"}],
    )
    request = prepare_ra_request(config)
    assert request["key_negotiation"] is True
    assert request["token"] is True
    assert request["policy_ids"] == ["test-policy"]
    assert request["attested_pods"] == [{"cluster_id": "test", "namespace": "test", "deployment": "test"}]


def test_validata_ra_request_valid():
    """测试验证有效的远程证明请求"""
    # 创建一个有效的请求
    request = {}
    # 不包含nonce的请求也是有效的
    validata_ra_request(request)

    # 包含有效nonce的请求
    valid_nonce = base64.b64encode(b'\x00' * RA_NONCE_LEN).decode('utf-8')
    request = {"hex_runtime_data": valid_nonce}
    validata_ra_request(request)


def test_validata_ra_request_invalid_nonce():
    """测试验证无效nonce的远程证明请求"""
    # 创建一个无效nonce的请求
    invalid_nonce = base64.b64encode(b'\x00' * (RA_NONCE_LEN + 1)).decode('utf-8')
    request = {"hex_runtime_data": invalid_nonce}
    with pytest.raises(error.ParamError) as excinfo:
        validata_ra_request(request)
    assert excinfo.value.param == "nonce"


def test_prepare_ra_request_with_custom_config():
    """测试使用自定义配置准备远程证明请求"""
    # 创建自定义配置
    config = RaConfig(
        ra_key_negotiation=False,
        ra_need_token=False,
        ra_policy_ids=["policy1", "policy2"],
        ra_attested_pods=[{"cluster_id": "c1"}, {"cluster_id": "c2"}]
    )

    # 准备请求并验证
    request = prepare_ra_request(config)
    assert request["key_negotiation"] is False
    assert request["token"] is False
    assert request["policy_ids"] == ["policy1", "policy2"]
    assert request["attested_pods"] == [{"cluster_id": "c1"}, {"cluster_id": "c2"}]


def test_ra_config_with_local_type():
    """测试使用本地类型的RaConfig"""
    # 创建本地类型的配置
    config = RaConfig(
        ra_url="https://example.com/ra",
        ra_type=RA_TYPE_LOCAL,
    )

    # 验证配置
    assert config.ra_url == "https://example.com/ra"
    assert config.ra_type == RA_TYPE_LOCAL


def test_ra_config_with_custom_policy_ids():
    """测试使用自定义策略ID的RaConfig"""
    # 创建带有自定义策略ID的配置
    config = RaConfig(
        ra_policy_ids=["policy1", "policy2", "policy3"]
    )

    # 验证配置
    assert config.ra_policy_ids == ["policy1", "policy2", "policy3"]


@pytest.fixture
def mock_response():
    """创建模拟的HTTP响应"""
    response = MagicMock()
    response.status_code = 200
    response.text = json.dumps({
        "Result": {
            "test-cluster": {
                "evidence": json.dumps({"proof": ""}),
                "token": "header.eyJ0ZHgiOnsicmVwb3J0X2RhdGEiOiJ0ZXN0LXJlcG9ydC1kYXRhIn0sInBvbGljaWVzX21hdGNoZWQiOlsidGVzdC1wb2xpY3kiXSwiandrIjp7fX0.signature",
                "key_info": {"pub_key_info": "test-public-key"}
            }
        }
    })
    return response


@patch("bytedance.jeddak_secure_channel.ra.request_bytedance_gateway")
def test_attest_server_tca_success(mock_request, mock_response):
    """测试TCA方式的服务器远程证明成功"""
    # 设置模拟响应
    mock_request.return_value = mock_response

    # 创建配置
    config = RaConfig(
        ra_url="http://test-ra-server:8080",
        ra_service_name="test-service",
        ra_policy_id="test-policy",
        ra_key_negotiation=True,
        bytedance_top_info="{}"
    )

    # 调用函数
    nonce = generate_nonce()
    with patch("bytedance.jeddak_secure_channel.ra.verify_nonce", return_value=True), \
            patch("bytedance.jeddak_secure_channel.ra.verify_jwt_token", return_value=True):
        status, pub_key = attest_server(None, config, nonce)

    # 验证结果
    assert status is True
    assert pub_key == "test-public-key"


@patch("bytedance.jeddak_secure_channel.ra.request_bytedance_gateway")
def test_attest_server_tca_failure_no_token(mock_request, mock_response):
    """测试TCA方式的服务器远程证明失败（无token）"""
    # 修改模拟响应，移除token
    response_data = json.loads(mock_response.text)
    response_data["Result"]["test-cluster"].pop("token")
    mock_response.text = json.dumps(response_data)
    mock_request.return_value = mock_response

    # 创建配置
    config = RaConfig(
        ra_url="http://test-ra-server:8080",
        ra_service_name="test-service",
        ra_policy_id="test-policy",
        ra_key_negotiation=True,
        bytedance_top_info="{}"
    )

    # 调用函数
    nonce = generate_nonce()
    status, pub_key = attest_server(None, config, nonce)

    # 验证结果
    assert status is False
    assert pub_key == ""


@patch("bytedance.jeddak_secure_channel.ra.request_bytedance_gateway")
def test_attest_client_success(mock_request, mock_response):
    """测试客户端远程证明成功"""
    # 设置模拟响应
    mock_request.return_value = mock_response

    # 准备客户端配置
    client_ra_config = {
        "ra_url": "http://test-ra-server:8080",
        "ra_service_name": "test-service",
        "ra_policy_id": "test-policy",
        "ra_key_negotiation": True,
        "ra_uid": "test-uid"
    }
    client_bytedance_top_info = "{}"

    # 调用函数
    with patch("bytedance.jeddak_secure_channel.ra.verify_jwt_token", return_value=True):
        result = attest_client(client_ra_config, client_bytedance_top_info)

    # 验证结果
    assert result is True


@patch("bytedance.jeddak_secure_channel.ra.request_bytedance_gateway")
def test_attest_client_with_pods_info(mock_request, mock_response):
    """测试使用pods_info的客户端远程证明"""
    # 设置模拟响应
    mock_request.return_value = mock_response

    # 准备客户端配置，使用pods_info而不是service_name
    client_ra_config = {
        "ra_url": "http://test-ra-server:8080",
        "ra_pods_info": json.dumps({
            "cluster_id": "test-cluster",
            "namespace": "test-namespace",
            "deployment": "test-deployment"
        }),
        "ra_policy_id": "test-policy",
        "ra_key_negotiation": True,
        "ra_uid": "test-uid"
    }
    client_bytedance_top_info = "{}"

    # 调用函数
    with patch("bytedance.jeddak_secure_channel.ra.verify_jwt_token", return_value=True):
        result = attest_client(client_ra_config, client_bytedance_top_info)

    # 验证结果
    assert result is True


@patch("bytedance.jeddak_secure_channel.ra.request_bytedance_gateway")
def test_attest_client_missing_required_params(mock_request):
    """测试缺少必要参数的客户端远程证明"""
    # 准备缺少service_name和pods_info的客户端配置
    client_ra_config = {
        "ra_url": "http://test-ra-server:8080",
        "ra_policy_id": "test-policy",
        "ra_key_negotiation": True,
        "ra_uid": "test-uid"
    }
    client_bytedance_top_info = "{}"

    # 调用函数，应抛出ServiceError异常
    with pytest.raises(error.ServiceError) as excinfo:
        attest_client(client_ra_config, client_bytedance_top_info)

    # 验证异常信息
    assert excinfo.value.service_name == "RA"
    assert "call TCA error" in excinfo.value.message


def test_verify_nonce_success():
    """测试nonce验证成功"""
    # 准备测试数据
    nonce = "1234567890abcdef"
    proof = None  # 无需Merkle证明的简单情况
    # 构造report_data为nonce_hash + pub_key_hash
    nonce_hash = "1234567890abcdef"  # 模拟的nonce哈希
    pub_key_hash = "0000000000000000000000000000000000000000000000000000000000000000"  # 空公钥的哈希
    report_data = nonce_hash + pub_key_hash
    pub_key_info = ""

    # 使用mock模拟哈希计算
    with patch("bytedance.jeddak_secure_channel.ra.hashlib.sha256") as mock_sha256:
        mock_hash = MagicMock()
        mock_hash.hexdigest.return_value = "1234567890abcdef"
        mock_sha256.return_value = mock_hash
        result = verify_nonce(proof, report_data, nonce, pub_key_info)

    # 验证结果
    assert result is True


def test_verify_nonce_failure_hash_mismatch():
    """测试nonce验证失败（哈希不匹配）"""
    # 准备测试数据
    nonce = "1234567890abcdef"
    proof = {"hash": "different_hash_value", "merkle_proof": []}
    report_data = "different_hash_value0000000000000000000000000000000000000000000000000000000000000000"
    pub_key_info = ""

    # 使用mock模拟哈希计算
    with patch("bytedance.jeddak_secure_channel.ra.hashlib.sha256") as mock_sha256:
        mock_hash = MagicMock()
        mock_hash.hexdigest.return_value = "1234567890abcdef"
        mock_sha256.return_value = mock_hash
        # 当哈希不匹配时，verify_inclusion应该抛出异常
        with patch("bytedance.jeddak_secure_channel.ra.verify_inclusion", side_effect=Exception("Hash mismatch")), \
                pytest.raises(Exception):
            verify_nonce(proof, report_data, nonce, pub_key_info)

    # 不需要断言，因为我们期望函数抛出异常


def test_verify_nonce_failure_merkle_proof():
    """测试nonce验证失败（Merkle证明验证失败）"""
    # 准备测试数据
    nonce = "1234567890abcdef"
    proof = {"hash": "1234567890abcdef", "merkle_proof": [{"left": "abc", "right": "def"}]}
    report_data = "1234567890abcdef0000000000000000000000000000000000000000000000000000000000000000"
    pub_key_info = ""

    # 使用mock模拟哈希计算和MerkleProof验证
    with patch("bytedance.jeddak_secure_channel.ra.hashlib.sha256") as mock_sha256, \
            patch("bytedance.jeddak_secure_channel.ra.verify_inclusion", side_effect=Exception("Merkle proof verification failed")), \
            pytest.raises(Exception):
        mock_hash = MagicMock()
        mock_hash.hexdigest.return_value = "1234567890abcdef"
        mock_sha256.return_value = mock_hash
        verify_nonce(proof, report_data, nonce, pub_key_info)


@patch("bytedance.jeddak_secure_channel.ra.requests.post")
def test_attest_server_local_success(mock_post):
    """测试本地方式的服务器远程证明成功"""
    # 设置模拟响应
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "ResponseMetadata": {"RequestId": "test-request-id", "HTTPStatusCode": 200, "Code": 0},
        "ResponseResult": {
            "test-pod": {
                "evidence": json.dumps({"proof": {"hash": "test-hash", "merkle_proof": []}}),
                "key_info": {"pub_key_info": "test-public-key"}
            }
        }
    }
    mock_post.return_value = mock_response

    # 创建配置
    config = RaConfig(
        ra_url="http://test-ra-server:8080",
        ra_type=RA_TYPE_LOCAL,
        ra_service_name="test-service",
        ra_policy_id="test-policy",
        ra_key_negotiation=True
    )

    # 调用函数
    with patch("bytedance.jeddak_secure_channel.ra.generate_nonce", return_value="test-nonce"):
        status, pub_key = attest_server(None, config)

    # 验证结果
    assert status is True
    assert pub_key == "test-public-key"
    # 验证请求参数
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "http://test-ra-server:8080"
    assert "json" in kwargs
    assert "nonce" in kwargs["json"]


@patch("bytedance.jeddak_secure_channel.ra.requests.post")
def test_attest_server_local_http_error(mock_post):
    """测试本地方式的服务器远程证明HTTP错误"""
    # 设置模拟响应为HTTP错误
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_post.return_value = mock_response

    # 创建配置
    config = RaConfig(
        ra_url="http://test-ra-server:8080",
        ra_type=RA_TYPE_LOCAL,
        ra_service_name="test-service",
        ra_policy_id="test-policy"
    )

    # 调用函数，应抛出ServiceError异常
    with pytest.raises(error.ServiceError) as excinfo:
        attest_server(None, config)

    # 验证异常信息
    assert excinfo.value.service_name == "RA"
    assert "code=500" in str(excinfo.value)


@patch("bytedance.jeddak_secure_channel.ra.requests.post")
def test_attest_server_local_invalid_response(mock_post):
    """测试本地方式的服务器远程证明无效响应"""
    # 设置模拟响应为无效JSON
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
    mock_post.return_value = mock_response

    # 创建配置
    config = RaConfig(
        ra_url="http://test-ra-server:8080",
        ra_type=RA_TYPE_LOCAL,
        ra_service_name="test-service",
        ra_policy_id="test-policy"
    )

    # 调用函数，应抛出ServiceError异常
    with pytest.raises(error.ServiceError) as excinfo:
        attest_server(None, config)

    # 验证异常信息
    assert excinfo.value.service_name == "RA"
    assert "not JSON" in str(excinfo.value)


@patch("bytedance.jeddak_secure_channel.ra.requests.post")
def test_attest_server_local_missing_key_info(mock_post):
    """测试本地方式的服务器远程证明缺少key_info"""
    # 设置模拟响应缺少key_info
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "ResponseMetadata": {"RequestId": "test-request-id", "HTTPStatusCode": 200, "Code": 0},
        "ResponseResult": {
            "test-pod": {
                "evidence": json.dumps({"proof": {"hash": "test-hash", "merkle_proof": []}})
                # 缺少key_info字段
            }
        }
    }
    mock_post.return_value = mock_response

    # 创建配置
    config = RaConfig(
        ra_url="http://test-ra-server:8080",
        ra_type=RA_TYPE_LOCAL,
        ra_service_name="test-service",
        ra_policy_id="test-policy",
        ra_key_negotiation=True
    )

    # 调用函数，应抛出ServiceError异常
    with pytest.raises(error.ServiceError) as excinfo:
        attest_server(None, config)

    # 验证异常信息
    assert excinfo.value.service_name == "RA"
    # 不检查具体错误消息，因为可能会变化


@patch("bytedance.jeddak_secure_channel.ra.requests.post")
def test_attest_server_network_error(mock_post):
    """测试服务器远程证明网络错误"""
    # 设置模拟响应为网络错误
    mock_post.side_effect = requests.exceptions.RequestException("Network error")

    # 创建配置
    config = RaConfig(
        ra_url="http://test-ra-server:8080",
        ra_type=RA_TYPE_LOCAL,
        ra_service_name="test-service",
        ra_policy_id="test-policy"
    )

    # 调用函数
    with pytest.raises(error.NetworkError) as excinfo:
        attest_server(None, config)

    # 验证异常信息
    assert excinfo.value.service_name == "RA"
    assert excinfo.value.service == "http://test-ra-server:8080"
    # endpoint可能为None，不进行断言


@patch("bytedance.jeddak_secure_channel.ra.request_bytedance_gateway")
def test_attest_client_network_error(mock_request):
    """测试客户端远程证明网络错误"""
    # 设置模拟响应为网络错误
    mock_request.side_effect = error.NetworkError(service_name="RA", service="RA", endpoint="test-endpoint")

    # 准备客户端配置
    client_ra_config = {
        "ra_url": "http://test-ra-server:8080",
        "ra_service_name": "test-service",
        "ra_policy_id": "test-policy",
        "ra_key_negotiation": True,
        "ra_uid": "test-uid"
    }
    client_bytedance_top_info = "{}"

    # 调用函数，应抛出NetworkError异常
    with pytest.raises(error.NetworkError) as excinfo:
        attest_client(client_ra_config, client_bytedance_top_info)

    # 验证异常信息
    assert excinfo.value.service_name == "RA"
    assert excinfo.value.service == "RA"
    assert excinfo.value.endpoint == "test-endpoint"
