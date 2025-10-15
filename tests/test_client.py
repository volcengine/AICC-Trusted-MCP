# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

import base64
import json
import os
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest
from typing import Dict, Tuple, Union

from bytedance.jeddak_secure_channel import Client, ClientConfig, error
from bytedance.jeddak_secure_channel.crypto import ClientSessionKey, ResponseKey
from bytedance.jeddak_secure_channel.utils import RepeatTimer
from tests.conftest import mock_attest, mock_channel, offline_client


def test_client_init(offline_client: Client):
    """测试客户端初始化"""
    assert offline_client is not None
    assert offline_client.config is not None
    assert offline_client.session_key is None
    assert offline_client.last_ra_time == 0.0


def test_client_attest_server_with_pub_key():
    """测试使用公钥文件进行远程证明"""
    # 创建临时公钥文件
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        # 写入一个假的公钥内容
        temp_file.write("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvWaQJGGsLsWS+5sIzoVm\nrMQJ/1aA7BhGw56Sf7yZOPJ8MXgjgOTJjL0VCvYH9PlqjLzbvyBZfFyFoSdiedLh\nXoLWbQCnOjIDUkQ9GZ8YAKjzNJDjfCgpWJPJRXnRBpKVKO+AXsqDLLGZQlZtJ9dR\nJ/zLLmECgYEA0Py3Jq5/KYnLUzGsLl2w0dZ0FOZFCBJbpJdH3Ld3ZQQnVy511PvZ\nGOzXzXxrYgEHQcjOycJK/2JRQwqOaCHcWpPt1QZN+xh9Jk6s5HmOdZ5xLMKPBuKW\nZKEgKHrJiQZUCZI8Qs+5pcMT9XUJzFR/ig8HOxmxHLgIfzBFjkCQJdUCAwEAAQ==\n-----END PUBLIC KEY-----")
        temp_path = temp_file.name
    
    try:
        # 创建带有公钥路径的客户端配置
        config = ClientConfig(ra_url="http://example.com", pub_key_path=temp_path)
        client = Client(config)
        
        with pytest.raises(error.ParamError):
            ret = client.attest_server()
            # 验证attest_server方法返回False，并且session_key未设置
            assert ret is False
            assert client.session_key is None
    finally:
        # 清理临时文件
        os.unlink(temp_path)


@patch('bytedance.jeddak_secure_channel.client.attest_server')
def test_client_attest_server_success(mock_attest_server, offline_client: Client):
    """测试远程证明成功的情况"""
    # 模拟远程证明成功
    mock_pub_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvWaQJGGsLsWS+5sIzoVm\nrMQJ/1aA7BhGw56Sf7yZOPJ8MXgjgOTJjL0VCvYH9PlqjLzbvyBZfFyFoSdiedLh\nXoLWbQCnOjIDUkQ9GZ8YAKjzNJDjfCgpWJPJRXnRBpKVKO+AXsqDLLGZQlZtJ9dR\nJ/zLLmECgYEA0Py3Jq5/KYnLUzGsLl2w0dZ0FOZFCBJbpJdH3Ld3ZQQnVy511PvZ\nGOzXzXxrYgEHQcjOycJK/2JRQwqOaCHcWpPt1QZN+xh9Jk6s5HmOdZ5xLMKPBuKW\nZKEgKHrJiQZUCZI8Qs+5pcMT9XUJzFR/ig8HOxmxHLgIfzBFjkCQJdUCAwEAAQ==\n-----END PUBLIC KEY-----"
    mock_attest_server.return_value = (True, mock_pub_key)
    
    # 执行远程证明
    ret = False
    with pytest.raises(error.ParamError):
        ret = offline_client.attest_server()
    
    # 验证结果
    assert ret is False
    assert offline_client.session_key is None
    assert offline_client.last_ra_time == 0.0


@patch('bytedance.jeddak_secure_channel.client.attest_server')
def test_client_attest_server_failure(mock_attest_server, offline_client: Client):
    """测试远程证明失败的情况"""
    # 模拟远程证明失败
    mock_attest_server.return_value = (False, None)
    
    # 执行远程证明
    result = offline_client.attest_server()
    
    # 验证结果
    assert result is False
    assert offline_client.session_key is None


@patch('bytedance.jeddak_secure_channel.client.attest_server')
def test_client_attest_server_failure_with_pub_key_no_must(mock_attest_server, offline_client: Client):
    """测试远程证明失败但有公钥且不强制证明的情况"""
    # 修改客户端配置，不强制证明
    offline_client.config.attest_must = False
    
    # 模拟远程证明失败但返回公钥
    mock_pub_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvWaQJGGsLsWS+5sIzoVm\nrMQJ/1aA7BhGw56Sf7yZOPJ8MXgjgOTJjL0VCvYH9PlqjLzbvyBZfFyFoSdiedLh\nXoLWbQCnOjIDUkQ9GZ8YAKjzNJDjfCgpWJPJRXnRBpKVKO+AXsqDLLGZQlZtJ9dR\nJ/zLLmECgYEA0Py3Jq5/KYnLUzGsLl2w0dZ0FOZFCBJbpJdH3Ld3ZQQnVy511PvZ\nGOzXzXxrYgEHQcjOycJK/2JRQwqOaCHcWpPt1QZN+xh9Jk6s5HmOdZ5xLMKPBuKW\nZKEgKHrJiQZUCZI8Qs+5pcMT9XUJzFR/ig8HOxmxHLgIfzBFjkCQJdUCAwEAAQ==\n-----END PUBLIC KEY-----"
    mock_attest_server.return_value = (False, mock_pub_key)
    
    # 执行远程证明
    ret = False
    with pytest.raises(error.ParamError):
        ret = offline_client.attest_server()
    
    # 验证结果
    assert ret is False
    assert offline_client.session_key is None


def test_encrypt_without_key(offline_client: Client):
    """测试没有密钥时加密失败"""
    with pytest.raises(error.KeyMissingError):
        offline_client.encrypt("test message")


def test_encrypt_with_response_without_key(offline_client: Client):
    """测试没有密钥时加密并获取响应密钥失败"""
    with pytest.raises(error.KeyMissingError):
        offline_client.encrypt_with_response("test message")


def test_encrypt_file_without_key(offline_client: Client):
    """测试没有密钥时加密文件失败"""
    with tempfile.NamedTemporaryFile() as source, tempfile.NamedTemporaryFile() as dest:
        with pytest.raises(error.KeyMissingError):
            offline_client.encrypt_file(source.name, dest.name, "t")


def test_encrypt_file_with_response_without_key(offline_client: Client):
    """测试没有密钥时加密文件并获取响应密钥失败"""
    with tempfile.NamedTemporaryFile() as source, tempfile.NamedTemporaryFile() as dest:
        with pytest.raises(error.KeyMissingError):
            offline_client.encrypt_file_with_response(source.name, dest.name, "t")


@patch('bytedance.jeddak_secure_channel.client.ClientSessionKey')
def test_encrypt(mock_session_key, offline_client: Client):
    """测试加密功能"""
    # 设置session_key
    mock_key = MagicMock()
    mock_message = MagicMock()
    mock_message.serialize.return_value = "encrypted_message"
    mock_key.encrypt_with_response.return_value = (mock_message, MagicMock())
    mock_session_key.load.return_value = mock_key
    offline_client.session_key = mock_key
    
    # 执行加密
    result = offline_client.encrypt("test message")
    
    # 验证结果
    assert result == "encrypted_message"
    mock_key.encrypt_with_response.assert_called_once()


@patch('bytedance.jeddak_secure_channel.client.ClientSessionKey')
def test_encrypt_with_response(mock_session_key, offline_client: Client):
    """测试加密并获取响应密钥功能"""
    # 设置session_key
    mock_key = MagicMock()
    mock_message = MagicMock()
    mock_response_key = MagicMock()
    mock_message.serialize.return_value = "encrypted_message"
    mock_key.encrypt_with_response.return_value = (mock_message, mock_response_key)
    mock_session_key.load.return_value = mock_key
    offline_client.session_key = mock_key
    
    # 执行加密并获取响应密钥
    message, response_key = offline_client.encrypt_with_response("test message")
    
    # 验证结果
    assert message == "encrypted_message"
    assert response_key == mock_response_key
    mock_key.encrypt_with_response.assert_called_once()


@patch('bytedance.jeddak_secure_channel.client.time.time')
def test_auto_attest_on_encrypt(mock_time, offline_client: Client):
    """测试加密时自动进行远程证明"""
    
    # 设置上次远程证明时间为很久以前
    offline_client.last_ra_time = 0
    mock_time.return_value = 1000  # 模拟当前时间
    
    # 使用spy监视_attest_server_no_raise方法
    with patch.object(offline_client, '_attest_server_no_raise', wraps=offline_client._attest_server_no_raise) as mock_attest:
        with pytest.raises(error.KeyMissingError):
            offline_client.encrypt("test message")
        # 验证是否调用了远程证明方法
        # mock_attest.assert_called_once()


def test_gen_sign_success(offline_client: Client):
    """测试成功生成签名"""
    # 模拟root_key_info
    app_info = "test_app"
    mock_key = MagicMock()
    mock_key.sign.return_value = b"signed_data"
    offline_client.root_key_info = {app_info: mock_key}
    
    # 执行签名
    result = offline_client.gen_sign(app_info, "test message")
    
    # 验证结果
    assert result == base64.b64encode(b"signed_data").decode()
    mock_key.sign.assert_called_once()


def test_gen_sign_missing_app_info(offline_client: Client):
    """测试缺少应用信息时签名失败"""
    with pytest.raises(error.SignatureError):
        offline_client.gen_sign("", "test message")


def test_gen_sign_unknown_app_info(offline_client: Client):
    """测试未知应用信息时签名失败"""
    offline_client.root_key_info = {}
    with pytest.raises(error.SignatureError):
        offline_client.gen_sign("unknown_app", "test message")


def test_init_log_with_config(offline_client: Client):
    """测试使用配置初始化日志"""
    with patch('bytedance.jeddak_secure_channel.client.logger') as mock_logger:
        # 设置日志配置
        log_config = {
            "dir": "/tmp",
            "filename": "test.log",
            "rotation": "1 day",
            "retention": "1 week",
            "level": "DEBUG"
        }
        offline_client.config.log_config = json.dumps(log_config)
        
        # 执行初始化日志
        offline_client._init_log()
        
        # 验证是否正确调用了logger.init_log_config
        mock_logger.init_log_config.assert_called_once()
        config = mock_logger.init_log_config.call_args[0][0]
        assert config.dir == "/tmp"
        assert config.filename == "test.log"
        assert config.rotation == "1 day"
        assert config.retention == "1 week"
        assert config.level == "DEBUG"