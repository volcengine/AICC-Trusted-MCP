# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

import json
import time
import unittest
from datetime import datetime, timezone
from threading import Event
from unittest.mock import patch, MagicMock

from bytedance.jeddak_secure_channel.utils import (
    RepeatTimer,
    WeakMethod,
    weak_repeat_timer,
    request_bytedance_gateway
)
from bytedance.jeddak_secure_channel import error


def top_config():
    """返回测试用的TOP配置"""
    return {
        "ak": "test_ak",
        "sk": "test_sk",
        "service": "test_service",
        "region": "cn-beijing",
        "method": "POST",
        "action": "TestAction",
        "version": "2024-12-24",
    }


class TestRequestBytedanceGateway(unittest.TestCase):
    @patch('bytedance.jeddak_secure_channel.utils.requests.request')
    def test_request_bytedance_gateway_with_url(self, mock_request):
        """测试使用URL参数调用request_bytedance_gateway"""
        # 准备测试数据
        url = "test.bytedance.com"
        body = {"key": "value"}
        additional_headers = {"X-Custom-Header": "custom_value"}
        config = top_config()
        
        # 模拟响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = json.dumps({"Result": "success"})
        mock_response.json.return_value = {"Result": "success"}
        mock_request.return_value = mock_response
        
        # 固定时间，使签名可预测
        fixed_date = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        with patch('bytedance.jeddak_secure_channel.utils.datetime') as mock_datetime:
            mock_datetime.now.return_value = fixed_date
            
            # 调用被测函数
            response = request_bytedance_gateway(url, body, additional_headers, config)
            
            # 验证结果
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"Result": "success"})
            
            # 验证请求
            args, kwargs = mock_request.call_args
            self.assertEqual(kwargs["method"], "POST")
            self.assertEqual(kwargs["url"], f"https://{url}/?Action=TestAction&Version=2024-12-24")
            self.assertEqual(kwargs["headers"]["X-Custom-Header"], "custom_value")
            self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")
            self.assertEqual(kwargs["headers"]["Host"], "test.bytedance.com")
            self.assertEqual(json.loads(kwargs["data"]), body)


    @patch('bytedance.jeddak_secure_channel.utils.requests.request')
    def test_request_bytedance_gateway_with_url_rewrite(self, mock_request):
        """测试使用url_rewrite参数调用request_bytedance_gateway"""
        # 准备测试数据
        url = ""
        body = {"key": "value"}
        additional_headers = None
        config = top_config()
        config["url_rewrite"] = "https://rewrite.bytedance.com"
        
        # 模拟响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = json.dumps({"Result": "success"})
        mock_response.json.return_value = {"Result": "success"}
        mock_request.return_value = mock_response
        
        # 固定时间，使签名可预测
        fixed_date = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        with patch('bytedance.jeddak_secure_channel.utils.datetime') as mock_datetime:
            mock_datetime.now.return_value = fixed_date
            
            # 调用被测函数
            response = request_bytedance_gateway(url, body, additional_headers, config)
            
            # 验证结果
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"Result": "success"})
            
            # 验证请求
            args, kwargs = mock_request.call_args
            self.assertEqual(kwargs["url"], "https://rewrite.bytedance.com?Action=TestAction&Version=2024-12-24")
            self.assertEqual(kwargs["headers"]["Host"], "rewrite.bytedance.com")
            self.assertEqual(json.loads(kwargs["data"]), body)


    @patch('bytedance.jeddak_secure_channel.utils.requests.request')
    def test_request_bytedance_gateway_with_custom_url(self, mock_request):
        """测试使用config中的url参数调用request_bytedance_gateway"""
        # 准备测试数据
        url = "original.bytedance.com"
        body = {"key": "value"}
        additional_headers = None
        config = top_config()
        config["url"] = "custom.bytedance.com"
        
        # 模拟响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = json.dumps({"Result": "success"})
        mock_response.json.return_value = {"Result": "success"}
        mock_request.return_value = mock_response
        
        # 固定时间，使签名可预测
        fixed_date = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        with patch('bytedance.jeddak_secure_channel.utils.datetime') as mock_datetime:
            mock_datetime.now.return_value = fixed_date
            
            # 调用被测函数
            response = request_bytedance_gateway(url, body, additional_headers, config)
            
            # 验证结果
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"Result": "success"})
            
            # 验证请求
            # args, kwargs = mock_request.call_args
            # self.assertEqual(kwargs["url"], "https://custom.bytedance.com?Action=TestAction&Version=2024-12-24")


    @patch('bytedance.jeddak_secure_channel.utils.requests.request')
    def test_request_bytedance_gateway_with_http_scheme(self, mock_request):
        """测试使用http_scheme参数调用request_bytedance_gateway"""
        # 准备测试数据
        url = "test.bytedance.com"
        body = {"key": "value"}
        additional_headers = None
        config = top_config()
        config["http_scheme"] = "http"
        
        # 模拟响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = json.dumps({"Result": "success"})
        mock_response.json.return_value = {"Result": "success"}
        mock_request.return_value = mock_response
        
        # 固定时间，使签名可预测
        fixed_date = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        with patch('bytedance.jeddak_secure_channel.utils.datetime') as mock_datetime:
            mock_datetime.now.return_value = fixed_date
            
            # 调用被测函数
            response = request_bytedance_gateway(url, body, additional_headers, config)
            
            # 验证结果
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"Result": "success"})
            
            # 验证请求
            args, kwargs = mock_request.call_args
            self.assertEqual(kwargs["url"], f"http://{url}/?Action=TestAction&Version=2024-12-24")


    def test_request_bytedance_gateway_error_cases(self):
        """测试request_bytedance_gateway的错误情况"""
        # 准备测试数据
        url = ""
        config_url = ""
        url_rewrite = ""
        expected_error = "top_url is None"
        body = {"key": "value"}
        additional_headers = None
        config = top_config()
        config["url"] = config_url
        config["url_rewrite"] = url_rewrite
        
        # 验证异常
        with self.assertRaises(error.ParamError) as context:
            request_bytedance_gateway(url, body, additional_headers, config)
        
        self.assertIn(expected_error, str(context.exception))


class TestRepeatTimer(unittest.TestCase):
    def test_repeat_timer(self):
        """测试RepeatTimer类的功能"""
        # 准备测试数据
        counter = [0]
        event = Event()
        
        def increment_counter():
            counter[0] += 1
            if counter[0] >= 3:
                event.set()
        
        # 创建并启动定时器
        timer = RepeatTimer(0.1, increment_counter)
        timer.daemon = True  # 确保测试退出时线程也会退出
        timer.start()
        
        # 等待计数器增加到3
        event.wait(1.0)  # 最多等待1秒
        timer.cancel()
        
        # 验证结果
        self.assertGreaterEqual(counter[0], 3, "定时器应该至少执行3次")


class TestWeakMethod(unittest.TestCase):
    def test_weak_method(self):
        """测试WeakMethod类的功能"""
        # 准备测试数据
        class TestClass:
            def __init__(self):
                self.called = False
                self.args = None
                self.kwargs = None
            
            def test_method(self, *args, **kwargs):
                self.called = True
                self.args = args
                self.kwargs = kwargs
                return "result"
        
        # 创建对象和弱引用方法
        obj = TestClass()
        weak_method = WeakMethod(obj.test_method)
        
        # 调用弱引用方法
        result = weak_method(1, 2, key="value")
        
        # 验证结果
        self.assertTrue(obj.called, "方法应该被调用")
        self.assertEqual(obj.args, (1, 2), "参数应该正确传递")
        self.assertEqual(obj.kwargs, {"key": "value"}, "关键字参数应该正确传递")
        self.assertEqual(result, "result", "返回值应该正确")
    
    def test_weak_method_with_garbage_collected_object(self):
        """测试当对象被垃圾回收后WeakMethod的行为"""
        # 准备测试数据
        class TestClass:
            def test_method(self):
                return "result"
        
        # 创建对象和弱引用方法
        obj = TestClass()
        weak_method = WeakMethod(obj.test_method)
        
        # 删除对象引用
        del obj
        
        # 调用弱引用方法
        result = weak_method()
        
        # 验证结果
        self.assertIsNone(result, "当对象被垃圾回收后，方法调用应该返回None")


class TestWeakRepeatTimer(unittest.TestCase):
    def test_weak_repeat_timer(self):
        """测试weak_repeat_timer函数的功能"""
        # 准备测试数据
        class TestClass:
            def __init__(self):
                self.counter = 0
                self.event = Event()
            
            def increment_counter(self):
                self.counter += 1
                if self.counter >= 3:
                    self.event.set()
        
        # 创建对象和定时器
        obj = TestClass()
        timer = weak_repeat_timer(0.1, obj.increment_counter)
        timer.daemon = True  # 确保测试退出时线程也会退出
        timer.start()
        
        # 等待计数器增加到3
        obj.event.wait(1.0)  # 最多等待1秒
        timer.cancel()
        
        # 验证结果
        self.assertGreaterEqual(obj.counter, 3, "定时器应该至少执行3次")
    
    def test_weak_repeat_timer_with_garbage_collected_object(self):
        """测试当对象被垃圾回收后weak_repeat_timer的行为"""
        # 准备测试数据
        class TestClass:
            def __init__(self):
                self.counter = 0
            
            def increment_counter(self):
                self.counter += 1
        
        # 创建对象和定时器
        obj = TestClass()
        timer = weak_repeat_timer(0.1, obj.increment_counter)
        timer.daemon = True  # 确保测试退出时线程也会退出
        timer.start()
        
        # 保存弱引用
        import weakref
        weak_obj = weakref.ref(obj)
        
        # 删除对象引用
        del obj
        
        # 等待一段时间，让垃圾回收发生
        time.sleep(0.5)
        
        # 验证结果
        self.assertIsNone(weak_obj(), "对象应该被垃圾回收")
        # 注意：我们无法直接验证定时器是否停止，因为它是在对象被垃圾回收时自动停止的


if __name__ == "__main__":
    unittest.main()
