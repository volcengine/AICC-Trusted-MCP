# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

from enum import IntEnum
from flask import jsonify
from logger import logger


class ResponseUtil:
    
    @staticmethod
    def success(res, method=None):
        rsp = {"Result": res}
        # metadata is empty when success
        rsp["ResponseMetadata"] = {
        }
        logger.debug(f"success resp: {str(rsp)} success")
        new_rsp = jsonify(rsp)
        logger.debug(f"success resp: {str(new_rsp)} success")
        return new_rsp
    
    @staticmethod
    def fail(err_msg, method):
        rsp = {"Result": {}}
        rsp["ResponseMetadata"] = {
            "Method": method,
            "Error": {
                "Code": int(ErrorCode.FAIL),
                "Message": err_msg
            }
        }
        return jsonify(rsp)
    
    @staticmethod
    def internal_server_error(method, err_msg="interl server error"):
        rsp = {"Result": {}}
        rsp["ResponseMetadata"] = {
            "Method": method,
            "Error": {
                "Code": int(ErrorCode.INTERNAL_SERVER_ERROR),
                "Message": err_msg
            }
        }
        return jsonify(rsp)
    

class ErrorCode(IntEnum):
    SUCCESS = 0,
    FAIL = 1,
    INTERNAL_SERVER_ERROR = 1
