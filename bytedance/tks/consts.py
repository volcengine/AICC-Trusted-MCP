# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

import os


class Conf:
    # RELATIVE_CONST_INDEX_PATH = './templates/html/main/index.html'
    # CONST_INDEX_PATH = './html/main/index.html'

    # cookie key名称，用以保存登陆态的session token
    SESSION_COOKIE_KEY = "session_token"
    # 合法时间戳的最大误差，单位秒
    TIMESTAMP_THRESHOLD = 60
    # session token的过期时间，单位秒
    SESSION_TOKEN_EXPIRE = 86400
    # redis配置
    REDIS_HOST = "localhost"
    REDIS_PORT = 6379
    REDIS_USERNAME = "default"
    REDIS_PASSWORD = ""
    # pcc后端的分流配置
    BACKEND_MAP = {
        "/api/tks/": ["http://localhost:10000", "appID", "AK", "SK"],
        "/api/bgs/": ["http://localhost:10001", "UID", "AK", "SK"],
        "/api/ras/": ["http://localhost:10002", "UID", "AK", "SK"],
        "/api/rag/": ["http://localhost:10003", "UID", "AK", "SK"],
    }
    STREAM_PATH = "/api/rag/collection/query_and_generate"

    UPLOAD_FOLDER = os.path.abspath("./upload/rag/doc")
    DOWNLOAD_FOLDER = os.path.abspath("./download/attest/report")
    ALLOWED_EXTENSIONS = {".txt", ".pdf", ".pptx", ".docx"}

    # pcc后端转发配置
    PCC_UID = "jeddak_team"
    PCC_PASSWORD = "some_password"
    PCC_AK = "some_AK"
    PCC_SK = "some_SK"
    RING_ID = "id_1234"
    POLICY_ID = "policy_1234"
    KEY_TYPE = "SYMMETRIC_256"

    RAG_SERVICE_NAME = "rag-deployment"
    HANDLER_SERVICE_NAME = "ai-handler"
    # RAG_SERVICE = {
    #     "ServiceInfo": {
    #         "_key": "rag",
    #         "_val": "rag-deployment"
    #     }
    # }
    # HANDLER_SERVICE = {
    #     "ServiceInfo": {
    #         "_key": "handler",
    #         "_val": "ai-handler"
    #     }
    # }
    # SERVICE_INFO_LIST = {"rag": RAG_SERVICE, "handler": HANDLER_SERVICE}
    SERVICE_INFO = {"ServiceInfo": {"rag": RAG_SERVICE_NAME, "handler": HANDLER_SERVICE_NAME}}

    PCC_URL = "https://jeddakchain.bytedance.com"
    PATH_MAP = {
        "/api_mobile/doc/update": "/api/rag/collection",
        "/api_mobile/rag/query_and_generate": "/api/rag/collection/query_and_generate",
        # security使用同一个接口，如果改成不同，ENV处理逻辑要改
        "/api_mobile/security/status": "/api/ras/v1/attestation_user",
        "/api_mobile/security/status/download": "/api/ras/v1/attestation_user",
        "/api_mobile/key/set": "/api/tks/",
    }

    # RAG_ADDR = 'http://localhost:10003'
    # RAG_COLLECTION_CREATE_ENDPOINT = '/api/rag/collection/create'
    # RAS_SHIM_ADDR = "http://localhost:10002"

    DOC_STATUS_MAP = {"creating": "处理中", "ready": "处理完成", "failed": "处理失败"}

    SALT = "ai-handler-salt"

    def update_from_env(self):
        for k in self.BACKEND_MAP:
            env_key = f"ENV_{k.split('/')[-2].upper()}_URL"
            # ENV_TKS_URL, ...
            if env_key in os.environ:
                self.BACKEND_MAP[k][0] = os.getenv(env_key)
        for k in self.PATH_MAP:
            env_key = f"HANDLER_{k.split('/')[2].upper()}_URL"
            if env_key in os.environ:
                self.PATH_MAP[k] = os.getenv(env_key)
        self.REDIS_USERNAME = (
            os.getenv("ENV_REDIS_USERNAME") if "ENV_REDIS_USERNAME" in os.environ else None
        )
        self.REDIS_PASSWORD = (
            os.getenv("ENV_REDIS_PASSWORD") if "ENV_REDIS_PASSWORD" in os.environ else None
        )
        if "ENV_REDIS_HOST" in os.environ:
            self.REDIS_HOST = os.getenv("ENV_REDIS_HOST")
        if "ENV_REDIS_PORT" in os.environ:
            self.REDIS_PORT = int(os.getenv("ENV_REDIS_PORT"))
        if "ENV_SESSION_TOKEN_EXPIRE" in os.environ:
            self.SESSION_TOKEN_EXPIRE = int(os.getenv("ENV_SESSION_TOKEN_EXPIRE"))
        if "RAG_SERVICE_NAME" in os.environ:
            self.RAG_SERVICE_NAME = os.getenv("RAG_SERVICE_NAME")
        if "HANDLER_SERVICE_NAME" in os.environ:
            self.HANDLER_SERVICE_NAME = os.getenv("HANDLER_SERVICE_NAME")
        if "RING_ID" in os.environ:
            self.RING_ID = os.getenv("RING_ID")
        if "POLICY_ID" in os.environ:
            self.POLICY_ID = os.getenv("POLICY_ID")
        if "KEY_TYPE" in os.environ:
            self.KEY_TYPE = os.getenv("KEY_TYPE")
        if "PCC_UID" in os.environ:
            self.PCC_UID = os.getenv("PCC_UID")
        if "PCC_PASSWORD" in os.environ:
            self.PCC_PASSWORD = os.getenv("PCC_PASSWORD")
        if "PCC_AK" in os.environ:
            self.PCC_AK = os.getenv("PCC_AK")
        if "PCC_SK" in os.environ:
            self.PCC_SK = os.getenv("PCC_SK")
        os.makedirs(conf.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(conf.DOWNLOAD_FOLDER, exist_ok=True)
        print(f"final backend_map: {self.BACKEND_MAP}")


conf = Conf()
