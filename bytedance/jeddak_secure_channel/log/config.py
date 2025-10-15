# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

__all__ = [
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "CRITICAL",
    "FORMAT",
    "LogConfig"
]

# Log level constants
DEBUG = "DEBUG"
INFO = "INFO"
WARNING = "WARNING"
ERROR = "ERROR"
CRITICAL = "CRITICAL"
# Log output format
FORMAT = "{time:YYYY-MM-DD HH:mm:ss} | {level} | {file.path}:{line} | {message}"


class LogConfig:
    """Log configuration class."""

    def __init__(self):
        self.rotation = 100  # Size limit for log files in MB
        self.retention = 7  # Days to retain log files
        self.compression = "zip"
        self.dir = "jsc_log"
        self.filename = "jsc.log"
        self.format = FORMAT
        self.level = INFO
