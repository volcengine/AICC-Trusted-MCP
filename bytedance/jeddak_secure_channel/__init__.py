__all__ = [
    "Client",
    "ClientConfig",
    "FileMode",
    "RaRequest",
    "RaResponse",
    "ResponseKey",
    "Server",
    "ServerConfig"
]

from .client import Client
from .config import ClientConfig, ServerConfig
from .crypto import FileMode, ResponseKey
from .ra import RaRequest, RaResponse
from .server import Server


def __getattr__(name: str) -> object:
    if name == "Server":
        from .server import Server
        return Server
    raise AttributeError(f"module {__name__} has no attribute {name}")
