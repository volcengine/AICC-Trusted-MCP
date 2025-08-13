__all__ = [
    "TKSError",
    "RAError",
]


class TKSError(Exception): ...  # noqa: E701


class RAError(TKSError): ...  # noqa: E701
